use std::fmt::{Debug, Formatter};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZero;
use crate::file_set::FileSet;
use crate::messages::Message;
use anyhow::{bail, Result};
use rand::random;
use savefile::IntrospectionError::IndexOutOfRange;
use savefile::prelude::Savefile;
use std::ops::Index;
use std::ops::{Range, RangeInclusive};
use std::path::PathBuf;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::debug;
use crate::client::ClientConfig;
use crate::server::{ServerConfig, ServerState};
use crate::util::setup_tracing;

pub const CHECKSUM_SIZE: usize = 16;
pub const CHECKSUM_SIZE_U64: u64 = CHECKSUM_SIZE as u64;

/// How many packets prior to end of burst that clients should consider EOF
/// approaching and make new request
pub const PRE_REQUEST_TIME: usize = 14;
pub const MIN_BURST_SIZE: usize = 15;
pub const MAX_BURST_SIZE: usize = 10000;

pub const MTU: u64 = 1400;
pub const MTU_USIZE: usize = MTU as usize;
pub const HEADER_SIZE: u64 = Message::PAYLOAD_HEADER_SIZE;
pub const PAYLOAD_SIZE: u64 = 1400 - HEADER_SIZE;
pub const PAYLOAD_SIZE_USIZE: usize = PAYLOAD_SIZE as usize;
pub const PAYLOAD_SIZE_USIZE_WITHOUT_HASH: usize = PAYLOAD_SIZE_USIZE - CHECKSUM_SIZE;

pub const DEFAULT_BIND_ADDRESS: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
pub const DEFAULT_MCAST_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(230, 1, 2, 3), 5523);


pub struct Position {
    pub phase: u16,
    pub offset: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Savefile)]
pub struct SessionId(u32);

impl SessionId {
    pub fn make_random() -> SessionId {
        SessionId(random())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Savefile)]
pub struct RetransmitGeneration(pub u16);


impl RetransmitGeneration {
    pub fn next(self) -> RetransmitGeneration {
        RetransmitGeneration(self.0.wrapping_add(1))
    }
}

/// Phases are always split on packet boundaries.
///
/// This means all packets can be identified by a
/// phase + index. The size of the last packet (only) can differ
/// from MTU.
#[derive(Savefile, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PacketIdx(u64);

impl PacketIdx {

    // TODO: Fail construction of invalid values through other means
    pub const INVALID: PacketIdx = PacketIdx(u64::MAX);

    pub(crate) fn saturating_sub(&self, index: IndexInPhase) -> PacketIdx {
        let new_index = self.index().0.saturating_sub(index.0);

        PacketIdx::new(self.phase(), IndexInPhase(new_index))
    }
}

impl Debug for PacketIdx {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}.{}",
            self.0>>48,
            self.0&0xffff_ffff_ffff
        )
    }
}

/// The index of a packet within a specific phase.
#[derive(Savefile, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IndexInPhase(pub u64);

/// Offset within a phase, in bytes
#[derive(Savefile, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PhaseOffset(pub u64);

impl PhaseOffset {
    pub const MAX_OFFSET: PhaseOffset = PhaseOffset(IndexInPhase::MAX_INDEX.0*PAYLOAD_SIZE);
    pub(crate) fn floor_index(&self) -> IndexInPhase {
        IndexInPhase(self.0 / PAYLOAD_SIZE)
    }
    pub(crate) fn ceil_index(&self) -> IndexInPhase {
        IndexInPhase(self.0.div_ceil(PAYLOAD_SIZE))
    }
}

impl IndexInPhase {
    pub const ZERO: IndexInPhase = IndexInPhase(0);
    pub const MAX_INDEX: IndexInPhase = IndexInPhase(0xffff_ffff_ffff);
}

trait PhaseSize {
    fn max_offset_exclusive(&self, phase: u16) -> Option<PhaseOffset>;
}

pub fn overlaps<T: Ord>(a: Range<T>, b: Range<T>) -> Option<Range<T>> {
    if a.end <= b.start || b.end <= a.start {
        return None;
    }
    Some((a.start.max(b.start)..b.end.min(a.end)).into())
}

/// Returns true if the range 'a' contains all of range 'b'.
///
/// Returns true if both are empty.
pub fn contains<T: Ord>(a: Range<T>, b: Range<T>) -> bool {
    a.start <= b.start && a.end >= b.end
}

pub fn calculate_phase_offset(index_in_phase: IndexInPhase) -> PhaseOffset {
    PhaseOffset(index_in_phase.0 * PAYLOAD_SIZE)
}

pub fn byte_range(index_in_phase: Range<IndexInPhase>) -> Range<PhaseOffset> {
    (PhaseOffset(index_in_phase.start.0 * PAYLOAD_SIZE)
        ..PhaseOffset((index_in_phase.end.0) * PAYLOAD_SIZE))
        .into()
}

impl PhaseOffset {
    pub const ZERO: PhaseOffset = PhaseOffset(0);

}

impl PacketIdx {
    pub fn deserialize(mut data: &mut Bytes) -> Result<PacketIdx> {
        Ok(PacketIdx(data.try_get_u64()?))
    }
    pub fn serialize(&self, mut data: &mut BytesMut) {
        data.put_u64(self.0);
    }

    pub fn new(phase: u16, index: IndexInPhase) -> Self {
        if index > IndexInPhase::MAX_INDEX {
            panic!("index too large");
        }
        Self((phase as u64) << 48 | index.0)
    }

    pub fn phase(self) -> u16 {
        (self.0 >> 48) as u16
    }
    pub fn index(self) -> IndexInPhase {
        const {
            if IndexInPhase::MAX_INDEX.0 != 0xffff_ffff_ffff {
                panic!("Internal error, inconsistency in MAX_INDEX and impl")
            }
        }
        IndexInPhase(self.0 & 0xffff_ffff_ffff)
    }

    fn phases(
        phases: Range<PacketIdx>,
        phase_size: &impl PhaseSize,
    ) -> impl Iterator<Item = (u16, Range<PhaseOffset>)> {
        (phases.start.phase()..=phases.end.phase()).filter_map(move |phase| {
            let range: Range<_> = ((if phases.start.phase() == phase {
                calculate_phase_offset(phases.start.index())
            } else {
                PhaseOffset::ZERO
            })..(if phases.end.phase() == phase {
                calculate_phase_offset(phases.end.index())
            } else {
                phase_size.max_offset_exclusive(phase)?
            }))
                .into();
            if range.start == range.end {
                return None;
            }
            Some((phase, range))
        })
    }
}

mod messages {
    use crate::{PacketIdx, PhaseOffset, RetransmitGeneration, SessionId, MTU_USIZE, IndexInPhase};
    use anyhow::{Result, bail};
    use arrayvec::ArrayVec;
    use savefile::prelude::Savefile;
    use savefile::{Deserializer, Serialize, Serializer};
    use std::ops::Range;
    use bytes::{Buf, BufMut, Bytes, BytesMut};

    pub const MAX_SECTIONS_PER_REQUEST: usize = 5;
    const MAX_SECTIONS_PER_PAYLOAD: usize = 5;

    #[derive(Savefile, PartialEq, Debug, Clone)]
    #[repr(u8)]
    pub enum LinkQualitySignal {
        KeepGoing,
        IncreaseWindow,
        LossDetected,
    }

    #[derive(Savefile, PartialEq, Debug)]
    pub struct Request {
        pub session_id: SessionId,
        pub phase: u16,
        pub retransmit_generation: RetransmitGeneration,
        /// Client did not receiver everything it wanted.
        pub loss: LinkQualitySignal,
        pub sections: ArrayVec<Range<IndexInPhase>, MAX_SECTIONS_PER_REQUEST>,
    }

    #[derive(Savefile, Clone, PartialEq, Eq, Debug)]
    pub struct Payload {
        pub session_id: SessionId,
        pub retransmit_generation: RetransmitGeneration,
        pub index: PacketIdx,
        /// We're approaching the end of the batch, clients
        /// are encouraged to make new requests (with retransmit_generation + 1)
        ///
        /// The new request should start at the given packedidx, to avoid retransmitting
        /// already queued stuff.
        pub eof_approaching: PacketIdx,
        pub data: Bytes,
    }

    impl Message {
        /// Size of a 0-payload `Message::Payload` message.
        ///
        /// Includes Message tag and payload size field.
        pub const PAYLOAD_HEADER_SIZE: u64 = 1 + 4 + 2 + 8 + 8 + 8;
    }

    #[derive(Savefile, PartialEq, Debug)]
    pub struct Announce {
        pub session_id: SessionId,
        pub fileset_size: u64,
        pub phases: u16,
        pub file_count: u64,
        pub total_size_bytes: u64,
    }

    #[derive(Savefile, PartialEq, Debug)]
    #[repr(u8,C)]
    pub enum Message {
        Request(Request),
        Payload(Payload),
        Announce(Announce),
        RequestAnnounce,
    }

    impl Message {
        pub(crate) fn session_id(&self) -> Option<SessionId> {
            match self {
                Message::Request(s) => Some(s.session_id),
                Message::Payload(p) => Some(p.session_id),
                Message::Announce(a) => Some(a.session_id),
                Message::RequestAnnounce => None,
            }
        }
        pub fn msg_serialize(&self, output: &mut BytesMut) {
            let bef = output.len();
            Serializer::bare_serialize(&mut output.writer(), 0, self).unwrap();
            assert!(output.len() - bef <= MTU_USIZE, "output was {} but MTU is {}", output.len(), MTU_USIZE);
        }

        pub fn msg_deserialize(mut input: Bytes) -> Result<Message> {
            //debug!("bef savefile: {:?}", input);
            let t= Ok(Deserializer::bare_deserialize(&mut input.reader(), 0)?);

            t
        }
    }
    #[cfg(test)]
    mod tests {
        use crate::messages::{Announce, LinkQualitySignal, Message, Payload, Request};
        use crate::{PacketIdx, PhaseOffset, RetransmitGeneration, SessionId};
        use compio::bytes::BytesMut;
        use smallvec::smallvec;

        fn roundtrip(message: Message) {
            let mut buf = BytesMut::new();
            message.msg_serialize(&mut buf);
            let roundtripped = Message::msg_deserialize(buf.freeze()).unwrap();
            assert_eq!(message, roundtripped);
        }
        #[test]
        fn roundtrip_messages() {
            roundtrip(Message::Request(Request {
                session_id: SessionId(42),
                retransmit_generation: RetransmitGeneration(37),
                phase: 3,
                sections: [std::ops::Range::from(PhaseOffset(0)..PhaseOffset(42))][..]
                    .try_into()
                    .unwrap(),
                loss: LinkQualitySignal::IncreaseWindow,
            }));
            roundtrip(Message::Payload(Payload {
                session_id: SessionId(42),
                retransmit_generation: RetransmitGeneration(37),
                index: PacketIdx::new(42, PhaseOffset::ZERO),
                eof_approaching: None,
                data: b"hello"[..].into(),
            }));
            roundtrip(Message::Announce(Announce {
                session_id: SessionId(42),
                fileset_size: 2,
                phases: 1,
                file_count: 43,
                total_size_bytes: 44,
            }));
            roundtrip(Message::RequestAnnounce);
        }
    }
}

mod disk_read_engine {
    use crate::file_set::{FileSet, Kind, OwnedSource, OwnedSourceId, Source};
    use crate::messages::Payload;
    use crate::{calculate_phase_offset, messages, IndexInPhase, PacketIdx, PhaseOffset, PhaseSize, RetransmitGeneration, SessionId, CHECKSUM_SIZE, CHECKSUM_SIZE_U64, PAYLOAD_SIZE, PAYLOAD_SIZE_USIZE, PAYLOAD_SIZE_USIZE_WITHOUT_HASH, PRE_REQUEST_TIME};
    use anyhow::{anyhow, bail, Result, Context};
    use indexmap::IndexMap;
    use indexmap::map::Entry;
    use lru::LruCache;
    use rangemap::RangeSet;
    use smallvec::SmallVec;
    use std::collections::{HashMap, HashSet};
    use std::io::{Read, Seek};
    use std::mem::MaybeUninit;
    use std::ops::{Range, RangeInclusive};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use bytes::BytesMut;
    use tracing::{debug, trace};

    const READ_WORKERS: usize = 16;
    const CACHE_SIZE_PACKETS: usize = 10000;
    const READ_ENGINE_BUF_SIZE: usize = 4096;
    const WORK_DIVISION_LENGTH: usize = 20 * READ_ENGINE_BUF_SIZE;

    struct BytesMutTake(BytesMut, usize, usize);

    fn split_large_ranges(
        mut range: Range<PhaseOffset>,
    ) -> impl Iterator<Item = Range<PhaseOffset>> {
        std::iter::from_fn(move || {
            let len = range.end - range.start;
            if len == 0 {
                return None;
            }
            if len < WORK_DIVISION_LENGTH as u64 {
                let ret = range.clone();
                range.start = range.end;
                return Some(ret);
            }
            let new = range.start.0 + WORK_DIVISION_LENGTH as u64;

            let mut ret = range.clone();
            ret.end.0 = new;
            range.start.0 = new;
            return Some(ret);
        })
    }

    struct WorkerRequest {
        path: PathBuf,
        offset_in_file: u64,
        file_size: u64,
        response: flume::Sender<Buf>,
    }

    #[derive(Debug)]
    pub enum ChecksummingState {
        Hashing { hasher: blake3::Hasher, offset: u64, hashed_bytes: Vec<u8> },
        Finished([u8; CHECKSUM_SIZE], Vec<u8>),
    }

    impl Default for ChecksummingState {
        fn default() -> Self {
            Self::Hashing {
                hasher: Default::default(),
                offset: 0,
                hashed_bytes: vec![],
            }
        }
    }

    pub struct ReadEngine {
        files: Arc<FileSet>,
        //TODO: GC?
        checksums: HashMap<OwnedSourceId, ChecksummingState>,
    }

    struct ReadAtom {
        offset_in_file: u64,
        size: u64,
        data: [u8; READ_ENGINE_BUF_SIZE],
        rest: Option<flume::Receiver<[u8; READ_ENGINE_BUF_SIZE]>>,
    }

    #[derive(Clone)]
    struct Buf {
        size: usize,
        data: [u8; READ_ENGINE_BUF_SIZE],
    }


    impl ReadEngine {
        /*
        async fn worker(
            session_id: SessionId,
            files: Arc<FileSet>,
            rx: flume::Receiver<WorkerRequest>) -> Result<()> {

            loop {
                debug!("WOrker working");
                let Ok(mut req) = rx.recv_async().await else {
                    debug!("Worker exiting");
                    return Ok(());
                };
                let mut file = compio::fs::File::open(&req.path).await?;

                let mut total_to_read = (req.file_size - req.offset_in_file);
                let to_read = total_to_read.min(READ_ENGINE_BUF_SIZE as u64);

                let mut buf = Buf {
                    size: to_read as usize,
                    data: [0;_],
                }
                    ;

                match file.read_exact_at(buf, req.offset_in_file).await.into_parts() {
                    (Ok(_), mut buf) => {

                        if let Ok(_) = req.response.send_async(buf.clone()).await {
                            if total_to_read > to_read {
                                req.offset_in_file += to_read;
                                total_to_read -= to_read;
                                loop {
                                    if req.offset_in_file >= req.file_size {
                                        break;
                                    }
                                    let to_read = total_to_read.min(READ_ENGINE_BUF_SIZE as u64);

                                    buf = match file.read_exact_at(buf, req.offset_in_file).await.into_parts() {
                                        (Ok(_), buf) => {
                                            if req.response.send_async(buf.clone()).await.is_err() {
                                                break;
                                            }
                                            req.offset_in_file += to_read;
                                            total_to_read -= to_read;
                                            buf
                                        }
                                        (Err(err), buf) => {
                                            panic!("Failed reading file: {}: {:?}", req.path.display(), err);
                                        }
                                    }
                                }
                            }
                        }

                    }
                    (Err(err), buf) => {
                        panic!("Failed reading file: {}: {:?}", req.path.display(), err);
                    }
                }
            }
        }


        fn fetch(&mut self, range: Range<PacketIdx>) {
            self.inflight.insert(range.into());
            debug!("CAching request sent");
            self.cacher_requests.send(range).expect("workers should continue to run");
        }

        fn process(&mut self, pkt: Payload)  {

            self.inflight.remove((pkt.index..self.successor(pkt.index)).into());

            debug_assert!(!self.packet_cache.contains_key(&pkt.index));

            self.packet_cache[self.packet_cache_insert_point] = pkt;
            self.packet_cache_insert_point+= 1;
            if self.packet_cache_insert_point >= CACHE_SIZE_PACKETS {
                self.packet_cache_insert_point = 0;
            }
        }*/

        pub fn get_packets(
            &mut self,
            retransmit_generation: RetransmitGeneration,
            session_id: SessionId,
            idx: Range<PacketIdx>,
            mut tx: impl Fn(Payload),
        ) -> Result<()> {
            //TODO: Reuse these buffers
            let mut tasks = Vec::new();

            trace!("visiting files to send idx {:?}", idx);
            self.files
                .visit(
                    idx.clone(),
                    //TODO: Change from crazy-many parameters to a struct
                    &mut |phase, phase_offset, source, offset, file_size, is_link| {
                        //TODO: Get rid of allocation here in 'to_owned'
                        tasks.push((phase, phase_offset, source.to_owned(), offset, file_size, is_link));
                    },
                )
                .expect("visit cannot fail");
            if !idx.is_empty() {
                assert!(!tasks.is_empty(), "no tasks for fetching range {idx:?}");
            }

            let mut buf = BytesMut::new();

            let mut output_idx = idx.clone();

            let task_len = tasks.len();

            for (task_i, (phase, phase_offset, source, offset, nominal_file_size, kind)) in
                tasks.into_iter().enumerate()
            {
                trace!("fetch task: {task_i}, offset = {offset}, nominal_file_size = {nominal_file_size}, kind = {kind:?}, phaserange {:?}", phase_offset);
                let real_file_size = nominal_file_size - CHECKSUM_SIZE_U64;

                // Size including any checksum (fragment)
                let full_chunk_size = (phase_offset.end - phase_offset.start);

                let chunk_size = if offset < real_file_size {
                    full_chunk_size.min(real_file_size - offset)
                }  else {
                    0
                };

                assert!(full_chunk_size + offset <= real_file_size + CHECKSUM_SIZE_U64,
                    "chunk_size = {}, offset = {}, this is greater than real file size {} + 16",
                    chunk_size, offset, real_file_size
                );
                buf.reserve(chunk_size as usize);
                let buflen = buf.len();

                match (kind, &source) {
                    (Kind::Normal, OwnedSource::Path(path)) => {
                        let mut file = std::fs::File::open(&path)?;
                        file.seek(std::io::SeekFrom::Start(offset as u64))?;
                        //TODO: Can we get rid of this initialization?
                        buf.resize(buflen + chunk_size as usize, 0);
                        file.read_exact(
                                &mut buf[buflen..]
                            )?;
                    }
                    (Kind::Symlink, OwnedSource::Path(path)) => {
                        let link = std::fs::read_link(&path)?;
                        let linkbytes= link.to_string_lossy();
                        let linkbuf = linkbytes.as_bytes();
                        assert_eq!(linkbuf.len() as u64, real_file_size);
                        buf.extend_from_slice(&linkbuf[offset as usize .. offset as usize + chunk_size as usize]);
                    }
                    (Kind::FileSet, OwnedSource::FileSet(fileset)) => {
                        assert_eq!(fileset.len() as u64, real_file_size);
                        buf.extend_from_slice(&fileset[offset as usize .. offset as usize + chunk_size as usize]);
                    }
                    x => {
                        unreachable!("unsupported read operation: {:?}", x)
                    }
                }

                //TODO: source.to_owned() allocates, fix that!
                let cksumstate = match self.checksums.get_mut(&source.to_owned_id()) {
                    Some(cksum) => cksum,
                    None => self.checksums.entry(source.to_owned_id()).or_default(),
                };

                // bytes read just now
                let cur_read_bytes = &buf[buflen..];
                assert_eq!(cur_read_bytes.len(), chunk_size as usize);

                match cksumstate {
                    ChecksummingState::Hashing {
                        hasher,
                        offset: already_hashed_offset,
                        hashed_bytes
                    } => {

                        if offset + chunk_size > *already_hashed_offset && offset <= *already_hashed_offset
                        {
                            if hashed_bytes.len() < (offset + chunk_size) as usize {
                                hashed_bytes.resize((offset + chunk_size) as usize, 0);
                                hashed_bytes[offset as usize..offset as usize+chunk_size as usize].copy_from_slice(&cur_read_bytes);
                            }

                            let new_part_start_at = *already_hashed_offset - offset;
                            let new_part_size = (offset + chunk_size) - *already_hashed_offset;
                            let upd_part = &cur_read_bytes[new_part_start_at as usize
                                ..(new_part_start_at + new_part_size) as usize];
                            //println!("Hashing with update-part: {}", String::from_utf8_lossy(upd_part));
                            hasher.update(
                                upd_part,
                            );
                            *already_hashed_offset = offset + chunk_size;
                            if offset + chunk_size == real_file_size {
                                let hash: [u8; CHECKSUM_SIZE] =
                                    hasher.finalize().as_bytes()[0..16].try_into().unwrap();
                                *cksumstate = ChecksummingState::Finished(hash, hashed_bytes.clone());
                            }
                        }
                    }
                    ChecksummingState::Finished(_,_) => {}
                }

                if offset <= real_file_size {
                    assert!(offset + chunk_size <= real_file_size);
                }
                assert!(offset + full_chunk_size <= real_file_size + CHECKSUM_SIZE_U64);

                if offset + full_chunk_size > real_file_size {
                    let checksum_read_start = offset.saturating_sub(real_file_size);
                    let checksum_read_end = offset + full_chunk_size - real_file_size;
                    let checksum_read = checksum_read_end - checksum_read_start;
                    trace!("copying checksum {:?}", checksum_read_start .. checksum_read_end);

                    buf.reserve(checksum_read as usize);
                    let source = source.to_owned();
                    buf.extend_from_slice(
                        &self.get_checksum(&source, real_file_size)?[checksum_read_start as usize..checksum_read_end as usize],
                    );
                }

                assert_eq!(
                    buf.len() - buflen,
                    full_chunk_size as usize
                );
                
                while !buf.is_empty() && ( task_i + 1 == task_len || buf.len() >= PAYLOAD_SIZE_USIZE ) {
                    let pktbuf =
                        buf.split_to(PAYLOAD_SIZE_USIZE.min(buf.len())).freeze();
                    trace!("server emitting payload: {} bytes", pktbuf.len());
                    let eof_approaching = ( output_idx.start == idx.end.saturating_sub(IndexInPhase(PRE_REQUEST_TIME as u64))).then_some(
                        idx.end
                    );
                    debug!("Sending {:?} eof {}", output_idx.start, eof_approaching.is_some());
                    tx(Payload {
                        session_id,
                        retransmit_generation,
                        index: output_idx.start,
                        eof_approaching: eof_approaching.unwrap_or(PacketIdx::INVALID),
                        data: pktbuf,
                    });
                    output_idx.start.0 += 1;
                }

            }

            Ok(())
        }

        pub async fn new(session_id: SessionId, files: FileSet) -> Self {
            let files = Arc::new(files);

            Self {
                files,
                checksums: Default::default(),
            }
        }

        fn successor(&self, index: PacketIdx) -> PacketIdx {
            let phase = index.phase();
            let phase_offset = calculate_phase_offset(index.index());
            if let Some(max_index_of_phase) = self.files.max_offset_exclusive(phase)
                && phase_offset >= max_index_of_phase
                && phase as usize != self.files.num_phases()
            {
                return PacketIdx::new(phase + 1, IndexInPhase::ZERO);
            }
            PacketIdx::new(phase, IndexInPhase(index.index().0 + 1))
        }

        fn get_checksum(
            &mut self,
            source: &OwnedSource,
            real_file_size: u64,
        ) -> Result<[u8; CHECKSUM_SIZE]> {
            let mut cksum = self.checksums.get_mut(&source.to_owned_id());
            if cksum.is_none() {
                cksum = Some(self.checksums.entry(source.to_owned_id()).or_default());
            }
            match cksum.as_mut().unwrap() {
                ChecksummingState::Hashing { hasher, offset, hashed_bytes } => {

                    match source {
                        OwnedSource::Path(path) => {
                            // TODO: Maybe don't re-hash everything
                            let hash : [u8;CHECKSUM_SIZE] = blake3::Hasher::new()
                                .update_mmap_rayon(&path).with_context(||anyhow!("checksumming file {}", path.display()))?   // mmaps the file + hashes it multithreaded
                                .finalize().as_bytes()[0..CHECKSUM_SIZE].try_into().unwrap();
                            trace!("Real file hashsum {:?}", hash);
                            Ok(hash)
                        }
                        OwnedSource::FileSet(buf) => {
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(buf);
                            let hash = hasher.finalize().as_bytes()[0..CHECKSUM_SIZE].try_into().unwrap();
                            trace!("Real fileset hashsum {:?}", hash);
                            Ok(hash)
                        }
                    }
                }
                ChecksummingState::Finished(sum, hashed_bytes) => {
                    #[cfg(debug_assertions)]
                    // TODO: Remove duplicate code
                    match source {
                        OwnedSource::Path(path) => {

                            let hash : [u8;CHECKSUM_SIZE] = blake3::Hasher::new()
                                .update_mmap_rayon(&path).with_context(||anyhow!("checksumming file {}", path.display()))?   // mmaps the file + hashes it multithreaded
                                .finalize().as_bytes()[0..CHECKSUM_SIZE].try_into().unwrap();

                            let mut hasher2 = blake3::Hasher::new();
                            hasher2.update(hashed_bytes);
                            let hash2 : [u8;CHECKSUM_SIZE] = hasher2.finalize().as_bytes()[0..CHECKSUM_SIZE].try_into().unwrap();


                            trace!("Hashed bytes: {}", path.display()/*, String::from_utf8_lossy(hashed_bytes)*/);
                            trace!("Real file hashsum (finished) {:?}, of hashed bytes: {:?}", hash, hash2);
                            assert_eq!(&hash, sum);
                        }
                        OwnedSource::FileSet(buf) => {
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(buf);
                            let hash: [u8;16] = hasher.finalize().as_bytes()[0..CHECKSUM_SIZE].try_into().unwrap();

                            assert_eq!(&hash, sum);
                        }
                    }
                    Ok(*sum)
                    //TODO: Use calculated hash
                    //Ok(*sum)
                },
            }
        }
    }
}

mod server {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::num::NonZeroUsize;
    use std::ops::Range;
    use std::panic::PanicHookInfo;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::disk_read_engine::ReadEngine;
    use crate::file_set::{FileSet, Meta};
    use crate::messages::{Announce, LinkQualitySignal, Message, Payload, Request};
    use crate::{overlaps, PacketIdx, RetransmitGeneration, SessionId, DEFAULT_BIND_ADDRESS, MAX_BURST_SIZE, MIN_BURST_SIZE, MTU, MTU_USIZE, DEFAULT_MCAST_ADDR, PhaseOffset};
    use anyhow::{Result, bail};
    use bytes::{Bytes, BytesMut};
    use lru::LruCache;
    use rangemap::RangeMap;
    use savefile::Serialize;
    use smallvec::SmallVec;
    use tokio::{select, spawn};
    use tracing::{debug, error, info, trace, warn};
    use crate::util::{reusable_multicast_socket, unicast_socket, TSocket, BSocket, blocking_socket, tokio_socket};

    #[derive(Clone, Debug)]
    pub struct ServerConfig {
        pub local_iface: Ipv4Addr,
        pub mcast_addr: SocketAddrV4,
        pub phases: Vec<PathBuf>,
    }

    impl Default for ServerConfig {
        fn default() -> Self {
            ServerConfig {
                local_iface: DEFAULT_BIND_ADDRESS,
                mcast_addr: DEFAULT_MCAST_ADDR,
                phases: vec![".".into()],
            }
        }
    }

    const PACK_LEADER_CHANGE_TIME: Duration = Duration::from_millis(100);

    pub struct ServerState {
        config: ServerConfig,
        logic_state: ServerLogicState,
        session_id: SessionId,
        multicast_socket: Arc<TSocket>,

    }

    struct Pacing {
        buffer_size_packets: usize,
    }

    impl Default for Pacing {
        fn default() -> Self {
            Self {
                buffer_size_packets: MIN_BURST_SIZE,
            }
        }
    }

    impl Pacing {
        pub fn report(&mut self, link_quality_signal: LinkQualitySignal) {
            match link_quality_signal {
                LinkQualitySignal::KeepGoing => {}
                LinkQualitySignal::IncreaseWindow => {
                    self.buffer_size_packets =
                        (((self.buffer_size_packets + 5) * 3) / 2).min(MAX_BURST_SIZE);
                }
                LinkQualitySignal::LossDetected => {
                    self.buffer_size_packets = (self.buffer_size_packets / 2).max(MIN_BURST_SIZE);
                    trace!("Reduce buffer size to {:?}", self.buffer_size_packets);
                }
            }
        }
    }



    struct ServerLogicState {
        session_id: SessionId,
        tx: flume::Sender<(RetransmitGeneration, Range<PacketIdx>)>,
        recently_sent_last_gc: RetransmitGeneration,
        current_retransmit_generation: RetransmitGeneration,

        pack_leader: SocketAddr,
        packet_leader_position: PacketIdx,
        pack_leader_last_head: Instant,
        pacing: Pacing,

        //TODO: Remove these?
        multicast_socket: Arc<TSocket>,


        time_when_last_out_of_date_retransmit_gen_accepted: Instant,

        meta: Meta,
    }

    impl ServerLogicState {
        fn send(
            &mut self,
            generation: RetransmitGeneration,
            range: impl Iterator<Item = Range<PacketIdx>>,
        ) {
            let mut budget = self.pacing.buffer_size_packets as u64;

            for mut r in range {
                let mut r_size = r.end.0 - r.start.0;
                if r_size > budget {
                    let overshot = r_size - budget;
                    r.end.0 -= overshot as u64;
                    r_size = budget;
                }
                trace!("Ordering backend to send {:?}: {:?}", generation, r);

                self.tx
                    .send((generation, r))
                    .expect("background task should not exit");

                budget -= r_size;
                if budget == 0 {
                    break;
                }
            }
        }
        fn process_request(&mut self, r: Request, src: SocketAddr) -> Result<()> {
            println!("Server received req: {:?}", r);
            if r.sections.is_empty() {
                bail!("empty request");
            }

            let first_section = &r.sections[0];
            let first_idx = PacketIdx::new(r.phase, first_section.start);
            if self.pack_leader != src && first_idx < self.packet_leader_position
                || self.pack_leader_last_head.elapsed() > PACK_LEADER_CHANGE_TIME
            {
                debug!("pack leader changed to {}", src);
                self.pack_leader = src;
                self.packet_leader_position = first_idx;
            }

            if r.retransmit_generation.0 != self.current_retransmit_generation.0 {
                trace!("Retransmit gen mismatch, {} vs {}",  r.retransmit_generation.0, self.current_retransmit_generation.0 );
                //TODO: Constants
                if self.time_when_last_out_of_date_retransmit_gen_accepted.elapsed() > Duration::from_secs(1) {
                    trace!("Retransmit gen mismatch timer elapsed");
                    self.time_when_last_out_of_date_retransmit_gen_accepted = Instant::now();
                }
                else {
                    trace!("ignore retransmit generation {} because current is {}",
                        r.retransmit_generation.0, self.current_retransmit_generation.0);
                    return Ok(());
                }
            }

            self.current_retransmit_generation = self.current_retransmit_generation.next();

            if self.pack_leader != src {
                trace!("peer {:?} is not pack leader {:?}. ", src, self.pack_leader);
                return Ok(());
            }
            self.pack_leader_last_head = Instant::now();

            if !matches!(r.loss, LinkQualitySignal::KeepGoing) {
                self.pacing.report(r.loss);
            }

            #[cfg(debug_assertions)]
            {
                for (ai, a) in r.sections.iter().enumerate() {
                    for b in r.sections.iter().skip(ai + 1) {
                        assert!(overlaps(a.clone(), b.clone()).is_none());
                    }
                }
            }

            self.send(
                self.current_retransmit_generation,
                r.sections.into_iter().map(|offset_range| {
                    PacketIdx::new(r.phase, offset_range.start)
                        ..PacketIdx::new(r.phase, offset_range.end)
                }),
            );
            Ok(())
        }

        async fn receive_message(&mut self, input: Bytes, src: SocketAddr) -> Result<()> {
            let msg = Message::msg_deserialize(input)?;
            if let Some(msg_session_id) = msg.session_id()
                && msg_session_id != self.session_id
            {
                bail!("colliding session discovered");
            }
            match msg {
                Message::Request(r) => {
                    trace!("server received request {:?}", r);
                    self.process_request(r, src)?;
                }
                Message::Payload(_) => {}
                Message::Announce(_) => {
                }
                Message::RequestAnnounce => {
                    ServerState::process_request_announce(self.session_id, &self.multicast_socket, src, &self.meta).await.expect("process request announce"); //TODO: Fix error hadnling
                }
            }

            Ok(())
        }
    }


    struct Accumulate {
        socket: Arc<BSocket>,
        max_buf_size_bytes: usize,
        send_buf: BytesMut,
        config: ServerConfig
    }

impl Accumulate {
    pub fn send(&mut self, payload: Payload) {
        let msg = Message::Payload(payload);
        let size_before = self.send_buf.len();
        msg.msg_serialize(&mut self.send_buf);
        let packet_size = self.send_buf.len() - size_before;

        if !self.send_buf.is_empty() && (packet_size != MTU_USIZE || self.send_buf.len() + MTU_USIZE > self.max_buf_size_bytes) {
            trace!("Sending {} packets, rem: {}", self.send_buf.len().div_ceil(MTU_USIZE), self.send_buf.len()%MTU_USIZE);
            self.flush()
        }
    }
    pub fn flush(&mut self) {
        if !self.send_buf.is_empty() {
            trace!("Sending {} final packets to {:?}", self.send_buf.len().div_ceil(MTU_USIZE), SocketAddr::V4(self.config.mcast_addr));
            if let Err(err) = self.socket
                .send_to(&self.send_buf, SocketAddr::V4(self.config.mcast_addr)) {
                error!("Failed to send {} byte buffer: {:?}", self.send_buf.len(), err);
                return;
            }
            //std::thread::sleep(Duration::from_secs(1));
            self.send_buf.clear();
        }
    }
}

    impl ServerState {
        async fn process_request_announce(
            session_id: SessionId,
            unicast_socket: &TSocket, dst: SocketAddr, meta: &Meta) -> Result<()> {
            let mut buf = BytesMut::new();
            let msg =Message::Announce(Announce {
                session_id: session_id,
                fileset_size: meta.fileset_buf.len() as u64,
                phases: meta.phases,
                file_count: meta.file_count,
                total_size_bytes: meta.total_size_bytes,
            });
            trace!("server sending announce: {:?} to {:?}", msg, dst);
            msg.msg_serialize(&mut buf);

            unicast_socket.send_to(&buf, dst).await?;

            Ok(())
        }

        pub async fn file_fetching_worker(
            rx: flume::Receiver<(RetransmitGeneration, Range<PacketIdx>)>,
            session_id: SessionId,
            config: ServerConfig,
            mut read_engine: ReadEngine,
            socket: Arc<BSocket>,
        ) -> Result<()> {


            //let max_buf_size_bytes = socket.max_send_batch() * MTU_USIZE;


            // Max GSO size is UDP max payload minus ip header + udp header
            const MAX_GSO_BYTES: usize = (u16::MAX as usize) - 8 - 20;
            // TODO: Terminology "send_batch" what is that?
            let max_buf_size_bytes = (socket.max_send_batch() * MTU_USIZE).min(MAX_GSO_BYTES);
            debug!("Max buf size: {}", max_buf_size_bytes);

            // TODO: Introduce constant
            let (socket_send_tx, socket_send_rx) = flume::bounded::<SendEvent>(1000);

            enum SendEvent {
                Prepare(Range<PacketIdx>),
                Payload(Payload)
            }

            std::thread::spawn(move||{
                let mut accumulator = Accumulate {
                    socket,
                    max_buf_size_bytes,
                    send_buf: BytesMut::with_capacity(max_buf_size_bytes),
                    config,
                };
                let mut cur_range = PacketIdx::INVALID .. PacketIdx::INVALID;
                #[derive(Clone)]
                enum PayloadBucket {
                    Awaiting,
                    Present(Payload),
                    Sent
                }
                let mut payloads = vec![];
                let mut pointer = 0;
                loop {
                    let pre_recv_work = Instant::now();
                    let Ok(ev) = socket_send_rx.recv() else {
                        info!("exiting socket send thread");
                        return;
                    };
                    if pre_recv_work.elapsed().as_millis() > 1 {
                        trace!("Receiving new work took {:?}", pre_recv_work.elapsed());
                    }
                    match ev {
                        SendEvent::Prepare(rng) => {
                            debug_assert!(cur_range.is_empty());
                            assert_eq!(rng.start.phase(), rng.end.phase());
                            payloads.clear();
                            cur_range = rng.clone();
                            payloads.resize((rng.end.0 - rng.start.0) as usize, PayloadBucket::Awaiting);
                            pointer = 0;
                        }
                        SendEvent::Payload(p) => {
                            assert!(p.index >= cur_range.start);
                            assert!(p.index < cur_range.end);
                            let offset = (p.index.0 - cur_range.start.0) as usize;
                            if matches!(payloads[offset], PayloadBucket::Awaiting) {
                                payloads[offset] = PayloadBucket::Present(p);
                            }
                        }
                    }

                    while pointer < payloads.len() && let PayloadBucket::Present(pkt) = &payloads[pointer] {
                        let PayloadBucket::Present(pkt) = std::mem::replace(&mut payloads[pointer], PayloadBucket::Sent) else {
                            unreachable!();
                        };
                        accumulator.send(pkt);
                        pointer += 1;
                    }
                    if pointer == payloads.len() {
                        accumulator.flush();
                    }
                }
            });



            std::thread::spawn(move||{


                //let mut prefetched_range: LruCache<PacketIdx, Payload> = LruCache::new(NonZeroUsize::new(1000).unwrap());
                loop {

                    let Ok((generation, pkts)) = rx.recv() else {
                        info!("worker exiting");
                        return;
                    };


                    trace!("file fetching worker ordered to fetch {:?}.{:?}", generation, pkts);
                    println!("file fetching worker ordered to fetch {:?}.{:?}", generation, pkts);
                    let bef_gp = Instant::now();

                    _ = socket_send_tx.send(SendEvent::Prepare(pkts.clone()));



                    let result = read_engine
                        .get_packets(generation, session_id, pkts, |pkt| {
                            _ = socket_send_tx.send(SendEvent::Payload(pkt));
                        });

                    let bef_el = bef_gp.elapsed();
                    //println!("get_packets took: {:?} send took {:?}, get itself {:?}", bef_el, send_took, bef_el - send_took);



                    trace!("file fetching worker done");
                    if let Err(err) = result {
                        error!("disk access failed {:?}", err);
                    }
                }
            });

            Ok(())
        }
        pub async fn run(config: ServerConfig) -> Result<()> {


            let (tx, rx) = flume::unbounded();

            let session_id = SessionId::make_random();


            let unicast_socket = Arc::new(blocking_socket(crate::util::unicast_socket(config.local_iface)?)?);

            let main_socket = Arc::new(tokio_socket(reusable_multicast_socket(config.mcast_addr, config.local_iface, true)?)?);

            info!("collecting file list");
            let mut files = FileSet::new(config.phases.clone())?;

            info!("Full Fileset: {:#?}", files);

            let meta = files.calculate_meta_and_assign_fileset_buf()?;
            let mut state = ServerState {
                config,
                logic_state: ServerLogicState {
                    session_id,
                    tx,
                    recently_sent_last_gc: RetransmitGeneration(0),
                    current_retransmit_generation: RetransmitGeneration(0),
                    pack_leader: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
                    packet_leader_position: PacketIdx(0),
                    pack_leader_last_head: Instant::now(),
                    pacing: Pacing::default(),

                    multicast_socket: main_socket.clone(),
                    time_when_last_out_of_date_retransmit_gen_accepted: Instant::now(),
                    meta
                },
                //TODO: don't store sessionid twice
                session_id,
                multicast_socket: main_socket.clone(),


            };


            let re = ReadEngine::new(state.session_id, files).await;

            info!("starting file fetching worker");
            Self::file_fetching_worker(rx, session_id, state.config.clone(), re, unicast_socket).await?;


            /*spawn(async move{
                let mut buf = BytesMut::with_capacity(MTU_USIZE);
                loop {
                    debug!("Server calling socket.recv_from on multicast socket");
                    buf.clear();
                    buf.reserve(MTU_USIZE);
                    let (size, src) = match main_socket.recv_single_from(&mut buf).await {
                        Ok(x) => x,
                        Err(err) => {
                            error!("receive failed: {:?}", err);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                    };

                    trace!("server received {}/{} byte announce packet on multicast", size, buf.len());
                    assert_eq!(size, buf.len());
                    let msg = Message::msg_deserialize(buf.split().freeze()); //TODO: Fix error hadnling
                    match msg {
                        Ok(Message::RequestAnnounce) => {
                            Self::process_request_announce(session_id, &main_socket, src, &meta).await.expect("process request announce"); //TODO: Fix error hadnling
                        }
                        Ok(_) => {
                            debug!("received non-announce-request on multicast socket.");
                        }
                        Err(x) => {
                            warn!("Message deserialize failed: {:?}", x);
                        }
                    }
                }
            });*/


            //TODO: Move to other method
            let mut buf = BytesMut::with_capacity(MTU_USIZE);

            loop {
                debug!("Server calling socket.recv_from");
                buf.clear();
                buf.reserve(MTU_USIZE);
                println!("Server calling socket.recv_from");
                let (size, src) = state.multicast_socket.recv_single_from(&mut buf).await?;
                println!("server received {}/{} main request packet", size, buf.len());

                assert_eq!(size, buf.len());
                match state
                    .logic_state
                    .receive_message(buf.split().freeze(), src).await
                {
                    Ok(()) => {
                    }
                    Err(err) => {
                        error!("failed to process incoming message {:?}", err);
                    }
                }
            }
        }
    }
}

mod client {
    use std::fs::{File, OpenOptions};
    use std::io::{IoSliceMut, Seek, SeekFrom, Write};
    use crate::file_set::{AtomicChecksum, FileSet};
    use crate::messages::{LinkQualitySignal, Message, Request};
    use crate::{PhaseOffset, SessionId, MTU_USIZE, PacketIdx, calculate_phase_offset, RetransmitGeneration, DEFAULT_BIND_ADDRESS, DEFAULT_MCAST_ADDR, CHECKSUM_SIZE_U64, CHECKSUM_SIZE, contains, IndexInPhase};
    use anyhow::{anyhow, bail, Result, Context};
    use savefile::{Deserialize, Deserializer, Serialize};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::ops::Range;
    use std::path::PathBuf;
    use std::pin::pin;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use arrayvec::ArrayVec;
    use bytes::{Buf, Bytes, BytesMut};
    use flume::Receiver;
    use futures_util::stream::FuturesUnordered;
    use futures_util::StreamExt;
    use indexmap::IndexSet;
    use rangemap::RangeSet;
    use tokio::spawn;
    use tokio::task::JoinHandle;
    use tracing::{debug, error, info, trace};
    use crate::util::{reusable_multicast_socket, unicast_socket, TSocket, tokio_socket};

    pub struct ClientConfig {
        pub paths: Vec<PathBuf>,
        pub bind_address: Ipv4Addr,
        pub mcast_addr: SocketAddrV4,
    }

    impl Default for ClientConfig {
        fn default() -> Self {
            ClientConfig {
                paths: vec!["out".into()],
                bind_address: DEFAULT_BIND_ADDRESS,
                mcast_addr: DEFAULT_MCAST_ADDR,
            }
        }
    }

    pub enum ClientStateEnum {
        Initializing,
        AwaitingFileSet {
            session_id: SessionId,
            phases: u16,
            server: SocketAddrV4,
            buf: Vec<u8>
        },
        Receiving {
            phases: Vec<(u16/*phase*/, PhaseOffset/*size*/)>,
            fileset: FileSetDiskWriter,
            session_id: SessionId,
            server: SocketAddrV4,
        },
        Invalid,
    }
    pub struct ClientState {
        state: ClientStateEnum,
        recv_socket: TSocket,
        send_socket: TSocket,
        config: ClientConfig,
    }

    trait BlockReceiver {
        async fn write(&mut self, dest: PacketIdx, data: Bytes, completed_range: Range<PhaseOffset>) -> Result<()>;
        fn try_write(&mut self, dest: PacketIdx, data: Bytes, completed_range: Range<PhaseOffset>) -> Result<bool>;

    }

    enum DiskWriteCommand {
        /// The Range is the completely transferred range that this write is a part of.
        ///
        /// The completeness assumes this write has occurred.
        Write(PacketIdx, Bytes, Range<PhaseOffset> /*completed subpart*/),
    }
    struct FileSetDiskWriter {
        jhs: Vec<JoinHandle<Result<()>>>,
        tx: flume::Sender<DiskWriteCommand>,
    }

    impl FileSetDiskWriter {
        pub async fn shutdown(mut self) -> Result<()> {
            let Self { jhs, tx } = self;
            drop(tx);

            for jh in jhs {
                match jh.await {
                    Ok(result) => {
                        result?;
                    }
                    Err(err) => {
                        bail!("Join error: {}", err);
                    }
                }
            }
            Ok(())
        }
    }

    pub const WRITE_BUFFER_SIZE_PACKETS: usize = 100;
    pub const HASHER_BUFFER_SIZE_PACKETS: usize = 100;

    /// TODO: Activate all workers again, just make sure one worker doesn't report
    /// file complete while it's written by others
    pub const WRITE_WORKERS: usize = 1;

    impl FileSetDiskWriter {
        pub async fn new(
            fileset: FileSet) -> FileSetDiskWriter {

            let fileset = Arc::new(fileset);
            let (tx,rx) = flume::bounded(WRITE_BUFFER_SIZE_PACKETS);

            let (hasher_tx, hasher_rx) = flume::bounded(HASHER_BUFFER_SIZE_PACKETS);

            let mut jhs = Vec::new();

            //TODO: Monitor join-handles and exit early when anything fails
            for _ in 0..WRITE_WORKERS {
                let hasher_rx: Receiver<(AtomicChecksum, PathBuf)> = hasher_rx.clone();
                jhs.push(spawn(async move {
                    loop{
                        let Ok((sum, path)) = hasher_rx.recv_async().await else {
                            break;
                        };
                        let hash : [u8;CHECKSUM_SIZE] = blake3::Hasher::new()
                            .update_mmap_rayon(&path).with_context(||anyhow!("checksumming file {}", path.display()))?   // mmaps the file + hashes it multithreaded
                            .finalize().as_bytes()[0..CHECKSUM_SIZE].try_into().unwrap();
                        if hash != sum.bytes() {
                            // TODO: better error handling?
                            trace!("Actual received file contents: {}", std::fs::read_to_string(&path).unwrap());
                            panic!("Hash mismatch for {}. Should: {:?}, was: {:?}", path.display(),
                                sum.bytes(), hash
                            );
                        }

                    }
                    Ok(())
                }));

            }

            struct CurFile {
                path: PathBuf,
                file: File,
                phase: u16,
            }

            for _ in 0..WRITE_WORKERS {
                let rx = rx.clone();
                let fileset = fileset.clone();
                let mut curfile : Option<CurFile> = None;
                let mut hasher_tx = hasher_tx.clone();

                jhs.push(spawn(async move {
                    // TODO: error handling

                    let mut cursor = fileset.make_cursor();

                    loop {
                        let Ok(ev) = rx.recv_async().await else {
                            return Ok(());
                        };
                        match ev {
                            // TODO: Buffer recycling?
                            DiskWriteCommand::Write(input_idx, mut bytes, completed_range) => {
                                //TODO: Error handling!
                                let input_phase = input_idx.phase();
                                let mut cur_phase_offset = calculate_phase_offset(input_idx.index());
                                let mut end_phase_offset = cur_phase_offset + bytes.len() as u64;

                                while cur_phase_offset != end_phase_offset {

                                    trace!("Processing phase {} {} byte write at {:?} (cur phase_offset.end: {:?})", input_phase, bytes.len(), cur_phase_offset, end_phase_offset);

                                    let need = cursor.seek(input_phase, cur_phase_offset)?;
                                    if let Some(curfile_inner) = curfile.as_mut() {
                                        if curfile_inner.path != need.path || curfile_inner.phase != input_phase {
                                            curfile = None;
                                        }
                                    }
                                    if curfile.is_none() {

                                        let path = need.path.to_path_buf();

                                        if let Some(parent) = path.parent() {
                                            std::fs::create_dir_all(parent)?;
                                        }

                                        curfile = Some(CurFile {
                                            path: path.clone(),
                                            file: OpenOptions::new().write(true).create(true).open(&path).with_context(
                                                ||format!("Opening file for writing {}", path.display()))?,
                                            phase: input_phase,
                                        });
                                    }


                                    let mut bytes_now = if  bytes.len() as u64 > need.file_size - need.file_offset {
                                        bytes.split_to(need.file_size as usize - need.file_offset as usize)
                                    } else {
                                        bytes.split_to(bytes.len())
                                    };

                                    let bytes_now_progress = bytes_now.len();


                                    let curfile_ref = curfile.as_mut().unwrap();
                                    let checksum_bytes = (need.file_offset + bytes_now.len() as u64).saturating_sub(need.file_size - CHECKSUM_SIZE_U64).min(bytes_now.len() as u64);

                                    if checksum_bytes > 0 {
                                        let checksum_byte_ref = &bytes_now[bytes_now.len()-checksum_bytes as usize..];
                                        let checksum_offset = need.file_offset.saturating_sub(need.file_size - CHECKSUM_SIZE_U64);
                                        trace!("Interpreting bytes at {:?} as checksum bytes for {:?}",
                                            cur_phase_offset, need.path.display()
                                        );
                                        need.checksum.partial_update(checksum_offset as usize, checksum_byte_ref);
                                        _ = bytes_now.split_off(bytes_now.len() - checksum_bytes as usize);
                                    }

                                    curfile_ref.file.seek(SeekFrom::Start(need.file_offset))?;
                                    curfile_ref.file.write_all(&bytes_now)?;

                                    if contains(completed_range.clone(), need.file_range.clone()) {
                                        let mut f = curfile.take().unwrap();
                                        //TODO: Make sure empty directories are created.
                                        // Could do as a pass when receiving bytes before empty dir in sequence
                                        f.file.set_len(need.file_size-CHECKSUM_SIZE_U64)?;
                                        //TODO: Change expensive asserts to debug_assert
                                        assert_eq!(need.file_range.end.0-need.file_range.start.0, need.file_size);
                                        debug_assert_eq!(
                                            std::fs::metadata(need.path).unwrap().len(),
                                            need.file_size - CHECKSUM_SIZE_U64
                                        );
                                        trace!("detected that file {} was complete, because completed range is {:?} and file range is {:?}", need.path.display(), completed_range, need.file_range);
                                        hasher_tx.send_async((need.checksum.clone(), need.path.to_path_buf())).await.expect("hashers do not die");
                                    }

                                    cur_phase_offset.0 += bytes_now_progress as u64;

                                }



                            }
                        }
                    }
                }));
            }

            FileSetDiskWriter {
                jhs,
                tx
            }

        }
    }

    impl BlockReceiver for FileSetDiskWriter {
        async fn write(&mut self, dest: PacketIdx, data: Bytes, completed_range: Range<PhaseOffset>) -> Result<()> {
            Ok(self.tx.send_async(DiskWriteCommand::Write(dest, data, completed_range)).await?)
        }

        fn try_write(&mut self, dest: PacketIdx, data: Bytes, completed_range: Range<PhaseOffset>) -> Result<bool> {
            Ok(self.tx.try_send(DiskWriteCommand::Write(dest, data, completed_range)).is_ok())
        }
    }


    impl BlockReceiver for Vec<u8> {
        async fn write(&mut self, dest: PacketIdx, data: Bytes, completed_range: Range<PhaseOffset>) -> Result<()> {
            self.try_write(dest, data, completed_range)?;
            Ok(())
        }

        fn try_write(&mut self, dest: PacketIdx, data: Bytes, completed_range: Range<PhaseOffset>) -> Result<bool> {
            if dest.phase() != 0 {
                bail!("wrong phase for initialization");
            }
            let dest = calculate_phase_offset(dest.index());
            trace!("block size: {}, dest: {}", self.len(), dest.0);
            self[dest.0 as usize .. dest.0 as usize + data.len()].copy_from_slice(&data);
            Ok(true)
        }
    }

    struct ClientProtocolHandler {
        //TODO: Remove
    }


    impl ClientProtocolHandler {
        pub async fn sync(
            session_id: SessionId,
            //TODO: Move sockets into some abstraction
            recv_socket: &TSocket,
            send_socket: &TSocket,
            mut receiver: &mut impl BlockReceiver,
            phases: &[(u16/*phase*/, PhaseOffset/*size*/)],
            peer: SocketAddrV4,

        ) -> Result<()> {

            /// Missing range per phase
            let mut missing = vec![];
            for (phase,phase_size) in phases.iter().copied() {
                if missing.len() < phase as usize + 1 {
                    missing.resize(phase as usize + 1, RangeSet::new());
                }
                let mut s = RangeSet::new();
                s.insert(PhaseOffset(0)..phase_size);
                missing[phase as usize] = s;
            }

            let mut sendbuf = BytesMut::new();

            async fn send_request(mut scratchbuf: &mut BytesMut, send_socket: &TSocket, phase: u16, session_id: SessionId, missing: impl Iterator<Item=&Range<PhaseOffset>>, retransmit_generation: RetransmitGeneration, loss: LinkQualitySignal, dst: SocketAddrV4, disallowed_range: Option<Range<PhaseOffset>>) -> Result<()> {
                let mut sections: ArrayVec<Range<IndexInPhase>, {super::messages::MAX_SECTIONS_PER_REQUEST}> = ArrayVec::new();
                trace!("Disallowed range: {:?}", disallowed_range);
                for mut rng in missing.cloned() {
                    trace!("Considering {:?}", rng);
                    if let Some(disallowed_range) = &disallowed_range {
                        if rng.start >= disallowed_range.start && rng.end <= disallowed_range.end {
                            trace!("wholly contained in disallowed");
                            continue;
                        }
                        if rng.end <= disallowed_range.start || rng.start >= disallowed_range.end {
                            // completely disjoint from disallowed range
                        } else {
                            // disallowed range overlaps
                            if rng.end > disallowed_range.end {
                                rng.start = disallowed_range.end;
                            }
                            if rng.start < disallowed_range.start {
                                rng.end = disallowed_range.start;
                            }
                            if rng.end <= rng.start {
                                trace!("wholly contained in disallowed2");
                                continue;
                            }
                        }
                    }
                    trace!("cut to: {:?}", rng);

                    let mut start = rng.start.floor_index();
                    let end = rng.end.ceil_index();

                    if let Some(prev) = (&sections).last() {
                        if end <= prev.end {
                            continue;
                        }
                        if start < prev.end {
                            start = prev.end;
                        }
                    }

                    trace!("Requesting {:?}", start..end);
                    if sections.try_push(start..end).is_err() {
                        break;
                    }
                }
                if sections.is_empty() {
                    // this can happen if we're processing a 'eof approaching' but there's
                    // actually nothing more to send.
                    trace!("Nothing more to send");
                    return Ok(());
                }
                let request = Message::Request(Request {
                    session_id,
                    phase,
                    retransmit_generation,
                    loss,
                    sections
                });
                scratchbuf.clear();
                trace!("sending request: {:?} to {:?}", request, dst);
                println!("sending request: {:?} to {:?}", request, dst);

                request.msg_serialize(&mut scratchbuf);
                send_socket.send_to(scratchbuf, SocketAddr::V4(dst)).await?;
                Ok(())
            }
            let mut last_retransmit_generation = RetransmitGeneration(0);
            /// We avoid stepping the generation back. But in degenerate cases,
            /// we may have to, to avoid getting stuck. So keep a retry count.
            let mut last_retransmit_generation_update_counter = 0;
            let mut loss: LinkQualitySignal = LinkQualitySignal::KeepGoing;
            let mut no_loss_counter = 0;

            let mut bytes_received = 0u64;
            let mut reception_start = Instant::now();
            let mut last_sped_print = Instant::now();


            /*
            TODO: cleanup
            let mut use_multi = true;

            let mut stream = None;
            let mut socket = None;
            let streamtemp2;
            let streamtemp ;

            if use_multi {

                streamtemp = pin!(streamtemp2);
                stream = Some(streamtemp);
            } else{
                socket = Some(recv_socket);
            }*/

            const TOTAL_BATCH_SIZE : usize = 64;
            let gro = recv_socket.match_recv_batch_size();
            // TODO: Strict terminology GRO/GSO vs whatever recvmmsg is splitting into
            let batch_size = TOTAL_BATCH_SIZE.div_ceil(gro).max(2);
            trace!("mmsg batch size: {}", batch_size);

            let mut iobufs = vec![vec![0u8;gro*MTU_USIZE]; batch_size];

            let mut io_vec_buffers: Vec<_> = vec![];

            for (i,buf) in (0..batch_size).zip(iobufs.iter_mut()) {
                io_vec_buffers.push(IoSliceMut::new(buf))
            }
            let mut meta_scratch = vec![];

            for (phase, phase_size) in phases {





                'phaseloop: loop {

                    debug!("working on phase {} in client", phase);
                    //let recv_start = Instant::now();

                    /* TODO: Cleanup
                    let r: std::result::Result<_, ()/*timeout*/> = if let Some(stream) = stream.as_mut() {
                        match compio::time::timeout(Duration::from_millis(250), stream.next()).await {
                            Ok(t) => {
                                Ok(t.unwrap()?)
                            }
                            ret => {
                                // Timeout
                                Err(())
                            }
                        }
                    } else {
                        let socket = socket.as_ref().unwrap();
                        match compio::time::timeout(Duration::from_millis(250), recv_socket.recv_managed(0)).await {
                            Ok(                                buf) => {
                                Ok(buf?.unwrap())
                            }
                            Err(_) => {Err(())}
                        }

                    };*/

                    //let r = compio::time::timeout(Duration::from_millis(250), recv_socket.recv(recvbuf)).await;
                    //println!("recv time {:?}", recv_start.elapsed());
                    debug!("client socket call completed or timed out");


                    let befrecv = Instant::now();
                    // TODO: Make this timeout variable

                    let result = tokio::time::timeout(Duration::from_millis(2250), recv_socket.recv_multi_from(&mut io_vec_buffers, &mut meta_scratch)).await;

                    //println!("Read time: {:?}", befrecv.elapsed());
                    let Ok(result) = result else {
                        trace!("timeout");
                        println!("timeout");
                        let phase_missing = &missing[*phase as usize];
                        send_request(&mut sendbuf,&send_socket, *phase, session_id,
                                               phase_missing.iter(), last_retransmit_generation, loss, peer, None
                        ).await?;
                        loss = LinkQualitySignal::KeepGoing;
                        continue;
                    };
                    let num_received = result?;

                    for buf in 0..num_received
                    {
                        let meta = meta_scratch[buf];
                        let msg_bytes:&[u8] = &(*io_vec_buffers[buf])[0..meta.len];

                        //TODO: better naming
                        for msg_bytes in msg_bytes.chunks(MTU_USIZE)
                        {
                            trace!("Received {} byte packet (batch of {})", msg_bytes.len(), num_received);

                            let msg = Message::msg_deserialize(Bytes::copy_from_slice(msg_bytes))?;
                            if let Some(msg_session_id) = msg.session_id() && msg_session_id != session_id {
                                // wrong session id
                            } else {
                                match msg {
                                    Message::Request(_) => {
                                        //TODO: Cleanup
                                        error!("ignore request");
                                    }
                                    Message::Payload(p) => {
                                        trace!("Received {:?} (eof: {:?})", p.index, p.eof_approaching);
                                        if p.index.phase() != *phase {
                                        } else {

                                            bytes_received += p.data.len() as u64 - CHECKSUM_SIZE_U64;
                                            if last_sped_print.elapsed() > Duration::from_millis(500) {
                                                println!("Speed: {} MB/s",
                                                    bytes_received as f64 / (1024.0 * 1024.0) / last_sped_print.elapsed().as_secs_f64()
                                                );
                                                bytes_received = 0;
                                                last_sped_print = Instant::now();
                                            }



                                            let retransmit_gen_delta = p.retransmit_generation.0.wrapping_sub(last_retransmit_generation.0);

                                            //TODO: Magic values
                                            if retransmit_gen_delta < u16::MAX - 100 || last_retransmit_generation_update_counter > 100 {
                                                last_retransmit_generation = p.retransmit_generation;
                                            } else {
                                                last_retransmit_generation_update_counter += 1;
                                            }

                                            let range_start = calculate_phase_offset(p.index.index());
                                            let range = range_start..PhaseOffset(range_start.0 + p.data.len() as u64);

                                            trace!("client received payload for range {:?} (data len {})", range, p.data.len());
                                            let phase_missing = &mut missing[*phase as usize];
                                            let holes_before = phase_missing.len();

                                            //TODO: Implement leadership support for client too


                                            if phase_missing.overlaps(&range) {
                                                trace!("received packet was useful");;

                                                phase_missing.remove(range.clone());
                                                let holes_after = phase_missing.len();
                                                if holes_after > holes_before {
                                                    println!("Loss detected: {:?}", phase_missing);
                                                    loss = LinkQualitySignal::LossDetected;
                                                    no_loss_counter = 0;
                                                } else {
                                                    no_loss_counter += 1;
                                                    if no_loss_counter > 100 && loss == LinkQualitySignal::KeepGoing {
                                                        loss = LinkQualitySignal::IncreaseWindow;
                                                        no_loss_counter = 0;
                                                    }
                                                }

                                                let missing_range_end = phase_missing.overlapping(range.end..PhaseOffset::MAX_OFFSET).next().cloned();
                                                let missing_range_start = phase_missing.overlapping(PhaseOffset::ZERO..range.start).rev().next().cloned();
                                                trace!("search for missing tree: {:?}", phase_missing);
                                                trace!("search for missing after {:?} got {:?}", range.end, missing_range_end);
                                                trace!("search for missing before {:?} got {:?}", range.start, missing_range_start);
                                                let consecutive_non_missing_range = missing_range_start.map(|x| x.end).unwrap_or(PhaseOffset::ZERO)..missing_range_end.map(|x| x.start).unwrap_or(PhaseOffset::MAX_OFFSET);
                                                trace!("current gap - non-missing offsets: {:?}", consecutive_non_missing_range);
                                                assert!(consecutive_non_missing_range.start <= consecutive_non_missing_range.end);

                                                let writ_time = Instant::now();
                                                if !receiver.try_write(p.index, p.data.clone(), consecutive_non_missing_range.clone())? {
                                                    receiver.write(p.index, p.data, consecutive_non_missing_range).await?;
                                                }
                                                //println!("receiver write took {:?}", writ_time.elapsed());


                                                if p.eof_approaching != PacketIdx::INVALID {
                                                    trace!("Eof approaching");
                                                    let next_to_send = p.eof_approaching;
                                                    assert_eq!(next_to_send.phase(), *phase); //TODO: Error handling

                                                    let allowed_range_start = calculate_phase_offset(next_to_send.index());
                                                    let disallowed_range = range.start .. allowed_range_start;


                                                    send_request(&mut sendbuf, &send_socket, *phase, session_id,
                                                                           phase_missing.iter(), last_retransmit_generation, loss.clone(), peer, Some(disallowed_range)
                                                    ).await?;
                                                    loss = LinkQualitySignal::KeepGoing;
                                                }
                                                {
                                                    if phase_missing.is_empty() {
                                                        debug!("Client exiting phase loop for phase {}", phase);
                                                        break 'phaseloop;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Message::Announce(_) => {
                                        error!("ignore announce");
                                    }
                                    Message::RequestAnnounce => {
                                        error!("ignore request announce");
                                    }
                                }
                            }
                        }
                    };
                }

            }

            Ok(())
        }
    }


    impl ClientState {
        pub async fn new(config: ClientConfig) -> Result<ClientState> {
            let send_socket = tokio_socket(unicast_socket(config.bind_address)?)?;
            let recv_socket = tokio_socket(reusable_multicast_socket(config.mcast_addr, config.bind_address, false)?)?;

            info!("client bound to socket");

            Ok(ClientState {
                state: ClientStateEnum::Initializing,
                recv_socket,
                send_socket,
                config,
            })
        }

        pub async fn init_session(
            &mut self,
        ) -> Result<(SessionId, u64 /*fileset size*/, u16 /*phases*/, SocketAddrV4)> {
            let req = Message::RequestAnnounce;



            loop {
                let mut buf = BytesMut::new();
                req.msg_serialize(&mut buf);
                trace!("sending request for announcement to {:?}", self.config.mcast_addr);
                self.send_socket
                    .send_to(&buf, SocketAddr::V4(self.config.mcast_addr))
                    .await?;
                let timeout = tokio::time::Instant::now() + Duration::from_secs(1);;

                while tokio::time::Instant::now() < timeout {
                    let mut databuf = BytesMut::with_capacity(MTU_USIZE);

                    let t = tokio::time::timeout_at(
                        timeout,
                        self.send_socket.recv_single_from(&mut databuf),
                    )
                        .await;
                    let Ok(r) = t else {
                        // Timeout
                        debug!("timeout waiting for announce");
                        continue;
                    };

                    let (size, SocketAddr::V4(src)) = r? else {
                        error!("Bad protocol in received message");
                        continue;
                    };

                    debug!("Client received {} byte message from {:?}", size, src);

                    let msg = Message::msg_deserialize(databuf.freeze())?;
                    debug!("Client received msg: {:?}", msg);
                    match msg {
                        Message::Request(_) => {}
                        Message::Payload(_) => {}
                        Message::Announce(a) => {
                            return Ok((a.session_id, a.fileset_size, a.phases, src));
                        }
                        Message::RequestAnnounce => {}
                    }

                }
            }
        }

        pub async fn run(&mut self) -> Result<()> {
            info!("client main loop starting");
            loop {
                match std::mem::replace(&mut self.state,  ClientStateEnum::Invalid) {
                    ClientStateEnum::Initializing => {
                        info!("client initializing");
                        let (session_id, fileset_size, phases, server) = self.init_session().await?;
                        if phases as usize != self.config.paths.len() + 1 {
                            bail!("need {} paths, because there are {} phases, not {}", phases-1, phases-1, self.config.paths.len());
                        }

                        let buf = vec![0; fileset_size as usize + CHECKSUM_SIZE];
                        self.state = ClientStateEnum::AwaitingFileSet {
                            session_id,
                            buf,
                            phases,
                            server,
                        };
                    }
                    ClientStateEnum::AwaitingFileSet { session_id, phases, server, mut buf } => {
                        info!("client loading fileset");
                        let phase_0_size = buf.len();
                        ClientProtocolHandler::sync(session_id, &self.recv_socket, &self.send_socket,
                                                    &mut buf, &[(0,PhaseOffset(phase_0_size as u64))], server
                        ).await?;

                        let calculated_checksum = blake3::hash(&buf[..buf.len()-CHECKSUM_SIZE]).as_bytes()[0..16].to_vec();
                        let received_checksum = &buf[buf.len()-CHECKSUM_SIZE..];
                        if &calculated_checksum != received_checksum {
                            bail!("Checksum mismatch - network corruption? Calculated checksum: {:?}, received: {:?}",
                                calculated_checksum, received_checksum
                            );
                        }

                        let mut fileset: FileSet = Deserializer::bare_deserialize(&mut buf.reader(), 0)?;

                        fileset.replace_phase_paths(&self.config.paths)?;

                        let phases = fileset.get_phases_excluding_first_phase();


                        let writer = FileSetDiskWriter::new(fileset).await;



                        self.state = ClientStateEnum::Receiving {
                            fileset: writer,
                            session_id: session_id,
                            server: server,
                            phases,
                        };
                    }
                    ClientStateEnum::Receiving { phases, mut  fileset, session_id, server } => {
                        info!("client receiving actual files, phases = {:?}", phases);

                        ClientProtocolHandler::sync(session_id, &self.recv_socket, &self.send_socket,
                                                    &mut fileset, &phases, server
                        ).await?;

                        fileset.shutdown().await?;

                        debug!("Sync done");
                        return Ok(());
                    }
                    ClientStateEnum::Invalid => {
                        unreachable!()
                    }
                }
            }
        }
    }
}

mod file_set {
    use std::borrow::Borrow;
    use crate::file_set::Entry::File;
    use crate::{byte_range, calculate_phase_offset, overlaps, IndexInPhase, PacketIdx, PhaseOffset, PhaseSize, CHECKSUM_SIZE, CHECKSUM_SIZE_U64};
    use anyhow::{Error, Result, anyhow, bail};
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use rayon::prelude::IntoParallelIterator;
    use std::ffi::{OsStr, OsString};
    use std::fs::{DirEntry, FileType, Metadata, Permissions};
    use std::ops::{Add, Sub};
    use std::ops::{Range, RangeInclusive};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use bytes::{BufMut, BytesMut};
    use savefile::prelude::Savefile;
    use savefile::Serializer;
    use tracing::{debug, error, info, trace};

    #[derive(Savefile,Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Kind {
        Normal,
        Symlink,
        /// Only used for the fileset itself
        FileSet,
    }

    const CHECKSUM_U32_WORDS: usize = CHECKSUM_SIZE/4;
    #[derive(Debug)]
    pub struct AtomicChecksum {
        data: [AtomicU32; CHECKSUM_U32_WORDS],
    }

    impl Clone for AtomicChecksum {
        fn clone(&self) -> Self {
            Self {
                data: [
                    AtomicU32::new(self.data[0].load(Ordering::Relaxed)),
                    AtomicU32::new(self.data[1].load(Ordering::Relaxed)),
                    AtomicU32::new(self.data[2].load(Ordering::Relaxed)),
                    AtomicU32::new(self.data[3].load(Ordering::Relaxed)),
                ]
            }
        }
    }
    impl Default for AtomicChecksum {
        fn default() -> Self {
            Self::new()
        }
    }
    impl AtomicChecksum {
        pub fn new() -> Self {
            Self {
                data: [
                    AtomicU32::new(0),
                    AtomicU32::new(0),
                    AtomicU32::new(0),
                    AtomicU32::new(0),
                ]
            }
        }
        pub fn update(&self, checksum: [u8; CHECKSUM_SIZE]) {
            for i in (0..CHECKSUM_U32_WORDS) {
                self.data[i].store(u32::from_le_bytes(checksum[4*i..4*(i+1)].try_into().unwrap()), Ordering::Relaxed);
            }
        }
        pub fn partial_update(&self, offset: usize, byts: &[u8]) {
            assert!(offset+ byts.len() <= CHECKSUM_SIZE);
            let mut temp = self.bytes();
            temp[offset..offset+byts.len()].copy_from_slice(byts);
            self.update(temp);
        }

        pub fn bytes(&self) -> [u8; CHECKSUM_SIZE] {
            let mut buf = [0u8; CHECKSUM_SIZE];
            for i in (0..CHECKSUM_U32_WORDS) {
                buf[4*i..4*(i+1)].copy_from_slice(&self.data[i].load(Ordering::Relaxed).to_le_bytes());
            }
            buf
        }
    }




    #[derive(Savefile,Debug)]
    struct RFile {
        name: PathBuf,
        // This is the size including the CHECKSUM
        size: u64,
        mode_bits: u32,
        offset: PhaseOffset,
        kind: Kind,
        #[savefile_ignore]
        #[savefile_introspect_ignore]
        has_checksum: AtomicBool,
        #[savefile_ignore]
        #[savefile_introspect_ignore]
        checksum: AtomicChecksum
    }

    impl Add<u64> for PhaseOffset {
        type Output = PhaseOffset;

        fn add(self, rhs: u64) -> Self::Output {
            PhaseOffset(self.0 + rhs)
        }
    }

    impl RFile {
        pub fn range(&self) -> Range<PhaseOffset> {
            self.offset..self.offset + self.size
        }
    }

    #[derive(Savefile,Debug)]
    struct RDirectory {
        offset: PhaseOffset,
        name: PathBuf,
        files: Vec<Entry>,
    }

    impl RDirectory {
        pub(crate) fn entry_for(&self, packet_offset: PhaseOffset) -> Option<&Entry> {
            let mut idx = match self.files
                .binary_search_by_key(&packet_offset, |entry| entry.first_offset())
            {
                Ok(found_index) => found_index,
                Err(found_index) => found_index - 1,
            };
            while idx < self.files.len() &&
                self.files[idx].last_offset_exclusive()<= packet_offset {
                idx += 1;
            }
            self.files.get(idx)
        }
    }

    #[derive(Savefile,Debug)]
    enum Entry {
        File(RFile),
        Directory(RDirectory),
        FileSet(Option<Arc<[u8]>>)
    }

    impl Entry {
        pub(crate) fn file_count(&self) -> u64 {
            match self {
                File(_) => {1}
                Entry::Directory(d) => {
                    d.files.iter().map(|x|x.file_count()).sum()
                }
                Entry::FileSet(_) => {0}
            }
        }
        pub(crate) fn file_size(&self) -> u64 {
            match self {
                File(f) => {f.size}
                Entry::Directory(d) => {
                    d.files.iter().map(|x|x.file_size()).sum()
                }
                Entry::FileSet(s) => {0}
            }
        }

        pub fn name(&self) -> &Path {
            match self {
                File(f) => &f.name,
                Entry::Directory(d) => &d.name,
                Entry::FileSet(_) => {Path::new("?fileset?")}
            }
        }
    }


    #[derive(Savefile, Debug)]
    pub struct FileSetPhaseEntry {
        #[savefile_ignore]
        path: PathBuf,
        entry: Entry,
    }

    #[derive(Savefile, Debug)]
    pub struct FileSet {
        /// Base and entry
        ///
        /// This does not include the fileset phase (phase 0)
        phases: Vec<FileSetPhaseEntry>,
    }

    impl FileSet {
        pub(crate) fn replace_phase_paths(&mut self, paths: &Vec<PathBuf>) -> Result<()> {
            if paths.len() +1  != self.phases.len() {
                bail!("Wrong number of input paths. The number of input paths must be {}, not {}", self.phases.len().saturating_sub(1), paths.len());
            }
            for (path, new_path) in self.phases.iter_mut().skip(1).zip(paths.iter()) {
                path.path = new_path.clone();
            }
            Ok(())
        }
    }

    pub struct Meta {
        pub fileset_buf: Arc<[u8]>,
        /// This is the number of phases excluding the FileSet phase
        pub phases: u16,
        pub file_count: u64,
        pub total_size_bytes: u64,
    }

    fn mode(permissions: Permissions) -> u32 {
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.mode() as u32
        }
        #[cfg(not(target_family = "unix"))]
        {
            511 // 0777
        }
    }

    pub struct FileSetCursor<'a> {
        set: &'a FileSet,
        cur_phase: u16,
        stack: Vec<&'a Entry>,
        path: PathBuf,
    }

    #[derive(Debug)]
    pub struct WriteNeed<'a> {
        pub path: &'a Path,
        pub file_offset: u64,
        // Size *including* checksum
        pub file_size: u64,
        pub checksum: &'a AtomicChecksum,
        /// PhaseOffset range occupied by complete file (including checksum)
        pub file_range: Range<PhaseOffset>,
    }

    impl<'a> FileSetCursor<'a> {
        fn cur_range(&self) -> Range<PhaseOffset> {
            if self.set.num_phases() == 0 {
                return (PhaseOffset::ZERO..PhaseOffset::ZERO).into();
            };

            if let Some(top) = self.stack.last() {
                (top.first_offset()..top.last_offset_exclusive()).into()
            } else {
                (self.set.phases.first().unwrap().entry.first_offset()
                    ..self.set.phases.last().unwrap().entry.last_offset_exclusive())
                    .into()
            }
        }
        pub fn seek(&mut self, packet_phase: u16, packet_offset: PhaseOffset) -> Result<WriteNeed> {
            if packet_phase as usize >= self.set.num_phases() {
                bail!("Bad phase");
            }
            if packet_phase == 0 {
                bail!("FileSetCursor is not intended for use with phase 0");
            }

            loop {
                if self.cur_phase != packet_phase {
                    self.path.clear();
                    self.stack.clear();
                    self.cur_phase = packet_phase;
                }
                if !self.stack.is_empty() && !self.cur_range().contains(&packet_offset) {
                    //debug!("Backing up, cur range is {} , {:?} which doesn't encompass packet {:?}", self.path.display(), self.cur_range(), packet_offset);
                    self.stack.pop();
                    self.path.pop();
                    continue;
                }

                if self.stack.is_empty() {
                    let FileSetPhaseEntry{ path, entry } = &self.set.phases[packet_phase as usize];
                    self.path = path.clone();
                    self.path.push(entry.name());
                    self.stack.push(entry);
                }

                let top = self.stack.last().unwrap();
                match top {
                    File(f) => {
                        let file_offset = packet_offset.0 - f.offset.0;
                        debug_assert!(file_offset < f.size);
                        return Ok(WriteNeed {
                            path: &self.path,
                            file_offset,
                            file_size: f.size,
                            checksum: &f.checksum,
                            file_range: f.offset .. f.offset + f.size,
                        });
                    }
                    Entry::Directory(d) => {
                        let entry = d.entry_for(packet_offset).expect("we know entry contains range");
                        debug!("Pushing name {:?}, seek: {}.{:?}, parent start: {:?} sub item range: {:?}", entry.name(), packet_phase, packet_offset,
                                d.offset,
                                 entry.first_offset()..entry.last_offset_exclusive());
                        self.path.push(entry.name());
                        self.stack.push(entry);
                    }
                    Entry::FileSet(_) => {
                        unreachable!("fileset is only in phase 0")
                    }
                }
            }
        }
    }

    impl PhaseSize for FileSet {
        /// Returns None if phase is empty
        fn max_offset_exclusive(&self, phase: u16) -> Option<PhaseOffset> {
            Some(
                self.phases[phase as usize]
                    .entry
                    .last_offset_exclusive()
            )
        }
    }

    impl FileSet {

        /// Phase 0 is exlcuded
        pub(crate) fn get_phases_excluding_first_phase(&self) -> Vec<(u16, PhaseOffset)> {
            let mut output = vec![];
            for (i,FileSetPhaseEntry{entry,..}) in self.phases.iter().enumerate().skip(1) {
                output.push((i as u16, entry.last_offset_exclusive()))
            }
            output
        }


        pub fn make_cursor<'a>(&'a self) -> FileSetCursor<'a> {
            FileSetCursor {
                set: self,
                cur_phase: 0,
                stack: vec![],
                path: Default::default(),
            }
        }

        pub fn num_phases(&self) -> usize {
            self.phases.len()
        }

        pub fn calculate_meta_and_assign_fileset_buf(&mut self) -> Result<Meta> {
            let mut fileset_buf = BytesMut::new();

            Serializer::bare_serialize(&mut (&mut fileset_buf).writer(), 0, self)?;

            let fileset_buf: Arc<[u8]> = fileset_buf.to_vec().into();

            let phase0 = &mut self.phases.get_mut(0).expect("phase 0 should always have been allocated").entry;
            match phase0 {
                File(_) => {}
                Entry::Directory(_) => {}
                Entry::FileSet(fs) => {
                    assert!(fs.is_none());
                    *fs = Some(fileset_buf.clone());

                }
            }

            Ok(Meta {
                fileset_buf,
                phases: self.phases.len() as u16,
                file_count: self.phases.iter().map(|x|x.entry.file_count()).sum(),
                total_size_bytes: self.phases.iter().map(|x|x.entry.file_size()).sum(),
            })
        }

        /// Always visits in PhaseOffset-order, guaranteed
        pub fn visit<'a>(
            &self,
            range: Range<PacketIdx>,
            f: &mut impl FnMut(u16, Range<PhaseOffset>, Source, u64, u64, Kind)
        ) -> Result<()> {

            for (phase, range) in PacketIdx::phases(range, self) {
                trace!("Fetch sub-range {}.{:?}", phase, range);
                let byte_range = range;
                let mut cwd = self.phases[phase as usize].path.clone();
                self.phases[phase as usize].entry.visit(
                    &mut cwd,
                    byte_range,
                    &mut |phase_offset, source, offset, file_size, is_link| {
                        f(phase, phase_offset, source, offset, file_size, is_link)
                    },
                )?;
            }
            Ok(())
        }

        pub fn new(items: Vec<impl AsRef<Path>>) -> Result<FileSet> {

            let mut items: Vec<PathBuf> = items.iter().map(|x| x.as_ref().into()).collect();
            info!("fileset created from paths: {:#?}", items);


            let mut phases = vec![
                FileSetPhaseEntry {
                    //TODO: get rid of ugly place-holder value
                    path: "?fileset?".into(),
                    entry: Entry::FileSet(None),
                }
            ];

            let mut non_fileset_phases : Vec<_> = items
                .par_iter()
                .map(|x| Ok(
                    FileSetPhaseEntry {
                        path: x.clone(),
                        entry:Entry::new(x)?
                    }
                )).collect::<Result<_>>()?
            ;

            phases.extend(non_fileset_phases);
            Ok(FileSet {
                phases
            }
            .assign_offsets())
        }

        fn assign_offsets(mut self) -> Self {
            Self {
                phases: self
                    .phases
                    .into_iter()
                    .map(|mut x| {
                        x.entry.assign_offsets(&mut PhaseOffset(0));
                        x
                    })
                    .collect(),
            }
        }
    }

    impl Sub for PhaseOffset {
        type Output = u64;

        fn sub(self, rhs: Self) -> Self::Output {
            self.0 - rhs.0
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum OwnedSourceId {
        Path(PathBuf),
        FileSet,
    }
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum OwnedSource {
        Path(PathBuf),
        FileSet(Arc<[u8]>),
    }

    #[derive(Clone, Debug)]
    pub enum Source<'a> {
        Path(&'a Path),
        FileSet(&'a Arc<[u8]>)
    }

    impl OwnedSource {
        pub fn to_owned_id(&self) -> OwnedSourceId {
            match self {
                OwnedSource::Path(p) => {OwnedSourceId::Path(p.to_path_buf())}
                OwnedSource::FileSet(_) => {OwnedSourceId::FileSet}
            }
        }
    }
    impl<'a> Source<'a> {

        pub fn to_owned(&self) -> OwnedSource {
            match self {
                Source::Path(p) => {OwnedSource::Path(p.to_path_buf())}
                Source::FileSet(a) => {OwnedSource::FileSet(Arc::clone(a))}
            }
        }
    }

    impl Entry {
        fn visit(
            &self,
            cwd: &mut PathBuf,
            range: Range<PhaseOffset>,
            func: &mut impl FnMut(Range<PhaseOffset>, Source, u64, u64, Kind),
        ) -> Result<()> {
            if range.start >= self.last_offset_exclusive() {
                bail!("Range {range:?} not present in Entry");
            }

            match self {
                Entry::File(f) => {
                    if let Some(overlap) = overlaps(f.range(), range.clone()) {
                        cwd.push(&f.name);
                        func(overlap.clone(), Source::Path(&cwd), overlap.start - f.offset, f.size, f.kind);
                        cwd.pop();
                    } else {
                        trace!("Ignoring file {} because it doesn't overlap range", f.name.display());
                    }
                    Ok(())
                }
                Entry::Directory(d) => {
                    if d.files.is_empty() {
                        // Can't be any bytes in here to visit
                        trace!("Ignoring directory {} because it's empty", d.name.display());
                        return Ok(());
                    }
                    let mut cur = match d
                        .files
                        .binary_search_by_key(&range.start, |entry| entry.first_offset())
                    {
                        Ok(x) => x,
                        Err(x) => {
                            x.saturating_sub(1)
                        },
                    };
                    cwd.push(&d.name);
                    trace!("recursing into dir {}", d.name.display());
                    while cur < d.files.len() {
                        if d.files[cur].first_offset() >= range.end {
                            // Done
                            break;
                        }
                        if d.files[cur].last_offset_exclusive() > range.start {
                            d.files[cur].visit(cwd, range.clone(), func)?;
                        } else {
                            trace!("Ignoring file {:?}.{cur} because it doesn't overlap range", d.name.display());
                        }
                        cur += 1;
                    }
                    cwd.pop();
                    Ok(())
                }
                Entry::FileSet(Some(buf)) => {
                    if let Some(overlap) = overlaps(PhaseOffset(0)..PhaseOffset(buf.len() as u64 + CHECKSUM_SIZE_U64), range.clone()) {
                        let offset = PhaseOffset(0);
                        let size = buf.len() as u64 + CHECKSUM_SIZE_U64;
                        func(overlap.clone(), Source::FileSet(buf), overlap.start - offset, size, Kind::FileSet);
                    }
                    Ok(())
                }
                Entry::FileSet(None) => {
                    bail!("visited FileSet entry before it had been populated")
                }
            }
        }
        fn first_offset(&self) -> PhaseOffset {
            match self {
                Entry::File(f) => f.offset,
                Entry::Directory(d) => d.offset,
                Entry::FileSet(_) => {PhaseOffset(0)}
            }
        }
        fn last_offset_exclusive(&self) -> PhaseOffset {
            match self {
                Entry::File(f) => f.offset + f.size,
                Entry::Directory(d) => {
                    if let Some(last) = d.files.last() {
                        last.last_offset_exclusive()
                    } else {
                        d.offset
                    }
                }
                Entry::FileSet(Some(d)) => {PhaseOffset(d.len() as u64 + CHECKSUM_SIZE_U64)}
                Entry::FileSet(_) => panic!("last_offset_exclusive called before FileSet added to structure")
            }
        }
        fn assign_offsets(&mut self, accum_offset: &mut PhaseOffset) {
            match self {
                Entry::File(f) => {
                    f.offset = *accum_offset;
                    accum_offset.0 += f.size;
                }
                Entry::Directory(d) => {
                    d.offset = *accum_offset;
                    for item in &mut d.files {
                        item.assign_offsets(accum_offset);
                    }
                }
                Entry::FileSet(_) => {
                }
            }
        }

        fn new(item: impl AsRef<Path>) -> Result<Entry> {
            let item: &Path = item.as_ref();
            let meta: Metadata = std::fs::metadata(item)?;
            Ok(if !meta.is_dir() {
                Entry::create_file(item.into(), meta)?
            } else {
                Entry::scan(item, "".into())?
            })
        }
        fn scan(name: &Path, logical_name: PathBuf) -> Result<Entry> {
            let dir: Vec<std::io::Result<DirEntry>> = std::fs::read_dir(name)?.collect();

            Ok(Entry::Directory(RDirectory {
                // Will be filled later
                offset: PhaseOffset(0),
                name: logical_name,
                files: dir
                    .into_par_iter()
                    .filter_map(
                        |entry: std::io::Result<DirEntry>| -> Option<Result<Entry>> {
                            let entry: DirEntry = match entry {
                                Ok(entry) => entry,
                                Err(err) => {
                                    return Some(Err(anyhow!("failed to read dir entry: {err}")));
                                }
                            };
                            let meta: Metadata = match entry.metadata() {
                                Ok(meta) => meta,
                                Err(err) => {
                                    return Some(Err(anyhow!("failed to get file metadata: {err}")));
                                }
                            };
                            let typ = meta.file_type();
                            if typ.is_file() || typ.is_symlink() {
                                return Some(Self::create_file(entry.file_name().into(), meta));
                            } else if typ.is_dir() {
                                return Some(Entry::scan(&entry.path(), entry.file_name().into()));
                            } else {
                                error!("{:?} is not a file or symlink", entry.path());
                                return None;
                            }
                        },
                    )
                    .collect::<Result<Vec<Entry>>>()?,
            }))
        }

        fn create_file(name: PathBuf, meta: Metadata) -> Result<Entry, Error> {
            Ok(Entry::File(RFile {
                name,
                size: meta.len() + CHECKSUM_SIZE as u64,
                mode_bits: mode(meta.permissions()),
                // Set to the correct value in a later pass
                offset: PhaseOffset(0),
                kind: if meta.file_type().is_symlink() {
                    Kind::Symlink
                } else {
                    Kind::Normal
                },
                has_checksum: Default::default(),
                checksum: Default::default(),
            }))
        }
    }

    impl FileSet {}

    #[cfg(test)]
    mod tests {
        use crate::disk_read_engine::ReadEngine;
        use crate::file_set::{AtomicChecksum, Entry, FileSet};
        use crate::{IndexInPhase, PacketIdx, PhaseOffset, RetransmitGeneration, SessionId};
        use std::fs::read_dir;

        #[test]
        fn scan_home() {
            let files = Entry::new("/home/anders").unwrap();
            debug!("Done");
            //debug!("Files: {:?}", files);
        }
        #[test]
        fn scan_home2() {
            let files = FileSet::new(vec!["/home/anders/sample"]).unwrap();


            files
                .visit(
                    (PacketIdx::new(0, PhaseOffset::ZERO)..PacketIdx::new(0, PhaseOffset(1000)))
                        .into(),
                    &mut |phase, idx, path, offset_in_file, file_size, link| {
                        debug!(
                            "Visit: {} / {:?} {:?} offset {}",
                            phase, idx, path, offset_in_file
                        );
                    },
                )
                .unwrap();
            debug!("Done");
            //debug!("Files: {:#?}", files);

            let mut cursor = files.make_cursor();

            let need = cursor.seek(0, PhaseOffset(1000)).unwrap();
            debug!("Cursor result: {:?}", need);
            let need = cursor.seek(0, PhaseOffset(4000)).unwrap();
            debug!("Cursor result: {:?}", need);
            let need = cursor.seek(0, PhaseOffset(4001)).unwrap();
            debug!("Cursor result: {:?}", need);
            let need = cursor.seek(0, PhaseOffset(000)).unwrap();
            debug!("Cursor result: {:?}", need);
        }

        #[compio::test]
        async fn read_engine() {
            let files = FileSet::new(vec!["/home/anders/sample"]).unwrap();
            let mut eng = ReadEngine::new(SessionId(0), files).await;

            let pkt = eng
                .get_packets(
                    RetransmitGeneration(0),
                    SessionId(0),
                    (PacketIdx::new(0, PhaseOffset(0))..PacketIdx::new(0, PhaseOffset(2))).into(),
                    async |pkt| {
                        debug!("Sending: {:?}", pkt);
                    },
                )
                .await;

            debug!("Pkt: {:?}", pkt);
        }

        #[test]
        fn atomic_checksum() {
            let mut sum = AtomicChecksum::new();
            sum.update([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
            assert_eq!(sum.bytes(), [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);

            sum.partial_update(15, &[1]);
            assert_eq!(sum.bytes(), [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,1]);
            sum.partial_update(11, &[1,2]);
            assert_eq!(sum.bytes(), [1,2,3,4,5,6,7,8,9,10,11,1,2,14,15,1]);
        }

    }
}

mod util {
    use std::io::ErrorKind::WouldBlock;
    use std::io::{ErrorKind, IoSliceMut};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;
    use bytes::BytesMut;
    use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::io::Interest;
    use tokio::net::UdpSocket;
    use tracing::{info, warn};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use crate::MTU_USIZE;

    pub fn fast_hash(bytes: &[u8]) -> u64 {
        const K: u64 = 0x517c_c1b7_2722_0a95; // odd, well-mixed constant

        let mut hash: u64 = 0;
        let mut chunks = bytes.chunks_exact(8);

        for chunk in &mut chunks {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            hash = (hash.rotate_left(5) ^ word).wrapping_mul(K);
        }

        // Fold in the remaining 1..=7 tail bytes.
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rem.len()].copy_from_slice(rem);
            let word = u64::from_le_bytes(buf);
            hash = (hash.rotate_left(5) ^ word).wrapping_mul(K);
        }

        // Final avalanche so all bits are well mixed.
        hash ^= hash >> 32;
        hash = hash.wrapping_mul(K);
        hash ^= hash >> 32;
        hash
    }

    pub struct TSocket {
        state: UdpSocketState,
        socket: tokio::net::UdpSocket,
    }

    pub struct BSocket {
        state: UdpSocketState,
        socket: std::net::UdpSocket,
    }

    pub struct RecvResult {
        pub src: SocketAddr,
        pub stride: usize,
        pub size: usize,
    }


    impl BSocket {
        pub fn max_send_batch(&self) -> usize {
            self.state.max_gso_segments()
        }

        pub fn send_to(&self, buf: &[u8], dst: SocketAddr) -> std::io::Result<()> {
            let transmit = Transmit {
                destination: dst,
                ecn: None,
                contents: buf.into(),
                segment_size: Some(MTU_USIZE),
                src_ip: None,
            };


            let mut backoff = 0;
            loop {
                if let Err(err) = self.state.send((&self.socket).into(), &transmit) {
                    if err.kind() == WouldBlock {
                        if backoff == 0 {
                            std::thread::yield_now();
                            backoff = 1;
                            continue;
                        } else {
                            backoff *= 2;
                            if backoff > 10_000_000 {
                                backoff = 10_000_000;
                            }
                            std::thread::sleep(Duration::from_nanos(backoff));
                            continue;
                        }
                    }
                    return Err(err);
                }
                break;

            }

            Ok(())
        }

    }

    impl TSocket {

        /// Not suitable for fast sending
        pub async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> std::io::Result<()> {
            let transmit = Transmit {
                destination: dst,
                ecn: None,
                contents: buf.into(),
                segment_size: Some(MTU_USIZE), // kernel splits into 1280 + 320
                src_ip: None,
            };

            // Single sendmsg with a UDP_SEGMENT cmsg. `send` logs+swallows non-fatal
            // UDP errors and only returns WouldBlock; use `try_send` to see every error.
            let mut backoff = 0;

            loop {
                if let Err(err) = self.state.send((&self.socket).into(), &transmit) {
                    if err.kind() == WouldBlock {
                        if backoff == 0 {
                            std::thread::yield_now();
                            backoff = 1;
                            continue;
                        } else {
                            backoff *= 2;
                            if backoff > 10_000_000 {
                                backoff = 10_000_000;
                            }
                            tokio::time::sleep(Duration::from_nanos(backoff)).await;
                            continue;
                        }
                    }
                    return Err(err);
                }
                break;

            }
            Ok(())
        }

        pub async fn recv_single_from<'a>(&self, data: &mut BytesMut) -> std::io::Result<(usize, SocketAddr)> {

            Ok(self.socket.recv_buf_from(data).await?)
        }

        pub fn match_recv_batch_size(&self) -> usize {
            self.state.gro_segments()
        }

        pub async fn recv_multi_from<'a>(&self, buf: &mut [IoSliceMut<'a>], meta_scratch: &mut Vec<RecvMeta>) -> std::io::Result<usize> {
            meta_scratch.resize(buf.len(), RecvMeta::default());
            loop {
                let n = match self.socket.async_io(Interest::READABLE, || {
                    let temp = self.state.recv((&self.socket).into(), buf, meta_scratch);
                    temp
                }).await {
                    Ok(n) => n,
                    // recv.readable() can lead to false positives. Try again.
                    Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                };

                return Ok(n);
            }
        }
    }

    pub fn unicast_socket(
        iface: Ipv4Addr,
    ) -> std::io::Result<std::net::UdpSocket> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        sock.set_recv_buffer_size(4 * 1024 * 1024)?;
        sock.set_send_buffer_size(4 * 1024 * 1024)?;

        // Bind to the port. Binding to INADDR_ANY (or the group addr) + reuse
        // lets several sockets share it.
        let bind_addr: SocketAddr = SocketAddrV4::new(iface, 0).into();
        sock.bind(&bind_addr.into())?;

        // Convert socket2 -> std -> compio.
        let std_sock: std::net::UdpSocket = sock.into();

        Ok(std_sock)
    }


    pub fn tokio_socket(socket: std::net::UdpSocket) -> std::io::Result<TSocket> {
        socket.set_nonblocking(true)?;
        let mut state = UdpSocketState::new((&socket).into())?;
        //TODO: Remove dupe code
        state.set_recv_buffer_size((&socket).into(), 2*MTU_USIZE*state.gro_segments())?;
        state.set_send_buffer_size((&socket).into(), 2*MTU_USIZE*state.max_gso_segments())?;
        let socket = UdpSocket::from_std(socket)?;
            Ok(
                TSocket {
                    state,
                    socket,
                }
            )
    }

    pub fn blocking_socket(socket: std::net::UdpSocket) -> std::io::Result<BSocket> {
        socket.set_nonblocking(false)?;
        let mut state = UdpSocketState::new((&socket).into())?;
        state.set_recv_buffer_size((&socket).into(), 2*MTU_USIZE*state.gro_segments())?;
        state.set_send_buffer_size((&socket).into(), 2*MTU_USIZE*state.max_gso_segments())?;
        Ok(
            BSocket {
                state,
                socket,
            }
        )
    }

    pub fn reusable_multicast_socket(
        group: SocketAddrV4,
        iface: Ipv4Addr,
        accept_unicast_too: bool
    ) -> std::io::Result<std::net::UdpSocket> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        sock.set_recv_buffer_size(4 * 1024 * 1024)?;
        sock.set_send_buffer_size(4 * 1024 * 1024)?;

        // The important bit — allow multiple binds to the same addr/port.
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?; // needed on Linux for multiple receivers

        // Bind to the port. Binding to INADDR_ANY (or the group addr) + reuse
        // lets several sockets share it.
        let bind_addr: SocketAddr = if accept_unicast_too  {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, group.port()).into()
        } else {
            SocketAddrV4::new(*group.ip(), group.port()).into()
        };

        sock.bind(&bind_addr.into())?;

        // Join the multicast group.
        sock.join_multicast_v4(&group.ip(), &iface)?;

        sock.set_multicast_loop_v4(true)?;

        // Convert socket2 -> std -> compio.
        let std_sock: std::net::UdpSocket = sock.into();

        Ok(std_sock)
    }

    pub fn setup_tracing() {

        if std::env::var("RUST_LOG_JSON").is_ok() {
            let stdout_log = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .json()
                .with_filter(tracing_subscriber::EnvFilter::from_default_env());

            let subscriber = tracing_subscriber::registry().with(stdout_log);
            _ = tracing::subscriber::set_global_default(subscriber);
        } else {
            let stdout_log = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_filter(tracing_subscriber::EnvFilter::from_default_env());

            let subscriber = tracing_subscriber::registry().with(stdout_log);
            _ = tracing::subscriber::set_global_default(subscriber);
        }
        info!("Tracing enabled");
    }



}


use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Interface to use
    #[arg(short, long)]
    iface: Ipv4Addr,

    /// Paths to send
    #[arg(short, long)]
    send: Vec<PathBuf>,

    /// Path to receive to
    #[arg(short, long)]
    recv: Vec<PathBuf>,

    /// Allow local operation
    #[arg(short, long, default_value = "true")]
    //TODO: Actually use
    local: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_tracing();

    let args = Args::parse();

    if !args.send.is_empty() && !args.recv.is_empty() {
        bail!("Can't both send and receive files")
    }

    if args.send.is_empty() && args.recv.is_empty() {
        bail!("Must give at least one --send or --recv argument");
    }

    if !args.send.is_empty() {
        ServerState::run(ServerConfig {
            local_iface: args.iface,
            phases: args.send,
            ..ServerConfig::default()
        }).await?;

    } else {
        let mut client = client::ClientState::new(ClientConfig {
            bind_address: args.iface,
            paths: args.recv,
            ..ClientConfig::default()
        }).await?;
        client.run().await?;
    }
    Ok(())
}


mod tests {
    use tokio::spawn;
    use crate::client;
    use crate::client::ClientConfig;
    use crate::server::ServerConfig;
    use crate::util::setup_tracing;

    #[tokio::test]
    async fn start_client() {
        setup_tracing();
        spawn(async move {
            let mut client = client::ClientState::new(ClientConfig::default()).await.unwrap();
            client.run().await.unwrap();

            std::process::exit(0);
        }).detach();


        super::server::ServerState::run(ServerConfig {
            phases: vec![
                "/home/anders/sample".into()
            ],
            ..ServerConfig::default()
        }).await.unwrap();


    }

}