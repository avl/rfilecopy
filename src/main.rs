use crate::file_set::FileSet;
use crate::messages::Message;
use anyhow::Result;
pub use compio::bytes::Bytes;
use compio::bytes::{Buf, BufMut, BytesMut};
use rand::random;
use savefile::IntrospectionError::IndexOutOfRange;
use savefile::prelude::Savefile;
use std::ops::Index;
use std::ops::{Range, RangeInclusive};

pub const CHECKSUM_SIZE: usize = 16;
pub const CHECKSUM_SIZE_U64: u64 = CHECKSUM_SIZE as u64;

/// How many packets prior to end of burst that clients should consider EOF
/// approaching and make new request
pub const PRE_REQUEST_TIME: usize = 10;
pub const MIN_BURST_SIZE: usize = 15;
pub const MAX_BURST_SIZE: usize = 10000;

pub const MTU: u64 = 1400;
pub const MTU_USIZE: usize = MTU as usize;
pub const HEADER_SIZE: u64 = (4 + 8);
pub const PAYLOAD_SIZE: u64 = 1400 - HEADER_SIZE;
pub const PAYLOAD_SIZE_USIZE: usize = PAYLOAD_SIZE as usize;
pub const PAYLOAD_SIZE_USIZE_WITHOUT_HASH: usize = PAYLOAD_SIZE_USIZE - CHECKSUM_SIZE;

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
#[derive(Savefile, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PacketIdx(u64);

/// The index of a packet within a specific phase.
#[derive(Savefile, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IndexInPhase(pub u64);

/// Offset within a phase, in bytes
#[derive(Savefile, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PhaseOffset(pub u64);

impl IndexInPhase {
    pub const ZERO: IndexInPhase = IndexInPhase(0);
    pub const MAX_INDEX: IndexInPhase = IndexInPhase(0xffff_ffff_ffff);
}

trait PhaseSize {
    fn max_index_eclusive(&self, phase: u16) -> Option<PhaseOffset>;
}

pub fn overlaps<T: Ord>(a: Range<T>, b: Range<T>) -> Option<Range<T>> {
    if a.end <= b.start || b.end <= a.start {
        return None;
    }
    Some((a.start.max(b.start)..b.end.min(a.end)).into())
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
    pub const MAX_OFFSET: PhaseOffset = PhaseOffset(0xffff_ffff_ffff);
}

impl PacketIdx {
    pub fn deserialize(mut data: &mut Bytes) -> Result<PacketIdx> {
        Ok(PacketIdx(data.try_get_u64()?))
    }
    pub fn serialize(&self, mut data: &mut BytesMut) {
        data.put_u64(self.0);
    }

    pub fn new(phase: u16, index: PhaseOffset) -> Self {
        if index > PhaseOffset::MAX_OFFSET {
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
                phase_size.max_index_eclusive(phase)?
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
    use crate::{PacketIdx, PhaseOffset, RetransmitGeneration, SessionId};
    use anyhow::{Result, bail};
    use arrayvec::ArrayVec;
    use compio::bytes::{Buf, BufMut, Bytes, BytesMut};
    use savefile::prelude::Savefile;
    use savefile::{Deserializer, Serialize, Serializer};
    use std::ops::Range;

    const MAX_SECTIONS_PER_REQUEST: usize = 5;
    const MAX_SECTIONS_PER_PAYLOAD: usize = 5;

    #[derive(Savefile, PartialEq, Debug)]
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
        pub sections: ArrayVec<Range<PhaseOffset>, MAX_SECTIONS_PER_REQUEST>,
    }

    #[derive(Savefile, Clone, PartialEq, Eq, Debug)]
    pub struct Payload {
        pub session_id: SessionId,
        pub retransmit_generation: RetransmitGeneration,
        pub index: PacketIdx,
        /// We're approaching the end of the batch, clients
        /// are encouraged to make new requests (with retransmit_generation + 1)
        pub eof_approaching: bool,
        pub data: Bytes,
    }

    #[derive(Savefile, PartialEq, Debug)]
    pub struct Announce {
        pub session_id: SessionId,
        pub retransmit_generation: RetransmitGeneration,
        pub fileset_size: u64,
        pub phases: u16,
        pub file_count: u64,
        pub total_size_bytes: u64,
    }

    #[derive(Savefile, PartialEq, Debug)]
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
            Serializer::bare_serialize(&mut output.writer(), 0, self).unwrap();
            /*match self {
                Message::Request(r) => {
                    output.put_u8(0);
                    output.put_u32(r.session_id);
                    output.put_u16(r.retransmit_generation);
                    output.put_u16(r.phase);
                    output.put_u8(r.sections.len() as u8);
                    for section in &r.sections {
                        output.put_u64(section.start);
                        output.put_u64(section.end - section.start);
                    }
                }
                Message::Payload(p) => {
                    output.put_u8(1);
                    output.put_u32(p.session_id);
                    output.put_u16(p.retransmit_generation);
                    p.index.serialize(output);
                    output.extend_from_slice(&p.data)
                }
                Message::Announce(a) => {
                    output.put_u8(2);
                    output.put_u32(a.session_id);
                    output.put_u16(a.retransmit_generation);
                    output.put_u64(a.file_count);
                    output.put_u64(a.total_size_bytes);
                }
                Message::RequestAnnounce => {
                    output.put_u8(3);
                }
            }*/
        }

        pub fn msg_deserialize(mut input: Bytes) -> Result<Message> {
            Ok(Deserializer::bare_deserialize(&mut input.reader(), 0)?)
            /*savefile::prelude::load_from_mem()

            match input.try_get_u8()? {
                0 => {
                    let session_id = input.try_get_u32()?;
                    let logical_time = input.try_get_u16()?;
                    let phase = input.try_get_u16()?;
                    let section_count: usize = input.try_get_u8()? as usize;
                    let mut sections = ArrayVec::new();
                    for _ in 0..section_count {
                        sections.push(
                            (input.try_get_u64()?..input.try_get_u64()?).into()
                        )
                    }
                    Ok(Message::Request(Request {
                        session_id,
                        retransmit_generation: logical_time,
                        phase,
                        sections,
                    }))
                }
                1 => {
                    let session_id = input.try_get_u32()?;
                    let logical_time = input.try_get_u16()?;
                    let index = PacketIdx::deserialize(&mut input)?;;
                    Ok(Message::Payload(Payload {
                        session_id,
                        retransmit_generation: logical_time,
                        index,
                        data: input,
                    }))
                }
                2 => {
                    let session_id = input.try_get_u32()?;
                    let logical_time = input.try_get_u16()?;
                    let file_count = input.try_get_u64()?;
                    let total_size_bytes = input.try_get_u64()?;
                    Ok(Message::Announce(Announce {
                        session_id,
                        retransmit_generation: logical_time,
                        file_count,
                        total_size_bytes,
                    }))
                }
                3 => {
                    Ok(Message::RequestAnnounce)
                }
                _ => bail!("Unexpected message type"),
            }*/
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
                eof_approaching: false,
                data: b"hello"[..].into(),
            }));
            roundtrip(Message::Announce(Announce {
                session_id: SessionId(42),

                retransmit_generation: RetransmitGeneration(37),
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
    use crate::file_set::FileSet;
    use crate::messages::Payload;
    use crate::{
        CHECKSUM_SIZE, CHECKSUM_SIZE_U64, PAYLOAD_SIZE, PAYLOAD_SIZE_USIZE,
        PAYLOAD_SIZE_USIZE_WITHOUT_HASH, PRE_REQUEST_TIME, PacketIdx, PhaseOffset, PhaseSize,
        RetransmitGeneration, SessionId, calculate_phase_offset, messages,
    };
    use anyhow::{Result, bail};
    use compio::BufResult;
    use compio::buf::{IoBuf, IoBufMut, SetLen};
    use compio::bytes::{Bytes, BytesMut};
    use compio::fs::File;
    use compio::io::AsyncReadAtExt;
    use indexmap::IndexMap;
    use indexmap::map::Entry;
    use lru::LruCache;
    use rangemap::RangeSet;
    use smallvec::SmallVec;
    use std::collections::{HashMap, HashSet};
    use std::mem::MaybeUninit;
    use std::ops::{Range, RangeInclusive};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const READ_WORKERS: usize = 16;
    const CACHE_SIZE_PACKETS: usize = 10000;
    const READ_ENGINE_BUF_SIZE: usize = 4096;
    const WORK_DIVISION_LENGTH: usize = 20 * READ_ENGINE_BUF_SIZE;

    struct BytesMutTake(BytesMut, usize, usize);

    impl IoBuf for BytesMutTake {
        fn as_init(&self) -> &[u8] {
            let r = self.0.as_init();
            &r[self.1..self.0.len()]
        }
    }

    impl SetLen for BytesMutTake {
        unsafe fn set_len(&mut self, len: usize) {
            unsafe { self.0.set_len(self.1 + len) }
        }
    }

    impl IoBufMut for BytesMutTake {
        fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
            &mut self.0.as_uninit()[self.1..self.2]
        }
    }

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
        Hashing { hasher: blake3::Hasher, offset: u64 },
        Finished([u8; CHECKSUM_SIZE]),
    }

    impl Default for ChecksummingState {
        fn default() -> Self {
            Self::Hashing {
                hasher: Default::default(),
                offset: 0,
            }
        }
    }

    pub struct ReadEngine {
        files: Arc<FileSet>,
        checksums: HashMap<PathBuf, ChecksummingState>,
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

    impl IoBuf for Buf {
        fn as_init(&self) -> &[u8] {
            &self.data
        }
    }

    impl SetLen for Buf {
        unsafe fn set_len(&mut self, len: usize) {
            self.size = len;
        }
    }

    impl IoBufMut for Buf {
        fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
            self.data.as_uninit()
        }
    }

    impl ReadEngine {
        /*
        async fn worker(
            session_id: SessionId,
            files: Arc<FileSet>,
            rx: flume::Receiver<WorkerRequest>) -> Result<()> {

            loop {
                println!("WOrker working");
                let Ok(mut req) = rx.recv_async().await else {
                    println!("Worker exiting");
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
            println!("CAching request sent");
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

        pub async fn get_packets(
            &mut self,
            logical_time: RetransmitGeneration,
            session_id: SessionId,
            idx: Range<PacketIdx>,
            mut tx: impl AsyncFnMut(Payload),
        ) -> Result<()> {
            //TODO: Reuse these buffers
            let mut tasks = Vec::new();

            self.files
                .visit(
                    idx.clone(),
                    &mut |phase, phase_offset, path, offset, file_size| {
                        tasks.push((phase, phase_offset, path.to_path_buf(), offset, file_size));
                    },
                )
                .expect("visit cannot fail");

            let mut buf = BytesMut::new();

            let mut output_idx = idx;

            let task_len = tasks.len();
            for (task_i, (phase, phase_offset, path, offset, nominal_file_size)) in
                tasks.into_iter().enumerate()
            {
                let mut file = compio::fs::File::open(&path).await?;
                let real_file_size = nominal_file_size - CHECKSUM_SIZE_U64;
                let chunk_size = (phase_offset.end - phase_offset.start).min(real_file_size);
                buf.reserve(chunk_size as usize + CHECKSUM_SIZE);
                let buflen = buf.len();
                buf = match file
                    .read_exact_at(
                        BytesMutTake(buf, buflen, buflen + chunk_size as usize),
                        offset,
                    )
                    .await
                    .into_parts()
                {
                    (Ok(_), mut buf) => {
                        let cksumstate = match self.checksums.get_mut(&path) {
                            Some(cksum) => cksum,
                            None => self.checksums.entry(path.to_path_buf()).or_default(),
                        };
                        match cksumstate {
                            ChecksummingState::Hashing {
                                hasher,
                                offset: hashed_offset,
                            } => {
                                if offset + chunk_size > *hashed_offset && *hashed_offset >= offset
                                {
                                    let new_part_start_at = *hashed_offset - offset;
                                    let new_part_size = (offset + chunk_size) - *hashed_offset;
                                    hasher.update(
                                        &buf.0[new_part_start_at as usize
                                            ..(new_part_start_at + new_part_size) as usize],
                                    );
                                    if offset + chunk_size == real_file_size {
                                        let hash: [u8; CHECKSUM_SIZE] =
                                            hasher.finalize().as_bytes()[0..16].try_into().unwrap();
                                        *cksumstate = ChecksummingState::Finished(hash);
                                    }
                                }
                            }
                            ChecksummingState::Finished(_) => {}
                        }
                        if offset + chunk_size == real_file_size {
                            buf.0.reserve(CHECKSUM_SIZE);
                            buf.0.extend_from_slice(
                                &self.get_checksum(&path, real_file_size).await?,
                            );
                        }
                        if task_i + 1 == task_len || buf.0.len() >= PAYLOAD_SIZE_USIZE {
                            let pktbuf =
                                buf.0.split_to(PAYLOAD_SIZE_USIZE.min(buf.0.len())).freeze();
                            tx(Payload {
                                session_id: session_id,
                                retransmit_generation: logical_time,
                                index: output_idx.start,
                                eof_approaching: task_i + PRE_REQUEST_TIME > task_len,
                                data: pktbuf,
                            })
                            .await;
                            output_idx.start.0 += 1;
                        }
                        buf.0
                    }
                    (Err(err), mut _buf) => {
                        panic!("Failed reading file: {}: {:?}", path.display(), err);
                    }
                };
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
            if let Some(max_index_of_phase) = self.files.max_index_eclusive(phase)
                && phase_offset >= max_index_of_phase
                && phase as usize != self.files.num_phases()
            {
                return PacketIdx::new(phase + 1, PhaseOffset::ZERO);
            }
            PacketIdx::new(phase, PhaseOffset(index.index().0 + 1))
        }

        async fn get_checksum(
            &mut self,
            p0: &Path,
            real_file_size: u64,
        ) -> Result<[u8; CHECKSUM_SIZE]> {
            let cksum = self.checksums.entry(p0.to_path_buf()).or_default();
            match cksum {
                ChecksummingState::Hashing { hasher, offset } => {
                    let f = File::open(p0).await?;
                    let mut vec = vec![0; READ_ENGINE_BUF_SIZE];
                    while *offset < real_file_size {
                        let to_read = (real_file_size - *offset).min(READ_ENGINE_BUF_SIZE as u64);
                        vec.resize(to_read as usize, 0);
                        vec = match f.read_exact_at(vec, *offset).await.into_parts() {
                            (Ok(_), buf) => {
                                hasher.update(&buf);
                                *offset += buf.len() as u64;
                                buf
                            }
                            (Err(err), _) => bail!("failed to read file {}", err), //TODO: Better error
                        };
                    }
                    Ok(hasher.finalize().as_bytes()[0..CHECKSUM_SIZE]
                        .try_into()
                        .unwrap())
                }
                ChecksummingState::Finished(sum) => Ok(*sum),
            }
        }
    }
}

mod server {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::disk_read_engine::ReadEngine;
    use crate::file_set::FileSet;
    use crate::messages::{LinkQualitySignal, Message, Request};
    use crate::{
        MAX_BURST_SIZE, MIN_BURST_SIZE, MTU, MTU_USIZE, PacketIdx, RetransmitGeneration, SessionId,
        overlaps,
    };
    use anyhow::{Result, bail};
    use compio::BufResult;
    use compio::bytes::{BufMut, Bytes, BytesMut};
    use compio::net::UdpSocket;
    use compio::runtime::spawn;
    use rangemap::RangeMap;
    use savefile::Serialize;
    use smallvec::SmallVec;

    #[derive(Clone, Debug)]
    struct Config {
        local_iface: Ipv4Addr,
        mcast_addr: SocketAddrV4,
        phases: Vec<PathBuf>,
    }

    const PACK_LEADER_CHANGE_TIME: Duration = Duration::from_millis(100);

    struct ServerState {
        config: Config,
        logic_state: ServerLogicState,
        session_id: SessionId,
        socket: compio::net::UdpSocket,
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
            if r.sections.is_empty() {
                bail!("empty request");
            }

            let first_section = &r.sections[0];
            let first_idx = PacketIdx::new(r.phase, first_section.start);
            if self.pack_leader != src && first_idx < self.packet_leader_position
                || self.pack_leader_last_head.elapsed() > PACK_LEADER_CHANGE_TIME
            {
                println!("pack leader changed to {}", src);
                self.pack_leader = src;
                self.packet_leader_position = first_idx;
            }

            if r.retransmit_generation.0 != self.current_retransmit_generation.0 + 1 {
                return Ok(());
            }

            if self.pack_leader != src {
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
                r.retransmit_generation,
                r.sections.into_iter().map(|offset_range| {
                    PacketIdx::new(r.phase, offset_range.start)
                        ..PacketIdx::new(r.phase, offset_range.end)
                }),
            );
            Ok(())
        }
        fn receive_message(&mut self, input: Bytes, src: SocketAddr) -> Result<()> {
            let msg = Message::msg_deserialize(input)?;
            if let Some(msg_session_id) = msg.session_id()
                && msg_session_id != self.session_id
            {
                bail!("colliding session discovered");
            }
            match msg {
                Message::Request(r) => {
                    self.process_request(r, src)?;
                }
                Message::Payload(_) => {}
                Message::Announce(_) => {}
                Message::RequestAnnounce => {}
            }

            Ok(())
        }
    }

    impl ServerState {
        pub async fn worker(
            rx: flume::Receiver<(RetransmitGeneration, Range<PacketIdx>)>,
            session_id: SessionId,
            config: Config,
            mut read_engine: ReadEngine,
        ) -> Result<()> {
            let socket =
                compio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(config.local_iface), 0))
                    .await?;

            spawn(async move {
                let mut buf = Some(BytesMut::new());
                loop {
                    let Ok((generation, pkts)) = rx.recv_async().await else {
                        return;
                    };
                    let result = read_engine
                        .get_packets(generation, session_id, pkts, async |pkt| {
                            let mut buf_inner = buf.take().expect("buffer is always returned");
                            Message::Payload(pkt).msg_serialize(&mut buf_inner);

                            buf = Some(
                                match socket
                                    .send_to(buf_inner.clone(), config.mcast_addr)
                                    .await
                                    .into_parts()
                                {
                                    (Ok(size), buf) => {
                                        if size != buf.len() {
                                            // TODO: better error handling?
                                            panic!("network MUT too small");
                                        }
                                        buf_inner
                                    }
                                    (Err(err), buf) => {
                                        eprintln!("socket transmit failed: {:?}", err);
                                        buf_inner
                                    }
                                },
                            );
                        })
                        .await;
                    if let Err(err) = result {
                        eprintln!("disk access failed {:?}", err);
                    }
                }
            })
            .detach();

            Ok(())
        }
        pub async fn run(config: Config) -> Result<()> {
            let (tx, rx) = flume::unbounded();
            let session_id = SessionId::make_random();

            let receive_socket = UdpSocket::bind(config.mcast_addr).await?;

            receive_socket.join_multicast_v4(&config.mcast_addr.ip(), &config.local_iface)?;
            receive_socket.set_multicast_loop_v4(true)?; //TODO: Don't use loopback unless local needed

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
                },
                //TODO: don't store sessionid twice
                session_id,
                socket: receive_socket,
            };

            let mut buf = BytesMut::with_capacity(MTU_USIZE);

            let files = FileSet::new(state.config.phases.clone())?;
            let re = ReadEngine::new(state.session_id, files).await;

            Self::worker(rx, session_id, state.config.clone(), re).await?;

            loop {
                buf = match state.socket.recv_from(buf).await.into_parts() {
                    (Ok((size, src)), rbuf) => {
                        match state
                            .logic_state
                            .receive_message(rbuf.clone().freeze(), src)
                        {
                            Ok(()) => {}
                            Err(err) => {
                                eprintln!("failed to process incoming message {:?}", err);
                            }
                        }
                        rbuf
                    }
                    (Err(err), rbuf) => {
                        eprintln!("socket error: {:?}", err);
                        compio::time::sleep(Duration::from_secs(1)).await;
                        rbuf
                    }
                };
            }
        }
    }
}

mod client {
    use crate::file_set::FileSet;
    use crate::messages::{LinkQualitySignal, Message, Request};
    use crate::{Bytes, PhaseOffset, SessionId, MTU_USIZE, PacketIdx, calculate_phase_offset, RetransmitGeneration};
    use anyhow::{Result, bail};
    use compio::bytes::{Buf, BufMut, BytesMut};
    use compio::net::UdpSocket;
    use savefile::{Deserialize, Deserializer, Serialize};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use arrayvec::ArrayVec;
    use compio::fs::{File, OpenOptions};
    use compio::io::AsyncWriteAtExt;
    use compio::runtime::{spawn, JoinHandle};
    use futures_util::stream::FuturesUnordered;
    use indexmap::IndexSet;
    use rangemap::RangeSet;

    pub struct ClientConfig {
        paths: Vec<PathBuf>,
        bind_address: Ipv4Addr,
        mcast_addr: SocketAddrV4,
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
    struct ClientState {
        state: ClientStateEnum,
        recv_socket: UdpSocket,
        send_socket: UdpSocket,
        config: ClientConfig,
    }

    trait BlockReceiver {
        async fn write(&mut self, dest: PacketIdx, data: Bytes) -> Result<()>;

    }

    enum DiskWriteCommand {
        Write(PacketIdx, Bytes),
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
    pub const WRITE_WORKERS: usize = 20;

    impl FileSetDiskWriter {
        pub fn new(
            paths: Vec<PathBuf>,
            fileset: FileSet) -> FileSetDiskWriter {

            let fileset = Arc::new(fileset);
            let (tx,rx) = flume::bounded(WRITE_BUFFER_SIZE_PACKETS);

            struct CurFile {
                path: PathBuf,
                file: File,
                phase: u16,
            }

            let mut jhs = Vec::new();
            for _ in 0..WRITE_WORKERS {
                let rx = rx.clone();
                let fileset = fileset.clone();
                let mut curfile : Option<CurFile> = None;
                let paths = paths.clone();
                jhs.push(spawn(async move {
                    // TODO: error handling

                    let mut cursor = fileset.make_cursor();

                    loop {
                        let Ok(ev) = rx.recv() else {
                            return Ok(());
                        };
                        match ev {
                            DiskWriteCommand::Write(idx, bytes) => {
                                //TODO: Error handling!
                                let need = cursor.seek(idx.phase(), calculate_phase_offset(idx.index()))?;
                                if let Some(curfile_inner) = curfile.as_mut() {
                                    if curfile_inner.path != need.path || curfile_inner.phase != idx.phase() {
                                        curfile = None;
                                    }
                                }
                                if curfile.is_none() {
                                    let path = paths[idx.phase() as usize  -1 ].join(need.path).to_path_buf();
                                    curfile = Some(CurFile {
                                        path: path.clone(),
                                        file: OpenOptions::new().write(true).create(true).open(path).await?,
                                        phase: idx.phase(),
                                    });
                                }
                                assert!(need.file_offset + bytes.len() as u64 <= need.file_size);

                                let curfile = curfile.as_mut().unwrap();
                                match curfile.file.write_all_at(bytes, need.file_offset).await.into_parts() {
                                    (Ok(_), _buf) => {

                                    },
                                    (Err(e), buf) => {
                                        bail!("Failed to write file: {:?}", e);
                                    }
                                };
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
        async fn write(&mut self, dest: PacketIdx, data: Bytes) -> Result<()> {
            Ok(self.tx.send_async(DiskWriteCommand::Write(dest, data)).await?)
        }

    }


    impl BlockReceiver for Vec<u8> {
        async fn write(&mut self, dest: PacketIdx, data: Bytes) -> Result<()> {
            if dest.phase() != 0 {
                bail!("wrong phase for initialization");
            }
            let dest = calculate_phase_offset(dest.index());
            self[dest.0 as usize .. dest.0 as usize + data.len()].copy_from_slice(&data);
            Ok(())
        }


    }

    struct ClientProtocolHandler {
        //TODO: Remove
    }


    impl ClientProtocolHandler {
        pub async fn sync(
                          session_id: SessionId,
                          //TODO: Move sockets into some abstraction
                          send_socket: &UdpSocket,
                          recv_socket: &UdpSocket,
                          mut receiver: &mut impl BlockReceiver,
                          phases: &[(u16/*phase*/, PhaseOffset/*size*/)],
                          peer: SocketAddrV4,

        ) -> Result<()> {
            let mut recvbuf = BytesMut::new();

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

            async fn send_request(mut buf: BytesMut, send_socket: &UdpSocket, phase: u16, session_id: SessionId, missing: &RangeSet<PhaseOffset>, retransmit_generation: RetransmitGeneration, loss: LinkQualitySignal, dst: SocketAddrV4) -> Result<BytesMut> {
                let mut sections = ArrayVec::new();
                for rng in missing.iter() {
                    if sections.try_push(rng.clone()).is_err() {
                        break;
                    }
                }
                let request = Message::Request(Request {
                    session_id,
                    phase,
                    retransmit_generation: retransmit_generation.next(),
                    loss,
                    sections
                });
                buf.clear();
                request.msg_serialize(&mut buf);
                Ok(match send_socket.send_to(buf, dst).await.into_parts() {
                    (Ok(size), buf) => {
                        if size != buf.len() {
                            bail!("network MTU too small");
                        }
                        buf
                    }
                    (Err(err), buf) => {
                        bail!("Failed to send request: {:?}", err);
                    }
                })

            }
            let mut last_retransmit_generation = RetransmitGeneration(0);
            let mut loss: LinkQualitySignal = LinkQualitySignal::KeepGoing;
            let mut no_loss_counter = 0;
            for (phase, phase_size) in phases {
                'phaseloop: loop {

                    let r = compio::time::timeout(Duration::from_millis(50), recv_socket.recv(recvbuf.clone())).await;

                    let msg = match r {
                        Ok(msg) => msg,
                        Err(_elapsed) => {
                            let phase_missing = &missing[*phase as usize];
                            sendbuf = send_request(sendbuf,&send_socket, *phase, session_id,
                                                   phase_missing, last_retransmit_generation, loss, peer
                            ).await?;
                            loss = LinkQualitySignal::KeepGoing;
                            recvbuf = BytesMut::new();
                            continue;
                        }
                    };

                    recvbuf = match msg.into_parts() {
                        (Ok(_), buf) => {
                            let msg = Message::msg_deserialize(buf.clone().freeze())?;
                            if let Some(msg_session_id) = msg.session_id() && msg_session_id != session_id {
                                // wrong session id
                            } else {
                                match msg {
                                    Message::Request(_) => {
                                        eprintln!("ignore request");
                                    }
                                    Message::Payload(p) => {
                                        let range_start = calculate_phase_offset(p.index.index());
                                        let range = range_start..PhaseOffset(range_start.0 + p.data.len() as u64);
                                        let phase_missing = &mut missing[*phase as usize];
                                        let holes_before = phase_missing.len();

                                        //TODO: Implement leadership support for client too

                                        let mut was_useful = false;
                                        if phase_missing.overlaps(&range) {
                                            was_useful = true;
                                        }

                                        phase_missing.remove(range);
                                        let holes_after = phase_missing.len();
                                        if holes_after != holes_before {
                                            loss = LinkQualitySignal::LossDetected;
                                            no_loss_counter = 0;
                                        } else if was_useful {
                                            no_loss_counter += 1;
                                            if no_loss_counter > 100 && loss == LinkQualitySignal::KeepGoing {
                                                loss = LinkQualitySignal::IncreaseWindow;
                                                no_loss_counter = 0;
                                            }
                                        }

                                        receiver.write(p.index, p.data).await?;

                                        if was_useful {
                                            if phase_missing.is_empty() {
                                                break 'phaseloop;
                                            }
                                        }

                                    }
                                    Message::Announce(_) => {
                                        eprintln!("ignore announce");
                                    }
                                    Message::RequestAnnounce => {
                                        eprintln!("ignore request announce");
                                    }
                                }
                            }
                            buf
                        }
                        (Err(e), buf) => {
                            bail!("receive failed");
                        }
                    };
                }

            }

            Ok(())
        }
    }


    impl ClientState {
        pub async fn new(config: ClientConfig) -> Result<ClientState> {
            let recv_socket = UdpSocket::bind(config.mcast_addr).await?;
            recv_socket.join_multicast_v4(&config.mcast_addr.ip(), &config.bind_address)?;
            recv_socket.set_multicast_loop_v4(true)?;

            let send_socket = UdpSocket::bind(SocketAddrV4::new(config.bind_address, 0)).await?;

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
                self.send_socket
                    .send_to(buf, self.config.mcast_addr)
                    .await
                    .into_parts()
                    .0?;

                match compio::time::timeout(
                    Duration::from_secs(1),
                    self.recv_socket.recv_from(BytesMut::new()),
                )
                .await
                {
                    Ok(x) => match x.into_parts() {
                        (Ok((_size, SocketAddr::V4(src))), mut buf) => {
                            let msg = Message::msg_deserialize(buf.freeze())?;
                            match msg {
                                Message::Request(_) => {}
                                Message::Payload(_) => {}
                                Message::Announce(a) => {
                                    return Ok((a.session_id, a.fileset_size, a.phases, src));
                                }
                                Message::RequestAnnounce => {}
                            }
                        }
                        (Ok(_), _) => {
                            bail!("unexpected message protocol")
                        }
                        (Err(err), _) => {
                            bail!("failed receiving message: {:?}", err)
                        }
                    },
                    Err(_err) => {
                        println!("timeout waiting for announce");
                    }
                }

                compio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        pub async fn run(&mut self) -> Result<()> {
            loop {
                match std::mem::replace(&mut self.state,  ClientStateEnum::Invalid) {
                    ClientStateEnum::Initializing => {
                        let (session_id, fileset_size, phases, server) = self.init_session().await?;
                        if phases as usize != self.config.paths.len() + 1 {
                            bail!("need {} paths, because there are {} phases, not {}", phases-1, phases-1, self.config.paths.len());
                        }

                        let buf = vec![0; fileset_size as usize];
                        self.state = ClientStateEnum::AwaitingFileSet {
                            session_id,
                            buf,
                            phases,
                            server,
                        };
                    }
                    ClientStateEnum::AwaitingFileSet { session_id, phases, server, mut buf } => {
                        let phase_0_size = buf.len();
                        ClientProtocolHandler::sync(session_id, &self.send_socket, &self.recv_socket,
                                                    &mut buf,&[(0,PhaseOffset(phase_0_size as u64))], server
                        ).await?;

                        let fileset: FileSet = Deserializer::bare_deserialize(&mut buf.reader(), 0)?;
                        let phases = fileset.get_phases();

                        let writer = FileSetDiskWriter::new(self.config.paths.clone(), fileset);

                        self.state = ClientStateEnum::Receiving {
                            fileset: writer,
                            session_id: session_id,
                            server: server,
                            phases,
                        };
                    }
                    ClientStateEnum::Receiving { phases, mut  fileset, session_id, server } => {

                        ClientProtocolHandler::sync(session_id, &self.send_socket, &self.recv_socket,
                                                    &mut fileset,&phases, server
                        ).await?;

                        fileset.shutdown().await;

                        println!("Sync done");
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
    use crate::file_set::Entry::File;
    use crate::{
        CHECKSUM_SIZE, IndexInPhase, PacketIdx, PhaseOffset, PhaseSize, byte_range,
        calculate_phase_offset, overlaps,
    };
    use anyhow::{Error, Result, anyhow, bail};
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use rayon::prelude::IntoParallelIterator;
    use std::ffi::{OsStr, OsString};
    use std::fs::{DirEntry, FileType, Metadata, Permissions};
    use std::ops::{Add, Sub};
    use std::ops::{Range, RangeInclusive};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use savefile::prelude::Savefile;

    #[derive(Savefile,Debug)]
    enum Kind {
        Normal,
        Symlink,
    }

    #[derive(Savefile,Debug)]
    struct RFile {
        name: PathBuf,
        // This is the size including the CHECKSUM
        size: u64,
        mode_bits: u32,
        offset: PhaseOffset,
        kind: Kind,
    }

    impl Add<u64> for PhaseOffset {
        type Output = PhaseOffset;

        fn add(self, rhs: u64) -> Self::Output {
            PhaseOffset(self.0 + rhs)
        }
    }

    impl RFile {
        pub fn range(&self) -> Range<PhaseOffset> {
            (self.offset..self.offset + self.size).into()
        }
    }

    #[derive(Savefile,Debug)]
    struct RDirectory {
        offset: PhaseOffset,
        name: PathBuf,
        files: Vec<Entry>,
    }

    #[derive(Savefile,Debug)]
    enum Entry {
        File(RFile),
        Directory(RDirectory),
    }

    impl Entry {
        pub fn name(&self) -> &Path {
            match self {
                File(f) => &f.name,
                Entry::Directory(d) => &d.name,
            }
        }
    }

    #[derive(Savefile, Debug)]
    pub struct FileSet {
        /// Base and entry
        phases: Vec<(PathBuf, Entry)>,
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
    }

    impl<'a> FileSetCursor<'a> {
        pub fn cur_range(&self) -> Range<PhaseOffset> {
            if self.set.num_phases() == 0 {
                return (PhaseOffset::ZERO..PhaseOffset::ZERO).into();
            };

            if let Some(top) = self.stack.last() {
                (top.first_offset()..top.last_offset_exclusive()).into()
            } else {
                (self.set.phases.first().unwrap().1.first_offset()
                    ..self.set.phases.last().unwrap().1.last_offset_exclusive())
                    .into()
            }
        }
        pub fn seek(&mut self, packet_phase: u16, packet_offset: PhaseOffset) -> Result<WriteNeed> {
            if packet_phase as usize >= self.set.num_phases() {
                bail!("Bad phase");
            }

            loop {
                if self.cur_phase != packet_phase {
                    self.path.clear();
                    self.stack.clear();
                }
                if !self.stack.is_empty() && !self.cur_range().contains(&packet_offset) {
                    self.stack.pop();
                    self.path.pop();
                    continue;
                }

                if self.stack.is_empty() {
                    let (phase_path, phase_entry) = &self.set.phases[packet_phase as usize];
                    self.path = phase_path.clone();
                    self.path.push(phase_entry.name());
                    self.stack.push(phase_entry);
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
                        });
                    }
                    Entry::Directory(d) => {
                        let file_index = match d
                            .files
                            .binary_search_by_key(&packet_offset, |entry| entry.first_offset())
                        {
                            Ok(found_index) => found_index,
                            Err(found_index) => found_index.saturating_sub(1),
                        };
                        let entry = &d.files[file_index];
                        println!("Pushing name {:?}", d.name);
                        self.path.push(entry.name());
                        self.stack.push(entry);
                    }
                }
            }
        }
    }

    impl PhaseSize for FileSet {
        /// Returns None if phase is empty
        fn max_index_eclusive(&self, phase: u16) -> Option<PhaseOffset> {
            Some(PhaseOffset(
                self.phases[phase as usize]
                    .1
                    .last_offset_exclusive()
                    .0
                    .div_ceil(crate::PAYLOAD_SIZE),
            ))
        }
    }

    impl FileSet {

        /// Phase 0 will be empty, since it's the fileset phase
        pub(crate) fn get_phases(&self) -> Vec<(u16, PhaseOffset)> {
            let mut output = vec![];
            output.push((0, PhaseOffset(0)));

            for (i,(_path, entry)) in self.phases.iter().enumerate() {
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

        /// Always visits in PhaseOffset-order, guaranteed
        pub fn visit(
            &self,
            range: Range<PacketIdx>,
            f: &mut impl FnMut(u16, Range<PhaseOffset>, &Path, u64, u64),
        ) -> Result<()> {
            for (phase, range) in PacketIdx::phases(range, self) {
                let byte_range = range;
                let mut cwd = self.phases[phase as usize].0.clone();
                self.phases[phase as usize].1.visit(
                    &mut cwd,
                    byte_range,
                    &mut |phase_offset, path, offset, file_size| {
                        f(phase, phase_offset, path, offset, file_size)
                    },
                )?;
            }
            Ok(())
        }

        pub fn new(items: Vec<impl AsRef<Path>>) -> Result<FileSet> {
            let items: Vec<PathBuf> = items.iter().map(|x| x.as_ref().into()).collect();
            Ok(FileSet {
                phases: items
                    .par_iter()
                    .map(|x| Ok((x.clone(), Entry::new(x)?)))
                    .collect::<Result<_>>()?,
            }
            .assign_offsets())
        }

        fn assign_offsets(mut self) -> Self {
            Self {
                phases: self
                    .phases
                    .into_iter()
                    .map(|mut x| {
                        x.1.assign_offsets(&mut PhaseOffset(0));
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

    impl Entry {
        fn visit(
            &self,
            cwd: &mut PathBuf,
            range: Range<PhaseOffset>,
            func: &mut impl FnMut(Range<PhaseOffset>, &Path, u64, u64),
        ) -> Result<()> {
            match self {
                Entry::File(f) => {
                    if let Some(overlap) = overlaps(f.range(), range.clone()) {
                        cwd.push(&f.name);
                        func(overlap.clone(), &cwd, overlap.start - f.offset, f.size);
                        cwd.pop();
                    }
                    Ok(())
                }
                Entry::Directory(d) => {
                    let mut cur = match d
                        .files
                        .binary_search_by_key(&range.start, |y| y.first_offset())
                    {
                        Ok(x) => x,
                        Err(x) => x.saturating_sub(1),
                    };
                    cwd.push(&d.name);
                    while cur < d.files.len() {
                        if d.files[cur].first_offset() >= range.end {
                            // Done
                            break;
                        }
                        d.files[cur].visit(cwd, range.clone(), func)?;
                        cur += 1;
                    }
                    cwd.pop();
                    Ok(())
                }
            }
        }
        fn first_offset(&self) -> PhaseOffset {
            match self {
                Entry::File(f) => f.offset,
                Entry::Directory(d) => d.offset,
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
            }
        }
        fn assign_offsets(&mut self, accum_offset: &mut PhaseOffset) {
            match self {
                Entry::File(f) => {
                    f.offset = *accum_offset;
                    accum_offset.0 += f.size;
                    accum_offset.0 += CHECKSUM_SIZE as u64;
                }
                Entry::Directory(d) => {
                    d.offset = *accum_offset;
                    for item in &mut d.files {
                        item.assign_offsets(accum_offset);
                    }
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
                                eprintln!("{:?} is not a file or symlink", entry.path());
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
            }))
        }
    }

    impl FileSet {}

    #[cfg(test)]
    mod tests {
        use crate::disk_read_engine::ReadEngine;
        use crate::file_set::{Entry, FileSet};
        use crate::{IndexInPhase, PacketIdx, PhaseOffset, RetransmitGeneration, SessionId};
        use std::fs::read_dir;

        #[test]
        fn scan_home() {
            let files = Entry::new("/home/anders").unwrap();
            println!("Done");
            //println!("Files: {:?}", files);
        }
        #[test]
        fn scan_home2() {
            let files = FileSet::new(vec!["/home/anders/sample"]).unwrap();

            files
                .visit(
                    (PacketIdx::new(0, PhaseOffset::ZERO)..PacketIdx::new(0, PhaseOffset(1000)))
                        .into(),
                    &mut |phase, idx, path, offset_in_file, file_size| {
                        println!(
                            "Visit: {} / {:?} {:?} offset {}",
                            phase, idx, path, offset_in_file
                        );
                    },
                )
                .unwrap();
            println!("Done");
            //println!("Files: {:#?}", files);

            let mut cursor = files.make_cursor();

            let need = cursor.seek(0, PhaseOffset(1000)).unwrap();
            println!("Cursor result: {:?}", need);
            let need = cursor.seek(0, PhaseOffset(4000)).unwrap();
            println!("Cursor result: {:?}", need);
            let need = cursor.seek(0, PhaseOffset(4001)).unwrap();
            println!("Cursor result: {:?}", need);
            let need = cursor.seek(0, PhaseOffset(000)).unwrap();
            println!("Cursor result: {:?}", need);
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
                        println!("Sending: {:?}", pkt);
                    },
                )
                .await;

            println!("Pkt: {:?}", pkt);
        }
    }
}

mod util {
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
}

fn main() {
    println!("Hello, world!");
}
