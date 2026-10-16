//! PST1, the Pi-Spark task message: reader and writer for the fixed header.
//!
//! Spec: `specs/pi-spark-task/SPEC.md` (Draft v0.1, contract 0.1.0, wire
//! version 1). The C reference checker is `specs/pi-spark-task/tools/pst_verify.c`;
//! this crate must give the same verdict on the same bytes (the test in
//! `tests/vectors.rs` walks the shared vectors).
//!
//! Bounds are fixed: a message is 224 header bytes plus at most 800 payload
//! bytes. Decoding borrows the payload from the input and allocates nothing.
//! There is no JSON anywhere in the decode path.
//!
//! First cut (aien-protocols-mv#31): the header only. Per-type payload
//! bodies, the side of the sender and the session rules are not read here.
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// Bytes in the fixed header.
pub const HEADER_LEN: usize = 224;
/// Largest payload.
pub const MAX_PAYLOAD: usize = 800;
/// Largest message (header plus payload).
pub const MAX_MESSAGE: usize = HEADER_LEN + MAX_PAYLOAD;
/// The four bytes that open every message.
pub const MAGIC: [u8; 4] = *b"PST1";
/// The only wire version.
pub const VERSION: u8 = 1;
/// Highest message type (section 5).
pub const MAX_TYPE: u8 = 14;
/// The `request` type.
pub const TYPE_REQUEST: u8 = 1;

const O_MAGIC: usize = 0;
const O_VERSION: usize = 4;
const O_TYPE: usize = 5;
const O_RES0: usize = 6;
const O_CAUSE: usize = 8;
const O_ORIGIN: usize = 40;
const O_OBJECTIVE: usize = 72;
const O_SUBJECT: usize = 104;
const O_PARENT: usize = 136;
const O_TASK: usize = 152;
const O_IDEM: usize = 168;
const O_ORDINAL: usize = 184;
const O_EFFECT: usize = 188;
const O_RES1: usize = 189;
const O_PLEN: usize = 190;
const O_DIGEST: usize = 192;

/// A refusal code from SPEC.md section 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BadMagic,
    BadVersion,
    Downgrade,
    BadType,
    WrongSide,
    BadLength,
    TrailingBytes,
    ReservedNonzero,
    NoCause,
    NoTask,
    NoObjective,
    DigestMismatch,
    BadEffectClass,
    SubjectMismatch,
}

impl Refusal {
    /// The code name exactly as SPEC.md section 7 and the C checker print it.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::BadMagic => "PST_BAD_MAGIC",
            Refusal::BadVersion => "PST_BAD_VERSION",
            Refusal::Downgrade => "PST_DOWNGRADE",
            Refusal::BadType => "PST_BAD_TYPE",
            Refusal::WrongSide => "PST_WRONG_SIDE",
            Refusal::BadLength => "PST_BAD_LENGTH",
            Refusal::TrailingBytes => "PST_TRAILING_BYTES",
            Refusal::ReservedNonzero => "PST_RESERVED_NONZERO",
            Refusal::NoCause => "PST_NO_CAUSE",
            Refusal::NoTask => "PST_NO_TASK",
            Refusal::NoObjective => "PST_NO_OBJECTIVE",
            Refusal::DigestMismatch => "PST_DIGEST_MISMATCH",
            Refusal::BadEffectClass => "PST_BAD_EFFECT_CLASS",
            Refusal::SubjectMismatch => "PST_SUBJECT_MISMATCH",
        }
    }
}

/// The decoded fixed header (SPEC.md section 4). Reserved bytes and the
/// magic are not stored: they have exactly one allowed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub msg_type: u8,
    pub cause_id: [u8; 32],
    pub origin_run_id: [u8; 32],
    pub objective_id: [u8; 32],
    pub subject_id: [u8; 32],
    pub parent_task_id: [u8; 16],
    pub task_id: [u8; 16],
    pub idempotence_key: [u8; 16],
    pub ordinal: u32,
    pub effect_class: u8,
    pub payload_len: u16,
    pub payload_digest: [u8; 32],
}

/// One accepted message: the header and the payload it borrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

/// Why `encode` could not write a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The payload is longer than 800 bytes.
    PayloadTooLong,
    /// `payload_len` in the header differs from the payload given.
    LengthMismatch,
    /// The output buffer is too small.
    BufferTooSmall,
}

fn arr<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[at..at + N]);
    a
}

fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Decode and check one message in the order of SPEC.md section 4.1, the
/// same order as the C checker, so the same bytes give the same code.
pub fn decode(b: &[u8]) -> Result<Message<'_>, Refusal> {
    // 1. length bounds
    if b.len() < HEADER_LEN || b.len() > MAX_MESSAGE {
        return Err(Refusal::BadLength);
    }
    // 2. magic
    if b[O_MAGIC..O_MAGIC + 4] != MAGIC {
        return Err(Refusal::BadMagic);
    }
    // 3. version
    if b[O_VERSION] < VERSION {
        return Err(Refusal::Downgrade);
    }
    if b[O_VERSION] > VERSION {
        return Err(Refusal::BadVersion);
    }
    // 4. type
    if b[O_TYPE] == 0 || b[O_TYPE] > MAX_TYPE {
        return Err(Refusal::BadType);
    }
    // 5. reserved
    if !all_zero(&b[O_RES0..O_RES0 + 2]) || b[O_RES1] != 0 {
        return Err(Refusal::ReservedNonzero);
    }
    // 6, 7. payload length against the bytes present
    let payload_len = u16::from_be_bytes(arr(b, O_PLEN));
    let body = &b[HEADER_LEN..];
    if body.len() < usize::from(payload_len) {
        return Err(Refusal::BadLength);
    }
    if body.len() > usize::from(payload_len) {
        return Err(Refusal::TrailingBytes);
    }
    // 8..11. field rules
    if b[O_EFFECT] > 2 {
        return Err(Refusal::BadEffectClass);
    }
    if all_zero(&b[O_CAUSE..O_CAUSE + 32]) {
        return Err(Refusal::NoCause);
    }
    if all_zero(&b[O_TASK..O_TASK + 16]) || all_zero(&b[O_IDEM..O_IDEM + 16]) {
        return Err(Refusal::NoTask);
    }
    if b[O_TYPE] == TYPE_REQUEST && all_zero(&b[O_OBJECTIVE..O_OBJECTIVE + 32]) {
        return Err(Refusal::NoObjective);
    }
    // 12. payload digest
    let digest: [u8; 32] = Sha256::digest(body).into();
    if digest[..] != b[O_DIGEST..O_DIGEST + 32] {
        return Err(Refusal::DigestMismatch);
    }
    Ok(Message {
        header: Header {
            version: b[O_VERSION],
            msg_type: b[O_TYPE],
            cause_id: arr(b, O_CAUSE),
            origin_run_id: arr(b, O_ORIGIN),
            objective_id: arr(b, O_OBJECTIVE),
            subject_id: arr(b, O_SUBJECT),
            parent_task_id: arr(b, O_PARENT),
            task_id: arr(b, O_TASK),
            idempotence_key: arr(b, O_IDEM),
            ordinal: u32::from_be_bytes(arr(b, O_ORDINAL)),
            effect_class: b[O_EFFECT],
            payload_len,
            payload_digest: arr(b, O_DIGEST),
        },
        payload: body,
    })
}

/// Write one message into `out` and return the byte count. Fields are written
/// exactly as given; the digest is not recomputed (use [`payload_digest`]).
pub fn encode(h: &Header, payload: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(EncodeError::PayloadTooLong);
    }
    if usize::from(h.payload_len) != payload.len() {
        return Err(EncodeError::LengthMismatch);
    }
    let n = HEADER_LEN + payload.len();
    if out.len() < n {
        return Err(EncodeError::BufferTooSmall);
    }
    let o = &mut out[..n];
    o[..HEADER_LEN].fill(0);
    o[O_MAGIC..O_MAGIC + 4].copy_from_slice(&MAGIC);
    o[O_VERSION] = h.version;
    o[O_TYPE] = h.msg_type;
    o[O_CAUSE..O_CAUSE + 32].copy_from_slice(&h.cause_id);
    o[O_ORIGIN..O_ORIGIN + 32].copy_from_slice(&h.origin_run_id);
    o[O_OBJECTIVE..O_OBJECTIVE + 32].copy_from_slice(&h.objective_id);
    o[O_SUBJECT..O_SUBJECT + 32].copy_from_slice(&h.subject_id);
    o[O_PARENT..O_PARENT + 16].copy_from_slice(&h.parent_task_id);
    o[O_TASK..O_TASK + 16].copy_from_slice(&h.task_id);
    o[O_IDEM..O_IDEM + 16].copy_from_slice(&h.idempotence_key);
    o[O_ORDINAL..O_ORDINAL + 4].copy_from_slice(&h.ordinal.to_be_bytes());
    o[O_EFFECT] = h.effect_class;
    o[O_PLEN..O_PLEN + 2].copy_from_slice(&h.payload_len.to_be_bytes());
    o[O_DIGEST..O_DIGEST + 32].copy_from_slice(&h.payload_digest);
    o[HEADER_LEN..].copy_from_slice(payload);
    Ok(n)
}

/// SHA-256 of a payload, for filling `Header::payload_digest`.
pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

fn hex(out: &mut String, bytes: &[u8]) {
    const HX: &[u8; 16] = b"0123456789abcdef";
    for &x in bytes {
        out.push(char::from(HX[usize::from(x >> 4)]));
        out.push(char::from(HX[usize::from(x & 15)]));
    }
}

/// The verdict line in the exact format of `pst_verify FILE` and
/// `vectors/expected.txt`.
pub fn verdict_line(result: &Result<Message<'_>, Refusal>) -> String {
    let m = match result {
        Err(r) => return format!("refuse {}", r.code()),
        Ok(m) => &m.header,
    };
    let mut s = String::with_capacity(512);
    s.push_str(&format!(
        "ok type={} version={} cause=",
        m.msg_type, m.version
    ));
    hex(&mut s, &m.cause_id);
    s.push_str(" origin=");
    hex(&mut s, &m.origin_run_id);
    s.push_str(" objective=");
    hex(&mut s, &m.objective_id);
    s.push_str(" subject=");
    hex(&mut s, &m.subject_id);
    s.push_str(" parent=");
    hex(&mut s, &m.parent_task_id);
    s.push_str(" task=");
    hex(&mut s, &m.task_id);
    s.push_str(" idem=");
    hex(&mut s, &m.idempotence_key);
    s.push_str(&format!(
        " ordinal={} effect={} len={} digest=",
        m.ordinal, m.effect_class, m.payload_len
    ));
    hex(&mut s, &m.payload_digest);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Header, &'static [u8]) {
        let payload: &'static [u8] = b"hello";
        let h = Header {
            version: VERSION,
            msg_type: TYPE_REQUEST,
            cause_id: [1; 32],
            origin_run_id: [2; 32],
            objective_id: [3; 32],
            subject_id: [4; 32],
            parent_task_id: [0; 16],
            task_id: [5; 16],
            idempotence_key: [6; 16],
            ordinal: 0,
            effect_class: 1,
            payload_len: 5,
            payload_digest: payload_digest(payload),
        };
        (h, payload)
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let (h, p) = sample();
        let mut out = [0u8; MAX_MESSAGE];
        let n = encode(&h, p, &mut out).unwrap();
        let m = decode(&out[..n]).unwrap();
        assert_eq!(m.header, h);
        assert_eq!(m.payload, p);
    }

    #[test]
    fn encode_refuses_what_it_cannot_write() {
        let (mut h, p) = sample();
        let mut small = [0u8; HEADER_LEN];
        assert_eq!(encode(&h, p, &mut small), Err(EncodeError::BufferTooSmall));
        h.payload_len = 4;
        let mut out = [0u8; MAX_MESSAGE];
        assert_eq!(encode(&h, p, &mut out), Err(EncodeError::LengthMismatch));
        let long = [0u8; MAX_PAYLOAD + 1];
        assert_eq!(
            encode(&h, &long, &mut [0u8; 2048]),
            Err(EncodeError::PayloadTooLong)
        );
    }
}
