use aien_protocol_types::Digest32;
use sha2::{Digest, Sha256};

pub fn compute_sha256(bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Digest32::from_bytes(arr)
}

pub fn compute_canonical_json_digest<T: serde::Serialize>(val: &T) -> Result<Digest32, serde_json::Error> {
    let json_bytes = serde_json::to_vec(val)?;
    Ok(compute_sha256(&json_bytes))
}

pub fn combine_digests(d1: &Digest32, d2: &Digest32) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(d1.as_bytes());
    hasher.update(d2.as_bytes());
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Digest32::from_bytes(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_deterministic() {
        let d1 = compute_sha256(b"hello aien protocols");
        let d2 = compute_sha256(b"hello aien protocols");
        assert_eq!(d1, d2);
        assert_ne!(d1, Digest32::ZERO);
    }
}
