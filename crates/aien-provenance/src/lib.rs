use aien_protocol_types::Digest32;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub fn compute_sha256(bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Digest32::from_bytes(arr)
}

pub fn compute_canonical_json_digest<T: Serialize>(val: &T) -> Result<Digest32, serde_json::Error> {
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

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct GrantPermissions: u32 {
        const READ = 0b0000_0001;
        const EVALUATE = 0b0000_0010;
        const TRAIN = 0b0000_0100;
        const DISTILL = 0b0000_1000;
        const REDISTRIBUTE = 0b0001_0000;
        const COMMERCIAL = 0b0010_0000;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceGrant {
    pub grant_id: Uuid,
    pub source_uri: String,
    pub license_spdx: String,
    pub permissions: GrantPermissions,
    pub issuer: String,
    pub issuer_signature: Option<Vec<u8>>,
    pub expires_at_epoch_sec: Option<u64>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    #[error("Source grant permission denied: required {required:?}, granted {granted:?}")]
    PermissionDenied {
        required: GrantPermissions,
        granted: GrantPermissions,
    },
    #[error("Incompatible license: {license} not in allowed set")]
    IncompatibleLicense { license: String },
    #[error("Grant has expired at {0}")]
    GrantExpired(u64),
    #[error("Missing signature from authority")]
    MissingSignature,
}

impl SourceGrant {
    pub fn new(source_uri: String, license_spdx: String, permissions: GrantPermissions, issuer: String) -> Self {
        Self {
            grant_id: Uuid::new_v4(),
            source_uri,
            license_spdx,
            permissions,
            issuer,
            issuer_signature: None,
            expires_at_epoch_sec: None,
        }
    }

    pub fn verify_permission(&self, required: GrantPermissions) -> Result<(), ProvenanceError> {
        if self.permissions.contains(required) {
            Ok(())
        } else {
            Err(ProvenanceError::PermissionDenied {
                required,
                granted: self.permissions,
            })
        }
    }

    pub fn verify_license(&self, allowed_licenses: &[&str]) -> Result<(), ProvenanceError> {
        if allowed_licenses.iter().any(|&l| l.eq_ignore_ascii_case(&self.license_spdx)) {
            Ok(())
        } else {
            Err(ProvenanceError::IncompatibleLicense {
                license: self.license_spdx.clone(),
            })
        }
    }

    pub fn compute_digest(&self) -> Digest32 {
        compute_canonical_json_digest(self).unwrap_or(Digest32::ZERO)
    }
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

    #[test]
    fn test_source_grant_permissions_and_licensing() {
        let grant = SourceGrant::new(
            "https://huggingface.co/datasets/aien/benchmark".to_string(),
            "Apache-2.0".to_string(),
            GrantPermissions::READ | GrantPermissions::EVALUATE | GrantPermissions::TRAIN,
            "Atlas Authority".to_string(),
        );

        assert!(grant.verify_permission(GrantPermissions::TRAIN).is_ok());
        assert!(grant.verify_permission(GrantPermissions::DISTILL).is_err());
        assert!(grant.verify_license(&["Apache-2.0", "MIT"]).is_ok());
        assert!(grant.verify_license(&["GPL-3.0"]).is_err());
    }
}
