use aien_protocol_types::Digest32;
use bitflags::bitflags;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
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
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

impl SourceGrant {
    pub fn new(
        source_uri: String,
        license_spdx: String,
        permissions: GrantPermissions,
        issuer: String,
    ) -> Self {
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

    pub fn with_expiration(mut self, expires_at_epoch_sec: u64) -> Self {
        self.expires_at_epoch_sec = Some(expires_at_epoch_sec);
        self
    }

    /// Computes the deterministic SHA-256 digest of the unsigned grant fields.
    pub fn compute_unsigned_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(self.grant_id.as_bytes());
        hasher.update(self.source_uri.as_bytes());
        hasher.update(self.license_spdx.as_bytes());
        hasher.update(&self.permissions.bits().to_le_bytes());
        hasher.update(self.issuer.as_bytes());
        if let Some(exp) = self.expires_at_epoch_sec {
            hasher.update(b"exp:present");
            hasher.update(&exp.to_le_bytes());
        } else {
            hasher.update(b"exp:none");
        }
        Digest32(hasher.finalize().into())
    }

    /// Signs the grant using the authority signing key.
    pub fn sign(&mut self, authority_signing_key: &SigningKey) {
        let digest = self.compute_unsigned_digest();
        let sig: Signature = authority_signing_key.sign(&digest.0);
        self.issuer_signature = Some(sig.to_bytes().to_vec());
    }

    /// Verifies the cryptographic signature of the grant against the authority verifying key.
    pub fn verify_signature(
        &self,
        authority_verifying_key: &VerifyingKey,
    ) -> Result<(), ProvenanceError> {
        let Some(ref sig_bytes) = self.issuer_signature else {
            return Err(ProvenanceError::MissingSignature);
        };
        let sig = Signature::from_slice(sig_bytes)
            .map_err(|e| ProvenanceError::InvalidSignatureFormat(e.to_string()))?;
        let digest = self.compute_unsigned_digest();
        authority_verifying_key
            .verify(&digest.0, &sig)
            .map_err(|e| ProvenanceError::SignatureVerificationFailed(e.to_string()))
    }

    /// Verifies that the grant has not expired given current epoch timestamp in seconds.
    pub fn verify_validity(&self, current_epoch_sec: u64) -> Result<(), ProvenanceError> {
        if let Some(exp) = self.expires_at_epoch_sec {
            if current_epoch_sec > exp {
                return Err(ProvenanceError::GrantExpired(exp));
            }
        }
        Ok(())
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
        if allowed_licenses
            .iter()
            .any(|&l| l.eq_ignore_ascii_case(&self.license_spdx))
        {
            Ok(())
        } else {
            Err(ProvenanceError::IncompatibleLicense {
                license: self.license_spdx.clone(),
            })
        }
    }

    /// Performs complete authorization verification: license, permissions, expiration, and authority signature.
    pub fn verify_all(
        &self,
        required_permissions: GrantPermissions,
        allowed_licenses: &[&str],
        current_epoch_sec: u64,
        authority_verifying_key: Option<&VerifyingKey>,
    ) -> Result<(), ProvenanceError> {
        self.verify_license(allowed_licenses)?;
        self.verify_permission(required_permissions)?;
        self.verify_validity(current_epoch_sec)?;
        if let Some(vk) = authority_verifying_key {
            self.verify_signature(vk)?;
        }
        Ok(())
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

    #[test]
    fn test_source_grant_signature_and_expiration() {
        let signing_key = SigningKey::from_slice(&[33u8; 32]).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);

        let mut grant = SourceGrant::new(
            "https://hf.co/datasets/aien/verified".to_string(),
            "Apache-2.0".to_string(),
            GrantPermissions::TRAIN | GrantPermissions::DISTILL,
            "Atlas Provenance Authority".to_string(),
        )
        .with_expiration(1000);

        // Missing signature rejected
        assert_eq!(
            grant.verify_signature(&verifying_key),
            Err(ProvenanceError::MissingSignature)
        );

        // Sign grant
        grant.sign(&signing_key);
        assert!(grant.verify_signature(&verifying_key).is_ok());

        // Wrong verifying key rejected
        let other_key = VerifyingKey::from(&SigningKey::from_slice(&[44u8; 32]).unwrap());
        assert!(grant.verify_signature(&other_key).is_err());

        // Validity checks
        assert!(grant.verify_validity(999).is_ok());
        assert_eq!(
            grant.verify_validity(1001),
            Err(ProvenanceError::GrantExpired(1000))
        );

        // verify_all succeeds within window with valid key
        assert!(grant
            .verify_all(
                GrantPermissions::TRAIN,
                &["Apache-2.0"],
                950,
                Some(&verifying_key)
            )
            .is_ok());
    }
}
