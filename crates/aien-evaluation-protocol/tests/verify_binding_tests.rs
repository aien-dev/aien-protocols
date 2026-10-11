//! Issue #20: verification must bind the signature to the key, tier and fingerprint.

use aien_evaluation_protocol::{
    verifying_key_fingerprint, CryptographicTier, EvaluationError, EvaluationReceipt,
    SignedEvaluationReceipt, SoftwareP256Signer, Verdict, VerifierIdentity, VerifierSigner,
};
use aien_protocol_types::{Digest32, EvaluationId, Timestamp};
use p256::ecdsa::SigningKey;

const TIER2: CryptographicTier = CryptographicTier::Tier2SoftwareKey;

fn signer(seed: u8) -> SoftwareP256Signer {
    SoftwareP256Signer::new(SigningKey::from_slice(&[seed; 32]).expect("valid p256 key"))
}

fn signed_by(signer: &SoftwareP256Signer) -> SignedEvaluationReceipt {
    let receipt = EvaluationReceipt {
        protocol_version: 1,
        evaluation_id: EvaluationId::new_v4(),
        request_digest: Digest32([1u8; 32]),
        subject_digest: Digest32([2u8; 32]),
        plan_digest: Digest32([3u8; 32]),
        evidence_root: Digest32([4u8; 32]),
        outcomes_root: Digest32([5u8; 32]),
        verdict: Verdict::Pass,
        verifier: VerifierIdentity {
            principal_id: "verifier-node-01".to_string(),
            key_id: signer.key_fingerprint(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([6u8; 32]),
            policy_bundle_digest: Digest32([7u8; 32]),
        },
        started_at: Timestamp(1000),
        completed_at: Timestamp(1050),
    };
    receipt.sign_with_signer(signer).expect("signing failed")
}

#[test]
fn genuine_receipt_verifies_strictly() {
    let s = signer(42);
    let signed = signed_by(&s);
    assert_eq!(
        signed.key_fingerprint,
        verifying_key_fingerprint(&s.verifying_key())
    );
    assert!(signed.verify_with(&s.verifying_key(), TIER2).unwrap());
}

#[test]
fn n10_wrong_key_with_same_tier_is_refused() {
    let signed = signed_by(&signer(42));
    let other = signer(43);
    assert!(signed.verify_with(&other.verifying_key(), TIER2).is_err());
    #[allow(deprecated)]
    let old = signed.verify(&other.verifying_key());
    assert!(old.is_err());
}

#[test]
fn n10_stored_fingerprint_mismatch_is_refused_even_with_valid_signature() {
    let s = signer(42);
    let mut signed = signed_by(&s);
    signed.key_fingerprint = "00".repeat(32); // not covered by the signed digest
    assert!(matches!(
        signed.verify_with(&s.verifying_key(), TIER2),
        Err(EvaluationError::KeyIdentityMismatch { .. })
    ));
    #[allow(deprecated)]
    let old = signed.verify(&s.verifying_key());
    assert!(matches!(
        old,
        Err(EvaluationError::KeyIdentityMismatch { .. })
    ));
}

#[test]
fn n10_claimed_tier4_signed_by_software_key_is_refused() {
    let s = signer(42);
    let mut signed = signed_by(&s);
    signed.cryptographic_tier = CryptographicTier::Tier4HardwareTpm; // also not in the digest
    assert!(matches!(
        signed.verify_with(&s.verifying_key(), TIER2),
        Err(EvaluationError::TierMismatch { .. })
    ));
    // The operator pinning Tier4 is also refused when the receipt honestly says Tier2.
    let honest = signed_by(&s);
    assert!(matches!(
        honest.verify_with(&s.verifying_key(), CryptographicTier::Tier4HardwareTpm),
        Err(EvaluationError::TierMismatch { .. })
    ));
}
