//! AEI1 extension receipt (specs/evidence/ADAPTIVE_EVIDENCE_INTERFACE.md section 2).
//! Wraps `EvaluationReceipt` unchanged; the added fields enter a new signed digest.

use crate::{
    compute_merkle_root, verifying_key_fingerprint, CryptographicTier, EvaluationError,
    EvaluationReceipt, VerifierSigner,
};
use aien_protocol_types::{Digest32, EvaluationId};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// `EvaluationReceipt.protocol_version` required for an AEI1 receipt (AEI1 2.1: bump so old verifiers refuse).
pub const AEI1_PROTOCOL_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvidenceClass {
    Production,
    Fixture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveEvidenceReceipt {
    pub base: EvaluationReceipt,
    pub world_id: Digest32,
    pub cortex_session: u64,
    pub generation: u64,
    pub execution_id: [u8; 32],
    pub transcript_digest: Digest32,
    pub cortex_chain_head: Digest32,
    pub producer_subsystem: String,
    pub proposer: String,
    /// Key fingerprint of the proposer; `proposer` alone is a name, so N-self (b) needs this.
    pub proposer_key_fingerprint: String,
    pub evidence_class: EvidenceClass,
}

fn put_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

impl AdaptiveEvidenceReceipt {
    pub fn compute_digest(&self) -> Digest32 {
        let mut h = Sha256::new();
        h.update(b"AEI1\0");
        h.update(self.base.compute_receipt_digest().0);
        h.update(self.world_id.0);
        h.update(self.cortex_session.to_le_bytes());
        h.update(self.generation.to_le_bytes());
        h.update(self.execution_id);
        h.update(self.transcript_digest.0);
        h.update(self.cortex_chain_head.0);
        put_str(&mut h, &self.producer_subsystem);
        put_str(&mut h, &self.proposer);
        put_str(&mut h, &self.proposer_key_fingerprint);
        h.update([match self.evidence_class {
            EvidenceClass::Production => 0u8,
            EvidenceClass::Fixture => 1u8,
        }]);
        Digest32(h.finalize().into())
    }

    pub fn sign_with_signer(
        &self,
        signer: &dyn VerifierSigner,
    ) -> Result<SignedAdaptiveEvidenceReceipt, EvaluationError> {
        let fingerprint = signer.key_fingerprint();
        if self.base.verifier.key_id != fingerprint {
            return Err(EvaluationError::KeyIdentityMismatch {
                expected: self.base.verifier.key_id.clone(),
                actual: fingerprint,
            });
        }
        Ok(SignedAdaptiveEvidenceReceipt {
            evidence: self.clone(),
            signature: signer.sign_digest(&self.compute_digest().0)?,
            cryptographic_tier: signer.cryptographic_tier(),
            key_fingerprint: fingerprint,
        })
    }

    /// N2/N3 at receipt level: the evaluator outcome digests, in order, must reproduce `outcomes_root`.
    pub fn outcomes_match(&self, outcome_digests: &[Digest32]) -> bool {
        compute_merkle_root(outcome_digests) == self.base.outcomes_root
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedAdaptiveEvidenceReceipt {
    pub evidence: AdaptiveEvidenceReceipt,
    pub signature: Vec<u8>,
    pub cryptographic_tier: CryptographicTier,
    pub key_fingerprint: String,
}

/// What the consumer already trusts or is about to admit. Never read from the receipt.
pub struct AdmissionContext<'a> {
    pub trusted_key: &'a VerifyingKey,
    pub expected_tier: CryptographicTier,
    pub admitted_subject: Digest32,
    pub expected_policy_digest: Digest32,
    pub expected_execution_id: [u8; 32],
    pub expected_transcript_digest: Digest32,
    pub promoter_key_fingerprint: &'a str,
    pub promoter_subsystem: &'a str,
}

/// Replay memory: consumed evaluation ids and which candidate each execution id was used for.
#[derive(Default)]
pub struct ReplayLedger {
    evaluations: HashSet<EvaluationId>,
    executions: HashMap<[u8; 32], Digest32>,
}

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum AdaptiveEvidenceError {
    #[error("unsigned receipt")]
    Unsigned,
    #[error("signature, key or tier check failed: {0}")]
    Signature(String),
    #[error("protocol version {0} is not the AEI1 version")]
    VersionMismatch(u32),
    #[error("receipt subject does not match the admitted candidate")]
    SubjectMismatch,
    #[error("policy digest mismatch")]
    PolicyMismatch,
    #[error("execution_id or transcript_digest does not match the transcript")]
    TranscriptJoinMismatch,
    #[error("evidence class is not Production")]
    NotProduction,
    #[error("world_id is zero")]
    MissingWorld,
    #[error("self-approval: {0}")]
    SelfApproval(&'static str),
    #[error("replay: {0}")]
    Replay(&'static str),
}

impl SignedAdaptiveEvidenceReceipt {
    /// AEI1 2.2 steps 1 to 4, 7, 8 plus replay. Refuses at the first failure; consumes the
    /// ledger entry only on success.
    pub fn verify_strict(
        &self,
        ctx: &AdmissionContext<'_>,
        ledger: &mut ReplayLedger,
    ) -> Result<(), AdaptiveEvidenceError> {
        use AdaptiveEvidenceError as E;
        let ev = &self.evidence;
        if self.signature.is_empty() {
            return Err(E::Unsigned);
        }
        if ev.base.protocol_version != AEI1_PROTOCOL_VERSION {
            return Err(E::VersionMismatch(ev.base.protocol_version));
        }
        if self.cryptographic_tier != ctx.expected_tier {
            return Err(E::Signature("tier mismatch".into()));
        }
        let fp = verifying_key_fingerprint(ctx.trusted_key);
        if self.key_fingerprint != fp || ev.base.verifier.key_id != fp {
            return Err(E::Signature("key fingerprint mismatch".into()));
        }
        let sig =
            Signature::from_slice(&self.signature).map_err(|e| E::Signature(e.to_string()))?;
        ctx.trusted_key
            .verify(&ev.compute_digest().0, &sig)
            .map_err(|e| E::Signature(e.to_string()))?;
        if ev.base.subject_digest != ctx.admitted_subject {
            return Err(E::SubjectMismatch);
        }
        if ev.base.verifier.policy_bundle_digest != ctx.expected_policy_digest {
            return Err(E::PolicyMismatch);
        }
        if ev.execution_id != ctx.expected_execution_id
            || ev.transcript_digest != ctx.expected_transcript_digest
        {
            return Err(E::TranscriptJoinMismatch);
        }
        if ev.world_id == Digest32::ZERO {
            return Err(E::MissingWorld);
        }
        if ev.evidence_class != EvidenceClass::Production {
            return Err(E::NotProduction);
        }
        if ctx.promoter_key_fingerprint == self.key_fingerprint {
            return Err(E::SelfApproval("promoter key is the producer key"));
        }
        if ctx.promoter_key_fingerprint == ev.proposer_key_fingerprint {
            return Err(E::SelfApproval("promoter key is the proposer key"));
        }
        if ctx.promoter_subsystem == ev.producer_subsystem {
            return Err(E::SelfApproval(
                "promoter subsystem is the producer subsystem",
            ));
        }
        if ledger.evaluations.contains(&ev.base.evaluation_id) {
            return Err(E::Replay("evaluation_id already consumed"));
        }
        if ledger
            .executions
            .get(&ev.execution_id)
            .is_some_and(|s| *s != ev.base.subject_digest)
        {
            return Err(E::Replay("execution_id already used for another candidate"));
        }
        ledger.evaluations.insert(ev.base.evaluation_id);
        ledger
            .executions
            .insert(ev.execution_id, ev.base.subject_digest);
        Ok(())
    }
}
