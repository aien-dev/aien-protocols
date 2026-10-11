//! AEI1 section 6 negative matrix, rows testable at receipt level.

use aien_evaluation_protocol::{
    compute_merkle_root, AdaptiveEvidenceError as E, AdaptiveEvidenceReceipt, AdmissionContext,
    CryptographicTier, EvaluationReceipt, EvidenceClass, ReplayLedger,
    SignedAdaptiveEvidenceReceipt, SoftwareP256Signer, Verdict, VerifierIdentity, VerifierSigner,
    AEI1_PROTOCOL_VERSION,
};
use aien_protocol_types::{Digest32, EvaluationId, Timestamp};
use p256::ecdsa::SigningKey;

const TIER2: CryptographicTier = CryptographicTier::Tier2SoftwareKey;

fn signer(seed: u8) -> SoftwareP256Signer {
    SoftwareP256Signer::new(SigningKey::from_slice(&[seed; 32]).expect("valid p256 key"))
}

fn outcomes() -> Vec<Digest32> {
    vec![Digest32([10; 32]), Digest32([11; 32]), Digest32([12; 32])]
}

fn body(s: &SoftwareP256Signer) -> AdaptiveEvidenceReceipt {
    AdaptiveEvidenceReceipt {
        base: EvaluationReceipt {
            protocol_version: AEI1_PROTOCOL_VERSION,
            evaluation_id: EvaluationId::new_v4(),
            request_digest: Digest32([1; 32]),
            subject_digest: Digest32([2; 32]),
            plan_digest: Digest32([3; 32]),
            evidence_root: Digest32([4; 32]),
            outcomes_root: compute_merkle_root(&outcomes()),
            verdict: Verdict::Pass,
            verifier: VerifierIdentity {
                principal_id: "judge".into(),
                key_id: s.key_fingerprint(),
                trust_epoch: 1,
                trusted_build_digest: Digest32([6; 32]),
                policy_bundle_digest: Digest32([7; 32]),
            },
            started_at: Timestamp(1000),
            completed_at: Timestamp(1050),
        },
        world_id: Digest32([20; 32]),
        cortex_session: 5,
        generation: 9,
        execution_id: [21; 32],
        transcript_digest: Digest32([22; 32]),
        cortex_chain_head: Digest32([23; 32]),
        producer_subsystem: "omega-living-body".into(),
        proposer: "proposer-agent".into(),
        proposer_key_fingerprint: signer(77).key_fingerprint(),
        evidence_class: EvidenceClass::Production,
    }
}

struct Fixture {
    judge: SoftwareP256Signer,
    promoter: SoftwareP256Signer,
}

impl Fixture {
    fn new() -> Self {
        Self {
            judge: signer(42),
            promoter: signer(99),
        }
    }
    fn receipt(&self) -> SignedAdaptiveEvidenceReceipt {
        body(&self.judge).sign_with_signer(&self.judge).unwrap()
    }
    fn check(&self, r: &SignedAdaptiveEvidenceReceipt, ledger: &mut ReplayLedger) -> Result<(), E> {
        self.check_as(
            r,
            ledger,
            &self.promoter.key_fingerprint(),
            "promoter-subsystem",
        )
    }
    fn check_as(
        &self,
        r: &SignedAdaptiveEvidenceReceipt,
        ledger: &mut ReplayLedger,
        promoter_fp: &str,
        promoter_sub: &str,
    ) -> Result<(), E> {
        let vk = self.judge.verifying_key();
        r.verify_strict(
            &AdmissionContext {
                trusted_key: &vk,
                expected_tier: TIER2,
                admitted_subject: Digest32([2; 32]),
                expected_policy_digest: Digest32([7; 32]),
                expected_execution_id: [21; 32],
                expected_transcript_digest: Digest32([22; 32]),
                promoter_key_fingerprint: promoter_fp,
                promoter_subsystem: promoter_sub,
            },
            ledger,
        )
    }
}

#[test]
fn genuine_receipt_is_admitted_once() {
    let f = Fixture::new();
    assert_eq!(f.check(&f.receipt(), &mut ReplayLedger::default()), Ok(()));
}

#[test]
fn n1_every_added_field_is_covered_by_the_signature() {
    let f = Fixture::new();
    type Mutator = Box<dyn Fn(&mut AdaptiveEvidenceReceipt)>;
    let muts: Vec<(&str, Mutator)> = vec![
        ("world_id", Box::new(|e| e.world_id = Digest32([1; 32]))),
        ("cortex_session", Box::new(|e| e.cortex_session += 1)),
        ("generation", Box::new(|e| e.generation += 1)),
        ("execution_id", Box::new(|e| e.execution_id = [0; 32])),
        (
            "transcript_digest",
            Box::new(|e| e.transcript_digest = Digest32([0; 32])),
        ),
        (
            "cortex_chain_head",
            Box::new(|e| e.cortex_chain_head = Digest32([0; 32])),
        ),
        (
            "producer_subsystem",
            Box::new(|e| e.producer_subsystem.push('x')),
        ),
        ("proposer", Box::new(|e| e.proposer.push('x'))),
        (
            "proposer_fp",
            Box::new(|e| e.proposer_key_fingerprint.push('x')),
        ),
        ("base.verdict", Box::new(|e| e.base.verdict = Verdict::Fail)),
        (
            "base.completed_at",
            Box::new(|e| e.base.completed_at = Timestamp(1)),
        ),
    ];
    for (name, m) in muts {
        let mut r = f.receipt();
        m(&mut r.evidence);
        assert!(
            matches!(
                f.check(&r, &mut ReplayLedger::default()),
                Err(E::Signature(_))
            ),
            "field {name} not covered"
        );
    }
}

#[test]
fn n2_missing_outcome_record_changes_outcomes_root() {
    let f = Fixture::new();
    let r = f.receipt();
    assert!(r.evidence.outcomes_match(&outcomes()));
    assert!(!r.evidence.outcomes_match(&outcomes()[..2]));
}

#[test]
fn n3_reordered_outcome_records_change_outcomes_root() {
    let f = Fixture::new();
    let mut swapped = outcomes();
    swapped.swap(0, 1);
    assert!(!f.receipt().evidence.outcomes_match(&swapped));
}

#[test]
fn n4_altered_policy_digest_is_refused() {
    let f = Fixture::new();
    let mut e = body(&f.judge);
    e.base.verifier.policy_bundle_digest = Digest32([8; 32]);
    let r = e.sign_with_signer(&f.judge).unwrap(); // validly signed, wrong policy
    assert_eq!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::PolicyMismatch)
    );
}

#[test]
fn n5_same_evaluation_id_twice_is_refused() {
    let f = Fixture::new();
    let r = f.receipt();
    let mut ledger = ReplayLedger::default();
    assert_eq!(f.check(&r, &mut ledger), Ok(()));
    assert!(matches!(f.check(&r, &mut ledger), Err(E::Replay(_))));
}

#[test]
fn n5_execution_id_reused_for_another_candidate_is_refused() {
    let f = Fixture::new();
    let mut ledger = ReplayLedger::default();
    assert_eq!(f.check(&f.receipt(), &mut ledger), Ok(()));
    // Different evaluation, same execution_id, different candidate (consumer admits that candidate).
    let mut e = body(&f.judge);
    e.base.subject_digest = Digest32([3; 32]);
    let r = e.sign_with_signer(&f.judge).unwrap();
    let vk = f.judge.verifying_key();
    let res = r.verify_strict(
        &AdmissionContext {
            trusted_key: &vk,
            expected_tier: TIER2,
            admitted_subject: Digest32([3; 32]),
            expected_policy_digest: Digest32([7; 32]),
            expected_execution_id: [21; 32],
            expected_transcript_digest: Digest32([22; 32]),
            promoter_key_fingerprint: &f.promoter.key_fingerprint(),
            promoter_subsystem: "promoter-subsystem",
        },
        &mut ledger,
    );
    assert!(matches!(res, Err(E::Replay(_))));
}

#[test]
fn n5_receipt_reused_for_another_candidate_is_refused() {
    let f = Fixture::new();
    let mut r = f.receipt();
    r.evidence.base.subject_digest = Digest32([3; 32]); // retarget: breaks signature
    assert!(matches!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::Signature(_))
    ));
}

#[test]
fn n6_unsigned_receipt_is_refused() {
    let f = Fixture::new();
    let mut r = f.receipt();
    r.signature.clear();
    assert_eq!(f.check(&r, &mut ReplayLedger::default()), Err(E::Unsigned));
}

#[test]
fn n7_subject_digest_differing_from_admitted_bytes_is_refused() {
    let f = Fixture::new();
    let mut e = body(&f.judge);
    e.base.subject_digest = Digest32([9; 32]);
    let r = e.sign_with_signer(&f.judge).unwrap();
    assert_eq!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::SubjectMismatch)
    );
}

#[test]
fn n_self_a_promoter_key_equals_producer_key() {
    let f = Fixture::new();
    let fp = f.judge.key_fingerprint();
    let res = f.check_as(
        &f.receipt(),
        &mut ReplayLedger::default(),
        &fp,
        "promoter-subsystem",
    );
    assert!(matches!(res, Err(E::SelfApproval(_))));
}

#[test]
fn n_self_b_promoter_key_equals_proposer_key() {
    let f = Fixture::new();
    let fp = signer(77).key_fingerprint();
    let res = f.check_as(
        &f.receipt(),
        &mut ReplayLedger::default(),
        &fp,
        "promoter-subsystem",
    );
    assert!(matches!(res, Err(E::SelfApproval(_))));
}

#[test]
fn n_self_c_promoter_subsystem_equals_producer_subsystem() {
    let f = Fixture::new();
    let fp = f.promoter.key_fingerprint();
    let res = f.check_as(
        &f.receipt(),
        &mut ReplayLedger::default(),
        &fp,
        "omega-living-body",
    );
    assert!(matches!(res, Err(E::SelfApproval(_))));
}

#[test]
fn n9_flipped_evidence_class_breaks_signature_and_fixture_is_not_production() {
    let f = Fixture::new();
    let mut r = f.receipt();
    r.evidence.evidence_class = EvidenceClass::Fixture;
    assert!(matches!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::Signature(_))
    ));
    let mut e = body(&f.judge);
    e.evidence_class = EvidenceClass::Fixture;
    let r = e.sign_with_signer(&f.judge).unwrap();
    assert_eq!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::NotProduction)
    );
}

#[test]
fn n10_claimed_tier_mismatch_is_refused() {
    let f = Fixture::new();
    let mut r = f.receipt();
    r.cryptographic_tier = CryptographicTier::Tier4HardwareTpm;
    assert!(matches!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::Signature(_))
    ));
}

#[test]
fn n11_transcript_join_mismatch_is_refused() {
    let f = Fixture::new();
    let mut e = body(&f.judge);
    e.transcript_digest = Digest32([0xee; 32]);
    let r = e.sign_with_signer(&f.judge).unwrap();
    assert_eq!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::TranscriptJoinMismatch)
    );
}

#[test]
fn n12_receipt_with_old_protocol_version_is_refused() {
    let f = Fixture::new();
    let mut e = body(&f.judge);
    e.base.protocol_version = 1;
    let r = e.sign_with_signer(&f.judge).unwrap();
    assert_eq!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::VersionMismatch(1))
    );
}

#[test]
fn zero_world_id_is_refused() {
    let f = Fixture::new();
    let mut e = body(&f.judge);
    e.world_id = Digest32::ZERO;
    let r = e.sign_with_signer(&f.judge).unwrap();
    assert_eq!(
        f.check(&r, &mut ReplayLedger::default()),
        Err(E::MissingWorld)
    );
}

#[test]
#[ignore = "n2_n3_cortex_and_transcript_record_gaps_need_trn1_verifier_and_cx_verify_not_in_this_crate"]
fn n2_n3_cortex_and_transcript_record_gaps_need_trn1_verifier_and_cx_verify_not_in_this_crate() {}

#[test]
#[ignore = "step6_cortex_chain_head_reachability_is_open_question_q4_no_contract_yet"]
fn step6_cortex_chain_head_reachability_is_open_question_q4_no_contract_yet() {}

#[test]
#[ignore = "n9_fixture_file_path_loader_and_observation_types_do_not_exist_yet"]
fn n9_fixture_file_path_loader_and_observation_types_do_not_exist_yet() {}

#[test]
#[ignore = "negative_controls_defective_verifier_variants_need_a_mutation_harness_not_built"]
fn negative_controls_defective_verifier_variants_need_a_mutation_harness_not_built() {}
