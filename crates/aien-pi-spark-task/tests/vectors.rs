//! Walks `specs/pi-spark-task/vectors/expected.txt` and requires the Rust
//! reader to print the same verdict line as the C reference checker
//! (`tools/pst_verify.c`) for every file, and to write every accepted message
//! back out as the identical bytes.

use std::path::PathBuf;

use aien_pi_spark_task::{decode, encode, verdict_line, MAX_MESSAGE};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/pi-spark-task/vectors")
}

#[test]
fn every_expected_line_matches_the_c_checker() {
    let dir = vectors_dir();
    let list = std::fs::read_to_string(dir.join("expected.txt")).expect("read expected.txt");
    let mut checked = 0usize;
    let mut accepted = 0usize;
    let mut failures = Vec::new();
    for line in list.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, want) = line
            .split_once(' ')
            .expect("line has a file name and a verdict");
        let bytes = std::fs::read(dir.join(name)).expect("read vector");
        let result = decode(&bytes);
        let got = verdict_line(&result);
        if got != want {
            failures.push(format!("{name}\n  expected: {want}\n  got:      {got}"));
        }
        if let Ok(msg) = &result {
            let mut out = [0u8; MAX_MESSAGE];
            let n = encode(&msg.header, msg.payload, &mut out).expect("re-encode accepted message");
            if out[..n] != bytes[..] {
                failures.push(format!("{name}: round trip gave different bytes"));
            }
            accepted += 1;
        }
        checked += 1;
    }
    assert!(
        failures.is_empty(),
        "{} of {checked} vectors differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked >= 23,
        "expected at least 23 vectors, found {checked}"
    );
    assert!(
        accepted >= 4,
        "expected at least 4 accepted vectors, found {accepted}"
    );
}
