//! End-to-end tests of the binary itself.
//!
//! These lock the *contract* the README documents: exit codes and the shape of
//! `--json` output. Everything here runs offline against a real SK ID Solutions
//! token in tests/fixtures/demo-proof.json.

use assert_cmd::Command;
use predicates::prelude::*;

fn tb() -> Command {
    let mut c = Command::cargo_bin("trustbeat").unwrap();
    // Never let a developer's real credentials leak into a test run.
    c.env_remove("TRUSTBEAT_API_KEY")
        .env("TRUSTBEAT_CONFIG_HOME", "/nonexistent");
    c
}

const PROOF: &str = "tests/fixtures/demo-proof.json";

#[test]
fn verify_a_valid_proof_exits_zero() {
    tb().args(["verify", PROOF])
        .assert()
        .success()
        .stdout(predicate::str::contains("PROOF VALID"));
}

#[test]
fn verify_binds_the_proof_to_the_wrong_file_and_exits_one() {
    let dir = tempdir();
    let file = dir.join("not-the-document.txt");
    std::fs::write(&file, b"some other content").unwrap();

    tb().args(["verify", PROOF, file.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("PROOF INVALID"));

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn verify_reports_the_tsa_and_the_anchor_time() {
    tb().args(["verify", PROOF])
        .assert()
        .success()
        .stdout(predicate::str::contains("2026-04-04T07:53:48Z"))
        .stdout(predicate::str::contains("SK TIMESTAMPING UNIT"));
}

#[test]
fn verify_json_is_machine_readable() {
    let out = tb().args(["verify", PROOF, "--json"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["valid"], true);
    assert_eq!(v["checks"].as_array().unwrap().len(), 4);
    assert_eq!(v["timestamp"]["time"], "2026-04-04T07:53:48Z");
    assert_eq!(v["timestamp"]["serial"], "7390573335772836610");
}

#[test]
fn verify_reads_a_proof_from_stdin() {
    tb().args(["verify", "-"])
        .write_stdin(std::fs::read_to_string(PROOF).unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("PROOF VALID"));
}

#[test]
fn a_malformed_proof_is_a_usage_error_not_an_invalid_proof() {
    // Exit 2 (bad input) must stay distinct from exit 1 (proof genuinely invalid).
    let dir = tempdir();
    let junk = dir.join("junk.json");
    std::fs::write(&junk, b"{not json").unwrap();

    tb().args(["verify", junk.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a valid proof bundle"));

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_missing_proof_file_exits_two() {
    tb().args(["verify", "/nonexistent/proof.json"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot read"));
}

#[test]
fn hash_prints_the_sha256() {
    let dir = tempdir();
    let file = dir.join("abc.txt");
    std::fs::write(&file, b"abc").unwrap();

    tb().args(["hash", file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ));

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn anchor_without_a_key_explains_itself_and_never_touches_the_network() {
    tb().args(["anchor", PROOF])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no API key found"));
}

#[test]
fn an_invalid_hash_is_rejected_before_any_request() {
    tb().args(["anchor", "--hash", "deadbeef"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("64-character SHA-256"));
}

#[test]
fn help_and_version_work() {
    tb().arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("verify"));
    tb().arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "trustbeat-cli-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
