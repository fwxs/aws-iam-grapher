//! End-to-end exit-code and JSON-error-envelope assertions (issue #144). Drives the built
//! `aws-iam-grapher` binary via `std::process::Command` — no `assert_cmd` dependency, the
//! handful of assertions here (exit code, stdout emptiness, stderr JSON shape) don't need a
//! fluent builder.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;
use testcontainers_modules::{
    neo4j::{Neo4j, Neo4jImage},
    testcontainers::{core::WaitFor, runners::AsyncRunner, ContainerAsync, ImageExt as _},
};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aws-iam-grapher"))
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../iam-collector/tests/fixtures")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env_remove("NEO4J_PASSWORD")
        .output()
        .expect("binary must spawn")
}

/// Parse the JSON error envelope from stderr. Non-JSON diagnostic lines (collection
/// warnings via `[!] ...`, printed via `eprintln!` before a later failure) may precede it,
/// so this looks for the `{` that starts the envelope rather than requiring the whole
/// stream to be pure JSON.
fn json_error_envelope(output: &Output) -> serde_json::Value {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let json_start = stderr
        .find('{')
        .unwrap_or_else(|| panic!("stderr had no JSON envelope: {stderr}"));
    serde_json::from_str(&stderr[json_start..])
        .unwrap_or_else(|e| panic!("stderr JSON envelope did not parse ({e}): {stderr}"))
}

// ---------------------------------------------------------------------------
// Class 2 — usage / validation, no Neo4j required
// ---------------------------------------------------------------------------

#[test]
fn usage_missing_input_file_offline_mode_exits_2() {
    let output = run(&["collect", "--mode", "offline"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--input-file"));
}

#[test]
fn usage_missing_input_file_offline_mode_json_envelope() {
    let output = run(&["--output", "json", "collect", "--mode", "offline"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let envelope = json_error_envelope(&output);
    assert_eq!(envelope["error"]["code"], "usage");
    assert!(envelope["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--input-file"));
}

#[test]
fn usage_graphviz_unsupported_query_exits_2() {
    let output = run(&[
        "--output",
        "graphviz",
        "query",
        "--neo4j-uri",
        "bolt://127.0.0.1:1",
        "list-snapshots",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    // --output graphviz means the error path itself isn't JSON-gated (graphviz has no
    // envelope format), so this asserts the plain-text path, not a JSON envelope.
    assert!(String::from_utf8_lossy(&output.stderr).contains("not supported for this query"));
}

// ---------------------------------------------------------------------------
// Class 3 — credential / connection failure, no Neo4j required (we point at a
// refusing port, and at a missing password — both are connection/credential
// failures regardless of root cause).
// ---------------------------------------------------------------------------

#[test]
fn credential_connection_refused_exits_3() {
    let pass_file = tempfile::NamedTempFile::new().expect("create temp pass file");
    std::fs::write(pass_file.path(), "dummy-test-password-xyz").expect("write pass file");

    let output = run(&[
        "--output",
        "json",
        "query",
        "--neo4j-uri",
        "bolt://127.0.0.1:1",
        "--neo4j-pass-file",
        pass_file.path().to_str().unwrap(),
        "list-snapshots",
    ]);

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let envelope = json_error_envelope(&output);
    assert_eq!(envelope["error"]["code"], "credential");
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(!message.contains("dummy-test-password-xyz"));
}

#[test]
fn credential_missing_neo4j_password_exits_3() {
    let output = run(&[
        "--output",
        "json",
        "collect",
        "--mode",
        "offline",
        "--input-file",
        fixture_path("account_auth_details_minimal.json")
            .to_str()
            .unwrap(),
        "--dry-run",
    ]);

    // --dry-run returns before the password is ever needed — this asserts the
    // *non*-dry-run path actually requires it.
    let output_live = run(&[
        "--output",
        "json",
        "collect",
        "--mode",
        "offline",
        "--input-file",
        fixture_path("account_auth_details_minimal.json")
            .to_str()
            .unwrap(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "dry-run must not require a password"
    );
    assert_eq!(output_live.status.code(), Some(3));
    let envelope = json_error_envelope(&output_live);
    assert_eq!(envelope["error"]["code"], "credential");
}

// ---------------------------------------------------------------------------
// Class 4 / empty-result — needs a live Neo4j with one ingested snapshot.
// ---------------------------------------------------------------------------

struct Neo4jHandle {
    uri: String,
    user: String,
    pass_file: tempfile::NamedTempFile,
}

async fn start_neo4j() -> Neo4jHandle {
    let container: ContainerAsync<Neo4jImage> = Neo4j::default()
        .with_ready_conditions(vec![
            WaitFor::message_on_either_std("Bolt enabled on"),
            WaitFor::message_on_either_std("Started."),
        ])
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .await
        .expect("Neo4j must start");

    let host = container.get_host().await.expect("host must be available");
    let port = container
        .image()
        .bolt_port_ipv4()
        .expect("bolt port must be available");
    let uri = format!("bolt://{host}:{port}");
    let user = container
        .image()
        .user()
        .expect("default user is set")
        .to_string();
    let pass = container
        .image()
        .password()
        .expect("default password is set")
        .to_string();

    Box::leak(Box::new(container));

    use std::io::Write as _;
    let mut pass_file = tempfile::NamedTempFile::new().expect("create temp pass file");
    pass_file
        .write_all(pass.as_bytes())
        .expect("write temp pass file");

    Neo4jHandle {
        uri,
        user,
        pass_file,
    }
}

fn collect_offline(neo4j: &Neo4jHandle) -> Output {
    Command::new(bin())
        .args([
            "collect",
            "--mode",
            "offline",
            "--input-file",
            fixture_path("account_auth_details_minimal.json")
                .to_str()
                .unwrap(),
            "--neo4j-uri",
            &neo4j.uri,
            "--neo4j-user",
            &neo4j.user,
            "--neo4j-pass-file",
            neo4j.pass_file.path().to_str().unwrap(),
        ])
        .env_remove("NEO4J_PASSWORD")
        .output()
        .expect("collect must spawn")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn credential_wrong_neo4j_password_exits_3() {
    let neo4j = start_neo4j().await;

    let mut wrong_pass_file = tempfile::NamedTempFile::new().expect("create temp pass file");
    use std::io::Write as _;
    wrong_pass_file
        .write_all(b"definitely-the-wrong-password")
        .expect("write temp pass file");

    let output = Command::new(bin())
        .args([
            "--output",
            "json",
            "query",
            "--neo4j-uri",
            &neo4j.uri,
            "--neo4j-user",
            &neo4j.user,
            "--neo4j-pass-file",
            wrong_pass_file.path().to_str().unwrap(),
            "list-snapshots",
        ])
        .env_remove("NEO4J_PASSWORD")
        .output()
        .expect("query must spawn");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let envelope = json_error_envelope(&output);
    assert_eq!(envelope["error"]["code"], "credential");
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(!message.contains("definitely-the-wrong-password"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn scope_not_found_nonexistent_snapshot_exits_4() {
    let neo4j = start_neo4j().await;
    let collect_output = collect_offline(&neo4j);
    assert!(
        collect_output.status.success(),
        "seed collect must succeed: {}",
        String::from_utf8_lossy(&collect_output.stderr)
    );

    let output = Command::new(bin())
        .args([
            "--output",
            "json",
            "query",
            "--neo4j-uri",
            &neo4j.uri,
            "--neo4j-user",
            &neo4j.user,
            "--neo4j-pass-file",
            neo4j.pass_file.path().to_str().unwrap(),
            "--account-id",
            "123456789012",
            "--snapshot-id",
            "does-not-exist-xyz",
            "entity-perms",
            "arn:aws:iam::123456789012:user/alice",
        ])
        .env_remove("NEO4J_PASSWORD")
        .output()
        .expect("query must spawn");

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let envelope = json_error_envelope(&output);
    assert_eq!(envelope["error"]["code"], "scope-not-found");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn empty_result_who_can_exits_0_with_empty_array() {
    let neo4j = start_neo4j().await;
    let collect_output = collect_offline(&neo4j);
    assert!(
        collect_output.status.success(),
        "seed collect must succeed: {}",
        String::from_utf8_lossy(&collect_output.stderr)
    );

    let output = Command::new(bin())
        .args([
            "--output",
            "json",
            "query",
            "--neo4j-uri",
            &neo4j.uri,
            "--neo4j-user",
            &neo4j.user,
            "--neo4j-pass-file",
            neo4j.pass_file.path().to_str().unwrap(),
            "--account-id",
            "123456789012",
            "who-can",
            "s3:GetObject",
        ])
        .env_remove("NEO4J_PASSWORD")
        .output()
        .expect("query must spawn");

    // Not asserting stderr is empty: a partial-snapshot warning legitimately prints there
    // for this offline fixture (no instance-profiles/MFA data) — orthogonal to this issue,
    // which only requires that success never touches exit code or stdout shape.
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be JSON");
    assert_eq!(parsed["results"], serde_json::json!([]));
}
