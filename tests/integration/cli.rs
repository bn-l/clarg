use super::common::*;

#[test]
fn test_positional_with_flags_error() {
    let input = hook_json("Read", serde_json::json!({"file_path": "/tmp/file"}));
    let (code, _stdout, _stderr) = run_clarg(&["config.yaml", "-i"], &input);
    assert_eq!(code, 2, "should fail closed on clap error");
}

#[test]
fn test_malformed_json_fail_closed() {
    let (code, stdout, stderr) = run_clarg(&["-i"], "not valid json{{{");
    assert_eq!(code, 2, "should fail closed on malformed JSON");
    assert!(stderr.contains("internal error"));
    // stdout should still be structured JSON
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should still be valid JSON");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn test_empty_stdin_fail_closed() {
    let (code, _stdout, stderr) = run_clarg(&["-i"], "");
    assert_eq!(code, 2, "should fail closed on empty stdin");
    assert!(stderr.contains("internal error"));
}

#[test]
fn test_help_flag() {
    let mut cmd = clarg_bin();
    cmd.arg("--help");
    cmd.stdin(std::process::Stdio::null());
    let output = cmd.output().expect("failed to run --help");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage:"),
        "should show clap help, not friendly usage. Got: {stdout}"
    );
    assert!(
        stdout.contains("--internal-access-only"),
        "should list CLI flags. Got: {stdout}"
    );
}

#[test]
fn test_version_flag() {
    let mut cmd = clarg_bin();
    cmd.arg("-V");
    cmd.stdin(std::process::Stdio::null());
    let output = cmd.output().expect("failed to run -V");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clarg"),
        "should show version string. Got: {stdout}"
    );
    assert!(
        !stdout.contains("QUICK SETUP"),
        "should show clap version, not friendly usage. Got: {stdout}"
    );
}

#[test]
fn test_help_flag_in_tty() {
    let (code, output) = run_clarg_in_pty(&["--help"]);
    assert_eq!(code, 0, "--help should exit 0 in TTY");
    assert!(
        output.contains("Usage:"),
        "should show clap help in TTY, not friendly usage. Got: {output}"
    );
    assert!(
        output.contains("--internal-access-only"),
        "should list CLI flags in TTY. Got: {output}"
    );
}

#[test]
fn test_version_flag_in_tty() {
    let (code, output) = run_clarg_in_pty(&["-V"]);
    assert_eq!(code, 0, "-V should exit 0 in TTY");
    assert!(
        output.contains("clarg"),
        "should show version string in TTY. Got: {output}"
    );
    assert!(
        !output.contains("QUICK SETUP"),
        "should show clap version, not friendly usage. Got: {output}"
    );
}

#[test]
fn test_bare_invocation_in_tty_shows_friendly_usage() {
    let (code, output) = run_clarg_in_pty(&[]);
    assert_eq!(code, 0, "bare clarg in TTY should exit 0");
    assert!(
        output.contains("QUICK SETUP"),
        "bare clarg in TTY should show friendly usage. Got: {output}"
    );
}
