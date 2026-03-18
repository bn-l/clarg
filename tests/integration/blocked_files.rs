use super::common::*;

#[test]
fn test_block_env_file_read() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "Read",
        serde_json::json!({"file_path": format!("{}/.env", cwd)}),
        cwd,
    );
    let (code, stdout, stderr) = run_clarg(&["-b", ".env"], &input);
    assert_eq!(code, 2, "should exit 2 (block)");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("stdout should be JSON");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert!(stderr.contains("Blocked by `clarg`"));
}

#[test]
fn test_allow_normal_file_read() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "Read",
        serde_json::json!({"file_path": format!("{}/src/main.rs", cwd)}),
        cwd,
    );
    let (code, stdout, _stderr) = run_clarg(&["-b", ".env"], &input);
    assert_eq!(code, 0, "should exit 0 (allow)");
    assert!(
        stdout.trim().is_empty() || !stdout.contains("deny"),
        "should not contain deny output"
    );
}

#[test]
fn test_multiple_blocked_patterns() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "Read",
        serde_json::json!({"file_path": format!("{}/api.secret", cwd)}),
        cwd,
    );
    let (code, _, _) = run_clarg(&["-b", ".env,*.secret"], &input);
    assert_eq!(code, 2, "*.secret should be blocked");
}
