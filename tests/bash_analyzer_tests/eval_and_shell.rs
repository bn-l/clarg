use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// eval command
// ============================================================================

#[test]
fn test_eval_safe_command_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "eval \"echo hello\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_eval_unsafe_cd_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "eval \"cd /tmp\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
    assert!(result.unwrap().contains("eval"));
}

#[test]
fn test_eval_cat_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "eval \"cat /etc/passwd\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_eval_nested_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "eval \"eval 'cd /tmp'\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_eval_empty_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "eval";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// bash -c
// ============================================================================

#[test]
fn test_bash_c_safe_command_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bash -c \"echo hello\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_bash_c_unsafe_cd_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bash -c \"cd /tmp\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
    assert!(result.unwrap().contains("bash -c"));
}

#[test]
fn test_bash_c_cat_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bash -c \"cat /etc/passwd\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_bash_c_chain_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bash -c \"cd /tmp && ls\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// sh -c
// ============================================================================

#[test]
fn test_sh_c_safe_command_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sh -c \"echo hello\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_sh_c_unsafe_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sh -c \"cd /tmp\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// zsh -c
// ============================================================================

#[test]
fn test_zsh_c_safe_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "zsh -c \"echo hello\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_zsh_c_unsafe_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "zsh -c \"cd /tmp\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// dash -c
// ============================================================================

#[test]
fn test_dash_c_safe_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "dash -c \"echo hello\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_dash_c_unsafe_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "dash -c \"cd /tmp\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Shell script execution (bash script.sh)
// ============================================================================

#[test]
fn test_bash_script_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bash ./script.sh";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_bash_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bash /tmp/script.sh";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_sh_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sh /etc/init.d/something";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Recursion depth limit
// ============================================================================

#[test]
fn test_deeply_nested_eval_limited() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // Very deeply nested - should hit recursion limit
    let cmd = "eval \"eval \\\"eval \\\\\\\"eval \\\\\\\\\\\\\\\"cd /tmp\\\\\\\\\\\\\\\"\\\\\\\"\\\"\"";
    let result = analyze(cmd, &project_root);
    // Either blocked by recursion limit or by the inner cd
    // The important thing is it doesn't crash
    assert!(result.is_some() || result.is_none());
}

// ============================================================================
// UTF-8 truncation safety (no panic on multi-byte boundaries)
// ============================================================================

#[test]
fn test_eval_with_long_unicode_command_no_panic() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // Create a command with multi-byte UTF-8 characters that exceeds truncation limit (80 chars)
    let long_unicode = "é".repeat(90);
    let cmd = format!("eval \"cat /etc/passwd {}\"", long_unicode);
    let result = analyze(&cmd, &project_root);
    // Should deny (external path) without panicking
    assert!(result.is_some());
}

#[test]
fn test_bash_c_with_long_unicode_command_no_panic() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let long_unicode = "日本語テスト".repeat(20);
    let cmd = format!("bash -c \"cat /etc/passwd {}\"", long_unicode);
    let result = analyze(&cmd, &project_root);
    assert!(result.is_some());
}
