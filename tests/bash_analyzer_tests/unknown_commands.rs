use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// Unknown commands with path-like arguments
// ============================================================================

#[test]
fn test_unknown_cmd_with_internal_path_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool ./file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_unknown_cmd_with_external_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_unknown_cmd_with_tilde_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool ~/.bashrc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_unknown_cmd_with_home_var_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool $HOME/.profile";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Unknown commands with non-path arguments
// ============================================================================

#[test]
fn test_unknown_cmd_with_text_args_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool hello world";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_unknown_cmd_with_flags_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool --verbose --output=result";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_unknown_cmd_with_numbers_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool 123 456";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// Unknown commands with mixed arguments
// ============================================================================

#[test]
fn test_unknown_cmd_mixed_args_one_bad_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool --flag hello /tmp/bad world";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_unknown_cmd_all_internal_paths_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool ./a ./b ./c";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// Commands that look like paths themselves
// ============================================================================

#[test]
fn test_absolute_command_path_with_external_arg() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // Even if command is /usr/bin/tool, we still check args
    let cmd = "/usr/bin/mytool /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_relative_command_path_with_internal_arg() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "./scripts/mytool ./data.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_unknown_cmd_with_dotdot_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool ../outside";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_unknown_cmd_hidden_file_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool .hidden";
    let result = analyze(cmd, &project_root);
    // .hidden is treated as relative to project root, so it's inside
    assert!(result.is_none());
}

// ============================================================================
// --flag=/outside/path extraction from flag values
// ============================================================================

#[test]
fn test_unknown_cmd_flag_equals_external_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool --config=/etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some(), "--config=/etc/passwd should be blocked");
}

#[test]
fn test_unknown_cmd_flag_equals_tilde_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool --input=~/.ssh/id_rsa";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some(), "--input=~/.ssh/id_rsa should be blocked");
}

#[test]
fn test_unknown_cmd_flag_equals_internal_path_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let internal = project_root.join("config.json");
    let cmd = format!("mycustomtool --config={}", internal.display());
    let result = analyze(&cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_unknown_cmd_flag_equals_non_path_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool --format=json --level=debug";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_unknown_cmd_short_flag_equals_external_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mycustomtool -c=/etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some(), "-c=/etc/passwd should be blocked");
}
