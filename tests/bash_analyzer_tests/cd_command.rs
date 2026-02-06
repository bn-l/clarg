use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// cd inside project (allowed)
// ============================================================================

#[test]
fn test_cd_to_subdirectory_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd src";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_cd_to_nested_subdirectory_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd src/lib/utils";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_cd_with_dot_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd .";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_cd_with_dotslash_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd ./src";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// cd outside project (blocked)
// ============================================================================

#[test]
fn test_cd_no_args_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
    assert!(result.unwrap().contains("$HOME"));
}

#[test]
fn test_cd_dash_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd -";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
    assert!(result.unwrap().contains("cd -"));
}

#[test]
fn test_cd_to_absolute_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd /tmp";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_to_etc_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd /etc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_to_root_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd /";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_to_tilde_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd ~";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_to_tilde_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd ~/.config";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_to_home_var_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd $HOME";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_to_parent_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd ..";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_to_parent_parent_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd ../..";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_with_parent_escaping_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd src/../../outside";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// cd in compound commands
// ============================================================================

#[test]
fn test_cd_in_and_chain_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd /tmp && ls";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cd_in_semicolon_chain_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello; cd /tmp; ls";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_safe_cd_in_chain_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cd src && ls -la";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// cd with sudo/env prefix
// ============================================================================

#[test]
fn test_sudo_cd_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sudo cd /tmp";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_env_cd_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "env cd /tmp";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}
