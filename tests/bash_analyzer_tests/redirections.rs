use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// Allowed redirections (inside project)
// ============================================================================

#[test]
fn test_redirect_to_file_inside_project() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > output.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_append_inside_project() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello >> output.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_stderr_inside_project() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd 2> error.log";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_to_dev_null() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd > /dev/null 2>&1";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_to_dev_zero() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd > /dev/zero";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// Blocked redirections (outside project)
// ============================================================================

#[test]
fn test_redirect_to_absolute_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > /tmp/outside.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
    assert!(result.unwrap().contains("redirection target"));
}

#[test]
fn test_redirect_to_etc() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_append_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello >> /tmp/log.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_stderr_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd 2> /tmp/error.log";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_combined_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd &> /tmp/all.log";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_with_tilde_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > ~/.bashrc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_with_home_var_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > $HOME/.profile";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Multiple redirections
// ============================================================================

#[test]
fn test_multiple_redirects_all_inside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd > out.txt 2> err.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_multiple_redirects_one_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd > out.txt 2> /tmp/err.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_redirect_relative_path_inside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > ./subdir/file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_parent_dir_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > ../outside.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}
