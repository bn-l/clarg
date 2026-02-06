use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// rg (ripgrep) command
// ============================================================================

#[test]
fn test_rg_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rg pattern";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_rg_with_path_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rg pattern ./src";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_rg_with_path_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rg pattern /etc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_rg_with_flags_and_outside_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rg -i --hidden pattern /etc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_rg_glob_flag_not_treated_as_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rg -g '*.rs' pattern";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_rg_type_flag_not_treated_as_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rg -t rust pattern";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// grep command
// ============================================================================

#[test]
fn test_grep_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "grep pattern file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_grep_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "grep pattern /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_grep_recursive_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "grep -r pattern /etc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_grep_with_e_flag_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // -e takes an argument (the pattern)
    let cmd = "grep -e 'pattern' file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// find command
// ============================================================================

#[test]
fn test_find_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "find . -name '*.rs'";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_find_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "find /etc -name 'passwd'";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_find_root_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "find / -name '*.conf'";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_find_home_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "find ~ -name '.bashrc'";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// fd command
// ============================================================================

#[test]
fn test_fd_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "fd pattern";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_fd_with_path_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "fd pattern ./src";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_fd_with_path_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "fd pattern /etc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// ag (silver searcher) command
// ============================================================================

#[test]
fn test_ag_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "ag pattern";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_ag_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "ag pattern /etc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// ack command
// ============================================================================

#[test]
fn test_ack_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "ack pattern";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_ack_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "ack pattern /etc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}
