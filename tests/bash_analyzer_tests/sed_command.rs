use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// sed with internal files (allowed)
// ============================================================================

#[test]
fn test_sed_on_internal_file_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed 's/foo/bar/' file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_sed_inplace_internal_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed -i 's/foo/bar/' file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_sed_inplace_backup_internal_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed -i.bak 's/foo/bar/' file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_sed_with_e_flag_internal_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed -e 's/foo/bar/' -e 's/baz/qux/' file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_sed_with_f_flag_internal_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed -f script.sed file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// sed with external files (blocked)
// ============================================================================

#[test]
fn test_sed_on_external_file_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed 's/foo/bar/' /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_sed_inplace_external_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed -i 's/foo/bar/' /etc/hosts";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_sed_tilde_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed -i 's/foo/bar/' ~/.bashrc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_sed_multiple_files_one_external_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed 's/foo/bar/' file1.txt /etc/passwd file2.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// sed with -f pointing to external script (blocked)
// ============================================================================

// TODO: Not yet implemented - sed -f argument is skipped without checking
// if the script file path is external
#[test]
#[ignore]
fn test_sed_f_flag_external_script_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "sed -f /tmp/malicious.sed file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_sed_no_file_args_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // sed reading from stdin
    let cmd = "sed 's/foo/bar/'";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_sed_expression_looks_like_path_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // The sed expression itself contains path-like chars
    let cmd = "sed 's|/old/path|/new/path|' file.txt";
    let result = analyze(cmd, &project_root);
    // Should be allowed - the paths are in the expression, not file args
    assert!(result.is_none());
}
