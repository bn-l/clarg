use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// cat command
// ============================================================================

#[test]
fn test_cat_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_cat_absolute_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cat_multiple_files_one_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat file1.txt /etc/passwd file2.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cat_with_flags_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat -n /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// cp command
// ============================================================================

#[test]
fn test_cp_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cp file1.txt file2.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_cp_source_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cp /etc/passwd ./copy.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cp_dest_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cp file.txt /tmp/copy.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_cp_recursive_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cp -r /etc ./backup";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// mv command
// ============================================================================

#[test]
fn test_mv_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mv file1.txt file2.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_mv_source_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mv /tmp/file.txt ./";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_mv_dest_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mv file.txt /tmp/";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// rm command
// ============================================================================

#[test]
fn test_rm_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rm file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_rm_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rm /tmp/file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_rm_recursive_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rm -rf /tmp/dir";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_rm_root_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "rm -rf /";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// touch command
// ============================================================================

#[test]
fn test_touch_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "touch newfile.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_touch_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "touch /tmp/newfile.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// mkdir command
// ============================================================================

#[test]
fn test_mkdir_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mkdir newdir";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_mkdir_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mkdir /tmp/newdir";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_mkdir_p_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "mkdir -p /tmp/a/b/c";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// head/tail commands
// ============================================================================

#[test]
fn test_head_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "head file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_head_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "head /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_tail_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "tail -f /var/log/syslog";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// less/more commands
// ============================================================================

#[test]
fn test_less_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "less /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_more_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "more /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// chmod/chown commands
// ============================================================================

#[test]
fn test_chmod_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "chmod +x script.sh";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_chmod_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "chmod 777 /tmp/file";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_chown_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "chown root /tmp/file";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// tar/zip commands
// ============================================================================

#[test]
fn test_tar_extract_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "tar -xf archive.tar -C /tmp";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_tar_create_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "tar -cf /tmp/archive.tar .";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// ln command
// ============================================================================

#[test]
fn test_ln_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "ln -s file.txt link.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_ln_target_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "ln -s /etc/passwd link";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// dd command (key=value path parsing)
// ============================================================================

#[test]
fn test_dd_if_external_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("dd if=/etc/passwd of=./stolen", &project_root);
    assert!(result.is_some(), "dd if=/etc/passwd should be blocked");
}

#[test]
fn test_dd_of_external_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("dd if=./data of=/tmp/exfil", &project_root);
    assert!(result.is_some(), "dd of=/tmp/exfil should be blocked");
}

#[test]
fn test_dd_internal_paths_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let if_path = project_root.join("input.bin");
    let of_path = project_root.join("output.bin");
    let cmd = format!("dd if={} of={}", if_path.display(), of_path.display());
    let result = analyze(&cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_dd_if_tilde_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("dd if=~/.ssh/id_rsa of=./stolen", &project_root);
    assert!(result.is_some());
}

#[test]
fn test_dd_no_path_args_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("dd bs=4096 count=1", &project_root);
    assert!(result.is_none());
}
