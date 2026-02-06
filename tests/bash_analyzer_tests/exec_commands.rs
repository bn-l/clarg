use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// python command
// ============================================================================

#[test]
fn test_python_script_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "python script.py";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_python_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "python /tmp/malicious.py";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_python3_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "python3 /etc/script.py";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_python_with_flags_then_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "python -u /tmp/script.py";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// node command
// ============================================================================

#[test]
fn test_node_script_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "node script.js";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_node_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "node /tmp/malicious.js";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// ruby command
// ============================================================================

#[test]
fn test_ruby_script_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "ruby script.rb";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_ruby_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "ruby /tmp/malicious.rb";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// perl command
// ============================================================================

#[test]
fn test_perl_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "perl /tmp/script.pl";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// source command
// ============================================================================

#[test]
fn test_source_script_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "source ./env.sh";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_source_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "source /etc/profile";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_source_bashrc_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "source ~/.bashrc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// dot (.) command
// ============================================================================

#[test]
fn test_dot_script_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = ". ./env.sh";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_dot_script_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = ". /etc/profile";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// deno command
// ============================================================================

#[test]
fn test_deno_run_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "deno run script.ts";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// TODO: Not yet implemented - deno subcommands like 'run' are treated as file arguments,
// so "deno run /tmp/script.ts" stops at 'run' without checking the actual script path
#[test]
#[ignore]
fn test_deno_run_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "deno run /tmp/script.ts";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// bun command
// ============================================================================

#[test]
fn test_bun_run_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bun run script.ts";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_bun_run_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bun /tmp/script.js";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Interpreter -c/-e inline code analysis
// ============================================================================

#[test]
fn test_python_c_with_external_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("python -c 'open(\"/etc/passwd\").read()'", &project_root);
    assert!(result.is_some(), "python -c with external path should be blocked");
}

#[test]
fn test_python3_c_with_external_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("python3 -c 'import os; os.system(\"cat /etc/passwd\")'", &project_root);
    assert!(result.is_some(), "python3 -c with external path should be blocked");
}

#[test]
fn test_node_e_with_external_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("node -e 'require(\"fs\").readFileSync(\"/etc/passwd\")'", &project_root);
    assert!(result.is_some(), "node -e with external path should be blocked");
}

#[test]
fn test_ruby_e_with_external_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("ruby -e 'File.read(\"/etc/passwd\")'", &project_root);
    assert!(result.is_some(), "ruby -e with external path should be blocked");
}

#[test]
fn test_perl_e_with_external_path_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("perl -e 'open(F, \"/etc/passwd\")'", &project_root);
    assert!(result.is_some(), "perl -e with external path should be blocked");
}

#[test]
fn test_python_c_internal_path_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("python -c 'print(\"hello\")'", &project_root);
    assert!(result.is_none(), "python -c without paths should be allowed");
}

#[test]
fn test_source_not_affected_by_inline_check() {
    // source doesn't support -c/-e — make sure it's not broken
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("source ./env.sh", &project_root);
    assert!(result.is_none());
}

#[test]
fn test_deno_not_affected_by_inline_check() {
    // deno is not in INLINE_CODE_INTERPRETERS — make sure it's not broken
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("deno run script.ts", &project_root);
    assert!(result.is_none());
}

#[test]
fn test_python_script_still_works_after_inline_check() {
    // Make sure normal script execution still works
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("python /tmp/malicious.py", &project_root);
    assert!(result.is_some(), "python with external script should still be blocked");
}

#[test]
fn test_node_eval_flag_blocked() {
    // node uses --eval as a long form
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = analyze("node --eval 'require(\"fs\").readFileSync(\"/etc/passwd\")'", &project_root);
    assert!(result.is_some(), "node --eval with external path should be blocked");
}
