use super::common::*;

#[test]
fn test_block_rg_external_path() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": canonical.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rg pattern /etc/"}
    })
    .to_string();
    let (code, _stdout, stderr) = run_clarg(&["-i"], &input);
    assert_eq!(code, 2, "should block rg with external path");
    assert!(stderr.contains("outside the project directory"));
}

#[test]
fn test_allow_rg_internal_path() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let internal_path = format!("{}/src", canonical.display());
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": canonical.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": format!("rg pattern {}", internal_path)}
    })
    .to_string();
    let (code, _stdout, _stderr) = run_clarg(&["-i"], &input);
    assert_eq!(code, 0, "should allow rg with internal path");
}

#[test]
fn test_block_cd_external_chained() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": canonical.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cd /tmp && ls"}
    })
    .to_string();
    let (code, _stdout, stderr) = run_clarg(&["-i"], &input);
    assert_eq!(code, 2, "should block cd to external directory in chain");
    assert!(stderr.contains("Blocked by `clarg`"));
}

#[test]
fn test_block_eval_external() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": canonical.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "eval \"cat /etc/passwd\""}
    })
    .to_string();
    let (code, _stdout, stderr) = run_clarg(&["-i"], &input);
    assert_eq!(code, 2, "should block eval with external path");
    assert!(stderr.contains("Blocked by `clarg`"));
}

#[test]
fn test_block_bash_c_external() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": canonical.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "bash -c \"cd /tmp\""}
    })
    .to_string();
    let (code, _stdout, stderr) = run_clarg(&["-i"], &input);
    assert_eq!(code, 2, "should block bash -c with external cd");
    assert!(stderr.contains("Blocked by `clarg`"));
}

#[test]
fn test_internal_only_blocks_write_outside() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": canonical.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/etc/malicious.conf", "content": "bad stuff"}
    })
    .to_string();
    let (code, _, stderr) = run_clarg(&["-i"], &input);
    assert_eq!(code, 2, "should block Write to outside path");
    assert!(stderr.contains("outside the project directory"));
}

#[test]
fn test_internal_only_blocks_grep_outside() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": canonical.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {"pattern": "password", "path": "/etc/"}
    })
    .to_string();
    let (code, _, _) = run_clarg(&["-i"], &input);
    assert_eq!(code, 2, "should block Grep to outside path");
}

#[test]
fn test_internal_only_blocks_glob_outside() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": canonical.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {"pattern": "**/*.conf", "path": "/etc"}
    })
    .to_string();
    let (code, _, _) = run_clarg(&["-i"], &input);
    assert_eq!(code, 2, "should block Glob to outside path");
}
