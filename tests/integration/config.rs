use super::common::*;

#[test]
fn test_yaml_config_equivalent() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();
    let config_path = tmp.path().join("config.yaml");
    std::fs::write(
        &config_path,
        "block_access_to:\n  - \".env\"\ncommands_forbidden:\n  - \"rm -rf\"\n",
    )
    .unwrap();

    // Test blocked file
    let input = hook_json_with_cwd(
        "Read",
        serde_json::json!({"file_path": format!("{}/.env", cwd)}),
        cwd,
    );
    let (code, stdout, _) = run_clarg(&[config_path.to_str().unwrap()], &input);
    assert_eq!(code, 2);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");

    // Test blocked command (uses hook_json_with_cwd for consistent cwd)
    let input = hook_json_with_cwd(
        "Bash",
        serde_json::json!({"command": "rm -rf /tmp"}),
        cwd,
    );
    let (code, _, _) = run_clarg(&[config_path.to_str().unwrap()], &input);
    assert_eq!(code, 2);
}

#[test]
fn test_claude_project_dir_override() {
    use std::io::Write;

    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();

    // cwd points to /tmp but CLAUDE_PROJECT_DIR overrides to our temp dir
    let input = serde_json::json!({
        "session_id": "test",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": format!("{}/file.txt", canonical.display())}
    })
    .to_string();

    let mut cmd = clarg_bin();
    cmd.args(["-i"]);
    cmd.env("CLAUDE_PROJECT_DIR", canonical.to_str().unwrap());
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(input.as_bytes()).unwrap();
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "CLAUDE_PROJECT_DIR should override cwd"
    );
}

#[test]
fn test_relative_config_resolved_against_project_dir() {
    use std::io::Write;

    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().canonicalize().unwrap();

    // Create .claude/clarg.yaml inside the temp "project"
    let config_dir = project_dir.join(".claude");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("clarg.yaml"),
        "internal_access_only: true\n",
    )
    .unwrap();

    let input = serde_json::json!({
        "session_id": "test",
        "cwd": project_dir,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": format!("{}/file.txt", project_dir.display())}
    })
    .to_string();

    // Run clarg from a *different* directory (simulating cd during session)
    // but with CLAUDE_PROJECT_DIR pointing to the project root
    let mut cmd = clarg_bin();
    cmd.arg(".claude/clarg.yaml"); // relative path
    cmd.env("CLAUDE_PROJECT_DIR", project_dir.to_str().unwrap());
    cmd.current_dir("/tmp"); // simulate changed cwd
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(input.as_bytes()).unwrap();
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "relative config path should resolve against CLAUDE_PROJECT_DIR, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_relative_config_without_project_dir_uses_cwd() {
    use std::io::Write;

    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().canonicalize().unwrap();

    // Create clarg.yaml inside the temp dir
    std::fs::write(
        project_dir.join("clarg.yaml"),
        "internal_access_only: false\n",
    )
    .unwrap();

    let input = serde_json::json!({
        "session_id": "test",
        "cwd": project_dir,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"}
    })
    .to_string();

    // No CLAUDE_PROJECT_DIR set — relative path should resolve against actual cwd
    let mut cmd = clarg_bin();
    cmd.arg("clarg.yaml");
    cmd.env_remove("CLAUDE_PROJECT_DIR");
    cmd.current_dir(&project_dir);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(input.as_bytes()).unwrap();
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "without CLAUDE_PROJECT_DIR, relative config should resolve against cwd, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
