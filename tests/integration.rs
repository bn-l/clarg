use std::process::Command;

fn clarg_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_clarg"))
}

fn hook_json(tool_name: &str, tool_input: serde_json::Value) -> String {
    serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp/test-project",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input
    })
    .to_string()
}

/// Helper to run clarg with given args and stdin, returning (exit code, stdout, stderr).
fn run_clarg(args: &[&str], stdin: &str) -> (i32, String, String) {
    use std::io::Write;
    let mut cmd = clarg_bin();
    cmd.args(args);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn clarg");
    if let Some(ref mut stdin_pipe) = child.stdin {
        stdin_pipe
            .write_all(stdin.as_bytes())
            .expect("failed to write stdin");
    }
    // Close stdin so child doesn't hang
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("failed to wait on clarg");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// --- Block .env file read ---

#[test]
fn test_block_env_file_read() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "Read",
        serde_json::json!({"file_path": format!("{}/.env", cwd)}),
        cwd,
    );
    let (code, stdout, stderr) = run_clarg(&["-b", ".env"], &input);
    assert_eq!(code, 2, "should exit 2 (block)");
    // stdout should contain structured JSON
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("stdout should be JSON");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert!(stderr.contains("Blocked by `clarg`"));
}

// --- Allow normal file read ---

#[test]
fn test_allow_normal_file_read() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "Read",
        serde_json::json!({"file_path": format!("{}/src/main.rs", cwd)}),
        cwd,
    );
    let (code, stdout, _stderr) = run_clarg(&["-b", ".env"], &input);
    assert_eq!(code, 0, "should exit 0 (allow)");
    assert!(
        stdout.trim().is_empty() || !stdout.contains("deny"),
        "should not contain deny output"
    );
}

// --- Block rm -rf command ---

#[test]
fn test_block_rm_rf() {
    let input = hook_json("Bash", serde_json::json!({"command": "rm -rf /"}));
    let (code, stdout, stderr) = run_clarg(&["-c", "rm -rf"], &input);
    assert_eq!(code, 2);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("stdout should be JSON");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(stderr.contains("rm -rf"));
}

// --- Block rg with external path (with -i) ---

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

// --- Allow internal rg (with -i) ---

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

// --- Block cd /tmp && ls (with -i) ---

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

// --- Block eval "cat /etc/passwd" (with -i) ---

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

// --- Block bash -c "cd /tmp" (with -i) ---

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

// --- YAML config produces same behavior as CLI flags ---

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

// --- Positional arg + any flag → clap error ---

#[test]
fn test_positional_with_flags_error() {
    let input = hook_json("Read", serde_json::json!({"file_path": "/tmp/file"}));
    let (code, _stdout, _stderr) = run_clarg(&["config.yaml", "-i"], &input);
    assert_eq!(code, 2, "should fail closed on clap error");
}

// --- Malformed JSON stdin → exit 2 (fail closed) ---

#[test]
fn test_malformed_json_fail_closed() {
    let (code, stdout, stderr) = run_clarg(&["-i"], "not valid json{{{");
    assert_eq!(code, 2, "should fail closed on malformed JSON");
    assert!(stderr.contains("internal error"));
    // stdout should still be structured JSON
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should still be valid JSON");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

// --- Empty stdin → exit 2 (fail closed) ---

#[test]
fn test_empty_stdin_fail_closed() {
    let (code, _stdout, stderr) = run_clarg(&["-i"], "");
    assert_eq!(code, 2, "should fail closed on empty stdin");
    assert!(stderr.contains("internal error"));
}

// --- --help → exit 0 with clap output ---

#[test]
fn test_help_flag() {
    let mut cmd = clarg_bin();
    cmd.arg("--help");
    cmd.stdin(std::process::Stdio::null());
    let output = cmd.output().expect("failed to run --help");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Check for clap-specific output (Usage/Options), not the friendly usage message
    assert!(
        stdout.contains("Usage:"),
        "should show clap help, not friendly usage. Got: {stdout}"
    );
    assert!(
        stdout.contains("--internal-access-only"),
        "should list CLI flags. Got: {stdout}"
    );
}

// --- -V → exit 0 with version ---

#[test]
fn test_version_flag() {
    let mut cmd = clarg_bin();
    cmd.arg("-V");
    cmd.stdin(std::process::Stdio::null());
    let output = cmd.output().expect("failed to run -V");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clarg"),
        "should show version string. Got: {stdout}"
    );
    assert!(
        !stdout.contains("QUICK SETUP"),
        "should show clap version, not friendly usage. Got: {stdout}"
    );
}

// --- PTY tests: --help/-V work even when stdin is a real terminal ---

/// Helper to spawn clarg in a PTY (stdin is a terminal device) and capture output.
/// Reads from the PTY master in a thread to avoid deadlock — PTYs yield EIO
/// (not EOF) when the slave side closes, so read_to_string blocks forever.
fn run_clarg_in_pty(args: &[&str]) -> (i32, String) {
    use std::io::Read;

    let (pty, pts) = pty_process::blocking::open().expect("failed to open pty");
    let _ = pty.resize(pty_process::Size::new(24, 80));

    let mut child = pty_process::blocking::Command::new(env!("CARGO_BIN_EXE_clarg"))
        .args(args)
        .spawn(pts)
        .expect("failed to spawn clarg in pty");

    // Read from PTY master in a thread — when the child exits and the slave
    // fd closes, reads return EIO which we treat as end-of-output.
    let reader = std::thread::spawn(move || {
        let mut pty = pty;
        let mut output = String::new();
        let mut buf = [0u8; 4096];
        loop {
            match pty.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => output.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(_) => break,
            }
        }
        output
    });

    let status = child.wait().expect("failed to wait on child");
    let output = reader.join().expect("pty reader thread panicked");

    (status.code().unwrap_or(-1), output)
}

#[test]
fn test_help_flag_in_tty() {
    let (code, output) = run_clarg_in_pty(&["--help"]);
    assert_eq!(code, 0, "--help should exit 0 in TTY");
    assert!(
        output.contains("Usage:"),
        "should show clap help in TTY, not friendly usage. Got: {output}"
    );
    assert!(
        output.contains("--internal-access-only"),
        "should list CLI flags in TTY. Got: {output}"
    );
}

#[test]
fn test_version_flag_in_tty() {
    let (code, output) = run_clarg_in_pty(&["-V"]);
    assert_eq!(code, 0, "-V should exit 0 in TTY");
    assert!(
        output.contains("clarg"),
        "should show version string in TTY. Got: {output}"
    );
    assert!(
        !output.contains("QUICK SETUP"),
        "should show clap version, not friendly usage. Got: {output}"
    );
}

#[test]
fn test_bare_invocation_in_tty_shows_friendly_usage() {
    let (code, output) = run_clarg_in_pty(&[]);
    assert_eq!(code, 0, "bare clarg in TTY should exit 0");
    assert!(
        output.contains("QUICK SETUP"),
        "bare clarg in TTY should show friendly usage. Got: {output}"
    );
}

// --- WebFetch / WebSearch always allowed ---

fn hook_json_with_cwd(tool_name: &str, tool_input: serde_json::Value, cwd: &str) -> String {
    serde_json::json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input
    })
    .to_string()
}

#[test]
fn test_web_tools_always_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "WebFetch",
        serde_json::json!({"url": "https://example.com"}),
        cwd,
    );
    let (code, _, _) = run_clarg(&["-b", ".env", "-c", "rm -rf", "-i"], &input);
    assert_eq!(code, 0, "WebFetch should always be allowed");

    let input = hook_json_with_cwd(
        "WebSearch",
        serde_json::json!({"query": "test query"}),
        cwd,
    );
    let (code, _, _) = run_clarg(&["-b", ".env", "-c", "rm -rf", "-i"], &input);
    assert_eq!(code, 0, "WebSearch should always be allowed");
}

// --- Task tool always allowed ---

#[test]
fn test_task_tool_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "Task",
        serde_json::json!({"prompt": "do something"}),
        cwd,
    );
    let (code, _, _) = run_clarg(&["-i"], &input);
    assert_eq!(code, 0, "Task should always be allowed");
}

// --- Unknown tool denied by default ---

#[test]
fn test_unknown_tool_denied() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "SomeNewTool",
        serde_json::json!({"anything": "here"}),
        cwd,
    );
    let (code, stdout, stderr) = run_clarg(&["-i", "-b", ".env"], &input);
    assert_eq!(code, 2, "unknown tools should be denied");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("stdout should be JSON");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(stderr.contains("unknown tool"));
}

// --- Multiple blocked file patterns ---

#[test]
fn test_multiple_blocked_patterns() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "Read",
        serde_json::json!({"file_path": format!("{}/api.secret", cwd)}),
        cwd,
    );
    let (code, _, _) = run_clarg(&["-b", ".env,*.secret"], &input);
    assert_eq!(code, 2, "*.secret should be blocked");
}

// --- No rules allows everything ---

#[test]
fn test_no_rules_allows_all() {
    let input = hook_json("Bash", serde_json::json!({"command": "rm -rf /"}));
    let (code, _, _) = run_clarg(&[], &input);
    assert_eq!(code, 0, "no rules should allow everything");
}

// --- Internal only blocks Write to outside path ---

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

// --- Internal only blocks Grep to outside path ---

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

// --- Internal only blocks Glob to outside path ---

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

// --- CLAUDE_PROJECT_DIR env var override ---

#[test]
fn test_claude_project_dir_override() {
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
        use std::io::Write;
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

// --- Log to file ---

#[test]
fn test_log_to_file() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("clarg.log");
    let input = hook_json("Bash", serde_json::json!({"command": "ls -la"}));
    let (code, _, _) = run_clarg(
        &["-l", log_path.to_str().unwrap()],
        &input,
    );
    assert_eq!(code, 0);
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(log_contents.contains("tool=Bash"));
    assert!(log_contents.contains("verdict=allow"));
}
