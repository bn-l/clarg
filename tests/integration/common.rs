use std::process::Command;

pub fn clarg_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_clarg"))
}

pub fn hook_json(tool_name: &str, tool_input: serde_json::Value) -> String {
    serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp/test-project",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input
    })
    .to_string()
}

pub fn hook_json_with_cwd(tool_name: &str, tool_input: serde_json::Value, cwd: &str) -> String {
    serde_json::json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input
    })
    .to_string()
}

/// Helper to run clarg with given args and stdin, returning (exit code, stdout, stderr).
pub fn run_clarg(args: &[&str], stdin: &str) -> (i32, String, String) {
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

/// Helper to spawn clarg in a PTY (stdin is a terminal device) and capture output.
/// Reads from the PTY master in a thread to avoid deadlock — PTYs yield EIO
/// (not EOF) when the slave side closes, so read_to_string blocks forever.
pub fn run_clarg_in_pty(args: &[&str]) -> (i32, String) {
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
