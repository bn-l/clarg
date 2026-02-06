use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// Write the structured deny JSON to stdout and reason to stderr.
pub fn output_deny(reason: &str) {
    let json = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    });
    println!("{}", json);
    eprintln!("{}", reason);
}

/// Log a message. If `log_path` is Some, append to that file; otherwise write to stderr.
pub fn log_message(log_path: Option<&Path>, msg: &str) {
    if let Some(path) = log_path {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{}", msg);
        }
    } else {
        eprintln!("{}", msg);
    }
}

/// Format a log entry for a tool evaluation.
pub fn format_log_entry(tool_name: &str, verdict: &str, reason: &str) -> String {
    let timestamp = chrono_free_timestamp();
    format!("[{timestamp}] tool={tool_name} verdict={verdict} reason={reason}")
}

/// Simple timestamp without chrono dependency.
fn chrono_free_timestamp() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    format!("{secs}")
}

/// Print the friendly usage message for interactive (TTY) invocation.
pub fn print_friendly_usage() {
    let version = env!("CARGO_PKG_VERSION");
    print!(
        r#"clarg v{version} — Claude Code hook handler

This tool is designed to run as a Claude Code PreToolUse hook.
It reads JSON from stdin and blocks operations based on configured rules.

QUICK SETUP — add to .claude/settings.json:

  {{
    "hooks": {{
      "PreToolUse": [{{
        "hooks": [{{
          "type": "command",
          "command": "/path/to/clarg -b '.env' -c 'rm -rf' -i"
        }}]
      }}]
    }}
  }}

Run `clarg --help` for all options.
"#
    );
}

/// Build the deny output JSON as a Value.
pub fn deny_json(reason: &str) -> serde_json::Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    })
}
