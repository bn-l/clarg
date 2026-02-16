use serde_json::json;

/// Write the structured deny JSON to stdout and reason to stderr.
pub fn output_deny(reason: &str) {
    let json = deny_json(reason);
    println!("{}", json);
    eprintln!("{}", reason);
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
Logs are written to $XDG_STATE_HOME/clarg/clarg.log (default: ~/.local/state/clarg/clarg.log).
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
