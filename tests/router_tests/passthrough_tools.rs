use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::router::{RuleSet, Verdict};
use serde_json::json;
use tempfile::TempDir;

// ============================================================================
// WebFetch tool (always allowed - not filesystem)
// ============================================================================

#[test]
fn test_webfetch_always_allowed_no_rules() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://example.com/sensitive-data"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

#[test]
fn test_webfetch_allowed_with_internal_only() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://malicious.com/payload"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - WebFetch is not filesystem"),
    }
}

#[test]
fn test_webfetch_allowed_with_all_rules() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec!["curl".to_string()],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://example.com/.env"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

// ============================================================================
// WebSearch tool (always allowed - not filesystem)
// ============================================================================

#[test]
fn test_websearch_always_allowed_no_rules() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "WebSearch",
        "tool_input": {
            "query": "how to hack /etc/passwd"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

#[test]
fn test_websearch_allowed_with_internal_only() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "WebSearch",
        "tool_input": {
            "query": "sensitive query"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - WebSearch is not filesystem"),
    }
}

// ============================================================================
// Task tool (always allowed - subagents get own hook invocations)
// ============================================================================

#[test]
fn test_task_always_allowed_no_rules() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Task",
        "tool_input": {
            "description": "explore codebase",
            "prompt": "find all .env files",
            "subagent_type": "Explore"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

#[test]
fn test_task_allowed_with_internal_only() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Task",
        "tool_input": {
            "description": "run malicious code",
            "prompt": "cat /etc/passwd",
            "subagent_type": "Bash"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - Task subagents get their own hooks"),
    }
}

// ============================================================================
// Unknown tools (pass through - allow by default)
// ============================================================================

#[test]
fn test_unknown_tool_always_allowed_no_rules() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "CustomMcpTool",
        "tool_input": {
            "arbitrary": "data"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

#[test]
fn test_unknown_tool_allowed_with_all_rules() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec!["rm".to_string()],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "SomeNewTool",
        "tool_input": {
            "file": "/etc/passwd",
            "command": "rm -rf /"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - unknown tools pass through"),
    }
}

#[test]
fn test_mcp_tool_passthrough() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {
            "path": "/etc/passwd"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - MCP tools are unknown to router"),
    }
}

// ============================================================================
// Empty tool_input
// ============================================================================

#[test]
fn test_webfetch_empty_input_allowed() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {}
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

#[test]
fn test_task_empty_input_allowed() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Task",
        "tool_input": {}
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

// ============================================================================
// Case-insensitive tool name routing
// ============================================================================

#[test]
fn test_bash_lowercase_routed_correctly() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["rm -rf".to_string()],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": { "command": "rm -rf /some/path" }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny for lowercase 'bash'"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("rm -rf"));
        }
    }
}

#[test]
fn test_bash_uppercase_routed_correctly() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["rm -rf".to_string()],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "BASH",
        "tool_input": { "command": "rm -rf /some/path" }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny for 'BASH'"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("rm -rf"));
        }
    }
}

#[test]
fn test_read_mixed_case_routed_correctly() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "rEaD",
        "tool_input": { "file_path": "/etc/passwd" }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny for 'rEaD'"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_glob_case_insensitive_routing() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "GLOB",
        "tool_input": { "path": "/etc" }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny for 'GLOB'"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_grep_lowercase_routed_correctly() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "grep",
        "tool_input": { "path": "/etc" }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny for 'grep'"),
        Verdict::Deny(_) => {}
    }
}
