use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// HELPER METHOD TESTS: file_path()
// ============================================================================

#[test]
fn test_file_path_returns_some_when_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/home/user/test.txt"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), Some("/home/user/test.txt"));
}

#[test]
fn test_file_path_returns_none_when_absent() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "command": "ls"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), None);
}

#[test]
fn test_file_path_returns_none_when_not_a_string() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": 12345
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), None);
}

#[test]
fn test_file_path_returns_none_when_tool_input_empty() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {}
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), None);
}

#[test]
fn test_file_path_returns_none_when_file_path_is_null() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": null
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), None);
}

#[test]
fn test_file_path_returns_none_when_file_path_is_object() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": {"nested": "object"}
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), None);
}

#[test]
fn test_file_path_returns_none_when_file_path_is_array() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": ["file1.txt", "file2.txt"]
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), None);
}

#[test]
fn test_file_path_returns_none_when_file_path_is_boolean() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": true
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), None);
}

// ============================================================================
// HELPER METHOD TESTS: command()
// ============================================================================

#[test]
fn test_command_returns_some_when_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "echo hello"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), Some("echo hello"));
}

#[test]
fn test_command_returns_none_when_absent() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "file_path": "/tmp/script.sh"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), None);
}

#[test]
fn test_command_returns_none_when_not_a_string() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": 42
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), None);
}

#[test]
fn test_command_with_complex_bash_script() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "for i in {1..10}; do echo $i; done"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), Some("for i in {1..10}; do echo $i; done"));
}

#[test]
fn test_command_returns_none_when_tool_input_empty() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {}
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), None);
}

#[test]
fn test_command_returns_none_when_command_is_null() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": null
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), None);
}

// ============================================================================
// HELPER METHOD TESTS: search_path()
// ============================================================================

#[test]
fn test_search_path_returns_some_when_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": "/home/user/project"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), Some("/home/user/project"));
}

#[test]
fn test_search_path_returns_none_when_absent() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "pattern": "*.rs"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), None);
}

#[test]
fn test_search_path_returns_none_when_not_a_string() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": ["dir1", "dir2"]
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), None);
}

#[test]
fn test_search_path_returns_none_when_tool_input_empty() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {}
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), None);
}

// ============================================================================
// HELPER METHOD TESTS: pattern()
// ============================================================================

#[test]
fn test_pattern_returns_some_when_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "pattern": "**/*.rs"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.pattern(), Some("**/*.rs"));
}

#[test]
fn test_pattern_returns_none_when_absent() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": "/home/user/project"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.pattern(), None);
}

#[test]
fn test_pattern_returns_none_when_not_a_string() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "pattern": 123
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.pattern(), None);
}

#[test]
fn test_pattern_returns_none_when_tool_input_empty() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {}
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.pattern(), None);
}

// ============================================================================
