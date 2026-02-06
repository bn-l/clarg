use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// TOOL_INPUT TESTS
// ============================================================================

#[test]
fn test_tool_input_empty_object() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {}
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input.is_object());
    assert_eq!(hook.tool_input.as_object().unwrap().len(), 0);
}

#[test]
fn test_tool_input_missing_uses_default() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input.is_null());
}

#[test]
fn test_tool_input_with_file_path() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/home/user/file.txt"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), Some("/home/user/file.txt"));
}

#[test]
fn test_tool_input_with_command() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "ls -la"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), Some("ls -la"));
}

#[test]
fn test_tool_input_with_path_and_pattern() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": "/home/user/project",
            "pattern": "*.rs"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), Some("/home/user/project"));
    assert_eq!(hook.pattern(), Some("*.rs"));
}

#[test]
fn test_tool_input_with_path_only() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {
            "path": "/home/user/src"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), Some("/home/user/src"));
}

#[test]
fn test_tool_input_with_nested_objects() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Custom",
        "tool_input": {
            "config": {
                "timeout": 30,
                "retries": 3
            }
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input.get("config").is_some());
    assert_eq!(hook.tool_input["config"]["timeout"], 30);
}

#[test]
fn test_tool_input_with_arrays() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Custom",
        "tool_input": {
            "files": ["file1.txt", "file2.txt", "file3.txt"]
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input.get("files").unwrap().is_array());
    assert_eq!(hook.tool_input["files"].as_array().unwrap().len(), 3);
}

// ============================================================================
