use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// COMPLEX SCENARIOS
// ============================================================================

#[test]
fn test_full_hook_input_all_fields() {
    let input = json!({
        "session_id": "sess-abc-123",
        "transcript_path": "/var/log/claude/transcript.json",
        "cwd": "/home/user/projects/my-app",
        "permission_mode": "approved",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/home/user/projects/my-app/src/main.rs",
            "offset": 0,
            "limit": 100
        },
        "tool_use_id": "toolu_abc123xyz789"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "sess-abc-123");
    assert_eq!(hook.transcript_path, Some("/var/log/claude/transcript.json".to_string()));
    assert_eq!(hook.cwd.to_str().unwrap(), "/home/user/projects/my-app");
    assert_eq!(hook.permission_mode, Some("approved".to_string()));
    assert_eq!(hook.hook_event_name, "PreToolUse");
    assert_eq!(hook.tool_name, "Read");
    assert_eq!(hook.file_path(), Some("/home/user/projects/my-app/src/main.rs"));
    assert_eq!(hook.tool_use_id, Some("toolu_abc123xyz789".to_string()));
}

#[test]
fn test_multiple_helper_methods_on_same_input() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": "/home/user/src",
            "pattern": "**/*.rs",
            "file_path": "/should/be/ignored",
            "command": "should also be ignored"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), Some("/home/user/src"));
    assert_eq!(hook.pattern(), Some("**/*.rs"));
    assert_eq!(hook.file_path(), Some("/should/be/ignored"));
    assert_eq!(hook.command(), Some("should also be ignored"));
}

#[test]
fn test_very_long_strings() {
    let long_string = "a".repeat(10000);
    let input = json!({
        "session_id": long_string,
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id.len(), 10000);
}

#[test]
fn test_tool_input_deeply_nested() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Custom",
        "tool_input": {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "level5": "deep value"
                        }
                    }
                }
            }
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["level1"]["level2"]["level3"]["level4"]["level5"], "deep value");
}

#[test]
fn test_tool_input_large_array() {
    let large_array: Vec<i32> = (0..1000).collect();
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Custom",
        "tool_input": {
            "items": large_array
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["items"].as_array().unwrap().len(), 1000);
}

// ============================================================================
// NULL VALUE TESTS
// ============================================================================

#[test]
fn test_transcript_path_explicit_null() {
    let input = json!({
        "session_id": "sess-123",
        "transcript_path": null,
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, None);
}

#[test]
fn test_permission_mode_explicit_null() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "permission_mode": null,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.permission_mode, None);
}

#[test]
fn test_tool_use_id_explicit_null() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": null
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_use_id, None);
}

#[test]
fn test_tool_input_explicit_null() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": null
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input.is_null());
}

// ============================================================================
// SPECIAL CHARACTER TESTS
// ============================================================================

#[test]
fn test_session_id_with_special_characters() {
    let input = json!({
        "session_id": "sess-!@#$%^&*()_+-={}[]|\\:\";<>?,./",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "sess-!@#$%^&*()_+-={}[]|\\:\";<>?,./");
}

#[test]
fn test_command_with_pipes_and_redirects() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "cat file.txt | grep pattern > output.txt 2>&1"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), Some("cat file.txt | grep pattern > output.txt 2>&1"));
}

#[test]
fn test_file_path_with_backslashes() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "C:\\Users\\user\\Documents\\file.txt"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), Some("C:\\Users\\user\\Documents\\file.txt"));
}

// ============================================================================
