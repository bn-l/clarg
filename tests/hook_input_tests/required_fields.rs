use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// REQUIRED FIELDS TESTS
// ============================================================================

#[test]
fn test_all_required_fields_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "test-session-123");
    assert_eq!(hook.cwd.to_str().unwrap(), "/home/user/project");
    assert_eq!(hook.hook_event_name, "PreToolUse");
    assert_eq!(hook.tool_name, "Read");
}

#[test]
fn test_missing_session_id_fails() {
    let input = json!({
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_missing_cwd_fails() {
    let input = json!({
        "session_id": "test-session-123",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_missing_hook_event_name_fails() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user/project",
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_missing_tool_name_fails() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

