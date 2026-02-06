use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// WRONG TYPE TESTS
// ============================================================================

#[test]
fn test_session_id_wrong_type_number() {
    let input = json!({
        "session_id": 12345,
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_session_id_wrong_type_boolean() {
    let input = json!({
        "session_id": true,
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_cwd_wrong_type_number() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": 12345,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_hook_event_name_wrong_type_array() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": ["PreToolUse"],
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_tool_name_wrong_type_object() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": {"name": "Read"}
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_transcript_path_wrong_type_number() {
    let input = json!({
        "session_id": "sess-123",
        "transcript_path": 12345,
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_permission_mode_wrong_type_boolean() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "permission_mode": true,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_tool_use_id_wrong_type_array() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": ["id1", "id2"]
    });

    let result: Result<HookInput, _> = serde_json::from_value(input);
    assert!(result.is_err());
}

#[test]
fn test_tool_input_wrong_type_string() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": "not an object"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input.is_string());
}

#[test]
fn test_tool_input_wrong_type_number() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": 12345
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input.is_number());
}

// ============================================================================
// EXTRA FIELDS TESTS
// ============================================================================

#[test]
fn test_extra_fields_ignored() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "extra_field_1": "ignored",
        "extra_field_2": 123,
        "extra_field_3": true
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "sess-123");
}

#[test]
fn test_many_extra_fields() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "unknown1": "value1",
        "unknown2": "value2",
        "unknown3": "value3",
        "unknown4": "value4",
        "unknown5": "value5"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "Read");
}

// ============================================================================
// PERMISSION MODE TESTS
// ============================================================================

#[test]
fn test_permission_mode_default() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.permission_mode, Some("default".to_string()));
}

#[test]
fn test_permission_mode_approved() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "permission_mode": "approved",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.permission_mode, Some("approved".to_string()));
}

#[test]
fn test_permission_mode_custom_value() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "permission_mode": "custom_mode_123",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.permission_mode, Some("custom_mode_123".to_string()));
}

// ============================================================================
