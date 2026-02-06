use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// HOOK EVENT NAME TESTS
// ============================================================================

#[test]
fn test_hook_event_name_pre_tool_use() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.hook_event_name, "PreToolUse");
}

#[test]
fn test_hook_event_name_post_tool_use() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PostToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.hook_event_name, "PostToolUse");
}

#[test]
fn test_hook_event_name_custom_value() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "CustomEvent",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.hook_event_name, "CustomEvent");
}

// ============================================================================
// TOOL_INPUT WITH NUMBERS, BOOLEANS, NULL
// ============================================================================

#[test]
fn test_tool_input_with_numbers() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Custom",
        "tool_input": {
            "timeout": 5000,
            "retries": 3,
            "priority": 1.5
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["timeout"], 5000);
    assert_eq!(hook.tool_input["retries"], 3);
    assert_eq!(hook.tool_input["priority"], 1.5);
}

#[test]
fn test_tool_input_with_booleans() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Custom",
        "tool_input": {
            "enabled": true,
            "disabled": false
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["enabled"], true);
    assert_eq!(hook.tool_input["disabled"], false);
}

#[test]
fn test_tool_input_with_null_values() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Custom",
        "tool_input": {
            "value1": null,
            "value2": null
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input["value1"].is_null());
    assert!(hook.tool_input["value2"].is_null());
}

#[test]
fn test_tool_input_with_mixed_types() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Custom",
        "tool_input": {
            "string": "value",
            "number": 42,
            "float": 3.14,
            "boolean": true,
            "null_value": null,
            "array": [1, 2, 3],
            "object": {"nested": "value"}
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input["string"].is_string());
    assert!(hook.tool_input["number"].is_number());
    assert!(hook.tool_input["float"].is_number());
    assert!(hook.tool_input["boolean"].is_boolean());
    assert!(hook.tool_input["null_value"].is_null());
    assert!(hook.tool_input["array"].is_array());
    assert!(hook.tool_input["object"].is_object());
}

// ============================================================================
