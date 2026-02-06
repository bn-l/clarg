use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// PATH TESTS
// ============================================================================

#[test]
fn test_cwd_absolute_path() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.cwd.to_str().unwrap(), "/home/user/project");
    assert!(hook.cwd.is_absolute());
}

#[test]
fn test_cwd_relative_path() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "./project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.cwd.to_str().unwrap(), "./project");
}

#[test]
fn test_cwd_with_spaces() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user/My Documents/Project Files",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.cwd.to_str().unwrap(), "/home/user/My Documents/Project Files");
}

#[test]
fn test_cwd_with_special_characters() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user/project [v2.0]/files & docs",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.cwd.to_str().unwrap(), "/home/user/project [v2.0]/files & docs");
}

#[test]
fn test_cwd_with_dots() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "../../../parent/dir",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.cwd.to_str().unwrap(), "../../../parent/dir");
}

#[test]
fn test_cwd_windows_style_path() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "C:\\Users\\user\\project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.cwd.to_str().is_some());
}

// ============================================================================
