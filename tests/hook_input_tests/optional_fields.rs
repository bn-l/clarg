use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// OPTIONAL FIELDS PRESENT TESTS
// ============================================================================

#[test]
fn test_all_optional_fields_present() {
    let input = json!({
        "session_id": "test-session-123",
        "transcript_path": "/tmp/transcript.txt",
        "cwd": "/home/user/project",
        "permission_mode": "approved",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {},
        "tool_use_id": "toolu_abc123"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, Some("/tmp/transcript.txt".to_string()));
    assert_eq!(hook.permission_mode, Some("approved".to_string()));
    assert_eq!(hook.tool_use_id, Some("toolu_abc123".to_string()));
}

#[test]
fn test_transcript_path_present() {
    let input = json!({
        "session_id": "test-session-123",
        "transcript_path": "/var/log/transcript.json",
        "cwd": "/home/user",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, Some("/var/log/transcript.json".to_string()));
}

#[test]
fn test_permission_mode_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.permission_mode, Some("default".to_string()));
}

#[test]
fn test_tool_use_id_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_use_id": "toolu_xyz789"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_use_id, Some("toolu_xyz789".to_string()));
}

// ============================================================================
// OPTIONAL FIELDS MISSING TESTS
// ============================================================================

#[test]
fn test_all_optional_fields_missing() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, None);
    assert_eq!(hook.permission_mode, None);
    assert_eq!(hook.tool_use_id, None);
}

#[test]
fn test_transcript_path_missing() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "permission_mode": "approved",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": "toolu_123"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, None);
}

#[test]
fn test_permission_mode_missing() {
    let input = json!({
        "session_id": "test-session-123",
        "transcript_path": "/tmp/transcript.txt",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": "toolu_123"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.permission_mode, None);
}

#[test]
fn test_tool_use_id_missing() {
    let input = json!({
        "session_id": "test-session-123",
        "transcript_path": "/tmp/transcript.txt",
        "cwd": "/home/user",
        "permission_mode": "approved",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_use_id, None);
}

// ============================================================================
// MIXED OPTIONAL FIELDS TESTS
// ============================================================================

#[test]
fn test_only_transcript_path_present() {
    let input = json!({
        "session_id": "test-session-123",
        "transcript_path": "/tmp/transcript.txt",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, Some("/tmp/transcript.txt".to_string()));
    assert_eq!(hook.permission_mode, None);
    assert_eq!(hook.tool_use_id, None);
}

#[test]
fn test_only_permission_mode_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "permission_mode": "approved",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, None);
    assert_eq!(hook.permission_mode, Some("approved".to_string()));
    assert_eq!(hook.tool_use_id, None);
}

#[test]
fn test_only_tool_use_id_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": "toolu_123"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, None);
    assert_eq!(hook.permission_mode, None);
    assert_eq!(hook.tool_use_id, Some("toolu_123".to_string()));
}

#[test]
fn test_transcript_path_and_permission_mode_present() {
    let input = json!({
        "session_id": "test-session-123",
        "transcript_path": "/tmp/transcript.txt",
        "cwd": "/home/user",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, Some("/tmp/transcript.txt".to_string()));
    assert_eq!(hook.permission_mode, Some("default".to_string()));
    assert_eq!(hook.tool_use_id, None);
}

#[test]
fn test_permission_mode_and_tool_use_id_present() {
    let input = json!({
        "session_id": "test-session-123",
        "cwd": "/home/user",
        "permission_mode": "approved",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": "toolu_456"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, None);
    assert_eq!(hook.permission_mode, Some("approved".to_string()));
    assert_eq!(hook.tool_use_id, Some("toolu_456".to_string()));
}

#[test]
fn test_transcript_path_and_tool_use_id_present() {
    let input = json!({
        "session_id": "test-session-123",
        "transcript_path": "/tmp/transcript.txt",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": "toolu_789"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, Some("/tmp/transcript.txt".to_string()));
    assert_eq!(hook.permission_mode, None);
    assert_eq!(hook.tool_use_id, Some("toolu_789".to_string()));
}

// ============================================================================
