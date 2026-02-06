use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// UNICODE TESTS
// ============================================================================

#[test]
fn test_unicode_in_session_id() {
    let input = json!({
        "session_id": "セッション-123-日本語",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "セッション-123-日本語");
}

#[test]
fn test_unicode_in_transcript_path() {
    let input = json!({
        "session_id": "sess-123",
        "transcript_path": "/tmp/日志/transcript™.txt",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, Some("/tmp/日志/transcript™.txt".to_string()));
}

#[test]
fn test_unicode_in_cwd() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/用户/проект/файлы",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.cwd.to_str().unwrap(), "/home/用户/проект/файлы");
}

#[test]
fn test_unicode_in_permission_mode() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "permission_mode": "承認済み",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.permission_mode, Some("承認済み".to_string()));
}

#[test]
fn test_unicode_in_hook_event_name() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse™",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.hook_event_name, "PreToolUse™");
}

#[test]
fn test_unicode_in_tool_name() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "読み取り"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "読み取り");
}

#[test]
fn test_unicode_in_tool_use_id() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": "toolu_ツール™_123"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_use_id, Some("toolu_ツール™_123".to_string()));
}

#[test]
fn test_unicode_in_tool_input_file_path() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/home/user/文档/ファイル™.txt"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), Some("/home/user/文档/ファイル™.txt"));
}

#[test]
fn test_unicode_in_tool_input_command() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "echo 'こんにちは世界'"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), Some("echo 'こんにちは世界'"));
}

// ============================================================================
// EMPTY STRING TESTS
// ============================================================================

#[test]
fn test_empty_session_id() {
    let input = json!({
        "session_id": "",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "");
}

#[test]
fn test_empty_transcript_path() {
    let input = json!({
        "session_id": "sess-123",
        "transcript_path": "",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.transcript_path, Some("".to_string()));
}

#[test]
fn test_empty_permission_mode() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "permission_mode": "",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.permission_mode, Some("".to_string()));
}

#[test]
fn test_empty_hook_event_name() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.hook_event_name, "");
}

#[test]
fn test_empty_tool_name() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": ""
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "");
}

#[test]
fn test_empty_tool_use_id() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_use_id": ""
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_use_id, Some("".to_string()));
}

#[test]
fn test_empty_file_path() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": ""
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.file_path(), Some(""));
}

#[test]
fn test_empty_command() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": ""
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.command(), Some(""));
}

#[test]
fn test_empty_search_path() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": ""
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), Some(""));
}

#[test]
fn test_empty_pattern() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "pattern": ""
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.pattern(), Some(""));
}

// ============================================================================
