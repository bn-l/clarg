use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// ADDITIONAL TOOL INPUT SCENARIOS
// ============================================================================

#[test]
fn test_tool_input_with_url() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://api.example.com/v1/data?key=value&filter=active"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["url"], "https://api.example.com/v1/data?key=value&filter=active");
}

#[test]
fn test_tool_input_with_query() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "WebSearch",
        "tool_input": {
            "query": "how to write Rust macros in 2026"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["query"], "how to write Rust macros in 2026");
}

#[test]
fn test_tool_input_with_prompt() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://example.com",
            "prompt": "Extract all headings and summarize the main points"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["prompt"], "Extract all headings and summarize the main points");
}

#[test]
fn test_notebook_edit_tool() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "NotebookEdit",
        "tool_input": {
            "notebook_path": "/home/user/notebook.ipynb",
            "cell_id": "cell-123",
            "new_source": "print('Hello, World!')",
            "cell_type": "code"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "NotebookEdit");
    assert_eq!(hook.tool_input["notebook_path"], "/home/user/notebook.ipynb");
}

#[test]
fn test_skill_tool() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Skill",
        "tool_input": {
            "skill": "commit",
            "args": "-m 'Fix bug'"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "Skill");
    assert_eq!(hook.tool_input["skill"], "commit");
}

// ============================================================================
// DEBUG OUTPUT TESTS
// ============================================================================

#[test]
fn test_debug_format() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    let debug_output = format!("{:?}", hook);
    assert!(debug_output.contains("sess-123"));
    assert!(debug_output.contains("Read"));
}

// ============================================================================
// EDGE CASE: MINIMAL VALID JSON
// ============================================================================

#[test]
fn test_minimal_valid_json() {
    let input = json!({
        "session_id": "s",
        "cwd": "/",
        "hook_event_name": "e",
        "tool_name": "t"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "s");
    assert_eq!(hook.cwd.to_str().unwrap(), "/");
    assert_eq!(hook.hook_event_name, "e");
    assert_eq!(hook.tool_name, "t");
}

// ============================================================================
// WHITESPACE TESTS
// ============================================================================

#[test]
fn test_strings_with_leading_trailing_whitespace() {
    let input = json!({
        "session_id": "  sess-123  ",
        "cwd": "/home/user",
        "hook_event_name": "  PreToolUse  ",
        "tool_name": "  Read  "
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "  sess-123  ");
    assert_eq!(hook.hook_event_name, "  PreToolUse  ");
    assert_eq!(hook.tool_name, "  Read  ");
}

#[test]
fn test_strings_with_newlines() {
    let input = json!({
        "session_id": "sess\n123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "sess\n123");
}

#[test]
fn test_strings_with_tabs() {
    let input = json!({
        "session_id": "sess\t123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read"
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.session_id, "sess\t123");
}
