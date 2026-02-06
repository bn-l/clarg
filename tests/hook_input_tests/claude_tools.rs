use clarg::hook_input::HookInput;
use serde_json::json;

// ============================================================================
// CLAUDE TOOL TESTS: Bash
// ============================================================================

#[test]
fn test_bash_tool_with_simple_command() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "ls -la",
            "description": "List files"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "Bash");
    assert_eq!(hook.command(), Some("ls -la"));
}

#[test]
fn test_bash_tool_with_timeout() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "sleep 10",
            "timeout": 5000
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["timeout"], 5000);
}

#[test]
fn test_bash_tool_with_run_in_background() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "long-running-task",
            "run_in_background": true
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["run_in_background"], true);
}

// ============================================================================
// CLAUDE TOOL TESTS: Read
// ============================================================================

#[test]
fn test_read_tool_with_file_path() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/home/user/project/src/main.rs"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "Read");
    assert_eq!(hook.file_path(), Some("/home/user/project/src/main.rs"));
}

#[test]
fn test_read_tool_with_offset_and_limit() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/var/log/app.log",
            "offset": 100,
            "limit": 50
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["offset"], 100);
    assert_eq!(hook.tool_input["limit"], 50);
}

#[test]
fn test_read_tool_with_pdf_pages() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/home/user/document.pdf",
            "pages": "1-5"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["pages"], "1-5");
}

// ============================================================================
// CLAUDE TOOL TESTS: Write
// ============================================================================

#[test]
fn test_write_tool_with_file_path_and_content() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/home/user/output.txt",
            "content": "Hello, World!"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "Write");
    assert_eq!(hook.file_path(), Some("/home/user/output.txt"));
    assert_eq!(hook.tool_input["content"], "Hello, World!");
}

// ============================================================================
// CLAUDE TOOL TESTS: Edit
// ============================================================================

#[test]
fn test_edit_tool_with_old_and_new_string() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/home/user/file.txt",
            "old_string": "foo",
            "new_string": "bar"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "Edit");
    assert_eq!(hook.file_path(), Some("/home/user/file.txt"));
    assert_eq!(hook.tool_input["old_string"], "foo");
    assert_eq!(hook.tool_input["new_string"], "bar");
}

#[test]
fn test_edit_tool_with_replace_all() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/home/user/file.txt",
            "old_string": "foo",
            "new_string": "bar",
            "replace_all": true
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_input["replace_all"], true);
}

// ============================================================================
// CLAUDE TOOL TESTS: Glob
// ============================================================================

#[test]
fn test_glob_tool_with_pattern() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "pattern": "**/*.rs"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "Glob");
    assert_eq!(hook.pattern(), Some("**/*.rs"));
}

#[test]
fn test_glob_tool_with_path_and_pattern() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": "/home/user/src",
            "pattern": "*.js"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.search_path(), Some("/home/user/src"));
    assert_eq!(hook.pattern(), Some("*.js"));
}

// ============================================================================
// CLAUDE TOOL TESTS: Grep
// ============================================================================

#[test]
fn test_grep_tool_with_pattern() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {
            "pattern": "TODO"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "Grep");
    assert_eq!(hook.pattern(), Some("TODO"));
}

#[test]
fn test_grep_tool_with_all_options() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {
            "pattern": "error",
            "path": "/var/log",
            "glob": "*.log",
            "-i": true,
            "output_mode": "content"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.pattern(), Some("error"));
    assert_eq!(hook.search_path(), Some("/var/log"));
    assert_eq!(hook.tool_input["glob"], "*.log");
    assert_eq!(hook.tool_input["-i"], true);
}

// ============================================================================
// CLAUDE TOOL TESTS: WebFetch
// ============================================================================

#[test]
fn test_webfetch_tool_with_url_and_prompt() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {
            "url": "https://example.com",
            "prompt": "Summarize the content"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "WebFetch");
    assert_eq!(hook.tool_input["url"], "https://example.com");
    assert_eq!(hook.tool_input["prompt"], "Summarize the content");
}

// ============================================================================
// CLAUDE TOOL TESTS: WebSearch
// ============================================================================

#[test]
fn test_websearch_tool_with_query() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "WebSearch",
        "tool_input": {
            "query": "Rust programming language"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "WebSearch");
    assert_eq!(hook.tool_input["query"], "Rust programming language");
}

#[test]
fn test_websearch_tool_with_domain_filters() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "WebSearch",
        "tool_input": {
            "query": "API documentation",
            "allowed_domains": ["docs.rs", "rust-lang.org"],
            "blocked_domains": ["stackoverflow.com"]
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert!(hook.tool_input["allowed_domains"].is_array());
    assert!(hook.tool_input["blocked_domains"].is_array());
}

// ============================================================================
// CLAUDE TOOL TESTS: Task
// ============================================================================

#[test]
fn test_task_create_tool() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "TaskCreate",
        "tool_input": {
            "subject": "Fix bug in login",
            "description": "The login button is not responding",
            "activeForm": "Fixing login bug"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "TaskCreate");
    assert_eq!(hook.tool_input["subject"], "Fix bug in login");
}

#[test]
fn test_task_update_tool() {
    let input = json!({
        "session_id": "sess-123",
        "cwd": "/home/user",
        "hook_event_name": "PreToolUse",
        "tool_name": "TaskUpdate",
        "tool_input": {
            "taskId": "task-123",
            "status": "completed"
        }
    });

    let hook: HookInput = serde_json::from_value(input).unwrap();
    assert_eq!(hook.tool_name, "TaskUpdate");
    assert_eq!(hook.tool_input["taskId"], "task-123");
    assert_eq!(hook.tool_input["status"], "completed");
}

// ============================================================================
