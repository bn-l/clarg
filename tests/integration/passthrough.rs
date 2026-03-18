use super::common::*;

#[test]
fn test_web_tools_always_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "WebFetch",
        serde_json::json!({"url": "https://example.com"}),
        cwd,
    );
    let (code, _, _) = run_clarg(&["-b", ".env", "-c", "rm -rf", "-i"], &input);
    assert_eq!(code, 0, "WebFetch should always be allowed");

    let input = hook_json_with_cwd(
        "WebSearch",
        serde_json::json!({"query": "test query"}),
        cwd,
    );
    let (code, _, _) = run_clarg(&["-b", ".env", "-c", "rm -rf", "-i"], &input);
    assert_eq!(code, 0, "WebSearch should always be allowed");
}

#[test]
fn test_task_tool_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "Task",
        serde_json::json!({"prompt": "do something"}),
        cwd,
    );
    let (code, _, _) = run_clarg(&["-i"], &input);
    assert_eq!(code, 0, "Task should always be allowed");
}

#[test]
fn test_unknown_tool_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let cwd = canonical.to_str().unwrap();

    let input = hook_json_with_cwd(
        "SomeNewTool",
        serde_json::json!({"anything": "here"}),
        cwd,
    );
    let (code, _stdout, _stderr) = run_clarg(&["-i", "-b", ".env"], &input);
    assert_eq!(code, 0, "unknown tools should be allowed");
}
