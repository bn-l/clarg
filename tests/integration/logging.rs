use super::common::*;

#[test]
fn test_log_dir_file() {
    let tmp = tempfile::tempdir().unwrap();
    let input = hook_json("Bash", serde_json::json!({"command": "ls -la"}));
    let (code, _, _) = run_clarg(
        &["-l", tmp.path().to_str().unwrap()],
        &input,
    );
    assert_eq!(code, 0);
    let log_path = tmp.path().join("clarg.log");
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(log_contents.contains("tool=Bash"), "log should contain tool name, got: {log_contents}");
    assert!(log_contents.contains("ALLOW"), "log should contain ALLOW verdict, got: {log_contents}");
}
