use super::common::*;

#[test]
fn test_block_rm_rf() {
    let input = hook_json("Bash", serde_json::json!({"command": "rm -rf /"}));
    let (code, stdout, stderr) = run_clarg(&["-c", "rm -rf"], &input);
    assert_eq!(code, 2);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("stdout should be JSON");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(stderr.contains("rm -rf"));
}

#[test]
fn test_no_rules_allows_all() {
    let input = hook_json("Bash", serde_json::json!({"command": "rm -rf /"}));
    let (code, _, _) = run_clarg(&[], &input);
    assert_eq!(code, 0, "no rules should allow everything");
}
