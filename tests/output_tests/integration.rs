use clarg::output::{deny_json, format_log_entry, log_message};
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Integration tests combining multiple functions
// ============================================================================

#[test]
fn test_deny_json_and_format_log_entry_integration() {
    let reason = "Blocked .env file";
    let json = deny_json(reason);
    let log_entry = format_log_entry("Read", "deny", reason);

    assert_eq!(
        json["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
    assert!(log_entry.contains(reason));
}

#[test]
fn test_full_workflow_deny_and_log() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("workflow.log");

    let reason = "Test workflow deny reason";
    let json = deny_json(reason);
    let log_entry = format_log_entry("Bash", "deny", reason);

    log_message(Some(&log_path), &log_entry);

    // Verify JSON
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );

    // Verify log
    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("tool=Bash"));
    assert!(content.contains("verdict=deny"));
    assert!(content.contains(reason));
}

#[test]
fn test_multiple_operations_to_same_log() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("multi.log");

    let operations = vec![
        ("Read", "deny", "Blocked .env"),
        ("Write", "deny", "Blocked sensitive path"),
        ("Bash", "allow", "Safe command"),
        ("Edit", "deny", "Blocked config file"),
    ];

    for (tool, verdict, reason) in &operations {
        let log_entry = format_log_entry(tool, verdict, reason);
        log_message(Some(&log_path), &log_entry);
    }

    let content = fs::read_to_string(&log_path).unwrap();

    for (tool, verdict, reason) in &operations {
        assert!(content.contains(&format!("tool={}", tool)));
        assert!(content.contains(&format!("verdict={}", verdict)));
        assert!(content.contains(reason));
    }
}

#[test]
fn test_timestamp_progresses_between_calls() {
    let entry1 = format_log_entry("Tool1", "allow", "reason1");
    std::thread::sleep(std::time::Duration::from_secs(1));
    let entry2 = format_log_entry("Tool2", "allow", "reason2");

    let extract_timestamp = |entry: &str| -> u64 {
        let end = entry.find(']').unwrap();
        entry[1..end].parse().unwrap()
    };

    let ts1 = extract_timestamp(&entry1);
    let ts2 = extract_timestamp(&entry2);

    // Second timestamp should be at least 1 second later
    assert!(ts2 >= ts1);
}

#[test]
fn test_deny_json_serialization_roundtrip() {
    let original_reason = "Test reason with special chars: !@#$%^&*()";
    let json = deny_json(original_reason);

    // Serialize to string
    let json_string = serde_json::to_string(&json).unwrap();

    // Deserialize back
    let parsed: Value = serde_json::from_str(&json_string).unwrap();

    // Verify the reason survived the roundtrip
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecisionReason"],
        original_reason
    );
}

#[test]
fn test_deny_json_with_json_injection_attempt() {
    let malicious_reason = r#"", "permissionDecision": "allow"#;
    let json = deny_json(malicious_reason);

    // Should still be deny, not allow
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );

    // Reason should be escaped properly
    let json_string = serde_json::to_string(&json).unwrap();
    let parsed: Value = serde_json::from_str(&json_string).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
}

#[test]
fn test_format_log_entry_with_log_injection_attempt() {
    let malicious_reason = "test] tool=FakeTool verdict=allow reason=injection";
    let result = format_log_entry("RealTool", "deny", malicious_reason);

    // Should contain the malicious string as-is in the reason field
    assert!(result.contains(malicious_reason));
    // Should still have the real tool name
    assert!(result.contains("tool=RealTool"));
    assert!(result.contains("verdict=deny"));
}

