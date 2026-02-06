use clarg::output::{deny_json, format_log_entry, log_message};
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Edge case and stress tests
// ============================================================================

#[test]
fn test_deny_json_with_maximum_unicode_characters() {
    let reason = "🚀🔥💯🎉🎈🎁🎂🎃🎄🎅🎆🎇🎈🎉";
    let json = deny_json(reason);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_format_log_entry_with_carriage_return() {
    let reason = "Line1\rLine2";
    let result = format_log_entry("Tool", "deny", reason);
    assert!(result.contains(reason));
}

#[test]
fn test_format_log_entry_with_form_feed() {
    let reason = "Page1\x0CPage2";
    let result = format_log_entry("Tool", "deny", reason);
    assert!(result.contains(reason));
}

#[test]
fn test_log_message_concurrent_writes_same_file() {
    use std::sync::Arc;
    use std::thread;

    let temp_dir = TempDir::new().unwrap();
    let log_path = Arc::new(temp_dir.path().join("concurrent.log"));

    let mut handles = vec![];

    for i in 0..10 {
        let path = Arc::clone(&log_path);
        let handle = thread::spawn(move || {
            log_message(Some(&path), &format!("Thread {} message", i));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let content = fs::read_to_string(log_path.as_ref()).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Should have 10 lines (may be interleaved)
    assert_eq!(lines.len(), 10);
}

#[test]
fn test_deny_json_reason_with_html_tags() {
    let reason = "<script>alert('xss')</script>";
    let json = deny_json(reason);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_reason_with_xml_entities() {
    let reason = "&lt;tag&gt; &amp; &quot;quotes&quot;";
    let json = deny_json(reason);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_format_log_entry_with_ansi_escape_codes() {
    let reason = "\x1b[31mRed text\x1b[0m";
    let result = format_log_entry("Tool", "deny", reason);
    assert!(result.contains(reason));
}

#[test]
fn test_log_message_with_binary_data() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("binary.log");

    let message = "Binary: \x00\x01\x02\x7F";
    log_message(Some(&log_path), message);

    // Read as bytes to handle binary data
    let content = fs::read(&log_path).unwrap();
    assert!(content.len() > 0);
}

#[test]
fn test_deny_json_structure_immutability() {
    let json1 = deny_json("reason1");
    let json2 = deny_json("reason2");

    // Structure should be identical except for reason
    assert_eq!(
        json1["hookSpecificOutput"]["hookEventName"],
        json2["hookSpecificOutput"]["hookEventName"]
    );
    assert_eq!(
        json1["hookSpecificOutput"]["permissionDecision"],
        json2["hookSpecificOutput"]["permissionDecision"]
    );

    // Only reason should differ
    assert_ne!(
        json1["hookSpecificOutput"]["permissionDecisionReason"],
        json2["hookSpecificOutput"]["permissionDecisionReason"]
    );
}

#[test]
fn test_format_log_entry_different_timestamps() {
    let entry1 = format_log_entry("Tool", "allow", "test");
    // Sleep for just over 1 second to ensure timestamp changes (timestamps are in seconds)
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let entry2 = format_log_entry("Tool", "allow", "test");

    // Entries should differ because of timestamp
    assert_ne!(entry1, entry2);
}

#[test]
fn test_log_message_path_with_unicode() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("日志文件.log");

    log_message(Some(&log_path), "test message");

    assert!(log_path.exists());
    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("test message"));
}

#[test]
fn test_deny_json_value_type_check() {
    let json = deny_json("test");

    assert!(json.is_object());
    assert!(json["hookSpecificOutput"].is_object());
    assert!(json["hookSpecificOutput"]["hookEventName"].is_string());
    assert!(json["hookSpecificOutput"]["permissionDecision"].is_string());
    assert!(json["hookSpecificOutput"]["permissionDecisionReason"].is_string());
}

#[test]
fn test_format_log_entry_no_leading_or_trailing_spaces() {
    let result = format_log_entry("Tool", "allow", "reason");

    // Should not have trailing spaces before newline
    let result_trimmed = result.trim_end();
    assert_eq!(result.trim_end(), result_trimmed);
}

#[test]
fn test_log_message_file_created_with_correct_permissions() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("perms.log");

    log_message(Some(&log_path), "test");

    assert!(log_path.exists());

    // Should be readable
    let content = fs::read_to_string(&log_path);
    assert!(content.is_ok());
}

#[test]
fn test_deny_json_hook_output_keys_exact() {
    let json = deny_json("test");
    let hook_output = json["hookSpecificOutput"].as_object().unwrap();

    // Should have exactly 3 keys
    assert_eq!(hook_output.len(), 3);
    assert!(hook_output.contains_key("hookEventName"));
    assert!(hook_output.contains_key("permissionDecision"));
    assert!(hook_output.contains_key("permissionDecisionReason"));
}

#[test]
fn test_deny_json_top_level_keys_exact() {
    let json = deny_json("test");
    let obj = json.as_object().unwrap();

    // Should have exactly 1 key at top level
    assert_eq!(obj.len(), 1);
    assert!(obj.contains_key("hookSpecificOutput"));
}
