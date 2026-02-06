use clarg::output::deny_json;
use serde_json::Value;

// ============================================================================
// deny_json tests
// ============================================================================

#[test]
fn test_deny_json_structure_is_correct() {
    let result = deny_json("test reason");

    assert!(result.is_object());
    assert!(result.get("hookSpecificOutput").is_some());

    let hook_output = &result["hookSpecificOutput"];
    assert_eq!(hook_output["hookEventName"], "PreToolUse");
    assert_eq!(hook_output["permissionDecision"], "deny");
    assert_eq!(hook_output["permissionDecisionReason"], "test reason");
}

#[test]
fn test_deny_json_all_keys_present() {
    let result = deny_json("test");
    let hook_output = &result["hookSpecificOutput"];

    assert!(hook_output.get("hookEventName").is_some());
    assert!(hook_output.get("permissionDecision").is_some());
    assert!(hook_output.get("permissionDecisionReason").is_some());
}

#[test]
fn test_deny_json_with_simple_reason() {
    let result = deny_json("Access denied");
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        "Access denied"
    );
}

#[test]
fn test_deny_json_with_empty_reason() {
    let result = deny_json("");
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        ""
    );
}

#[test]
fn test_deny_json_with_unicode_reason() {
    let reason = "文件被拒绝访问 🚫 Доступ запрещен";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_unicode_emojis() {
    let reason = "❌ Access denied 🔒 Security risk ⚠️";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_very_long_reason() {
    let reason = "a".repeat(10000);
    let result = deny_json(&reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_special_characters() {
    let reason = "!@#$%^&*()_+-=[]{}|;':,.<>?/~`";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_json_quotes() {
    let reason = r#"File contains "quotes" and more "nested quotes""#;
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_json_braces() {
    let reason = "Object like {key: value} and array like [1, 2, 3]";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_newlines() {
    let reason = "Line 1\nLine 2\nLine 3";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_tabs() {
    let reason = "Column1\tColumn2\tColumn3";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_backslashes() {
    let reason = r"Path: C:\Users\test\file.txt";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_is_valid_json() {
    let result = deny_json("test reason");
    let json_string = serde_json::to_string(&result).unwrap();
    let parsed: Value = serde_json::from_str(&json_string).unwrap();
    assert_eq!(parsed, result);
}

#[test]
fn test_deny_json_serializes_correctly() {
    let result = deny_json("test");
    let serialized = serde_json::to_string(&result);
    assert!(serialized.is_ok());

    let json_str = serialized.unwrap();
    assert!(json_str.contains("hookSpecificOutput"));
    assert!(json_str.contains("PreToolUse"));
    assert!(json_str.contains("deny"));
    assert!(json_str.contains("test"));
}

#[test]
fn test_deny_json_with_null_character() {
    let reason = "Before\0After";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_with_control_characters() {
    let reason = "Control\x01\x02\x03chars";
    let result = deny_json(reason);
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecisionReason"],
        reason
    );
}

#[test]
fn test_deny_json_hook_event_name_is_correct() {
    let result = deny_json("any reason");
    assert_eq!(
        result["hookSpecificOutput"]["hookEventName"],
        "PreToolUse"
    );
}

#[test]
fn test_deny_json_permission_decision_is_deny() {
    let result = deny_json("any reason");
    assert_eq!(
        result["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
}

