use clarg::output::deny_json;

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
fn test_deny_json_value_type_check() {
    let json = deny_json("test");

    assert!(json.is_object());
    assert!(json["hookSpecificOutput"].is_object());
    assert!(json["hookSpecificOutput"]["hookEventName"].is_string());
    assert!(json["hookSpecificOutput"]["permissionDecision"].is_string());
    assert!(json["hookSpecificOutput"]["permissionDecisionReason"].is_string());
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
