use clarg::config::Config;
use std::path::PathBuf;
use super::helpers::create_yaml_file;

// ============================================================================
// Config::from_yaml TESTS - Error Cases
// ============================================================================

#[test]
fn test_from_yaml_file_does_not_exist() {
    let path = PathBuf::from("/this/file/does/not/exist.yaml");
    let result = Config::from_yaml(&path);

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_invalid_yaml_syntax() {
    let yaml = r#"
block_access_to:
  - ".env"
  - "*.secret
  - missing quote
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_invalid_yaml_syntax_missing_colon() {
    let yaml = r#"
block_access_to
  - ".env"
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_wrong_type_block_access_to_string() {
    let yaml = r#"
block_access_to: "should be array not string"
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_wrong_type_commands_forbidden_string() {
    let yaml = r#"
commands_forbidden: "should be array not string"
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_wrong_type_internal_access_only_string() {
    let yaml = r#"
internal_access_only: "true"
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_wrong_type_log_to_array() {
    let yaml = r#"
log_to: ["/tmp/clarg.log"]
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_wrong_type_block_access_to_number() {
    let yaml = r#"
block_access_to: 123
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_wrong_type_commands_forbidden_number() {
    let yaml = r#"
commands_forbidden: 456
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_wrong_type_internal_access_only_number() {
    let yaml = r#"
internal_access_only: 789
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}

// ============================================================================
// Config::from_yaml TESTS - Extra Fields & Null Values
// ============================================================================

#[test]
fn test_from_yaml_extra_fields_ignored() {
    let yaml = r#"
block_access_to:
  - ".env"
extra_field: "should be ignored"
another_field: 123
nested:
  field: "also ignored"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_to, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_yaml_null_block_access_to() {
    let yaml = r#"
block_access_to: null
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // null should be treated as an error for Vec fields
    assert!(result.is_err());
}

#[test]
fn test_from_yaml_null_commands_forbidden() {
    let yaml = r#"
commands_forbidden: null
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // null should be treated as an error for Vec fields
    assert!(result.is_err());
}

#[test]
fn test_from_yaml_null_log_to() {
    let yaml = r#"
log_to: null
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.log_to, None);
}

#[test]
fn test_from_yaml_null_internal_access_only() {
    let yaml = r#"
internal_access_only: null
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // null should be treated as an error for bool fields
    assert!(result.is_err());
}

// ============================================================================
