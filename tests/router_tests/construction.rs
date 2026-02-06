use clarg::config::Config;
use clarg::router::RuleSet;
use tempfile::TempDir;

// ============================================================================
// RuleSet::build with various configs
// ============================================================================

#[test]
fn test_build_with_empty_config() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_build_with_internal_only() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_build_with_blocked_files() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string(), "*.secret".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_build_with_blocked_commands() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["rm -rf".to_string(), "drop table".to_string()],
        log_to: None,
        internal_access_only: false,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_build_with_all_rules() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec!["rm -rf".to_string()],
        log_to: None,
        internal_access_only: true,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_build_with_invalid_regex_fails() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["[invalid".to_string()],
        log_to: None,
        internal_access_only: false,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_err());
}

#[test]
fn test_build_with_nonexistent_project_root_for_internal_only_fails() {
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let result = RuleSet::build(&config, std::path::Path::new("/nonexistent/path/xyz123"));
    assert!(result.is_err());
}

#[test]
fn test_build_blocked_files_without_internal_only() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_build_with_multiple_file_patterns() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![
            ".env".to_string(),
            "*.secret".to_string(),
            "node_modules/".to_string(),
            "**/*.key".to_string(),
        ],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_build_with_multiple_command_patterns() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![
            "rm -rf".to_string(),
            "drop table".to_string(),
            "truncate".to_string(),
            r"curl.*\|.*bash".to_string(),
        ],
        log_to: None,
        internal_access_only: false,
    };
    let result = RuleSet::build(&config, tmp.path());
    assert!(result.is_ok());
}
