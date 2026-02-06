use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::router::{RuleSet, Verdict};
use serde_json::json;
use std::path::PathBuf;
use tempfile::TempDir;

fn make_bash_input(command: &str, cwd: PathBuf) -> HookInput {
    let json = json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": command
        }
    });
    serde_json::from_value(json).unwrap()
}

fn make_read_input(file_path: &str, cwd: PathBuf) -> HookInput {
    let json = json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": file_path
        }
    });
    serde_json::from_value(json).unwrap()
}

// ============================================================================
// Rule ordering for Bash: internalonly -> blocked_commands
// ============================================================================

#[test]
fn test_bash_internalonly_before_blocked_commands_external() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["cat".to_string()],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    // This command triggers BOTH rules
    let input = make_bash_input("cat /etc/passwd", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            // internal_only should trigger first (checks path before command pattern)
            // The reason should mention the external path, not the blocked command
            assert!(
                reason.contains("/etc/passwd") || reason.contains("outside"),
                "expected internal_only to trigger, got: {}",
                reason
            );
        }
    }
}

#[test]
fn test_bash_blocked_commands_triggers_when_internal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["dangerous".to_string()],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    // This command is internal but matches blocked pattern
    let input = make_bash_input("dangerous ./file.txt", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            // blocked_commands should trigger because path is internal
            assert!(
                reason.contains("dangerous"),
                "expected blocked_commands to trigger, got: {}",
                reason
            );
        }
    }
}

#[test]
fn test_bash_both_rules_pass_allows() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["rm -rf".to_string()],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    // Internal path, non-matching command
    let input = make_bash_input("ls ./src", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

// ============================================================================
// Rule ordering for file tools: internalonly -> blocked_files
// ============================================================================

#[test]
fn test_file_internalonly_before_blocked_files() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    // External path that also matches blocked_files pattern
    let input = make_read_input("/outside/.env", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            // internal_only should trigger first
            assert!(
                reason.contains("outside"),
                "expected internal_only to trigger, got: {}",
                reason
            );
        }
    }
}

#[test]
fn test_file_blocked_files_triggers_when_internal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    // Internal path that matches blocked_files
    let file_path = project_root.join(".env").to_string_lossy().to_string();
    let input = make_read_input(&file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            // blocked_files should trigger because path is internal
            assert!(
                reason.contains(".env"),
                "expected blocked_files to trigger, got: {}",
                reason
            );
        }
    }
}

#[test]
fn test_file_both_rules_pass_allows() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    // Internal path, non-matching pattern
    let file_path = project_root.join("src/main.rs").to_string_lossy().to_string();
    let input = make_read_input(&file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

// ============================================================================
// Only internalonly configured
// ============================================================================

#[test]
fn test_only_internalonly_blocks_external() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_read_input("/etc/passwd", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_only_internalonly_allows_internal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let file_path = project_root.join("file.txt").to_string_lossy().to_string();
    let input = make_read_input(&file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

// ============================================================================
// Only blocked_files configured
// ============================================================================

#[test]
fn test_only_blocked_files_allows_non_matching_internal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    // Internal path that doesn't match pattern - should be allowed
    let file_path = project_root.join("config.json").to_string_lossy().to_string();
    let input = make_read_input(&file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - path doesn't match blocked pattern"),
    }
}

#[test]
fn test_only_blocked_files_blocks_matching_pattern() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let file_path = project_root.join(".env").to_string_lossy().to_string();
    let input = make_read_input(&file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains(".env"));
        }
    }
}

// ============================================================================
// Only blocked_commands configured
// ============================================================================

#[test]
fn test_only_blocked_commands_allows_external_paths_in_bash() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["rm -rf".to_string()],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    // External path but no internal_only check
    let input = make_bash_input("cat /etc/passwd", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - no internal_only configured"),
    }
}

#[test]
fn test_only_blocked_commands_blocks_matching_pattern() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec!["rm -rf".to_string()],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_bash_input("rm -rf /important", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("rm -rf"));
        }
    }
}

// ============================================================================
// No rules configured
// ============================================================================

#[test]
fn test_no_rules_allows_everything_bash() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_bash_input("rm -rf / && cat /etc/passwd", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - no rules configured"),
    }
}

#[test]
fn test_no_rules_allows_everything_read() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_read_input("/etc/shadow", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow - no rules configured"),
    }
}
