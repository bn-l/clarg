use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::router::{RuleSet, Verdict};
use serde_json::json;
use std::path::PathBuf;
use tempfile::TempDir;

fn make_grep_input(path: &str, pattern: &str, cwd: PathBuf) -> HookInput {
    let json = json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {
            "path": path,
            "pattern": pattern
        }
    });
    serde_json::from_value(json).unwrap()
}

fn make_grep_input_path_only(path: &str, cwd: PathBuf) -> HookInput {
    let json = json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {
            "path": path
        }
    });
    serde_json::from_value(json).unwrap()
}

// ============================================================================
// Grep with no rules configured
// ============================================================================

#[test]
fn test_grep_no_rules_allows_anything() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_grep_input("/etc", "password", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

// ============================================================================
// Grep with internal_only
// ============================================================================

#[test]
fn test_grep_internal_only_blocks_external_path() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_grep_input("/etc", "root", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("outside") || reason.contains("/etc"));
        }
    }
}

#[test]
fn test_grep_internal_only_allows_internal_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let path = project_root.join("src").to_string_lossy().to_string();
    let input = make_grep_input(&path, "TODO", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

#[test]
fn test_grep_internal_only_blocks_home_var() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_grep_input("$HOME/.ssh", "key", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_grep_internal_only_blocks_parent_traversal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let path = project_root.join("../../other").to_string_lossy().to_string();
    let input = make_grep_input(&path, "secret", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

// ============================================================================
// Grep with blocked_files
// ============================================================================

#[test]
fn test_grep_blocked_files_denies_blocked_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".secret".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let path = project_root.join(".secret").to_string_lossy().to_string();
    let input = make_grep_input(&path, "api_key", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains(".secret"));
        }
    }
}

#[test]
fn test_grep_blocked_files_allows_non_blocked_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".secret".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let path = project_root.join("src").to_string_lossy().to_string();
    let input = make_grep_input(&path, "import", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

// ============================================================================
// Grep with both internal_only and blocked_files
// ============================================================================

#[test]
fn test_grep_internal_checked_before_blocked_files() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec!["config/".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    // External path that also matches blocked_files
    let input = make_grep_input("/external/config", "api_key", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            // Should be blocked by internal_only
            assert!(reason.contains("outside"));
        }
    }
}

// ============================================================================
// Missing path in tool_input
// ============================================================================

#[test]
fn test_grep_missing_path_allowed() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec!["*.secret".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {
            "pattern": "TODO"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow when path is missing"),
    }
}

// ============================================================================
// Relative paths
// ============================================================================

#[test]
fn test_grep_relative_path_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_grep_input_path_only("./tests", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

#[test]
fn test_grep_relative_parent_traversal_blocked() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_grep_input_path_only("../../secrets", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_grep_absolute_internal_path_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let path = project_root.to_string_lossy().to_string();
    let input = make_grep_input(&path, "pattern", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}
