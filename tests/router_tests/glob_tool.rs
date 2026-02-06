use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::router::{RuleSet, Verdict};
use serde_json::json;
use std::path::PathBuf;
use tempfile::TempDir;

fn make_glob_input(path: &str, pattern: &str, cwd: PathBuf) -> HookInput {
    let json = json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": path,
            "pattern": pattern
        }
    });
    serde_json::from_value(json).unwrap()
}

fn make_glob_input_path_only(path: &str, cwd: PathBuf) -> HookInput {
    let json = json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {
            "path": path
        }
    });
    serde_json::from_value(json).unwrap()
}

// ============================================================================
// Glob with no rules configured
// ============================================================================

#[test]
fn test_glob_no_rules_allows_anything() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_glob_input("/etc", "*.conf", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

// ============================================================================
// Glob with internal_only
// ============================================================================

#[test]
fn test_glob_internal_only_blocks_external_path() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_glob_input("/etc", "*.conf", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("outside") || reason.contains("/etc"));
        }
    }
}

#[test]
fn test_glob_internal_only_allows_internal_path() {
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
    let input = make_glob_input(&path, "*.rs", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

#[test]
fn test_glob_internal_only_blocks_tilde_path() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_glob_input("~/Documents", "*.txt", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_glob_internal_only_blocks_parent_traversal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let path = project_root.join("../..").to_string_lossy().to_string();
    let input = make_glob_input(&path, "*", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

// ============================================================================
// Glob with blocked_files
// ============================================================================

#[test]
fn test_glob_blocked_files_denies_blocked_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec!["secrets".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let path = project_root.join("secrets").to_string_lossy().to_string();
    let input = make_glob_input(&path, "**/*.key", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("secrets"));
        }
    }
}

#[test]
fn test_glob_blocked_files_allows_non_blocked_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec!["secrets".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let path = project_root.join("src").to_string_lossy().to_string();
    let input = make_glob_input(&path, "**/*.js", project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

// ============================================================================
// Glob with both internal_only and blocked_files
// ============================================================================

#[test]
fn test_glob_internal_checked_before_blocked_files() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec!["secrets/".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    // External path that also matches blocked_files
    let input = make_glob_input("/external/secrets", "*.key", tmp.path().to_path_buf());

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
fn test_glob_missing_path_allowed() {
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
        "tool_name": "Glob",
        "tool_input": {
            "pattern": "*.txt"
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
fn test_glob_relative_path_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_glob_input_path_only("./src", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

#[test]
fn test_glob_relative_parent_traversal_blocked() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_glob_input_path_only("../outside", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}
