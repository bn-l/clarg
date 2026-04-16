use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::router::{RuleSet, Verdict};
use serde_json::json;
use std::path::PathBuf;
use tempfile::TempDir;

fn make_file_tool_input(tool_name: &str, file_path: &str, cwd: PathBuf) -> HookInput {
    let json = json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {
            "file_path": file_path
        }
    });
    serde_json::from_value(json).unwrap()
}

// ============================================================================
// Read tool
// ============================================================================

#[test]
fn test_read_no_rules_allows_anything() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Read", "/etc/passwd", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

#[test]
fn test_read_internal_only_blocks_external() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Read", "/etc/passwd", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("outside") || reason.contains("/etc/passwd"));
        }
    }
}

#[test]
fn test_read_internal_only_allows_internal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let file_path = project_root.join("src/main.rs").to_string_lossy().to_string();
    let input = make_file_tool_input("Read", &file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

#[test]
fn test_read_blocked_files_denies_match() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let file_path = project_root.join(".env").to_string_lossy().to_string();
    let input = make_file_tool_input("Read", &file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains(".env"));
        }
    }
}

#[test]
fn test_read_blocked_files_allows_non_match() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let file_path = project_root.join("config.json").to_string_lossy().to_string();
    let input = make_file_tool_input("Read", &file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow"),
    }
}

// ============================================================================
// Write tool
// ============================================================================

#[test]
fn test_write_internal_only_blocks_external() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Write", "/tmp/malicious.sh", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_write_internal_only_allows_internal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let file_path = project_root.join("output.txt").to_string_lossy().to_string();
    let input = make_file_tool_input("Write", &file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

#[test]
fn test_write_blocked_files_denies_match() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec!["*.secret".to_string()],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let file_path = project_root.join("api.secret").to_string_lossy().to_string();
    let input = make_file_tool_input("Write", &file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains(".secret") || reason.contains("api.secret"));
        }
    }
}

// ============================================================================
// Edit tool
// ============================================================================

#[test]
fn test_edit_internal_only_blocks_external() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Edit", "/etc/hosts", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_edit_internal_only_allows_internal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let file_path = project_root.join("src/lib.rs").to_string_lossy().to_string();
    let input = make_file_tool_input("Edit", &file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

#[test]
fn test_edit_blocked_files_denies_match() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![".env*".to_string()],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let file_path = project_root.join(".env.local").to_string_lossy().to_string();
    let input = make_file_tool_input("Edit", &file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

// ============================================================================
// Missing file_path in tool_input
// ============================================================================

#[test]
fn test_file_tool_missing_file_path_allowed() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {}
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow when file_path is missing"),
    }
}

// ============================================================================
// Rule ordering: internal_only checked before blocked_files
// ============================================================================

#[test]
fn test_file_tool_internal_only_checked_before_blocked_files() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    // External path that also matches blocked_files pattern
    let input = make_file_tool_input("Read", "/outside/.env", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            // Should be blocked by internal_only, mentioning "outside"
            assert!(reason.contains("outside"));
        }
    }
}

// ============================================================================
// Path traversal attempts
// ============================================================================

#[test]
fn test_read_parent_traversal_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let file_path = project_root.join("../../../etc/passwd").to_string_lossy().to_string();
    let input = make_file_tool_input("Read", &file_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_write_tilde_expansion_blocked() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Write", "~/.bashrc", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(_) => {}
    }
}

// ============================================================================
// NotebookEdit tool
// ============================================================================

fn make_notebook_edit_input(notebook_path: &str, cwd: PathBuf) -> HookInput {
    let json = json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "NotebookEdit",
        "tool_input": {
            "notebook_path": notebook_path,
            "new_source": "print('hello')",
            "cell_type": "code"
        }
    });
    serde_json::from_value(json).unwrap()
}

#[test]
fn test_notebookedit_internal_only_blocks_external() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_notebook_edit_input("/etc/notebooks/evil.ipynb", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny for NotebookEdit with external path"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("outside"));
        }
    }
}

#[test]
fn test_notebookedit_internal_only_allows_internal() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let nb_path = project_root.join("notebook.ipynb").to_string_lossy().to_string();
    let input = make_notebook_edit_input(&nb_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got: {}", reason),
    }
}

#[test]
fn test_notebookedit_blocked_files_denies_match() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let config = Config {
        block_access_to: vec!["*.ipynb".to_string()],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, &project_root).unwrap();
    let nb_path = project_root.join("secret.ipynb").to_string_lossy().to_string();
    let input = make_notebook_edit_input(&nb_path, project_root.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny for blocked notebook"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("ipynb"));
        }
    }
}

#[test]
fn test_notebookedit_no_rules_allows() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_notebook_edit_input("/anywhere/notebook.ipynb", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(_) => panic!("expected allow with no rules"),
    }
}

#[test]
fn test_notebookedit_case_insensitive_routing() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();

    let json = json!({
        "session_id": "test-session",
        "cwd": tmp.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "NOTEBOOKEDIT",
        "tool_input": {
            "notebook_path": "/etc/evil.ipynb",
            "new_source": "x",
            "cell_type": "code"
        }
    });
    let input: HookInput = serde_json::from_value(json).unwrap();

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny for NOTEBOOKEDIT (uppercase)"),
        Verdict::Deny(_) => {}
    }
}

// ============================================================================
// special_flags: no_root / no_system_dirs
// ============================================================================

#[test]
fn test_read_no_root_blocks_root() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: true,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Read", "/", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("no_root"), "got: {}", reason);
        }
    }
}

#[test]
fn test_write_no_system_dirs_blocks_etc() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: true,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Write", "/etc/passwd", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("no_system_dirs"), "got: {}", reason);
            assert!(reason.contains("/etc"), "got: {}", reason);
        }
    }
}

#[test]
fn test_edit_no_system_dirs_allows_tmp_when_only_system_flag_active() {
    // /tmp is intentionally excluded from the system-dirs list.
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: true,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Edit", "/tmp/scratch.txt", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got deny: {}", reason),
    }
}

#[test]
fn test_edit_no_system_dirs_allows_private_tmp() {
    // /private/tmp is the canonical target of /tmp on macOS and is an
    // explicit exception to the SYSTEM_DIRS `/private` prefix.
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: true,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input(
        "Edit",
        "/private/tmp/scratch.txt",
        tmp.path().to_path_buf(),
    );

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got deny: {}", reason),
    }
}

#[test]
fn test_read_no_system_dirs_blocks_private_etc() {
    // Exception is scoped to /private/tmp only; /private/etc still blocks.
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: true,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Read", "/private/etc/hosts", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("no_system_dirs"), "got: {}", reason);
            assert!(reason.contains("/private"), "got: {}", reason);
        }
    }
}

#[test]
fn test_path_tool_with_only_system_paths_rule_does_not_short_circuit_allow() {
    // Regression guard: evaluate_path_tool's early-return must include
    // the system_paths check; otherwise turning on just `no_root` alone
    // would silently allow all targets.
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: true,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Read", "/", tmp.path().to_path_buf());

    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny — system_paths is the only active rule"),
        Verdict::Deny(_) => {}
    }
}

#[test]
fn test_read_no_system_dirs_inside_project_allowed() {
    // Simulate a project rooted at the tmp dir; in-project reads must
    // be allowed even if tmp itself is under a hypothetical system dir.
    let tmp = TempDir::new().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let file_path = canonical.join("src/main.rs").to_string_lossy().to_string();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: true,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, &canonical).unwrap();
    let input = make_file_tool_input("Read", &file_path, canonical.clone());

    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!("expected allow, got deny: {}", reason),
    }
}

// ============================================================================
// Regression: ~user expansion must work for path tools (Read/Write/Edit).
// Without the fix, `Read { file_path: "~root/.bashrc" }` was joined to the
// project root and falsely accepted as "inside project".
// ============================================================================

#[test]
fn test_read_tilde_root_blocked_by_no_system_dirs() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: false,
        no_root: false,
        no_system_dirs: true,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Read", "~root/.bashrc", tmp.path().to_path_buf());
    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny — ~root bypass on path tool"),
        Verdict::Deny(reason) => {
            assert!(reason.contains("no_system_dirs"), "got: {}", reason);
        }
    }
}

#[test]
fn test_write_tilde_user_blocked_by_internal_access_only() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Write", "~alice/secret.txt", tmp.path().to_path_buf());
    match ruleset.evaluate(&input) {
        Verdict::Allow => panic!("expected deny"),
        Verdict::Deny(reason) => {
            assert!(
                reason.contains("outside") || reason.contains("project"),
                "got: {}",
                reason
            );
        }
    }
}

// ============================================================================
// Bash special tilde forms (~+ / ~- / ~N) on path tools — must not
// synthesize a fake home like `/Users/+/...` and wrongly deny.
// ============================================================================

#[test]
fn test_read_tilde_plus_allowed_under_internal_only() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Read", "~+/Cargo.toml", tmp.path().to_path_buf());
    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!(
            "`~+` must not synthesize a fake home, got deny: {}",
            reason
        ),
    }
}

#[test]
fn test_write_tilde_minus_allowed_under_internal_only() {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: true,
        no_root: false,
        no_system_dirs: false,
        no_unknown_tools: false,
    };
    let ruleset = RuleSet::build(&config, tmp.path()).unwrap();
    let input = make_file_tool_input("Write", "~-/out.txt", tmp.path().to_path_buf());
    match ruleset.evaluate(&input) {
        Verdict::Allow => {}
        Verdict::Deny(reason) => panic!(
            "`~-` must not synthesize a fake home, got deny: {}",
            reason
        ),
    }
}
