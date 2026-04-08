//! Tests for the "absolute" pattern group: patterns starting with `~`,
//! `~/`, `$HOME`, or `$HOME/` are home-expanded and match against
//! filesystem-absolute paths anywhere, not just under the project root.

use clarg::blocked_files::BlockedFilesRule;
use std::path::Path;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serialize all tests in this module that mutate `HOME`. Cargo runs
/// tests in parallel by default, so without this lock concurrent tests
/// would stomp on each other's env.
pub static HOME_LOCK: Mutex<()> = Mutex::new(());

/// Set `HOME` for the duration of the closure, restoring the previous
/// value afterwards. Guarded by `HOME_LOCK` so only one test touches
/// the global env at a time.
fn with_home<F: FnOnce(&Path)>(home: &Path, f: F) {
    // `lock()` may return a poisoned guard if a prior test panicked
    // while holding it — that's fine, we just take the inner guard.
    let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("HOME").ok();
    // SAFETY: the lock ensures no other test in this binary is reading
    // or writing HOME concurrently.
    unsafe { std::env::set_var("HOME", home) };
    f(home);
    unsafe {
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}

// ============================================================================
// Home-prefixed absolute patterns
// ============================================================================

#[test]
fn test_tilde_slash_pattern_blocks_absolute_path_outside_project() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |home_path| {
        let rule = BlockedFilesRule::new(
            &["~/.aws/credentials".to_string()],
            tmp.path(),
        )
        .unwrap();

        let target = home_path.join(".aws/credentials");
        assert!(
            rule.check(&target).is_some(),
            "~/.aws/credentials pattern should block {}",
            target.display()
        );
    });
}

#[test]
fn test_tilde_doublestar_blocks_any_file_under_home_dir() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |home_path| {
        let rule =
            BlockedFilesRule::new(&["~/.ssh/**".to_string()], tmp.path()).unwrap();

        assert!(rule.check(&home_path.join(".ssh/id_rsa")).is_some());
        assert!(rule.check(&home_path.join(".ssh/config")).is_some());
        assert!(
            rule.check(&home_path.join(".ssh/keys/github.pem"))
                .is_some()
        );
    });
}

#[test]
fn test_tilde_pattern_does_not_match_different_home_subdir() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |home_path| {
        let rule = BlockedFilesRule::new(
            &["~/.aws/credentials".to_string()],
            tmp.path(),
        )
        .unwrap();

        // Same basename in a different location should not match.
        let target = home_path.join("Documents/credentials");
        assert!(rule.check(&target).is_none());
    });
}

#[test]
fn test_tilde_pattern_does_not_match_outside_home() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |_home_path| {
        let rule =
            BlockedFilesRule::new(&["~/.ssh/**".to_string()], tmp.path()).unwrap();

        // An .ssh dir that isn't under HOME should not match the
        // home-expanded absolute pattern.
        assert!(rule.check(Path::new("/etc/ssh/sshd_config")).is_none());
    });
}

#[test]
fn test_dollar_home_pattern_expands_like_tilde() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |home_path| {
        let rule = BlockedFilesRule::new(
            &["$HOME/.netrc".to_string()],
            tmp.path(),
        )
        .unwrap();

        assert!(rule.check(&home_path.join(".netrc")).is_some());
    });
}

#[test]
fn test_bare_tilde_blocks_everything_under_home() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |home_path| {
        // Bare `~` expands to HOME and should block anything inside it.
        let rule = BlockedFilesRule::new(&["~".to_string()], tmp.path()).unwrap();

        assert!(rule.check(&home_path.join("anything.txt")).is_some());
        assert!(
            rule.check(&home_path.join("deeply/nested/file.txt"))
                .is_some()
        );
    });
}

#[test]
fn test_tilde_pattern_ignores_project_relative_paths() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |_home_path| {
        let rule = BlockedFilesRule::new(
            &["~/.ssh/id_rsa".to_string()],
            tmp.path(),
        )
        .unwrap();

        // A project-relative `.ssh/id_rsa` should not be blocked by the
        // absolute pattern.
        let project_root = tmp.path().canonicalize().unwrap();
        let in_project = project_root.join(".ssh/id_rsa");
        assert!(rule.check(&in_project).is_none());
    });
}

// ============================================================================
// Regression: absolute paths outside the project root were previously
// skipped entirely by the ignore-crate-based rule. Now they are checked
// against the absolute pattern group.
// ============================================================================

#[test]
fn test_path_outside_project_root_is_checked_against_absolute_patterns() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |home_path| {
        let rule = BlockedFilesRule::new(
            &["~/.ssh/id_rsa".to_string()],
            tmp.path(),
        )
        .unwrap();

        // The target lives under HOME, which is outside the project's
        // tmp root. The absolute pattern still matches it.
        let target = home_path.join(".ssh/id_rsa");
        assert!(rule.check(&target).is_some());
    });
}

#[test]
fn test_home_pattern_is_not_re_expanded_after_construction() {
    // expand_home runs once at construction; later mutations of HOME
    // must not retroactively change which paths are blocked.
    let tmp = TempDir::new().unwrap();
    let home_a = TempDir::new().unwrap();
    let home_a_path = home_a.path().canonicalize().unwrap();
    let home_b = TempDir::new().unwrap();
    let home_b_path = home_b.path().canonicalize().unwrap();

    let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("HOME").ok();
    unsafe { std::env::set_var("HOME", &home_a_path) };
    let rule =
        BlockedFilesRule::new(&["~/.ssh/id_rsa".to_string()], tmp.path()).unwrap();
    // Now flip HOME to a different dir.
    unsafe { std::env::set_var("HOME", &home_b_path) };
    // The original (home_a) path should still be blocked; the new
    // (home_b) path should NOT be — the rule was baked at construction.
    let blocked = rule.check(&home_a_path.join(".ssh/id_rsa"));
    let allowed = rule.check(&home_b_path.join(".ssh/id_rsa"));
    unsafe {
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
    assert!(blocked.is_some(), "expected home_a path to remain blocked");
    assert!(allowed.is_none(), "expected home_b path NOT to be blocked");
}

// ============================================================================
// Bare absolute patterns (no `~`/`$HOME` prefix) — fix #1 from review
// ============================================================================

#[test]
fn test_bare_absolute_pattern_blocks_filesystem_path() {
    let tmp = TempDir::new().unwrap();
    let rule =
        BlockedFilesRule::new(&["/etc/shadow".to_string()], tmp.path()).unwrap();
    assert!(
        rule.check(Path::new("/etc/shadow")).is_some(),
        "/etc/shadow pattern should block real /etc/shadow"
    );
}

#[test]
fn test_bare_absolute_pattern_does_not_match_unrelated_paths() {
    let tmp = TempDir::new().unwrap();
    let rule =
        BlockedFilesRule::new(&["/etc/shadow".to_string()], tmp.path()).unwrap();
    // Same basename, different parent — must not match.
    assert!(rule.check(Path::new("/etc/shadow.bak")).is_none());
    // Same basename buried under a different absolute prefix — must not match.
    assert!(rule.check(Path::new("/var/etc/shadow")).is_none());
}

#[test]
fn test_unanchored_basename_pattern_blocks_outside_project() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();
    // After fix #1, an unanchored basename pattern fires for paths
    // outside the project root too. Fail-closed.
    assert!(rule.check(Path::new("/Users/someone/.env")).is_some());
    assert!(rule.check(Path::new("/tmp/scratch/.env")).is_some());
    // Different basename → still allowed.
    assert!(rule.check(Path::new("/etc/passwd")).is_none());
}

#[test]
fn test_directory_pattern_blocks_outside_project() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["node_modules/".to_string()], tmp.path())
        .unwrap();
    // Parent walk catches files inside a `node_modules` dir anywhere.
    assert!(
        rule.check(Path::new("/var/cache/node_modules/lib/file.js"))
            .is_some()
    );
    // No node_modules ancestor → no match.
    assert!(
        rule.check(Path::new("/var/cache/other/lib/file.js"))
            .is_none()
    );
}

#[test]
fn test_double_star_pattern_blocks_outside_project() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["**/*.pem".to_string()], tmp.path()).unwrap();
    assert!(
        rule.check(Path::new("/etc/ssl/certs/ca.pem")).is_some(),
        "**/*.pem should match an outside-project .pem file"
    );
    assert!(rule.check(Path::new("/etc/ssl/certs/ca.crt")).is_none());
}

#[test]
fn test_anchored_project_pattern_still_anchors_inside_project() {
    // Sanity check: a `/foo` pattern still works as project-anchored
    // for paths under the project root, even though the same pattern
    // also matches `/foo` at the filesystem root for outside-project
    // targets via the abs-form fallback.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let rule =
        BlockedFilesRule::new(&["/root.txt".to_string()], &project_root).unwrap();
    assert!(rule.check(&project_root.join("root.txt")).is_some());
    // Anchored: not at the top of the project → not blocked.
    assert!(
        rule.check(&project_root.join("subdir/root.txt"))
            .is_none()
    );
}

// ============================================================================
// Mixing project and absolute patterns
// ============================================================================

#[test]
fn test_mixed_pattern_groups_both_fire() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |home_path| {
        let rule = BlockedFilesRule::new(
            &[
                ".env".to_string(),               // project-scoped
                "~/.aws/credentials".to_string(), // home-absolute
            ],
            &project_root,
        )
        .unwrap();

        // Project pattern fires inside the project.
        assert!(rule.check(&project_root.join(".env")).is_some());
        // Absolute pattern fires outside the project.
        assert!(rule.check(&home_path.join(".aws/credentials")).is_some());
        // Neither pattern matches an unrelated file inside the project.
        assert!(rule.check(&project_root.join("src/main.rs")).is_none());
    });
}

// ============================================================================
// Fail-closed behavior when HOME is missing/empty (fix #3 from review)
// ============================================================================

#[test]
fn test_new_with_home_pattern_and_unset_home_errors() {
    let tmp = TempDir::new().unwrap();
    let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("HOME").ok();
    unsafe { std::env::remove_var("HOME") };
    let result = BlockedFilesRule::new(&["~/.ssh/id_rsa".to_string()], tmp.path());
    unsafe {
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
    let err = match result {
        Ok(_) => panic!("expected fail-closed when HOME is unset"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("HOME"),
        "error message should mention HOME, got: {msg}"
    );
    assert!(
        msg.contains("~/.ssh/id_rsa"),
        "error message should identify the offending pattern, got: {msg}"
    );
}

#[test]
fn test_new_with_home_pattern_and_empty_home_errors() {
    let tmp = TempDir::new().unwrap();
    let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("HOME").ok();
    unsafe { std::env::set_var("HOME", "") };
    let result = BlockedFilesRule::new(&["$HOME/.netrc".to_string()], tmp.path());
    unsafe {
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
    assert!(
        result.is_err(),
        "expected fail-closed when HOME is empty string"
    );
}

#[test]
fn test_new_with_only_project_patterns_does_not_check_home() {
    // No home-prefixed patterns → HOME is irrelevant; construction
    // must succeed even if HOME is unset.
    let tmp = TempDir::new().unwrap();
    let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("HOME").ok();
    unsafe { std::env::remove_var("HOME") };
    let result =
        BlockedFilesRule::new(&[".env".to_string(), "*.secret".to_string()], tmp.path());
    unsafe {
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
    assert!(result.is_ok(), "non-home patterns should not require HOME");
}

// ============================================================================
// Reason-string shape
// ============================================================================

#[test]
fn test_absolute_pattern_reason_includes_expanded_pattern_and_path() {
    let tmp = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    with_home(&home_path, |home_path| {
        let rule =
            BlockedFilesRule::new(&["~/.ssh/id_rsa".to_string()], tmp.path())
                .unwrap();

        let target = home_path.join(".ssh/id_rsa");
        let reason = rule.check(&target).expect("should block");
        assert!(reason.contains("Blocked by `clarg`"));
        assert!(reason.contains(target.to_str().unwrap()));
        // The reported pattern should be the home-expanded absolute form.
        assert!(
            reason.contains(home_path.join(".ssh/id_rsa").to_str().unwrap()),
            "reason should mention expanded pattern, got: {}",
            reason
        );
    });
}
