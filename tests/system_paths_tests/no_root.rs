//! Pure-rule tests for `no_root`. These avoid the bash analyzer and
//! the router — they feed pre-resolved paths directly to the rule,
//! so any bug in `SystemPathsRule::check_no_root` shows up here.
//!
//! Targets live on the router side; these confirm the matcher itself
//! is right, including lexical-variant normalization via `resolve_target`.

use clarg::internalonly::resolve_target;
use clarg::system_paths::SystemPathsRule;
use std::path::Path;

fn rule() -> SystemPathsRule {
    // Project root `/tmp/proj` — unrelated to the root/glob inputs we test.
    SystemPathsRule::new(true, false, Path::new("/tmp/proj"), Path::new("/tmp/proj"))
}

// Helper: lexically resolve a raw token the way the router would,
// then check it against the rule. This exercises the same path
// normalization that `resolve_target` applies in production.
fn check_raw(rule: &SystemPathsRule, raw: &str) -> Option<String> {
    let resolved = resolve_target(raw, Path::new("/tmp/proj"));
    rule.check(&resolved)
}

#[test]
fn test_no_root_blocks_exact_root() {
    let r = rule();
    assert!(r.check(Path::new("/")).is_some());
}

#[test]
fn test_no_root_blocks_normalized_root_aliases() {
    let r = rule();
    // All of these lexically normalize to "/".
    for raw in &["/", "/.", "/..", "/./", "/../", "/./..", "/../.", "/../.."] {
        assert!(
            check_raw(&r, raw).is_some(),
            "expected '{}' (normalized root) to be blocked",
            raw
        );
    }
}

#[test]
fn test_no_root_blocks_root_glob_forms() {
    let r = rule();
    // Direct glob children of root.
    for raw in &["/*", "/**", "/?", "/[abc]"] {
        assert!(
            check_raw(&r, raw).is_some(),
            "expected '{}' to be blocked",
            raw
        );
    }
}

#[test]
fn test_no_root_blocks_lexically_normalized_root_globs() {
    let r = rule();
    // These all normalize to `/*` via `.` / `..` elimination.
    for raw in &["/./*", "/../*", "/tmp/../*"] {
        assert!(
            check_raw(&r, raw).is_some(),
            "expected '{}' (normalizes to /*) to be blocked",
            raw
        );
    }
}

#[test]
fn test_no_root_does_not_block_non_root_absolute_paths() {
    let r = rule();
    for path in &[
        "/tmp/x",
        "/usr/bin",
        "/Users/me/file",
        "/home/me/file",
        "/etc/passwd",
    ] {
        assert!(
            r.check(Path::new(path)).is_none(),
            "expected '{}' to NOT trigger no_root",
            path
        );
    }
}

#[test]
fn test_no_root_does_not_block_project_relative_paths() {
    let r = rule();
    // Relative paths resolve inside the project root, not to `/`.
    for raw in &["foo", "./foo", "src/main.rs", "a/b/c"] {
        assert!(
            check_raw(&r, raw).is_none(),
            "expected relative '{}' to NOT trigger no_root",
            raw
        );
    }
}

#[test]
fn test_no_root_does_not_block_root_followed_by_non_glob_segment() {
    let r = rule();
    // `/foo` is NOT "root" — it's a specific child. (Descendants are
    // the job of no_system_dirs if configured.)
    assert!(r.check(Path::new("/foo")).is_none());
    assert!(r.check(Path::new("/somewhere-not-listed")).is_none());
}
