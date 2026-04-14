use clarg::system_paths::SystemPathsRule;
use std::path::Path;

#[test]
fn test_is_active_when_no_root_only() {
    let rule = SystemPathsRule::new(true, false, Path::new("/tmp/proj"), Path::new("/tmp/proj"));
    assert!(rule.is_active());
}

#[test]
fn test_is_active_when_no_system_dirs_only() {
    let rule = SystemPathsRule::new(false, true, Path::new("/tmp/proj"), Path::new("/tmp/proj"));
    assert!(rule.is_active());
}

#[test]
fn test_is_active_when_both_flags() {
    let rule = SystemPathsRule::new(true, true, Path::new("/tmp/proj"), Path::new("/tmp/proj"));
    assert!(rule.is_active());
}

#[test]
fn test_is_inactive_when_both_flags_off() {
    let rule = SystemPathsRule::new(false, false, Path::new("/tmp/proj"), Path::new("/tmp/proj"));
    assert!(!rule.is_active());
}

#[test]
fn test_inactive_rule_allows_everything() {
    let rule = SystemPathsRule::new(false, false, Path::new("/tmp/proj"), Path::new("/tmp/proj"));
    assert!(rule.check(Path::new("/")).is_none());
    assert!(rule.check(Path::new("/etc/passwd")).is_none());
    assert!(rule.check(Path::new("/usr/bin/env")).is_none());
}
