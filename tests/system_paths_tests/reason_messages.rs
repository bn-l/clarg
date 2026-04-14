//! Confirms deny messages identify the flag and the target path so
//! the LLM can self-correct.

use clarg::system_paths::SystemPathsRule;
use std::path::Path;

#[test]
fn test_no_root_reason_is_specific() {
    let r = SystemPathsRule::new(true, false, Path::new("/tmp/p"), Path::new("/tmp/p"));
    let reason = r.check(Path::new("/")).expect("should block");
    assert!(
        reason.contains("no_root"),
        "expected flag name in reason: {}",
        reason
    );
    assert!(
        reason.contains("/"),
        "expected target path in reason: {}",
        reason
    );
}

#[test]
fn test_no_root_glob_reason_mentions_glob() {
    let r = SystemPathsRule::new(true, false, Path::new("/tmp/p"), Path::new("/tmp/p"));
    let reason = r.check(Path::new("/*")).expect("should block");
    assert!(reason.contains("no_root"), "got: {}", reason);
}

#[test]
fn test_no_system_dirs_reason_includes_matched_system_dir_and_path() {
    let r = SystemPathsRule::new(false, true, Path::new("/tmp/p"), Path::new("/tmp/p"));
    let reason = r.check(Path::new("/etc/passwd")).expect("should block");
    assert!(
        reason.contains("no_system_dirs"),
        "expected flag name in reason: {}",
        reason
    );
    assert!(
        reason.contains("/etc"),
        "expected matched system dir in reason: {}",
        reason
    );
    assert!(
        reason.contains("/etc/passwd"),
        "expected full target path in reason: {}",
        reason
    );
}
