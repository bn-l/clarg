//! Escape-hatch tests: when a project lives under a listed system
//! directory (e.g. `/var/www/site`), `no_system_dirs` must NOT
//! block in-project paths. This includes the symlink-alias case on
//! macOS where `/var` really resolves to `/private/var` after
//! canonicalization — the rule stores both the raw and canonical
//! roots and checks against either.

use clarg::system_paths::SystemPathsRule;
use std::path::Path;

#[test]
fn test_no_system_dirs_allows_paths_inside_project_root_when_project_is_under_system_dir() {
    // Project at /var/www/site. raw == canonical (no symlink).
    let r = SystemPathsRule::new(
        false,
        true,
        Path::new("/var/www/site"),
        Path::new("/var/www/site"),
    );
    // In-project path: escape hatch fires, allowed.
    assert!(r.check(Path::new("/var/www/site/src/main.rs")).is_none());
    assert!(r.check(Path::new("/var/www/site")).is_none());
}

#[test]
fn test_no_system_dirs_blocks_sibling_outside_project_even_under_same_system_prefix() {
    // Project /var/www/site — but /var/www/other is a different tree.
    let r = SystemPathsRule::new(
        false,
        true,
        Path::new("/var/www/site"),
        Path::new("/var/www/site"),
    );
    assert!(r.check(Path::new("/var/www/other/file")).is_some());
    assert!(r.check(Path::new("/var/log/syslog")).is_some());
    // And the system dir itself (parent of project) is still blocked.
    assert!(r.check(Path::new("/var")).is_some());
}

#[cfg(unix)]
#[test]
fn test_project_root_escape_hatch_handles_canonical_vs_alias_paths() {
    // Simulate macOS-style symlink alias: `/var` -> `/private/var`.
    // Project's raw root `/var/www/site` canonicalizes to
    // `/private/var/www/site`. Tools may reference either form; both
    // must escape the `no_system_dirs` check for in-project targets,
    // and `/var/log` (outside project, under /var) must still block.
    let raw = Path::new("/var/www/site");
    let canonical = Path::new("/private/var/www/site");
    let r = SystemPathsRule::new(false, true, raw, canonical);

    // Path expressed via the raw (alias) root — escape hatch via raw_root.
    assert!(
        r.check(Path::new("/var/www/site/src/main.rs")).is_none(),
        "alias-form path inside project should be allowed"
    );
    // Path expressed via the canonical root — escape hatch via canonical_root.
    assert!(
        r.check(Path::new("/private/var/www/site/src/main.rs")).is_none(),
        "canonical-form path inside project should be allowed"
    );
    // Outside the project but still under a system dir: blocked.
    assert!(
        r.check(Path::new("/var/log/syslog")).is_some(),
        "out-of-project /var/log should still block"
    );
    assert!(
        r.check(Path::new("/private/etc/hosts")).is_some(),
        "out-of-project /private/etc should still block"
    );
}

#[test]
fn test_no_root_escape_hatch_does_not_apply() {
    // no_root should fire on bare `/` regardless of project location.
    let r = SystemPathsRule::new(
        true,
        false,
        Path::new("/var/www/site"),
        Path::new("/var/www/site"),
    );
    assert!(r.check(Path::new("/")).is_some());
}
