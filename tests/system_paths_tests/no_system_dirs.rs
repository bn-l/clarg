//! Pure-rule tests for `no_system_dirs`. Hardcodes representative
//! blocked / allowed paths rather than deriving them from the
//! production `SYSTEM_DIRS` constant — so implementation and tests
//! can't share the same bug.

use clarg::system_paths::SystemPathsRule;
use std::path::Path;

fn rule() -> SystemPathsRule {
    // Project root deliberately does NOT shadow any system dir, so the
    // escape hatch is a no-op for these cases.
    SystemPathsRule::new(false, true, Path::new("/tmp/proj"), Path::new("/tmp/proj"))
}

#[test]
fn test_no_system_dirs_blocks_exact_system_dirs() {
    let r = rule();
    for path in &[
        "/etc",
        "/usr",
        "/var",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/boot",
        "/proc",
        "/sys",
        "/root",
        "/srv",
        "/System",
        "/Library",
        "/private",
        "/Applications",
        "/cores",
        "/Network",
    ] {
        assert!(
            r.check(Path::new(path)).is_some(),
            "expected system dir '{}' to be blocked",
            path
        );
    }
}

#[test]
fn test_no_system_dirs_blocks_descendants_of_system_dirs() {
    let r = rule();
    for path in &[
        "/etc/passwd",
        "/etc/hosts",
        "/usr/bin/env",
        "/usr/local/bin/something",
        "/var/log/syslog",
        "/var/www/html",
        "/System/Library/Fonts",
        "/Library/Preferences/com.apple.Finder.plist",
        "/private/etc/hosts",
        "/Applications/Chrome.app/Contents",
        "/boot/vmlinuz",
        "/proc/1/cmdline",
        "/sys/class/net",
        "/root/.bashrc",
    ] {
        assert!(
            r.check(Path::new(path)).is_some(),
            "expected descendant '{}' to be blocked",
            path
        );
    }
}

#[test]
fn test_no_system_dirs_does_not_block_prefix_lookalikes() {
    let r = rule();
    // These superficially share a string prefix with listed dirs but
    // are distinct components — component-wise starts_with must NOT match.
    for path in &[
        "/usr2/bin",
        "/etcetera/file",
        "/varnish/cache",
        "/Systematic",
        "/LibraryX",
        "/privateer",
        "/rooted/file",
        "/bindings/x",
        "/booted",
        "/srv2",
    ] {
        assert!(
            r.check(Path::new(path)).is_none(),
            "expected lookalike '{}' to NOT be blocked",
            path
        );
    }
}

#[test]
fn test_no_system_dirs_does_not_block_excluded_dirs() {
    let r = rule();
    // Intentionally excluded from the curated list.
    for path in &[
        "/tmp/x",
        "/tmp",
        "/opt/homebrew/bin/bash",
        "/opt/third-party",
        "/Users/me/file",
        "/Users",
        "/home/me/file",
        "/home",
        "/dev/null",
        "/dev/urandom",
        "/run/user/1000",
        "/mnt/data",
        "/media/usb",
    ] {
        assert!(
            r.check(Path::new(path)).is_none(),
            "expected excluded path '{}' to NOT be blocked",
            path
        );
    }
}

#[test]
fn test_no_system_dirs_allows_private_tmp_exception() {
    // /private/tmp (and descendants) is an explicit exception — /tmp
    // is a symlink to /private/tmp on macOS and must work.
    let r = rule();
    for path in &[
        "/private/tmp",
        "/private/tmp/",
        "/private/tmp/scratch.txt",
        "/private/tmp/nested/dir/file",
    ] {
        assert!(
            r.check(Path::new(path)).is_none(),
            "expected /private/tmp exception '{}' to NOT be blocked",
            path
        );
    }
    // Sibling children of /private must still block.
    for path in &["/private", "/private/etc/hosts", "/private/var/log/x"] {
        assert!(
            r.check(Path::new(path)).is_some(),
            "expected non-tmp /private path '{}' to still be blocked",
            path
        );
    }
}

#[test]
fn test_no_system_dirs_allows_var_temp_exceptions() {
    // macOS `$TMPDIR` lives under /var/folders (canonically
    // /private/var/folders), and /var/tmp is the persistent temp dir.
    // Both spellings must work since targets are only lexically normalized.
    let r = rule();
    for path in &[
        "/var/folders",
        "/var/folders/66/bbm03j656rz04vx9k1r095400000gn/T/tmp.abc123",
        "/private/var/folders",
        "/private/var/folders/66/bbm03j656rz04vx9k1r095400000gn/T/foo.txt",
        "/var/tmp",
        "/var/tmp/scratch.txt",
        "/private/var/tmp",
        "/private/var/tmp/nested/dir/file",
    ] {
        assert!(
            r.check(Path::new(path)).is_none(),
            "expected temp exception '{}' to NOT be blocked",
            path
        );
    }
    // Siblings under /var and /private/var must still block, as must
    // lookalikes that share a string prefix (component-wise starts_with).
    for path in &[
        "/var",
        "/var/log/system.log",
        "/var/db/x",
        "/private/var",
        "/private/var/log/x",
        "/var/tmpfoo",
        "/var/folders2/x",
        "/private/var/tmp2",
    ] {
        assert!(
            r.check(Path::new(path)).is_some(),
            "expected non-temp /var path '{}' to still be blocked",
            path
        );
    }
}

#[test]
fn test_no_system_dirs_temp_exception_does_not_survive_dotdot_escape() {
    // Paths are normalized before the check, so `..` climbing out of an
    // exempt temp dir lands on the real (blocked) target.
    let r = rule();
    for path in &[
        "/var/tmp/../log/system.log",
        "/private/var/folders/../db/x",
    ] {
        let normalized = clarg::internalonly::normalize_path(Path::new(path));
        assert!(
            r.check(&normalized).is_some(),
            "expected '{}' (normalized '{}') to be blocked",
            path,
            normalized.display()
        );
    }
}

#[test]
fn test_no_system_dirs_allows_usr_bin_log_exception() {
    // /usr/bin/log (macOS unified logging CLI) is an explicit exception.
    let r = rule();
    assert!(
        r.check(Path::new("/usr/bin/log")).is_none(),
        "expected /usr/bin/log to NOT be blocked"
    );
    // Lookalikes that share a string prefix but differ in the final
    // component must still block (component-wise starts_with).
    for path in &["/usr/bin/login", "/usr/bin/logger"] {
        assert!(
            r.check(Path::new(path)).is_some(),
            "expected lookalike '{}' to still be blocked",
            path
        );
    }
}

#[test]
fn test_no_system_dirs_with_no_root_flag_blocks_root_too() {
    // Combined rule: bare `/` is caught by no_root, /etc by no_system_dirs.
    let r = SystemPathsRule::new(
        true,
        true,
        Path::new("/tmp/proj"),
        Path::new("/tmp/proj"),
    );
    assert!(r.check(Path::new("/")).is_some());
    assert!(r.check(Path::new("/etc/passwd")).is_some());
    assert!(r.check(Path::new("/tmp/scratch")).is_none());
}
