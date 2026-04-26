use std::path::{Component, Path, PathBuf};

/// Curated list of OS-level system directories that should never be
/// modified via clarg when `no_system_dirs` is enabled. Unified for
/// Linux and macOS. Intentional exclusions with rationale:
///   - `/` is handled by `no_root`
///   - `/home`, `/Users` are user data (covered by `internal_access_only`)
///   - `/tmp` is a common scratch space; blocking breaks normal workflows
///   - `/opt` hosts third-party installs (e.g. Homebrew) and sometimes projects
///   - `/dev` hosts legitimate I/O targets like `/dev/null`
///   - `/run`, `/mnt`, `/media` are edge-case user-mounted trees
pub const SYSTEM_DIRS: &[&str] = &[
    "/bin",
    "/boot",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/proc",
    "/root",
    "/sbin",
    "/srv",
    "/sys",
    "/usr",
    "/var",
    "/System",
    "/Library",
    "/private",
    "/Applications",
    "/cores",
    "/Network",
];

/// Exceptions carved out of `SYSTEM_DIRS`: paths that would otherwise
/// match a listed prefix but are allowed through.
///
/// * `/private/tmp` — on macOS, `/tmp` is a symlink to `/private/tmp`, so
///   canonicalized or explicitly-written paths land here. `/tmp` itself
///   is intentionally excluded from `SYSTEM_DIRS`, so allowing
///   `/private/tmp` preserves that intent.
/// * `/usr/bin/log` — macOS unified logging CLI; commonly invoked for
///   diagnostics and considered safe under `no_system_dirs`.
pub const SYSTEM_DIRS_EXCEPTIONS: &[&str] = &["/private/tmp", "/usr/bin/log"];

/// Rule for `no_root` and `no_system_dirs` special flags.
///
/// * `no_root` — blocks any path that resolves (lexically, via
///   `normalize_path`) to the filesystem root `/`, or to a glob-only
///   child of root (e.g. `/*`, `/**`, `/?`, `/[abc]`).
/// * `no_system_dirs` — blocks any path that is equal to or a
///   descendant of one of the curated `SYSTEM_DIRS` entries, unless
///   the path lies inside the project root (escape hatch).
pub struct SystemPathsRule {
    no_root: bool,
    no_system_dirs: bool,
    /// Raw (pre-canonicalization) project root, for the escape-hatch
    /// check when targets reference the project via a symlink alias.
    raw_root: PathBuf,
    /// Canonicalized project root.
    canonical_root: PathBuf,
}

impl SystemPathsRule {
    pub fn new(
        no_root: bool,
        no_system_dirs: bool,
        raw_root: &Path,
        canonical_root: &Path,
    ) -> Self {
        Self {
            no_root,
            no_system_dirs,
            raw_root: raw_root.to_path_buf(),
            canonical_root: canonical_root.to_path_buf(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.no_root || self.no_system_dirs
    }

    /// Check a resolved (lexically normalized, absolute) path.
    /// Returns `Some(reason)` if blocked; `None` if allowed.
    pub fn check(&self, resolved: &Path) -> Option<String> {
        if self.no_root {
            if let Some(reason) = self.check_no_root(resolved) {
                return Some(reason);
            }
        }
        if self.no_system_dirs {
            // Escape hatch: paths inside the project root are always
            // allowed by this rule, even if the project itself lives
            // under a listed system prefix (e.g. `/var/www/site`).
            if self.is_inside_project(resolved) {
                log::debug!(
                    "system_paths: '{}' is inside project root, skipping no_system_dirs",
                    resolved.display()
                );
            } else if let Some(reason) = check_no_system_dirs(resolved) {
                return Some(reason);
            }
        }
        None
    }

    fn check_no_root(&self, resolved: &Path) -> Option<String> {
        let comps: Vec<Component> = resolved.components().collect();

        // Exactly `/`
        if comps.len() == 1 && matches!(comps[0], Component::RootDir) {
            return Some(format!(
                "Blocked by `clarg`: 'no_root' flag prevents targeting filesystem root '/' (resolved path: '{}')",
                resolved.display()
            ));
        }

        // `/<segment-with-glob-metachar>` — e.g. /*, /**, /?, /[abc], /foo*
        // Anything matching this shape iterates root's direct children.
        if comps.len() == 2 && matches!(comps[0], Component::RootDir) {
            if let Component::Normal(os) = &comps[1] {
                let s = os.to_string_lossy();
                if contains_glob_meta(&s) {
                    return Some(format!(
                        "Blocked by `clarg`: 'no_root' flag prevents targeting filesystem root '/' via glob (resolved path: '{}')",
                        resolved.display()
                    ));
                }
            }
        }
        None
    }

    fn is_inside_project(&self, resolved: &Path) -> bool {
        resolved.starts_with(&self.canonical_root) || resolved.starts_with(&self.raw_root)
    }
}

fn check_no_system_dirs(resolved: &Path) -> Option<String> {
    // Allow-list: exceptions win over any matching SYSTEM_DIRS prefix.
    for exc in SYSTEM_DIRS_EXCEPTIONS {
        let exc_path = Path::new(exc);
        if resolved == exc_path || resolved.starts_with(exc_path) {
            return None;
        }
    }
    for dir in SYSTEM_DIRS {
        let dir_path = Path::new(dir);
        // `starts_with` on `Path` is component-wise, so `/usr2/bin`
        // does NOT start with `/usr` (it would if we did string
        // `str::starts_with`). This naturally avoids lookalike bugs.
        if resolved == dir_path || resolved.starts_with(dir_path) {
            return Some(format!(
                "Blocked by `clarg`: 'no_system_dirs' flag prevents access to system directory '{}' via path '{}'",
                dir,
                resolved.display()
            ));
        }
    }
    None
}

/// True iff `s` contains at least one shell glob metacharacter.
/// Used to detect root-iterating globs like `/*`, `/[abc]`, `/foo*`.
fn contains_glob_meta(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '*' | '?' | '['))
}
