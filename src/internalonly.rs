use std::path::{Component, Path, PathBuf};

/// Resolve the project root by canonicalizing it (it must exist).
pub fn resolve_project_root(root: &Path) -> std::io::Result<PathBuf> {
    root.canonicalize()
}

/// Normalize a path logically (resolve `.` and `..`) without filesystem access.
/// This is needed for paths that may not exist yet (e.g., Write targets).
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {} // skip `.`
            Component::ParentDir => {
                // Pop only if we have a normal component to pop
                if matches!(components.last(), Some(Component::Normal(_))) {
                    components.pop();
                } else if matches!(
                    components.last(),
                    Some(Component::RootDir) | Some(Component::Prefix(_))
                ) {
                    // At root, `..` stays at root (no-op)
                } else {
                    components.push(component);
                }
            }
            _ => components.push(component),
        }
    }
    if components.is_empty() {
        PathBuf::from(".")
    } else {
        components.iter().collect()
    }
}

/// Expand `~`, `~user`, and `$HOME` in a path string to an absolute path.
///
/// For the `~user` form, we cannot look up the real password database
/// without an OS-specific dependency, so we fall back to platform
/// defaults (`/root` or `/var/root` for `~root`; `/home/<user>` or
/// `/Users/<user>` otherwise). This is intentionally close to what bash
/// itself will resolve at runtime, which is what lets safety rules
/// like `no_system_dirs` correctly block `cat ~root/.bashrc`.
///
/// Bash also reserves special tilde-prefixes — `~+` (=`$PWD`), `~-`
/// (=`$OLDPWD`), and `~[+-]?N` (dirstack refs). Those are NOT login
/// names, so we leave them as literal. Downstream resolution joins
/// them against `project_root`, which is a sound approximation: `~+`
/// in normal use IS the project root, and the dirstack forms are
/// unpredictable but treating them as project-relative avoids false
/// "synthetic home `/Users/+`" denials for valid in-project usage.
pub fn expand_home(path_str: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    if path_str == "~" {
        return PathBuf::from(&home);
    }
    if let Some(rest) = path_str.strip_prefix("~/") {
        return PathBuf::from(format!("{home}/{rest}"));
    }
    if path_str == "$HOME" {
        return PathBuf::from(&home);
    }
    if let Some(rest) = path_str.strip_prefix("$HOME/") {
        return PathBuf::from(format!("{home}/{rest}"));
    }
    // `~<tilde-prefix>` form. Only apply the `~user` fallback when the
    // prefix syntactically looks like a POSIX login name; bash's special
    // forms (`~+`, `~-`, `~N`, `~+N`, `~-N`) fall through as literal.
    if let Some(tail) = path_str.strip_prefix('~') {
        let (user, rest) = match tail.find('/') {
            Some(i) => (&tail[..i], &tail[i..]),
            None => (tail, ""),
        };
        if is_valid_login_name(user) {
            return PathBuf::from(format!("{}{rest}", tilde_user_home(user)));
        }
    }
    PathBuf::from(path_str)
}

/// Is `s` syntactically a POSIX login name? Matches `[A-Za-z_][A-Za-z0-9_.-]*`.
///
/// This is how bash identifies a tilde-prefix as a user home lookup vs.
/// one of its special forms. It rejects empty strings, `+`/`-` (bash's
/// `~+`/`~-`), all-digit strings (`~N`), and anything with weird
/// characters.
pub(crate) fn is_valid_login_name(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Platform-standard home directory for the `~user` form.
///
/// Root lands in a directory inside `SYSTEM_DIRS` on every major Unix,
/// so `no_system_dirs` will catch `~root/...` via the usual path check.
/// Non-root users land in `/home/<user>` (Linux) or `/Users/<user>`
/// (macOS), which are outside any project root so `internal_access_only`
/// will catch them — but note these user-data directories are not in
/// `SYSTEM_DIRS` by design, so `no_system_dirs` alone does NOT block
/// `~alice/...`. That matches the intent of `no_system_dirs`: it guards
/// OS-level infrastructure, not other users' files.
#[cfg(target_os = "macos")]
pub(crate) fn tilde_user_home(user: &str) -> String {
    if user == "root" {
        "/var/root".to_string()
    } else {
        format!("/Users/{user}")
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn tilde_user_home(user: &str) -> String {
    if user == "root" {
        "/root".to_string()
    } else {
        format!("/home/{user}")
    }
}

/// Resolve a target path relative to the project root if it's relative,
/// expanding `~` and `$HOME`, and normalizing the result.
pub fn resolve_target(path_str: &str, project_root: &Path) -> PathBuf {
    let expanded = expand_home(path_str);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        project_root.join(expanded)
    };
    let result = normalize_path(&absolute);
    log::debug!("resolve_target: '{}' -> '{}'", path_str, result.display());
    result
}

/// Resolve a target path WITHOUT applying `~`/`$HOME` expansion.
///
/// Used for path references whose upstream parser has already
/// bash-expanded tilde/$HOME based on the source-level quote context
/// (see `bash_analyzer::find_redirections`). Re-running `expand_home`
/// here would double-expand quoted literals like `'~/foo'` — which
/// bash treats as literal relative filenames, not home-expanded paths.
pub fn resolve_literal_target(path_str: &str, project_root: &Path) -> PathBuf {
    let pb = PathBuf::from(path_str);
    let absolute = if pb.is_absolute() {
        pb
    } else {
        project_root.join(pb)
    };
    let result = normalize_path(&absolute);
    log::debug!(
        "resolve_literal_target: '{}' -> '{}'",
        path_str,
        result.display()
    );
    result
}

/// Check if a resolved path is inside the project root.
/// Returns Some(reason) if it's outside, None if it's inside.
pub fn check_path_containment(
    target: &Path,
    project_root: &Path,
    context: &str,
) -> Option<String> {
    if target.starts_with(project_root) {
        log::debug!(
            "containment: '{}' is inside root '{}'",
            target.display(),
            project_root.display()
        );
        None
    } else {
        log::debug!(
            "containment: '{}' is OUTSIDE root '{}'",
            target.display(),
            project_root.display()
        );
        Some(format!(
            "Blocked by `clarg`: {} '{}' is outside the project directory '{}'",
            context,
            target.display(),
            project_root.display()
        ))
    }
}
