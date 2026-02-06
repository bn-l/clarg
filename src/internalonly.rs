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

/// Expand `~` and `$HOME` in a path string to the actual home directory.
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
    PathBuf::from(path_str)
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
    normalize_path(&absolute)
}

/// Check if a resolved path is inside the project root.
/// Returns Some(reason) if it's outside, None if it's inside.
pub fn check_path_containment(
    target: &Path,
    project_root: &Path,
    context: &str,
) -> Option<String> {
    if target.starts_with(project_root) {
        None
    } else {
        Some(format!(
            "Blocked by `clarg`: {} '{}' is outside the project directory '{}'",
            context,
            target.display(),
            project_root.display()
        ))
    }
}
