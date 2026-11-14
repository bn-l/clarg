//! `no_broad_search`: keep the names in your home folder private.
//!
//! Nothing may search, list or glob-enumerate `$HOME` or anything above it
//! (`/Users`, `/`). Subfolders (`~/projects`, `~/.config`) and specific
//! known paths (`cat ~/.zshrc`) stay allowed.

use crate::bash_analyzer::{ExtractedPath, PathContext};
use eyre::{Result, bail};
use crate::system_paths::contains_glob_meta;
use std::path::{Component, Path, PathBuf};

pub struct BroadSearchRule {
    /// `$HOME`, plus its canonical form when that differs.
    homes: Vec<PathBuf>,
}

impl BroadSearchRule {
    /// Fails when `$HOME` is unset or empty: the folder to protect would be
    /// unknown, and a silently disabled rule would fail open.
    pub fn new() -> Result<Self> {
        let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) else {
            bail!(
                "no_broad_search: the HOME environment variable is unset or empty, so \
                 the home folder to protect is unknown; refusing to install a \
                 silently-broken rule"
            );
        };
        let home = PathBuf::from(home);
        let mut homes = vec![home.clone()];
        if let Ok(canonical) = home.canonicalize()
            && canonical != home
        {
            homes.push(canonical);
        }
        Ok(Self { homes })
    }

    /// Is `path` the home folder or an ancestor of it (`/Users`, `/`)?
    pub fn is_home_or_above(&self, path: &Path) -> bool {
        self.homes.iter().any(|home| home.starts_with(path))
    }

    /// Check one extracted Bash path (already resolved).
    pub fn check(&self, ep: &ExtractedPath, resolved: &Path) -> Option<String> {
        // `ls ~/*`, `echo ~/*`, `du -sh ~/.c*`: the shell itself lists the
        // folder the first wildcard component sits in.
        if ep.unquoted_glob
            && let Some(parent) = glob_parent(resolved)
            && self.is_home_or_above(&parent)
        {
            return Some(format!(
                "Blocked by `clarg`: 'no_broad_search' prevents expanding '{}', which would list the contents of '{}' ({}). Name the files you need, or glob inside a specific subfolder.",
                ep.raw,
                self.display(&parent),
                self.describe(&parent)
            ));
        }
        match &ep.context {
            PathContext::SearchRoot { command } => self.check_root(command, resolved),
            PathContext::InlineCodeRef { interpreter, .. } if self.is_home_or_above(resolved) => {
                Some(format!(
                    "Blocked by `clarg`: 'no_broad_search' prevents '{}' code from using '{}' ({}). Use a specific subfolder instead.",
                    interpreter,
                    self.display(resolved),
                    self.describe(resolved)
                ))
            }
            _ => None,
        }
    }

    /// Check the root a search or listing walks (`command` names the tool).
    pub fn check_root(&self, command: &str, resolved: &Path) -> Option<String> {
        self.is_home_or_above(resolved).then(|| {
            format!(
                "Blocked by `clarg`: 'no_broad_search' prevents '{}' from searching or listing '{}' ({}). Use the project or a specific subfolder instead (e.g. `~/projects/<name>`). To find a file by name, `mdfind -name <name>` searches the Spotlight index.",
                command,
                self.display(resolved),
                self.describe(resolved)
            )
        })
    }

    /// Messages are read by the agent, so they name the *user's* folder.
    fn describe(&self, path: &Path) -> &'static str {
        if self.homes.iter().any(|h| h == path) {
            "the user's home folder"
        } else {
            "a folder above the user's home folder"
        }
    }

    fn display(&self, path: &Path) -> String {
        if self.homes.iter().any(|h| h == path) {
            "~".to_string()
        } else {
            path.display().to_string()
        }
    }
}

/// The folder a glob enumerates: everything before the first component
/// that contains a glob character (`/Users/bml` for `/Users/bml/*/src`).
fn glob_parent(resolved: &Path) -> Option<PathBuf> {
    let mut parent = PathBuf::new();
    for component in resolved.components() {
        if let Component::Normal(name) = component
            && contains_glob_meta(&name.to_string_lossy())
        {
            return Some(parent);
        }
        parent.push(component);
    }
    None
}

/// The folder Claude Code's `Glob` tool walks: its `path` (or the current
/// directory) joined with the literal start of `pattern`, up to the first
/// component with a wildcard. An absolute or `~` pattern stands alone.
/// `path: ~` + `pattern: .config/**/*.toml` → `~/.config`.
pub fn glob_tool_root(path: Option<&str>, pattern: Option<&str>) -> String {
    let literal: Vec<&str> = pattern
        .unwrap_or("")
        .split('/')
        .take_while(|c| !c.contains(['*', '?', '[', '{']))
        .collect();
    let prefix = literal.join("/");
    if prefix.starts_with('/') || prefix.starts_with('~') || (prefix.is_empty() && pattern.is_some_and(|p| p.starts_with('/'))) {
        return if prefix.is_empty() { "/".to_string() } else { prefix };
    }
    let base = path.unwrap_or(".");
    if prefix.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base.trim_end_matches('/'), prefix)
    }
}
