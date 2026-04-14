use bstr::{BStr, ByteSlice};
use eyre::{Result, eyre};
use gix_ignore::Search;
use gix_ignore::glob::pattern::Case;
use gix_ignore::search::{Ignore, Match};
use std::path::{Path, PathBuf};

use crate::internalonly::expand_home;

/// Gitignore-pattern file access blocker backed by `gix-ignore`.
///
/// Two pattern groups are kept:
///
/// * `project_search` — patterns are matched against paths expressed
///   *relative to the project root* whenever the target lives inside
///   that root, preserving classic gitignore semantics: `/foo` anchors
///   at the project root, unanchored `.env` matches by basename at any
///   depth, and so on. For targets that live *outside* the project
///   root, the same patterns are also tested against the path's
///   absolute form (with the leading `/` stripped). That fallback lets
///   bare patterns like `/etc/shadow` actually block `/etc/shadow`,
///   and lets unanchored basename patterns like `.env` keep blocking
///   `.env` files wherever clarg sees a tool target.
/// * `absolute_search` — patterns that start with `~`, `~/`, `$HOME`,
///   or `$HOME/` are home-expanded at construction time and parsed as
///   anchored absolute patterns. They are matched against the
///   absolute-form bytes of the target path so they can block paths
///   anywhere on the filesystem (e.g. `~/.ssh/id_rsa`,
///   `~/.aws/credentials`).
pub struct BlockedFilesRule {
    root: PathBuf,
    project_search: Search,
    absolute_search: Search,
}

impl BlockedFilesRule {
    pub fn new(patterns: &[String], project_root: &Path) -> Result<Self> {
        // Fail-closed: if any pattern needs home expansion but `HOME`
        // is missing or empty, refuse construction. Otherwise we'd
        // silently install a no-op (or wildly wrong) rule, which
        // contradicts the rest of clarg's fail-closed posture.
        if let Some(first_home) = patterns.iter().find(|p| is_home_prefixed(p)) {
            let home = std::env::var("HOME").unwrap_or_default();
            if home.is_empty() {
                return Err(eyre!(
                    "blocked_files: pattern '{}' references the home directory \
                     (`~`/`$HOME`) but the HOME environment variable is unset \
                     or empty; refusing to install a silently-broken rule",
                    first_home
                ));
            }
        }

        let mut project_patterns: Vec<String> = Vec::new();
        let mut absolute_patterns: Vec<String> = Vec::new();

        for raw in patterns {
            if is_home_prefixed(raw) {
                let expanded = expand_home(raw);
                let as_str = expanded.to_string_lossy().into_owned();
                log::debug!(
                    "blocked_files: absolute pattern '{}' -> '{}'",
                    raw,
                    as_str
                );
                absolute_patterns.push(as_str);
            } else {
                log::debug!("blocked_files: project pattern '{}'", raw);
                project_patterns.push(raw.clone());
            }
        }

        let project_search = Search::from_overrides(project_patterns, Ignore::default());
        let absolute_search = Search::from_overrides(absolute_patterns, Ignore::default());

        Ok(Self {
            root: project_root.to_path_buf(),
            project_search,
            absolute_search,
        })
    }

    /// Check if a path is blocked. Returns `Some(reason)` if blocked,
    /// `None` if allowed.
    ///
    /// No directory hint is provided; the rule will opportunistically
    /// probe the filesystem to decide whether directory-only patterns
    /// (e.g. `secrets/`) should match the leaf.
    pub fn check(&self, path: &Path) -> Option<String> {
        self.check_with_hint(path, None)
    }

    /// Check with an explicit directory hint.
    ///
    /// `is_dir_hint = Some(true)` tells the matcher the caller already
    /// knows the target is a directory (e.g. `cd <X>`, `mkdir <X>`).
    /// `is_dir_hint = None` falls back to a filesystem `is_dir()` probe
    /// so that existing directories still trip `secrets/`-style patterns.
    /// Directory-only gitignore semantics are preserved: a file named
    /// `secrets` will NOT match `secrets/` even with the hint set to
    /// `Some(false)`.
    pub fn check_with_hint(&self, path: &Path, is_dir_hint: Option<bool>) -> Option<String> {
        let path_display = path.display().to_string();
        let bytes = path.as_os_str().as_encoded_bytes();

        // Absolute-form bytes: strip the leading `/` so the Search — which
        // has an implicit root — sees a "relative" path it can match.
        let abs_form: &[u8] = if bytes.first() == Some(&b'/') {
            &bytes[1..]
        } else {
            bytes
        };

        // Resolve the effective directory hint: caller's hint wins;
        // otherwise probe the filesystem (returns false for
        // non-existent paths, which is the safe default).
        let effective_hint: Option<bool> = is_dir_hint.or_else(|| {
            if path.is_dir() { Some(true) } else { None }
        });

        // 1. Absolute search (~/$HOME-prefixed patterns) against the
        //    absolute-form bytes — works for any path on the filesystem.
        if let Some(reason) =
            match_search(&self.absolute_search, abs_form, &path_display, effective_hint)
        {
            return Some(reason);
        }

        // 2. Project search. For targets under the project root we use
        //    the project-relative bytes, preserving classic gitignore
        //    anchoring (`/foo` => `<project>/foo`). For targets outside
        //    the project root we fall back to the absolute-form bytes
        //    so bare absolute patterns (`/etc/shadow`) and unanchored
        //    basename patterns (`.env`) still fire — fail-closed.
        let project_bytes: &[u8] = if path.is_absolute() {
            match path.strip_prefix(&self.root) {
                Ok(rel) => rel.as_os_str().as_encoded_bytes(),
                Err(_) => abs_form,
            }
        } else {
            bytes
        };
        if let Some(reason) =
            match_search(&self.project_search, project_bytes, &path_display, effective_hint)
        {
            return Some(reason);
        }

        log::debug!("blocked_files: '{}' not matched", path_display);
        None
    }
}

/// Does this raw pattern reference the user's home directory? Only these
/// forms are treated as absolute; bare `$HOMEFOO` or similar are left alone.
fn is_home_prefixed(raw: &str) -> bool {
    raw == "~"
        || raw.starts_with("~/")
        || raw == "$HOME"
        || raw.starts_with("$HOME/")
}

/// Match `path_bytes` against `search`, walking parent directories upward
/// to emulate the `ignore` crate's `matched_path_or_any_parents`. Returns
/// the formatted reason string on the first non-negated match.
///
/// `leaf_is_dir` is forwarded to the leaf `try_match` so directory-only
/// patterns (e.g. `secrets/`) can fire when the caller knows — or a
/// filesystem probe confirmed — that the leaf is itself a directory.
fn match_search(
    search: &Search,
    path_bytes: &[u8],
    path_display: &str,
    leaf_is_dir: Option<bool>,
) -> Option<String> {
    if path_bytes.is_empty() {
        return None;
    }
    // Test the full path first, honouring the leaf dir hint.
    if let Some(reason) = try_match(search, path_bytes, leaf_is_dir, path_display) {
        return Some(reason);
    }
    // Walk parents as directories.
    let mut cur = path_bytes;
    while let Some(pos) = cur.rfind(b"/") {
        cur = &cur[..pos];
        if cur.is_empty() {
            break;
        }
        if let Some(reason) = try_match(search, cur, Some(true), path_display) {
            return Some(reason);
        }
    }
    None
}

fn try_match(
    search: &Search,
    path_bytes: &[u8],
    is_dir: Option<bool>,
    path_display: &str,
) -> Option<String> {
    let bs = BStr::new(path_bytes);
    let m: Match<'_> = search.pattern_matching_relative_path(bs, is_dir, Case::Sensitive)?;
    if m.pattern.is_negative() {
        log::debug!(
            "blocked_files: '{}' matched negation pattern '{}', allowing",
            path_display,
            m.pattern
        );
        return None;
    }
    let pattern_str = format!("{}", m.pattern);
    log::info!(
        "blocked_files: '{}' matched pattern '{}'",
        path_display,
        pattern_str
    );
    Some(format!(
        "Blocked by `clarg`: access to '{}' is forbidden because it matched the pattern '{}'",
        path_display, pattern_str
    ))
}
