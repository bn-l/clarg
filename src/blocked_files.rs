use eyre::{Result, WrapErr};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::{Path, PathBuf};

pub struct BlockedFilesRule {
    matcher: Gitignore,
    root: PathBuf,
}

impl BlockedFilesRule {
    pub fn new(patterns: &[String], project_root: &Path) -> Result<Self> {
        let mut builder = GitignoreBuilder::new(project_root);
        for pattern in patterns {
            log::debug!("blocked_files: adding pattern '{}'", pattern);
            builder
                .add_line(None, pattern)
                .wrap_err_with(|| format!("invalid gitignore pattern: {pattern}"))?;
        }
        let matcher = builder
            .build()
            .wrap_err("failed to build gitignore matcher")?;
        Ok(Self {
            matcher,
            root: project_root.to_path_buf(),
        })
    }

    /// Check if a path is blocked. Returns Some(reason) if blocked, None if allowed.
    pub fn check(&self, path: &Path) -> Option<String> {
        // matched_path_or_any_parents panics if the path is not under the root
        // (ignore crate assertion in gitignore.rs). Paths outside the project
        // root cannot match project-relative blocked patterns, so skip them.
        if !path.starts_with(&self.root) {
            log::debug!(
                "blocked_files: '{}' outside project root, skipping",
                path.display(),
            );
            return None;
        }
        let is_dir = path.to_str().is_some_and(|s| s.ends_with('/'));
        let matched = self.matcher.matched_path_or_any_parents(path, is_dir);
        if matched.is_ignore() {
            let pattern_str = matched
                .inner()
                .map(|g| g.original().to_string())
                .unwrap_or_else(|| "<unknown pattern>".to_string());
            log::info!(
                "blocked_files: '{}' matched pattern '{}'",
                path.display(),
                pattern_str
            );
            Some(format!(
                "Blocked by `clarg`: access to '{}' is forbidden because it matched the pattern '{}'",
                path.display(),
                pattern_str
            ))
        } else {
            log::debug!("blocked_files: '{}' not matched", path.display());
            None
        }
    }
}
