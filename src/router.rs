use eyre::Result;
use std::path::Path;

use crate::bash_analyzer;
use crate::blocked_commands::BlockedCommandsRule;
use crate::blocked_files::BlockedFilesRule;
use crate::config::Config;
use crate::hook_input::HookInput;
use crate::internalonly::{check_path_containment, resolve_project_root, resolve_target};

#[derive(Debug)]
pub enum Verdict {
    Allow,
    Deny(String),
}

pub struct RuleSet {
    project_root: std::path::PathBuf,
    internalonly: Option<InternalOnlyCtx>,
    blocked_files: Option<BlockedFilesRule>,
    blocked_commands: Option<BlockedCommandsRule>,
}

/// Context for internal-only checking: just the resolved project root.
struct InternalOnlyCtx {
    project_root: std::path::PathBuf,
}

impl RuleSet {
    pub fn build(config: &Config, raw_project_root: &Path) -> Result<Self> {
        let internalonly = if config.internal_access_only {
            let project_root = resolve_project_root(raw_project_root)?;
            Some(InternalOnlyCtx { project_root })
        } else {
            None
        };

        let blocked_files = if !config.block_access_to.is_empty() {
            Some(BlockedFilesRule::new(
                &config.block_access_to,
                raw_project_root,
            )?)
        } else {
            None
        };

        let blocked_commands = if !config.commands_forbidden.is_empty() {
            Some(BlockedCommandsRule::new(&config.commands_forbidden)?)
        } else {
            None
        };

        Ok(Self {
            project_root: raw_project_root.to_path_buf(),
            internalonly,
            blocked_files,
            blocked_commands,
        })
    }

    pub fn evaluate(&self, input: &HookInput) -> Verdict {
        let tool_name_lower = input.tool_name.to_ascii_lowercase();
        match tool_name_lower.as_str() {
            "bash" => self.evaluate_bash(input),
            "read" | "write" | "edit" | "notebookedit" => self.evaluate_file_tool(input),
            "glob" => self.evaluate_glob(input),
            "grep" => self.evaluate_grep(input),
            // Non-filesystem tools — always allow
            "webfetch" | "websearch" | "task" => Verdict::Allow,
            // Unknown tools — pass through
            _ => Verdict::Allow,
        }
    }

    fn evaluate_bash(&self, input: &HookInput) -> Verdict {
        let command = match input.command() {
            Some(c) => c,
            None => return Verdict::Allow,
        };

        // Check internal-only (path analysis of bash commands)
        if let Some(ctx) = &self.internalonly {
            if let Some(reason) =
                bash_analyzer::analyze(command, &ctx.project_root)
            {
                return Verdict::Deny(reason);
            }
        }

        // Check blocked files against paths extracted from the command
        if let Some(rule) = &self.blocked_files {
            let paths = bash_analyzer::extract_paths(command);
            for path_str in &paths {
                // Resolve relative paths against project root
                let resolved = resolve_target(path_str, &self.project_root);
                // Only check paths under the project root — the gitignore
                // matcher requires paths to be under its root, and external
                // paths can't match project-relative blocked patterns anyway.
                if resolved.starts_with(&self.project_root) {
                    if let Some(reason) = rule.check(&resolved) {
                        return Verdict::Deny(reason);
                    }
                }
            }
        }

        // Check blocked commands
        if let Some(rule) = &self.blocked_commands {
            if let Some(reason) = rule.check(command) {
                return Verdict::Deny(reason);
            }
        }

        Verdict::Allow
    }

    fn evaluate_file_tool(&self, input: &HookInput) -> Verdict {
        let file_path = match input.file_path().or_else(|| input.notebook_path()) {
            Some(p) => p,
            None => return Verdict::Allow,
        };

        // Check internal-only
        if let Some(ctx) = &self.internalonly {
            let resolved = resolve_target(file_path, &ctx.project_root);
            if let Some(reason) = check_path_containment(
                &resolved,
                &ctx.project_root,
                "path",
            ) {
                return Verdict::Deny(reason);
            }
        }

        // Check blocked files
        if let Some(rule) = &self.blocked_files {
            let path = std::path::Path::new(file_path);
            if let Some(reason) = rule.check(path) {
                return Verdict::Deny(reason);
            }
        }

        Verdict::Allow
    }

    fn evaluate_glob(&self, input: &HookInput) -> Verdict {
        let search_path = match input.search_path() {
            Some(p) => p,
            None => return Verdict::Allow,
        };

        // Check internal-only
        if let Some(ctx) = &self.internalonly {
            let resolved = resolve_target(search_path, &ctx.project_root);
            if let Some(reason) = check_path_containment(
                &resolved,
                &ctx.project_root,
                "path",
            ) {
                return Verdict::Deny(reason);
            }
        }

        // Check blocked files
        if let Some(rule) = &self.blocked_files {
            let path = std::path::Path::new(search_path);
            if let Some(reason) = rule.check(path) {
                return Verdict::Deny(reason);
            }
        }

        Verdict::Allow
    }

    fn evaluate_grep(&self, input: &HookInput) -> Verdict {
        let search_path = match input.search_path() {
            Some(p) => p,
            None => return Verdict::Allow,
        };

        // Check internal-only
        if let Some(ctx) = &self.internalonly {
            let resolved = resolve_target(search_path, &ctx.project_root);
            if let Some(reason) = check_path_containment(
                &resolved,
                &ctx.project_root,
                "path",
            ) {
                return Verdict::Deny(reason);
            }
        }

        // Check blocked files
        if let Some(rule) = &self.blocked_files {
            let path = std::path::Path::new(search_path);
            if let Some(reason) = rule.check(path) {
                return Verdict::Deny(reason);
            }
        }

        Verdict::Allow
    }
}
