use eyre::Result;
use std::path::Path;

use crate::bash_analyzer::{self, PathContext};
use crate::blocked_commands::BlockedCommandsRule;
use crate::blocked_files::BlockedFilesRule;
use crate::config::Config;
use crate::hook_input::HookInput;
use crate::internalonly::{check_path_containment, resolve_project_root, resolve_target};
use crate::util::truncate;

#[derive(Debug)]
pub enum Verdict {
    Allow,
    Deny(String),
}

pub struct RuleSet {
    /// Canonicalized project root (when internal_access_only or blocked_files is active).
    project_root: std::path::PathBuf,
    internal_access_only: bool,
    blocked_files: Option<BlockedFilesRule>,
    blocked_commands: Option<BlockedCommandsRule>,
}

impl RuleSet {
    pub fn build(config: &Config, raw_project_root: &Path) -> Result<Self> {
        // Canonicalize the project root when any filesystem rule needs it.
        let needs_canonical =
            config.internal_access_only || !config.block_access_to.is_empty();
        let project_root = if needs_canonical {
            resolve_project_root(raw_project_root)?
        } else {
            raw_project_root.to_path_buf()
        };

        let blocked_files = if !config.block_access_to.is_empty() {
            Some(BlockedFilesRule::new(
                &config.block_access_to,
                &project_root,
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
            project_root,
            internal_access_only: config.internal_access_only,
            blocked_files,
            blocked_commands,
        })
    }

    pub fn evaluate(&self, input: &HookInput) -> Verdict {
        let tool_name_lower = input.tool_name.to_ascii_lowercase();
        match tool_name_lower.as_str() {
            "bash" => self.evaluate_bash(input),
            "read" | "write" | "edit" | "notebookedit" => {
                let path = input.file_path().or_else(|| input.notebook_path());
                match path {
                    Some(p) => self.evaluate_path_tool(p),
                    None => Verdict::Allow,
                }
            }
            "glob" | "grep" => match input.search_path() {
                Some(p) => self.evaluate_path_tool(p),
                None => Verdict::Allow,
            },
            // Known non-filesystem tools — always allow
            "webfetch" | "websearch" | "task" | "askuserquestion"
            | "todowrite" | "skill" | "sendmessage" | "teamcreate"
            | "teamdelete" | "enterplanmode" | "exitplanmode"
            | "taskcreate" | "taskget" | "taskupdate" | "tasklist"
            | "taskoutput" | "taskstop" => Verdict::Allow,
            // Unknown tools — deny by default
            _ => Verdict::Deny(format!(
                "Blocked by `clarg`: unknown tool '{}' is not in the allowlist",
                input.tool_name
            )),
        }
    }

    fn evaluate_bash(&self, input: &HookInput) -> Verdict {
        let command = match input.command() {
            Some(c) => c,
            None => return Verdict::Allow,
        };

        // Single extraction pass — used by both internal-only and blocked-files checks
        let paths = bash_analyzer::extract_paths(command);

        // Check internal-only (path containment)
        if self.internal_access_only {
            for ep in &paths {
                match &ep.context {
                    PathContext::CdImplicitHome => {
                        return Verdict::Deny(
                            "Blocked by `clarg`: 'cd' with no arguments would navigate to $HOME, outside the project directory".to_string()
                        );
                    }
                    PathContext::CdDash => {
                        return Verdict::Deny(
                            "Blocked by `clarg`: 'cd -' could navigate outside the project directory".to_string()
                        );
                    }
                    PathContext::InlineCodeRef {
                        interpreter,
                        flag,
                        code_snippet,
                    } => {
                        let resolved = resolve_target(&ep.raw, &self.project_root);
                        if check_path_containment(
                            &resolved,
                            &self.project_root,
                            "path",
                        )
                        .is_some()
                        {
                            return Verdict::Deny(format!(
                                "Blocked by `clarg`: '{} {} \"{}\"' references external path '{}'",
                                interpreter,
                                flag,
                                truncate(code_snippet, 80),
                                ep.raw
                            ));
                        }
                    }
                    _ => {
                        let resolved =
                            resolve_target(&ep.raw, &self.project_root);
                        if let Some(reason) = check_path_containment(
                            &resolved,
                            &self.project_root,
                            ep.context.label(),
                        ) {
                            return Verdict::Deny(reason);
                        }
                    }
                }
            }
        }

        // Check blocked files against extracted paths
        if let Some(rule) = &self.blocked_files {
            for ep in &paths {
                // Skip non-path contexts
                if matches!(
                    ep.context,
                    PathContext::CdImplicitHome | PathContext::CdDash
                ) {
                    continue;
                }
                let resolved =
                    resolve_target(&ep.raw, &self.project_root);
                // Only check paths under the project root — the gitignore
                // matcher requires paths to be under its root.
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

    /// Evaluate a single-path tool (Read, Write, Edit, NotebookEdit, Glob, Grep).
    fn evaluate_path_tool(&self, path: &str) -> Verdict {
        if !self.internal_access_only && self.blocked_files.is_none() {
            return Verdict::Allow;
        }

        let resolved = resolve_target(path, &self.project_root);

        // Check internal-only
        if self.internal_access_only {
            if let Some(reason) = check_path_containment(
                &resolved,
                &self.project_root,
                "path",
            ) {
                return Verdict::Deny(reason);
            }
        }

        // Check blocked files
        if let Some(rule) = &self.blocked_files {
            if let Some(reason) = rule.check(&resolved) {
                return Verdict::Deny(reason);
            }
        }

        Verdict::Allow
    }
}
