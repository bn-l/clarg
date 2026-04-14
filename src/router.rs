use eyre::Result;
use std::path::{Path, PathBuf};

use crate::bash_analyzer::{self, ExtractedPath, PathContext};
use crate::blocked_commands::BlockedCommandsRule;
use crate::blocked_files::BlockedFilesRule;
use crate::config::Config;
use crate::hook_input::HookInput;
use crate::internalonly::{
    check_path_containment, resolve_literal_target, resolve_project_root, resolve_target,
};
use crate::system_paths::SystemPathsRule;
use crate::util::truncate;

#[derive(Debug)]
pub enum Verdict {
    Allow,
    Deny(String),
}

/// Resolve an extracted path respecting its context. `Redirection`
/// targets have already been bash-expanded by the redirection parser
/// (tilde/`$HOME` resolved per source-level quote context), so we must
/// NOT call `resolve_target` — that would double-expand quoted
/// literals like `'~/foo'`. All other contexts go through the normal
/// resolver.
fn resolve_ep(ep: &ExtractedPath, project_root: &Path) -> PathBuf {
    match ep.context {
        PathContext::Redirection => resolve_literal_target(&ep.raw, project_root),
        _ => resolve_target(&ep.raw, project_root),
    }
}

pub struct RuleSet {
    /// Canonicalized project root (when a filesystem rule needs one).
    project_root: std::path::PathBuf,
    internal_access_only: bool,
    system_paths: Option<SystemPathsRule>,
    blocked_files: Option<BlockedFilesRule>,
    blocked_commands: Option<BlockedCommandsRule>,
    no_unknown_tools: bool,
}

impl RuleSet {
    pub fn build(config: &Config, raw_project_root: &Path) -> Result<Self> {
        // Canonicalize the project root when any filesystem rule needs it.
        let system_paths_active = config.no_root || config.no_system_dirs;
        let needs_canonical = config.internal_access_only
            || !config.block_access_to.is_empty()
            || system_paths_active;
        let project_root = if needs_canonical {
            let canonical = resolve_project_root(raw_project_root)?;
            log::debug!(
                "canonicalized project root: {} -> {}",
                raw_project_root.display(),
                canonical.display()
            );
            canonical
        } else {
            raw_project_root.to_path_buf()
        };

        let system_paths = if system_paths_active {
            log::debug!(
                "building system_paths rule: no_root={}, no_system_dirs={}",
                config.no_root,
                config.no_system_dirs
            );
            Some(SystemPathsRule::new(
                config.no_root,
                config.no_system_dirs,
                raw_project_root,
                &project_root,
            ))
        } else {
            None
        };

        let blocked_files = if !config.block_access_to.is_empty() {
            log::debug!(
                "building blocked_files rule with {} patterns",
                config.block_access_to.len()
            );
            Some(BlockedFilesRule::new(
                &config.block_access_to,
                &project_root,
            )?)
        } else {
            None
        };

        let blocked_commands = if !config.commands_forbidden.is_empty() {
            log::debug!(
                "building blocked_commands rule with {} patterns",
                config.commands_forbidden.len()
            );
            Some(BlockedCommandsRule::new(&config.commands_forbidden)?)
        } else {
            None
        };

        Ok(Self {
            project_root,
            internal_access_only: config.internal_access_only,
            system_paths,
            blocked_files,
            blocked_commands,
            no_unknown_tools: config.no_unknown_tools,
        })
    }

    pub fn evaluate(&self, input: &HookInput) -> Verdict {
        let tool_name_lower = input.tool_name.to_ascii_lowercase();
        log::debug!("routing tool '{}' (normalized: '{}')", input.tool_name, tool_name_lower);
        match tool_name_lower.as_str() {
            "bash" => self.evaluate_bash(input),
            "read" | "write" | "edit" | "notebookedit" => {
                let path = input.file_path().or_else(|| input.notebook_path());
                match path {
                    Some(p) => {
                        log::debug!("path tool '{}': target='{}'", input.tool_name, p);
                        self.evaluate_path_tool(p)
                    }
                    None => {
                        log::debug!("path tool '{}': no path in input, allowing", input.tool_name);
                        Verdict::Allow
                    }
                }
            }
            "glob" | "grep" => match input.search_path() {
                Some(p) => {
                    log::debug!("search tool '{}': path='{}'", input.tool_name, p);
                    self.evaluate_path_tool(p)
                }
                None => {
                    log::debug!("search tool '{}': no path in input, allowing", input.tool_name);
                    Verdict::Allow
                }
            },
            // Known non-filesystem tools — always allow
            "webfetch" | "websearch" | "task" | "askuserquestion"
            | "todowrite" | "skill" | "sendmessage" | "teamcreate"
            | "teamdelete" | "enterplanmode" | "exitplanmode"
            | "taskcreate" | "taskget" | "taskupdate" | "tasklist"
            | "taskoutput" | "taskstop" => {
                log::debug!("known non-filesystem tool '{}', allowing", input.tool_name);
                Verdict::Allow
            }
            // Unknown tools — deny if no_unknown_tools, else allow.
            _ if self.no_unknown_tools => {
                log::debug!(
                    "unknown tool '{}', denying due to no_unknown_tools",
                    input.tool_name
                );
                Verdict::Deny(format!(
                    "Blocked by `clarg`: unknown tool '{}' is not allowed because 'no_unknown_tools' is enabled",
                    input.tool_name
                ))
            }
            _ => {
                log::debug!("unknown tool '{}', allowing by default", input.tool_name);
                Verdict::Allow
            }
        }
    }

    fn evaluate_bash(&self, input: &HookInput) -> Verdict {
        let command = match input.command() {
            Some(c) => c,
            None => {
                log::debug!("bash tool: no command in input, allowing");
                return Verdict::Allow;
            }
        };

        log::debug!("bash: evaluating command (len={})", command.len());

        // Single extraction pass — used by system_paths, internal-only, and blocked-files checks
        let paths = bash_analyzer::extract_paths(command);
        log::debug!("bash: extracted {} paths from command", paths.len());
        for ep in &paths {
            log::debug!("bash:   path='{}' context={:?}", ep.raw, ep.context);
        }

        // Order: system_paths -> internal_access_only -> blocked_files -> blocked_commands.
        // system_paths fires first so its more specific deny messages (e.g. "no_root"
        // or "system directory '/etc'") surface instead of the broader
        // "outside the project directory" from internal_access_only.

        // 1. system_paths (no_root / no_system_dirs)
        if let Some(rule) = &self.system_paths {
            for ep in &paths {
                // Skip pseudo-paths that don't carry a real target:
                // cd-context markers (dedicated `-i` messaging) and the
                // inline-code sentinel (opaque boundary — handled below).
                if matches!(
                    ep.context,
                    PathContext::CdImplicitHome
                        | PathContext::CdDash
                        | PathContext::InlineCodeExecution { .. }
                ) {
                    continue;
                }
                let resolved = resolve_ep(ep, &self.project_root);
                if let Some(reason) = rule.check(&resolved) {
                    return Verdict::Deny(reason);
                }
            }
        }

        // 2. internal-only (path containment)
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
                    PathContext::InlineCodeExecution {
                        interpreter,
                        flag,
                        code_snippet,
                    } => {
                        return Verdict::Deny(format!(
                            "Blocked by `clarg`: '{} {}' inline code cannot be statically verified as internal-only: \"{}\"",
                            interpreter,
                            flag,
                            truncate(code_snippet, 80)
                        ));
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
                        let resolved = resolve_ep(ep, &self.project_root);
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

        // 3. blocked files. The gix-ignore matcher handles paths both inside
        // and outside the project root, so no containment pre-check is needed.
        if let Some(rule) = &self.blocked_files {
            for ep in &paths {
                // Skip non-path contexts
                if matches!(
                    ep.context,
                    PathContext::CdImplicitHome
                        | PathContext::CdDash
                        | PathContext::InlineCodeExecution { .. }
                ) {
                    continue;
                }
                let resolved = resolve_ep(ep, &self.project_root);
                let is_dir_hint = ep.context.implies_directory();
                if let Some(reason) = rule.check_with_hint(&resolved, is_dir_hint) {
                    return Verdict::Deny(reason);
                }
            }
        }

        // 4. blocked commands
        if let Some(rule) = &self.blocked_commands {
            if let Some(reason) = rule.check(command) {
                return Verdict::Deny(reason);
            }
        }

        Verdict::Allow
    }

    /// Evaluate a single-path tool (Read, Write, Edit, NotebookEdit, Glob, Grep).
    fn evaluate_path_tool(&self, path: &str) -> Verdict {
        if !self.internal_access_only
            && self.blocked_files.is_none()
            && self.system_paths.is_none()
        {
            log::debug!("path_tool: no filesystem rules active, allowing");
            return Verdict::Allow;
        }

        let resolved = resolve_target(path, &self.project_root);
        log::debug!("path_tool: resolved '{}' -> '{}'", path, resolved.display());

        // Order matches evaluate_bash: system_paths -> internal_access_only -> blocked_files.

        // 1. system_paths
        if let Some(rule) = &self.system_paths {
            if let Some(reason) = rule.check(&resolved) {
                log::debug!("path_tool: system_paths matched");
                return Verdict::Deny(reason);
            }
        }

        // 2. internal-only
        if self.internal_access_only {
            if let Some(reason) = check_path_containment(
                &resolved,
                &self.project_root,
                "path",
            ) {
                log::debug!("path_tool: containment check failed");
                return Verdict::Deny(reason);
            }
        }

        // 3. blocked files
        if let Some(rule) = &self.blocked_files {
            if let Some(reason) = rule.check(&resolved) {
                log::debug!("path_tool: blocked_files matched");
                return Verdict::Deny(reason);
            }
        }

        Verdict::Allow
    }
}
