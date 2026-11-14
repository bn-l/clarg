use eyre::Result;
use std::path::{Path, PathBuf};

use crate::bash_analyzer::{self, ExtractedPath, PathContext};
use crate::blocked_commands::BlockedCommandsRule;
use crate::broad_search::{BroadSearchRule, glob_tool_root};
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
/// resolver. Relative paths resolve against `base`, the shell's
/// starting directory.
fn resolve_ep(ep: &ExtractedPath, base: &Path) -> PathBuf {
    match ep.context {
        PathContext::Redirection => resolve_literal_target(&ep.raw, base),
        _ => resolve_target(&ep.raw, base),
    }
}

pub struct RuleSet {
    /// Canonicalized project root (when a filesystem rule needs one).
    project_root: std::path::PathBuf,
    internal_access_only: bool,
    system_paths: Option<SystemPathsRule>,
    blocked_files: Option<BlockedFilesRule>,
    blocked_commands: Option<BlockedCommandsRule>,
    broad_search: Option<BroadSearchRule>,
    no_unknown_tools: bool,
}

impl RuleSet {
    pub fn build(config: &Config, raw_project_root: &Path) -> Result<Self> {
        // Canonicalize the project root when any filesystem rule needs it.
        let system_paths_active = config.no_root || config.no_system_dirs;
        let needs_canonical = config.internal_access_only
            || !config.block_access_to.is_empty()
            || system_paths_active
            || config.no_broad_search;
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
            broad_search: if config.no_broad_search {
                log::debug!("building broad_search rule");
                BroadSearchRule::new()
            } else {
                None
            },
            no_unknown_tools: config.no_unknown_tools,
        })
    }

    /// The shell's working directory when a command starts: the hook's
    /// `cwd` when it is an existing absolute directory (canonicalized like
    /// the project root), otherwise the project root. Relative paths are
    /// resolved against it; the project root stays the containment
    /// boundary for `internal_access_only`.
    fn start_dir(&self, input: &HookInput) -> PathBuf {
        if input.cwd.is_absolute()
            && let Ok(canonical) = input.cwd.canonicalize()
            && canonical.is_dir()
        {
            return canonical;
        }
        self.project_root.clone()
    }

    pub fn evaluate(&self, input: &HookInput) -> Verdict {
        let tool_name_lower = input.tool_name.to_ascii_lowercase();
        log::debug!("routing tool '{}' (normalized: '{}')", input.tool_name, tool_name_lower);
        match tool_name_lower.as_str() {
            "bash" => self.evaluate_bash(input),
            // Monitor runs a shell command in the same environment as
            // Bash. Its WebSocket form (`ws`, no `command`) runs nothing.
            "monitor" => match input.command() {
                Some(_) => self.evaluate_bash(input),
                None => {
                    log::debug!("monitor: no command (WebSocket source), allowing");
                    Verdict::Allow
                }
            },
            "read" | "write" | "edit" | "notebookedit" | "lsp" => {
                let path = input
                    .file_path()
                    .or_else(|| input.notebook_path())
                    .or_else(|| input.lsp_file_path());
                match path {
                    Some(p) => {
                        log::debug!("path tool '{}': target='{}'", input.tool_name, p);
                        self.evaluate_path_tool(p, &self.start_dir(input))
                    }
                    None => {
                        log::debug!("path tool '{}': no path in input, allowing", input.tool_name);
                        Verdict::Allow
                    }
                }
            }
            // The root a search walks: Grep's `path` (default: the current
            // directory); for Glob, `path` joined with the literal start of
            // the pattern, so an absolute pattern like `~/**/x` is checked.
            "grep" => self.evaluate_search_tool(input, input.search_path().unwrap_or(".")),
            "glob" => self.evaluate_search_tool(
                input,
                &glob_tool_root(input.search_path(), input.pattern()),
            ),
            // Known non-filesystem tools — always allow
            "webfetch" | "websearch" | "task" | "agent" | "askuserquestion"
            | "todowrite" | "skill" | "sendmessage" | "teamcreate"
            | "teamdelete" | "enterplanmode" | "exitplanmode"
            | "taskcreate" | "taskget" | "taskupdate" | "tasklist"
            | "taskoutput" | "taskstop" | "toolsearch" | "subagenthandback"
            | "schedulewakeup" | "listagents" | "croncreate" | "crondelete"
            | "cronlist" | "enterworktree" | "exitworktree"
            | "listmcpresourcestool" | "readmcpresourcetool"
            | "readmcpresourcedirtool" => {
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

        let base = self.start_dir(input);
        log::debug!("bash: starting directory {}", base.display());

        // Single extraction pass — used by system_paths, internal-only, and blocked-files checks
        let paths = bash_analyzer::extract_paths_from(command, Some(&base));
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
                let resolved = resolve_ep(ep, &base);
                if let Some(reason) = rule.check_with_glob(&resolved, ep.unquoted_glob) {
                    return Verdict::Deny(reason);
                }
            }
        }

        // 1b. no_broad_search: never search, list or glob-enumerate $HOME
        // or anything above it.
        if let Some(rule) = &self.broad_search {
            for ep in &paths {
                if matches!(
                    ep.context,
                    PathContext::CdImplicitHome
                        | PathContext::CdDash
                        | PathContext::InlineCodeExecution { .. }
                ) {
                    continue;
                }
                let resolved = resolve_ep(ep, &base);
                if let Some(reason) = rule.check(ep, &resolved) {
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
                        let resolved = resolve_target(&ep.raw, &base);
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
                        let resolved = resolve_ep(ep, &base);
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
                let resolved = resolve_ep(ep, &base);
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

    /// Evaluate Claude Code's Grep / Glob tool by the root it walks.
    fn evaluate_search_tool(&self, input: &HookInput, root: &str) -> Verdict {
        log::debug!("search tool '{}': root='{}'", input.tool_name, root);
        let base = self.start_dir(input);
        if let Verdict::Deny(reason) = self.evaluate_path_tool(root, &base) {
            return Verdict::Deny(reason);
        }
        if let Some(rule) = &self.broad_search {
            let resolved = resolve_target(root, &base);
            if let Some(reason) = rule.check_root(&input.tool_name, &resolved) {
                return Verdict::Deny(reason);
            }
        }
        Verdict::Allow
    }

    /// Evaluate a single-path tool (Read, Write, Edit, NotebookEdit, LSP, Glob, Grep).
    /// Relative paths resolve against `base`.
    fn evaluate_path_tool(&self, path: &str, base: &Path) -> Verdict {
        if !self.internal_access_only
            && self.blocked_files.is_none()
            && self.system_paths.is_none()
        {
            log::debug!("path_tool: no filesystem rules active, allowing");
            return Verdict::Allow;
        }

        let resolved = resolve_target(path, base);
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
