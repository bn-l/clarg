use crate::internalonly::{check_path_containment, resolve_target};
use crate::util::truncate;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

/// Maximum recursion depth for eval/bash -c parsing.
const MAX_RECURSION: usize = 5;

/// Regex for shell output redirections: `>file`, `>>file`, `2>file`, `&>file`
static REDIRECT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\d*>{1,2}|&>)\s*(\S+)").unwrap()
});

/// File-manipulating commands whose non-flag arguments are paths.
const FILE_COMMANDS: &[&str] = &[
    "cat", "less", "more", "head", "tail", "cp", "mv", "rm", "touch", "mkdir",
    "rmdir", "chmod", "chown", "ln", "stat", "file", "wc", "sort", "uniq",
    "diff", "patch", "tee", "install", "rsync", "scp", "tar", "zip", "unzip",
    "gzip", "gunzip", "bzip2", "xz",
];

/// Search commands that take paths as non-flag arguments, but have some flags
/// that consume an argument.
const SEARCH_COMMANDS: &[&str] = &["rg", "grep", "find", "fd", "ag", "ack"];

/// Flags for search commands that consume the next argument (so we skip it).
const SEARCH_ARG_FLAGS: &[&str] = &[
    "-e", "-f", "-g", "--glob", "-t", "--type", "-T", "--type-not",
    "--iglob", "-m", "--max-count", "-A", "-B", "-C", "--context",
    "--max-depth", "--maxdepth", "-d", "--depth", "--ignore-file",
    "--color", "--colors", "-j", "--threads", "--path-separator",
    "--sortr", "--sort", "-E", "--encoding", "--regex-size-limit",
    "--dfa-size-limit", "-p", "--path", "--search-path", "--exec",
    "--exec-batch", "-x",
];

/// Execute-like commands where the first non-flag argument is a file to run.
const EXEC_COMMANDS: &[&str] = &[
    "python", "python3", "node", "ruby", "perl", "lua", "php",
    "source", ".", "deno", "bun", "tsx", "ts-node",
];

/// Interpreters that support -c/-e flags for inline code execution.
const INLINE_CODE_INTERPRETERS: &[&str] = &[
    "python", "python3", "ruby", "perl", "lua", "php", "node",
];

/// Download commands where specific flags point to output paths.
const DOWNLOAD_COMMANDS: &[&str] = &["curl", "wget"];

/// Regex to extract absolute paths and home paths from inline code strings.
static PATH_IN_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:/[a-zA-Z0-9_.@-][a-zA-Z0-9_.@/-]*|~/[a-zA-Z0-9_.@/-]+|\$HOME/[a-zA-Z0-9_.@/-]+)"#).unwrap()
});

// ============================================================================
// Extracted path types
// ============================================================================

/// A filesystem path extracted from a bash command, tagged with how it was referenced.
#[derive(Debug, Clone)]
pub struct ExtractedPath {
    pub raw: String,
    pub context: PathContext,
}

/// Context for how a path was referenced in a command.
#[derive(Debug, Clone)]
pub enum PathContext {
    /// Shell output redirection (>, >>, 2>, &>)
    Redirection,
    /// Explicit cd target
    CdTarget,
    /// cd with no arguments (implicit $HOME navigation)
    CdImplicitHome,
    /// cd - (unpredictable navigation)
    CdDash,
    /// Argument to a file-manipulating command (cat, cp, mv, rm, etc.)
    FileCommandArg,
    /// Path argument to a search command (rg, grep, find, fd, etc.)
    SearchCommandArg,
    /// Script/file argument to an exec command (python, node, etc.)
    ExecTarget,
    /// Path found inside inline code (python -c, node -e, etc.)
    InlineCodeRef {
        interpreter: String,
        flag: String,
        code_snippet: String,
    },
    /// Output path for download commands (curl -o, wget -O)
    DownloadOutput,
    /// Upload/data file path for curl (-d @file, -F, -T, etc.)
    UploadData,
    /// File argument to sed
    SedFile,
    /// Path argument to dd (if=, of=)
    DdPath,
    /// Path-like argument to an unrecognized command
    UnknownCommandArg,
}

impl PathContext {
    /// Label for use in containment error messages.
    pub fn label(&self) -> &str {
        match self {
            PathContext::Redirection => "redirection target",
            PathContext::DownloadOutput => "download output path",
            PathContext::UploadData => "upload/data file path",
            // InlineCodeRef has custom message handling in check_extracted_path
            _ => "path",
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Analyze a full bash command string for paths outside the project root.
/// Returns Some(reason) if any violation is found.
///
/// This is a convenience wrapper over `extract_paths` that checks each extracted
/// path for containment within the project root.
pub fn analyze(command: &str, project_root: &Path) -> Option<String> {
    let paths = extract_paths(command);
    for ep in paths {
        if let Some(reason) = check_extracted_path(&ep, project_root) {
            return Some(reason);
        }
    }
    None
}

/// Extract all filesystem paths referenced by a bash command.
/// Returns structured results with context about how each path was referenced.
pub fn extract_paths(command: &str) -> Vec<ExtractedPath> {
    let mut paths = Vec::new();
    extract_paths_recursive(command, &mut paths, 0);
    paths
}

// ============================================================================
// Containment checking (used by analyze())
// ============================================================================

/// Check a single extracted path for containment violations.
fn check_extracted_path(ep: &ExtractedPath, project_root: &Path) -> Option<String> {
    match &ep.context {
        PathContext::CdImplicitHome => Some(
            "Blocked by `clarg`: 'cd' with no arguments would navigate to $HOME, outside the project directory".to_string()
        ),
        PathContext::CdDash => Some(
            "Blocked by `clarg`: 'cd -' could navigate outside the project directory".to_string()
        ),
        PathContext::InlineCodeRef { interpreter, flag, code_snippet } => {
            let resolved = resolve_target(&ep.raw, project_root);
            if check_path_containment(&resolved, project_root, "path").is_some() {
                Some(format!(
                    "Blocked by `clarg`: '{} {} \"{}\"' references external path '{}'",
                    interpreter, flag, truncate(code_snippet, 80), ep.raw
                ))
            } else {
                None
            }
        }
        _ => {
            let resolved = resolve_target(&ep.raw, project_root);
            check_path_containment(&resolved, project_root, ep.context.label())
        }
    }
}

// ============================================================================
// Extraction engine (single parser — the only place command structure is parsed)
// ============================================================================

fn extract_paths_recursive(command: &str, paths: &mut Vec<ExtractedPath>, depth: usize) {
    if depth > MAX_RECURSION {
        return;
    }

    // Collect redirection targets
    for cap in REDIRECT_RE.captures_iter(command) {
        let target = &cap[1];
        if !target.starts_with("/dev/") {
            paths.push(ExtractedPath {
                raw: target.to_string(),
                context: PathContext::Redirection,
            });
        }
    }

    // Split on shell operators and extract paths from each sub-command
    let sub_commands = split_shell_operators(command);
    for sub_cmd in &sub_commands {
        let trimmed = sub_cmd.trim();
        if trimmed.is_empty() {
            continue;
        }
        extract_paths_from_sub_command(trimmed, paths, depth);
    }
}

fn extract_paths_from_sub_command(sub_cmd: &str, paths: &mut Vec<ExtractedPath>, depth: usize) {
    let cleaned = REDIRECT_RE.replace_all(sub_cmd, "");
    let tokens = match shlex::split(&cleaned) {
        Some(t) => t,
        None => return,
    };
    if tokens.is_empty() {
        return;
    }

    // Skip env var prefixes and sudo/env
    let mut start = 0;
    while start < tokens.len() {
        let t = &tokens[start];
        if t.contains('=') && !t.starts_with('-') && !t.starts_with('/') {
            start += 1;
        } else if t == "sudo" || t == "env" {
            start += 1;
        } else {
            break;
        }
    }
    if start >= tokens.len() {
        return;
    }

    let cmd_name = &tokens[start];
    let args = &tokens[start + 1..];

    match cmd_name.as_str() {
        "cd" => {
            if args.is_empty() {
                paths.push(ExtractedPath {
                    raw: String::new(),
                    context: PathContext::CdImplicitHome,
                });
            } else if args[0] == "-" {
                paths.push(ExtractedPath {
                    raw: "-".to_string(),
                    context: PathContext::CdDash,
                });
            } else {
                paths.push(ExtractedPath {
                    raw: args[0].clone(),
                    context: PathContext::CdTarget,
                });
            }
        }
        "eval" => {
            if !args.is_empty() {
                extract_paths_recursive(&args.join(" "), paths, depth + 1);
            }
        }
        "bash" | "sh" | "zsh" | "dash" => {
            if let Some(pos) = args.iter().position(|t| t == "-c") {
                if let Some(inner) = args.get(pos + 1) {
                    extract_paths_recursive(inner, paths, depth + 1);
                    return;
                }
            }
            // Treat as script execution
            for arg in args {
                if !arg.starts_with('-') {
                    paths.push(ExtractedPath {
                        raw: arg.clone(),
                        context: PathContext::ExecTarget,
                    });
                    break;
                }
            }
        }
        cmd if FILE_COMMANDS.contains(&cmd) => {
            for arg in args {
                if !arg.starts_with('-') {
                    paths.push(ExtractedPath {
                        raw: arg.clone(),
                        context: PathContext::FileCommandArg,
                    });
                }
            }
        }
        cmd if SEARCH_COMMANDS.contains(&cmd) => {
            let mut i = 0;
            while i < args.len() {
                let arg = &args[i];
                if SEARCH_ARG_FLAGS.contains(&arg.as_str()) {
                    i += 2;
                    continue;
                }
                if arg.starts_with('-') && arg.contains('=') {
                    i += 1;
                    continue;
                }
                if arg.starts_with('-') {
                    i += 1;
                    continue;
                }
                paths.push(ExtractedPath {
                    raw: arg.clone(),
                    context: PathContext::SearchCommandArg,
                });
                i += 1;
            }
        }
        cmd if EXEC_COMMANDS.contains(&cmd) => {
            // Check for inline code interpreters first
            if INLINE_CODE_INTERPRETERS.contains(&cmd) {
                let code_flags: &[&str] = match cmd {
                    "node" => &["-e", "--eval"],
                    _ => &["-c", "-e"],
                };
                if let Some(pos) = args.iter().position(|t| code_flags.contains(&t.as_str())) {
                    if let Some(code_arg) = args.get(pos + 1) {
                        for mat in PATH_IN_CODE_RE.find_iter(code_arg) {
                            let path_str = mat.as_str();
                            if !path_str.starts_with("/dev/") {
                                paths.push(ExtractedPath {
                                    raw: path_str.to_string(),
                                    context: PathContext::InlineCodeRef {
                                        interpreter: cmd.to_string(),
                                        flag: args[pos].clone(),
                                        code_snippet: code_arg.clone(),
                                    },
                                });
                            }
                        }
                        return;
                    }
                }
            }
            // Normal exec: first non-flag arg is the script path
            for arg in args {
                if !arg.starts_with('-') {
                    paths.push(ExtractedPath {
                        raw: arg.clone(),
                        context: PathContext::ExecTarget,
                    });
                    break;
                }
            }
        }
        cmd if DOWNLOAD_COMMANDS.contains(&cmd) => {
            extract_download_paths(args, cmd, paths);
        }
        "sed" => {
            extract_sed_paths(args, paths);
        }
        "dd" => {
            let path_keys = ["if", "of"];
            for arg in args {
                if let Some((key, value)) = arg.split_once('=') {
                    if path_keys.contains(&key) {
                        paths.push(ExtractedPath {
                            raw: value.to_string(),
                            context: PathContext::DdPath,
                        });
                    }
                }
            }
        }
        _ => {
            for arg in args {
                if arg.starts_with('-') {
                    // Check --flag=value patterns for embedded paths
                    if let Some((_flag, value)) = arg.split_once('=') {
                        if looks_like_path(value) {
                            paths.push(ExtractedPath {
                                raw: value.to_string(),
                                context: PathContext::UnknownCommandArg,
                            });
                        }
                    }
                    continue;
                }
                if looks_like_path(arg) {
                    paths.push(ExtractedPath {
                        raw: arg.clone(),
                        context: PathContext::UnknownCommandArg,
                    });
                }
            }
        }
    }
}

/// Extract paths from download command arguments.
fn extract_download_paths(args: &[String], cmd: &str, paths: &mut Vec<ExtractedPath>) {
    let output_flags: &[&str] = match cmd {
        "curl" => &["-o", "--output"],
        "wget" => &["-O", "--output-document"],
        _ => &[],
    };
    let data_long_flags: &[&str] = match cmd {
        "curl" => &[
            "--data", "--data-binary", "--data-raw", "--data-urlencode",
            "--form", "--upload-file",
        ],
        _ => &[],
    };
    let data_short_flags: &[&str] = match cmd {
        "curl" => &["-d", "-F", "-T"],
        _ => &[],
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if output_flags.contains(&arg.as_str()) {
            if let Some(path_arg) = args.get(i + 1) {
                paths.push(ExtractedPath {
                    raw: path_arg.clone(),
                    context: PathContext::DownloadOutput,
                });
            }
            i += 2;
            continue;
        }
        if data_long_flags.contains(&arg.as_str()) || data_short_flags.contains(&arg.as_str()) {
            if let Some(data_arg) = args.get(i + 1) {
                if let Some(p) = extract_path_from_curl_data(data_arg) {
                    paths.push(ExtractedPath {
                        raw: p,
                        context: PathContext::UploadData,
                    });
                }
            }
            i += 2;
            continue;
        }
        // Handle --flag=value forms
        for flag in output_flags.iter().chain(data_long_flags) {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if data_long_flags.contains(flag) {
                    if let Some(p) = extract_path_from_curl_data(value) {
                        paths.push(ExtractedPath {
                            raw: p,
                            context: PathContext::UploadData,
                        });
                    }
                } else {
                    paths.push(ExtractedPath {
                        raw: value.to_string(),
                        context: PathContext::DownloadOutput,
                    });
                }
            }
        }
        // Handle concatenated short flags: -d@path, -T/path
        for flag in data_short_flags {
            if arg.starts_with(flag) && arg.len() > flag.len() {
                let value = &arg[flag.len()..];
                if let Some(p) = extract_path_from_curl_data(value) {
                    paths.push(ExtractedPath {
                        raw: p,
                        context: PathContext::UploadData,
                    });
                }
            }
        }
        i += 1;
    }
}

/// Extract a path from a curl data argument.
fn extract_path_from_curl_data(data_arg: &str) -> Option<String> {
    if let Some(at_path) = data_arg.strip_prefix('@') {
        if !at_path.is_empty() {
            return Some(at_path.to_string());
        }
    } else if data_arg.contains("=@") {
        if let Some((_, path)) = data_arg.split_once("=@") {
            if !path.is_empty() {
                return Some(path.to_string());
            }
        }
    } else if looks_like_path(data_arg) {
        return Some(data_arg.to_string());
    }
    None
}

/// Extract paths from sed arguments.
fn extract_sed_paths(args: &[String], paths: &mut Vec<ExtractedPath>) {
    let mut i = 0;
    let mut skip_next = false;
    while i < args.len() {
        if skip_next {
            skip_next = false;
            i += 1;
            continue;
        }
        let arg = &args[i];
        if arg == "-e" || arg == "-f" {
            skip_next = true;
            i += 1;
            continue;
        }
        if arg == "-i" || arg.starts_with("-i") {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        if looks_like_path(arg) {
            paths.push(ExtractedPath {
                raw: arg.clone(),
                context: PathContext::SedFile,
            });
        }
        i += 1;
    }
}

// ============================================================================
// Shell operator splitting
// ============================================================================

/// Split a command string on shell operators (&&, ||, ;, |) while respecting quotes.
pub fn split_shell_operators(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    while let Some(ch) = chars.next() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        if ch == '\\' && !in_single_quote {
            escape_next = true;
            current.push(ch);
            continue;
        }

        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            current.push(ch);
            continue;
        }

        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            current.push(ch);
            continue;
        }

        if in_single_quote || in_double_quote {
            current.push(ch);
            continue;
        }

        match ch {
            '&' if chars.peek() == Some(&'&') => {
                chars.next(); // consume second '&'
                parts.push(std::mem::take(&mut current));
            }
            '|' if chars.peek() == Some(&'|') => {
                chars.next(); // consume second '|'
                parts.push(std::mem::take(&mut current));
            }
            '|' => {
                // Single pipe — still a boundary for command analysis
                parts.push(std::mem::take(&mut current));
            }
            ';' => {
                parts.push(std::mem::take(&mut current));
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.trim().is_empty() {
        parts.push(current);
    }

    parts
}

// ============================================================================
// Utilities
// ============================================================================

/// Heuristic: does a token look like a filesystem path?
pub fn looks_like_path(token: &str) -> bool {
    token.contains('/')
        || token.starts_with('.')
        || token.starts_with('~')
        || token.starts_with("$HOME")
}
