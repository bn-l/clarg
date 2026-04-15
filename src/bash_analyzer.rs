use crate::internalonly::{
    check_path_containment, is_valid_login_name, resolve_literal_target, resolve_target,
    tilde_user_home,
};
use crate::util::truncate;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

/// Maximum recursion depth for eval/bash -c parsing.
const MAX_RECURSION: usize = 5;

/// File-manipulating commands whose non-flag arguments are paths.
const FILE_COMMANDS: &[&str] = &[
    "cat", "less", "more", "head", "tail", "cp", "mv", "rm", "touch",
    "chmod", "chown", "ln", "stat", "file", "wc", "sort", "uniq",
    "diff", "patch", "tee", "install", "rsync", "scp", "tar", "zip", "unzip",
    "gzip", "gunzip", "bzip2", "xz",
];

/// Commands whose non-flag arguments are directories (so blocked-file
/// matching can treat the path as a directory even when it doesn't yet
/// exist on disk). `mkdir`/`rmdir` create or remove directories;
/// `pushd` navigates the dir stack.
const DIR_TARGET_COMMANDS: &[&str] = &["mkdir", "rmdir", "pushd"];

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

/// Regex to catch a bare filesystem-root reference (`/`) inside a
/// quoted string literal in inline code — e.g. `os.chdir('/')` or
/// `std::fs::read_dir("/")`. PATH_IN_CODE_RE requires at least one
/// char after `/`, so it misses single-slash root targets.
static BARE_ROOT_IN_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"`](/)['"`]"#).unwrap()
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
    /// Inline code execution (python -c, node -e, ruby -e, ...).
    ///
    /// `raw` is the code argument itself, not a filesystem path. This
    /// sentinel represents an **opaque boundary**: because arbitrary
    /// interpreter code cannot be statically verified (relative paths,
    /// dynamic path construction, shell-out, base64, etc.), any rule
    /// whose contract is "deny external filesystem access" must treat
    /// this as an unconditional deny. Rules that only care about
    /// literal paths (system_paths / blocked_files) should *skip* this
    /// variant and rely on the sibling `InlineCodeRef` entries that
    /// carry the regex-extracted literal paths for defense-in-depth.
    InlineCodeExecution {
        interpreter: String,
        flag: String,
        code_snippet: String,
    },
    /// Output path for download commands (curl -o, wget -O)
    DownloadOutput,
    /// Upload/data file path for curl (-d @file, -F, -T, etc.)
    UploadData,
    /// Helper/config file consumed by a command flag
    /// (e.g. `curl --config <file>`, `wget --input-file <file>`).
    HelperFile,
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
            PathContext::HelperFile => "helper file path",
            // InlineCodeRef / InlineCodeExecution have custom messaging
            _ => "path",
        }
    }

    /// Does this context imply the referenced target is a directory?
    ///
    /// Used by `BlockedFilesRule` to decide whether gitignore-style
    /// directory-only patterns (e.g. `secrets/`) should fire on the
    /// leaf. `Some(true)` means the caller *knows* the target is a
    /// directory; `None` means the caller doesn't know and the rule
    /// should fall back to a filesystem probe.
    pub fn implies_directory(&self) -> Option<bool> {
        match self {
            // `cd <X>`, `mkdir <X>`, `rmdir <X>`, `pushd <X>`:
            // shell/command semantics require X be a directory.
            PathContext::CdTarget => Some(true),
            _ => None,
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
///
/// Shell brace expansions (`/{etc,var}/passwd`) are expanded here so that
/// every path the shell would actually touch is checked by downstream
/// rules. Without this, safety flags like `no_system_dirs` could be
/// bypassed by writing `cat /{etc,var}/passwd` instead of `cat /etc/passwd`.
///
/// Quote-aware brace handling: bash does NOT brace-expand quoted or
/// escaped braces (`cat '/{etc,var}'` is a literal filename, not
/// `/etc` and `/var`). To respect this without replacing the shlex
/// tokenizer, we mask `{`, `}`, and `,` inside single/double quotes
/// and backslash-escaped forms with private-use-area sentinels before
/// tokenization. Post-expansion we unmask sentinels back to their
/// original characters, so `raw` strings users see are byte-identical
/// to what bash would resolve.
pub fn extract_paths(command: &str) -> Vec<ExtractedPath> {
    // Strip heredocs / here-strings from the raw command BEFORE masking so
    // that `mask_quoted_braces`'s quote-state machine isn't poisoned by
    // unbalanced quotes inside a literal heredoc body. `strip_heredocs`
    // also runs again at the top of `extract_paths_recursive` to cover
    // recursion entry points (`eval "..."`, `bash -c "..."`).
    let stripped = strip_heredocs(command);
    let masked = mask_quoted_braces(&stripped);
    let mut paths = Vec::new();
    extract_paths_recursive(&masked, &mut paths, 0);
    let expanded = expand_brace_paths(paths);
    expanded.into_iter().map(unmask_extracted_path).collect()
}

// ============================================================================
// Quote-aware brace masking
// ============================================================================
//
// We pick Private Use Area codepoints so the sentinels cannot collide
// with real filename bytes or appear in legitimate shell input. Shlex
// copies them through as regular characters; the brace expander (which
// only recognizes literal ASCII `{`/`}`/`,`) ignores them.

const SENTINEL_LBRACE: char = '\u{E000}';
const SENTINEL_RBRACE: char = '\u{E001}';
const SENTINEL_COMMA: char = '\u{E002}';

/// Replace every `{`, `}`, and `,` that appears inside single/double
/// quotes — or is preceded by an unquoted backslash — with a private
/// sentinel codepoint. Unquoted, unescaped braces are left intact so
/// downstream `expand_braces` still expands them.
fn mask_quoted_braces(cmd: &str) -> String {
    let bytes = cmd.as_bytes();
    let mut out = String::with_capacity(cmd.len());
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b >= 0x80 {
            let len = utf8_char_len(b);
            let end = (i + len).min(bytes.len());
            out.push_str(&cmd[i..end]);
            i = end;
            continue;
        }
        match b {
            b'\'' if !in_double => {
                in_single = !in_single;
                out.push('\'');
                i += 1;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                out.push('"');
                i += 1;
            }
            b'\\' if !in_single && i + 1 < bytes.len() => {
                let nb = bytes[i + 1];
                match nb {
                    b'{' => {
                        out.push('\\');
                        out.push(SENTINEL_LBRACE);
                        i += 2;
                    }
                    b'}' => {
                        out.push('\\');
                        out.push(SENTINEL_RBRACE);
                        i += 2;
                    }
                    b',' => {
                        out.push('\\');
                        out.push(SENTINEL_COMMA);
                        i += 2;
                    }
                    _ => {
                        // Pass `\<c>` through verbatim so shlex still
                        // sees the escape.
                        out.push('\\');
                        if nb >= 0x80 {
                            let len = utf8_char_len(nb);
                            let end = (i + 1 + len).min(bytes.len());
                            out.push_str(&cmd[i + 1..end]);
                            i = end;
                        } else {
                            out.push(nb as char);
                            i += 2;
                        }
                    }
                }
            }
            b'{' if in_single || in_double => {
                out.push(SENTINEL_LBRACE);
                i += 1;
            }
            b'}' if in_single || in_double => {
                out.push(SENTINEL_RBRACE);
                i += 1;
            }
            b',' if in_single || in_double => {
                out.push(SENTINEL_COMMA);
                i += 1;
            }
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// Restore sentinel codepoints back to `{`, `}`, `,`.
fn unmask_braces(s: &str) -> String {
    if !s.contains(SENTINEL_LBRACE) && !s.contains(SENTINEL_RBRACE) && !s.contains(SENTINEL_COMMA) {
        return s.to_string();
    }
    s.chars()
        .map(|c| match c {
            SENTINEL_LBRACE => '{',
            SENTINEL_RBRACE => '}',
            SENTINEL_COMMA => ',',
            c => c,
        })
        .collect()
}

/// Unmask sentinels in `raw` and any embedded `code_snippet` so the
/// values we expose to users / downstream rules are byte-identical to
/// what bash would resolve.
fn unmask_extracted_path(mut ep: ExtractedPath) -> ExtractedPath {
    ep.raw = unmask_braces(&ep.raw);
    match &mut ep.context {
        PathContext::InlineCodeRef { code_snippet, .. }
        | PathContext::InlineCodeExecution { code_snippet, .. } => {
            *code_snippet = unmask_braces(code_snippet);
        }
        _ => {}
    }
    ep
}

/// Post-process: for each extracted path whose raw form contains a
/// comma-separated brace expression, replace it with one entry per
/// expansion (preserving context). Entries without braces pass through
/// unchanged. Invalid / range braces (`{1..5}`) are left untouched.
fn expand_brace_paths(paths: Vec<ExtractedPath>) -> Vec<ExtractedPath> {
    let mut out = Vec::with_capacity(paths.len());
    for ep in paths {
        let expansions = expand_braces(&ep.raw);
        if expansions.len() == 1 {
            out.push(ExtractedPath {
                raw: expansions.into_iter().next().unwrap(),
                context: ep.context,
            });
        } else {
            for exp in expansions {
                out.push(ExtractedPath {
                    raw: exp,
                    context: ep.context.clone(),
                });
            }
        }
    }
    out
}

/// Expand shell comma-brace patterns (`{a,b,c}`) in a string into all
/// possible concrete strings. Supports nesting and backslash escapes.
/// Range expansions (`{1..5}`) are NOT supported — they fall through
/// unchanged. Unmatched / empty braces also fall through unchanged.
///
/// This is a string-level operation; it does not know about shell quoting
/// (shlex has already stripped quotes by the time we see a token).
///
/// Depth and result counts are capped to guard against pathological
/// inputs.
pub fn expand_braces(s: &str) -> Vec<String> {
    expand_braces_inner(s, 0)
}

/// Upper bound on recursion depth for brace expansion.
const BRACE_MAX_DEPTH: usize = 8;
/// Upper bound on total expansions returned from a single input.
const BRACE_MAX_RESULTS: usize = 64;

fn expand_braces_inner(s: &str, depth: usize) -> Vec<String> {
    if depth >= BRACE_MAX_DEPTH {
        return vec![s.to_string()];
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => i += 2,
            b'{' => {
                let open = i;
                let mut j = i + 1;
                let mut dp: i32 = 1;
                let mut commas: Vec<usize> = Vec::new();
                while j < bytes.len() && dp > 0 {
                    match bytes[j] {
                        b'\\' if j + 1 < bytes.len() => j += 2,
                        b'{' => {
                            dp += 1;
                            j += 1;
                        }
                        b'}' => {
                            dp -= 1;
                            if dp == 0 {
                                break;
                            }
                            j += 1;
                        }
                        b',' if dp == 1 => {
                            commas.push(j);
                            j += 1;
                        }
                        _ => j += 1,
                    }
                }
                if dp != 0 || commas.is_empty() {
                    // Unmatched brace, `{x}`, or range `{1..5}` with
                    // no top-level comma. Not a comma-expansion; skip.
                    i += 1;
                    continue;
                }
                let close = j;
                let prefix = &s[..open];
                let suffix = &s[close + 1..];
                let mut parts: Vec<&str> = Vec::new();
                let mut last = open + 1;
                for &c in &commas {
                    parts.push(&s[last..c]);
                    last = c + 1;
                }
                parts.push(&s[last..close]);

                let mut results = Vec::new();
                for p in parts {
                    if results.len() >= BRACE_MAX_RESULTS {
                        break;
                    }
                    let combined = format!("{prefix}{p}{suffix}");
                    results.extend(expand_braces_inner(&combined, depth + 1));
                }
                if results.len() > BRACE_MAX_RESULTS {
                    results.truncate(BRACE_MAX_RESULTS);
                }
                return results;
            }
            _ => i += 1,
        }
    }
    vec![s.to_string()]
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
        PathContext::InlineCodeExecution { interpreter, flag, code_snippet } => Some(format!(
            "Blocked by `clarg`: '{} {}' inline code cannot be statically verified as internal-only: \"{}\"",
            interpreter, flag, truncate(code_snippet, 80)
        )),
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
        PathContext::Redirection => {
            // `find_redirections` has already applied bash-aware
            // tilde/$HOME expansion based on quote context, so skip
            // `expand_home` to avoid double-expanding quoted literals
            // like `'~/foo'` (which bash treats as a literal filename).
            let resolved = resolve_literal_target(&ep.raw, project_root);
            check_path_containment(&resolved, project_root, ep.context.label())
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

    // Strip heredocs / here-strings here too, not just at the top of
    // `extract_paths`: `eval` and `bash -c` recurse into us with the
    // *inner* string (which still contains shell syntax including any
    // heredoc operators) by calling this function directly.
    let stripped = strip_heredocs(command);
    let command = stripped.as_str();

    // Collect redirection targets (quote-aware; handles `> "/tmp/out.txt"`,
    // `> '/tmp/out side.txt'`, etc.).
    for r in find_redirections(command) {
        if !r.target.starts_with("/dev/") {
            paths.push(ExtractedPath {
                raw: r.target,
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
    let cleaned = strip_redirections(sub_cmd);
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
        cmd if DIR_TARGET_COMMANDS.contains(&cmd) => {
            // Non-flag args are directories (mkdir, rmdir, pushd).
            // Emit CdTarget so directory-only blocked patterns fire via
            // `PathContext::implies_directory()` downstream.
            for arg in args {
                if !arg.starts_with('-') {
                    paths.push(ExtractedPath {
                        raw: arg.clone(),
                        context: PathContext::CdTarget,
                    });
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
                        // Opaque-boundary sentinel: any rule that claims
                        // "internal-only" must fail closed on inline code
                        // because it cannot be statically verified.
                        paths.push(ExtractedPath {
                            raw: code_arg.clone(),
                            context: PathContext::InlineCodeExecution {
                                interpreter: cmd.to_string(),
                                flag: args[pos].clone(),
                                code_snippet: code_arg.clone(),
                            },
                        });
                        // Defense-in-depth: regex-extracted literal paths
                        // still populate the list so no_root / no_system_dirs /
                        // blocked_files fire on obvious external references
                        // even when `-i` is not set.
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
                        // Also catch bare `/` inside quoted string literals,
                        // which PATH_IN_CODE_RE misses (it requires at least
                        // one char after the slash).
                        for cap in BARE_ROOT_IN_CODE_RE.captures_iter(code_arg) {
                            let slash = cap.get(1).unwrap().as_str().to_string();
                            paths.push(ExtractedPath {
                                raw: slash,
                                context: PathContext::InlineCodeRef {
                                    interpreter: cmd.to_string(),
                                    flag: args[pos].clone(),
                                    code_snippet: code_arg.clone(),
                                },
                            });
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
    // Flags whose argument is a plain filesystem path (config file,
    // input-urls file, etc.) — no `@` / `=@` parsing needed.
    let helper_long_flags: &[&str] = match cmd {
        "curl" => &["--config"],
        "wget" => &["--input-file"],
        _ => &[],
    };
    let helper_short_flags: &[&str] = match cmd {
        "curl" => &["-K"],
        "wget" => &["-i"],
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
        // Separated forms for helper-file flags (e.g. `curl --config <file>`,
        // `curl -K <file>`, `wget --input-file <file>`, `wget -i <file>`).
        if helper_long_flags.contains(&arg.as_str())
            || helper_short_flags.contains(&arg.as_str())
        {
            if let Some(path_arg) = args.get(i + 1) {
                paths.push(ExtractedPath {
                    raw: path_arg.clone(),
                    context: PathContext::HelperFile,
                });
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
        // Helper-flag --flag=value forms.
        for flag in helper_long_flags {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if !value.is_empty() {
                    paths.push(ExtractedPath {
                        raw: value.to_string(),
                        context: PathContext::HelperFile,
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
        // Concatenated short form for helper flags: -K/tmp/curlrc, -i/tmp/urls.
        for flag in helper_short_flags {
            if arg.starts_with(flag) && arg.len() > flag.len() {
                let value = &arg[flag.len()..];
                paths.push(ExtractedPath {
                    raw: value.to_string(),
                    context: PathContext::HelperFile,
                });
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
///
/// `-e <expr>` / `--expression=<expr>` / `-e<concat>` are sed script
/// expressions, not file paths — skip them.
///
/// `-f <path>` / `--file=<path>` / `-f<concat>` / `--file <path>` point
/// at an external sed script file — extract as `SedFile`.
///
/// `-i` / `-i<suffix>` (GNU in-place edit) have no path argument.
fn extract_sed_paths(args: &[String], paths: &mut Vec<ExtractedPath>) {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        // Separated long/short forms that consume the next arg.
        if arg == "-e" || arg == "--expression" {
            // Expression, skip the next arg (it's sed code, not a path).
            i += 2;
            continue;
        }
        if arg == "-f" || arg == "--file" {
            if let Some(next) = args.get(i + 1) {
                paths.push(ExtractedPath {
                    raw: next.clone(),
                    context: PathContext::SedFile,
                });
            }
            i += 2;
            continue;
        }

        // `=` forms.
        if arg.starts_with("--expression=") {
            i += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--file=") {
            if !val.is_empty() {
                paths.push(ExtractedPath {
                    raw: val.to_string(),
                    context: PathContext::SedFile,
                });
            }
            i += 1;
            continue;
        }

        // Concatenated short forms: `-e<expr>`, `-f<path>`.
        if arg.len() > 2 && arg.starts_with("-e") {
            i += 1;
            continue;
        }
        if arg.len() > 2 && arg.starts_with("-f") {
            let val = &arg[2..];
            paths.push(ExtractedPath {
                raw: val.to_string(),
                context: PathContext::SedFile,
            });
            i += 1;
            continue;
        }

        // `-i` (GNU: no arg) / `-i<suffix>` (GNU with backup suffix).
        if arg == "-i" || arg.starts_with("-i") {
            i += 1;
            continue;
        }

        // Any other flag: skip.
        if arg.starts_with('-') {
            i += 1;
            continue;
        }

        // Non-flag arg: treat as file path.
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
// Heredoc / here-string scanning (quote-aware)
// ============================================================================
//
// Bash heredocs (`<<DELIM`, `<<-DELIM`, `<<'DELIM'`, `<<"DELIM"`) and
// here-strings (`<<<word`) are literal stdin payloads — their bodies
// must NOT be scanned as shell syntax. Without this pass,
// `find_redirections` and `split_shell_operators` would see body
// characters like `>` or `|` and misinterpret them as operators,
// producing false positives such as a markdown blockquote `> /` in a
// README body firing the `no_root` rule.
//
// Design:
//   * Walk the command string with the same quote-state machine as
//     `find_redirections`.
//   * At each unquoted `<<`, record an op span covering only the
//     `<<[-]DELIM` operator, and queue a pending heredoc. Same-line
//     content after the operator is intentionally NOT stripped, so
//     valid shell like `cat <<EOF > /tmp/out` still has its `>`
//     redirection picked up downstream.
//   * At each unquoted newline, drain pending heredocs in FIFO order.
//     Each body span runs from just after the newline through the
//     closing-delimiter line (inclusive of its trailing newline).
//     For `<<-`, leading tabs on the candidate line are stripped
//     before comparison.
//   * At each unquoted `<<<` (here-string), strip the operator AND
//     the one shell token that follows (bareword or quoted).
//   * Unclosed heredocs strip through end-of-input (fail-closed: we
//     don't scan content we can't reliably bound).

/// One byte span to be removed by `strip_heredocs`.
#[derive(Debug, Clone)]
pub struct HeredocSpan {
    pub start: usize,
    pub end: usize,
}

struct PendingHeredoc {
    delim: String,
    strip_tabs: bool,
}

/// Walk `cmd` and return the byte spans corresponding to heredoc
/// operators, heredoc bodies (including the closing delimiter line),
/// and here-string operator+token pairs. Spans are returned in
/// ascending start-offset order and are pairwise disjoint.
pub fn find_heredoc_spans(cmd: &str) -> Vec<HeredocSpan> {
    let bytes = cmd.as_bytes();
    let mut out: Vec<HeredocSpan> = Vec::new();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape_next = false;
    let mut pending: Vec<PendingHeredoc> = Vec::new();

    while i < bytes.len() {
        let b = bytes[i];

        if escape_next {
            escape_next = false;
            i = advance_char(bytes, i);
            continue;
        }
        if b == b'\\' && !in_single {
            escape_next = true;
            i += 1;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if in_single || in_double {
            i = advance_char(bytes, i);
            continue;
        }

        // Newline outside quotes: drain any pending heredoc bodies.
        if b == b'\n' && !pending.is_empty() {
            i += 1;
            for heredoc in std::mem::take(&mut pending) {
                let body_start = i;
                let mut line_start = i;
                let body_end;
                loop {
                    let mut line_end = line_start;
                    while line_end < bytes.len() && bytes[line_end] != b'\n' {
                        line_end += 1;
                    }
                    let line = &cmd[line_start..line_end];
                    let candidate: &str = if heredoc.strip_tabs {
                        line.trim_start_matches('\t')
                    } else {
                        line
                    };
                    if candidate == heredoc.delim {
                        body_end = if line_end < bytes.len() {
                            line_end + 1
                        } else {
                            line_end
                        };
                        break;
                    }
                    if line_end >= bytes.len() {
                        // Unclosed heredoc — fail closed by consuming
                        // everything to end of input.
                        body_end = bytes.len();
                        break;
                    }
                    line_start = line_end + 1;
                }
                out.push(HeredocSpan {
                    start: body_start,
                    end: body_end,
                });
                i = body_end;
            }
            continue;
        }

        if b == b'<' && i + 1 < bytes.len() && bytes[i + 1] == b'<' {
            // `<<<` is a here-string; strip operator + one token.
            if i + 2 < bytes.len() && bytes[i + 2] == b'<' {
                let op_start = i;
                let mut j = i + 3;
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                let end = if j >= bytes.len() {
                    j
                } else {
                    parse_hs_token_end(cmd, j)
                };
                out.push(HeredocSpan {
                    start: op_start,
                    end,
                });
                i = end;
                continue;
            }

            // Heredoc: `<<[-]DELIM` (DELIM may be quoted).
            let op_start = i;
            let mut j = i + 2;
            let strip_tabs = j < bytes.len() && bytes[j] == b'-';
            if strip_tabs {
                j += 1;
            }
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            let (delim_end, delim) = match parse_heredoc_delim(cmd, j) {
                Some(v) => v,
                None => {
                    // Malformed `<<` with no parseable delimiter: skip
                    // the operator and let the rest of the scanner
                    // proceed without queuing a heredoc.
                    i += 2;
                    continue;
                }
            };
            out.push(HeredocSpan {
                start: op_start,
                end: delim_end,
            });
            pending.push(PendingHeredoc { delim, strip_tabs });
            i = delim_end;
            continue;
        }

        i = advance_char(bytes, i);
    }

    out
}

/// Step `i` forward by one full UTF-8 character.
fn advance_char(bytes: &[u8], i: usize) -> usize {
    if i >= bytes.len() {
        return i;
    }
    let b = bytes[i];
    if b < 0x80 {
        i + 1
    } else {
        i + utf8_char_len(b)
    }
}

/// Parse a heredoc delimiter word starting at `start` and return the
/// byte offset just past the word together with the delimiter text
/// after bash-style quote removal.
///
/// The delimiter is a shell word that may freely mix bare characters,
/// `'single'`-quoted segments, `"double"`-quoted segments, and
/// backslash-escaped characters — bash quote-removes all of them
/// before matching the closing line. Examples that all resolve to the
/// literal `EOF`:
///
///   * `<<EOF`           — bareword
///   * `<<'EOF'`         — wholly single-quoted
///   * `<<"EOF"`         — wholly double-quoted
///   * `<<\EOF`          — escaped first char
///   * `<<E"OF"`         — bare `E` + double-quoted `OF`
///   * `<<E'O'F`         — bare-quoted-bare mix
///
/// The word terminates at the first unquoted whitespace or shell
/// metacharacter (`;`, `|`, `&`, `<`, `>`, `(`, `)`, `` ` ``, `#`,
/// `\n`). Parameter / command substitutions inside the delimiter
/// (`$VAR`, `$(...)`, `` `...` ``) are NOT resolved — they are copied
/// literally, which means a delim like `<<EOF$VAR` will not match a
/// closing `EOF` line. That's a soundness concern for security
/// (bash *would* expand and close), but `$VAR`/`$(...)` in a heredoc
/// delim is a deliberately obscure form; we accept the conservative
/// strip-to-EOF behavior here and rely on the caller to never trust
/// a strip whose closer wasn't actually matched.
fn parse_heredoc_delim(cmd: &str, start: usize) -> Option<(usize, String)> {
    let bytes = cmd.as_bytes();
    if start >= bytes.len() {
        return None;
    }
    let mut i = start;
    let mut out = String::new();

    while i < bytes.len() {
        let b = bytes[i];

        // Unquoted word terminators.
        if matches!(
            b,
            b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')' | b'`' | b'#'
        ) {
            break;
        }

        // Single-quoted segment: contents are pure literal.
        if b == b'\'' {
            i += 1;
            let q_start = i;
            while i < bytes.len() && bytes[i] != b'\'' {
                i = advance_char(bytes, i);
            }
            out.push_str(&cmd[q_start..i]);
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }

        // Double-quoted segment: `\` only escapes a small set; rest is
        // literal. We don't expand `$VAR` here (see fn-doc above).
        if b == b'"' {
            i += 1;
            let mut chunk_start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push_str(&cmd[chunk_start..i]);
                    i += 1;
                    let next = bytes[i];
                    let clen = if next < 0x80 { 1 } else { utf8_char_len(next) };
                    let end = (i + clen).min(bytes.len());
                    out.push_str(&cmd[i..end]);
                    i = end;
                    chunk_start = i;
                } else {
                    i = advance_char(bytes, i);
                }
            }
            out.push_str(&cmd[chunk_start..i]);
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }

        // Backslash-escape outside any quotes.
        if b == b'\\' && i + 1 < bytes.len() {
            i += 1;
            let next = bytes[i];
            let clen = if next < 0x80 { 1 } else { utf8_char_len(next) };
            let end = (i + clen).min(bytes.len());
            out.push_str(&cmd[i..end]);
            i = end;
            continue;
        }

        // Bare character.
        let clen = if b < 0x80 { 1 } else { utf8_char_len(b) };
        let end = (i + clen).min(bytes.len());
        out.push_str(&cmd[i..end]);
        i = end;
    }

    if out.is_empty() {
        None
    } else {
        Some((i, out))
    }
}

/// Find the byte offset just past the end of a here-string token
/// beginning at `start`.
///
/// A here-string takes a full shell word, so the parser must keep
/// going past whitespace and shell metachars whenever they appear
/// inside an active sub-context:
///
///   * `'...'`            — single-quoted segment (literal)
///   * `"..."`            — double-quoted segment (`$()`/`${}`/`` ` ``
///                          remain active inside)
///   * `$(...)` (nested)  — command substitution; tracks balanced `()`
///                          and quote toggles within
///   * `${...}` (nested)  — parameter expansion; tracks balanced `{}`
///   * `` `...` ``        — backtick command substitution
///   * `\c`               — backslash-escape of next char
///
/// Top-level termination is the same set of unquoted shell metachars
/// used elsewhere in this module.
///
/// Without this, a here-string like `cat <<< $(echo /etc/passwd)`
/// would be terminated at `(` and the trailing `/etc/passwd)` would
/// re-tokenize into a spurious external file path.
fn parse_hs_token_end(cmd: &str, start: usize) -> usize {
    let bytes = cmd.as_bytes();
    let mut i = start;
    let mut in_single = false;
    let mut in_double = false;
    let mut paren_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let mut backtick_open = false;
    let mut escape_next = false;

    while i < bytes.len() {
        let b = bytes[i];

        if escape_next {
            escape_next = false;
            i = advance_char(bytes, i);
            continue;
        }
        if b == b'\\' && !in_single {
            escape_next = true;
            i += 1;
            continue;
        }

        // Single-quoted is literal — only `'` exits.
        if in_single {
            if b == b'\'' {
                in_single = false;
                i += 1;
                continue;
            }
            i = advance_char(bytes, i);
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = true;
            i += 1;
            continue;
        }

        // Double-quote toggles. Inside double-quotes, `$()` / `${}` /
        // backticks remain active.
        if b == b'"' {
            in_double = !in_double;
            i += 1;
            continue;
        }

        // Open a `$()` command substitution.
        if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            paren_depth += 1;
            i += 2;
            continue;
        }
        // Open a `${}` parameter expansion.
        if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            brace_depth += 1;
            i += 2;
            continue;
        }
        // Backtick command substitution toggles.
        if b == b'`' {
            backtick_open = !backtick_open;
            i += 1;
            continue;
        }

        // Track nested `()` inside an active `$()`.
        if paren_depth > 0 {
            if b == b'(' {
                paren_depth += 1;
                i += 1;
                continue;
            }
            if b == b')' {
                paren_depth -= 1;
                i += 1;
                continue;
            }
        }
        // Track nested `{}` inside an active `${}`.
        if brace_depth > 0 {
            if b == b'{' {
                brace_depth += 1;
                i += 1;
                continue;
            }
            if b == b'}' {
                brace_depth -= 1;
                i += 1;
                continue;
            }
        }

        // Inside any active sub-context, swallow the byte without
        // terminating on metachars.
        if in_double || backtick_open || paren_depth > 0 || brace_depth > 0 {
            i = advance_char(bytes, i);
            continue;
        }

        // Top-level metachar terminates the word.
        if matches!(
            b,
            b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')' | b'#'
        ) {
            break;
        }

        i = advance_char(bytes, i);
    }
    i
}

/// Replace every span returned by `find_heredoc_spans` with a single
/// space, preserving token boundaries on either side. Returns the
/// original string unchanged when no heredoc / here-string is present.
pub fn strip_heredocs(cmd: &str) -> String {
    if !cmd.contains("<<") {
        return cmd.to_string();
    }
    let spans = find_heredoc_spans(cmd);
    if spans.is_empty() {
        return cmd.to_string();
    }
    let mut out = String::with_capacity(cmd.len());
    let mut cursor = 0;
    for span in &spans {
        if span.start > cursor {
            out.push_str(&cmd[cursor..span.start]);
        }
        out.push(' ');
        cursor = span.end;
    }
    if cursor < cmd.len() {
        out.push_str(&cmd[cursor..]);
    }
    out
}

// ============================================================================
// Redirection scanning (quote-aware)
// ============================================================================

/// One redirection found in a command string.
///
/// `start`..`end` spans the entire operator + optional whitespace + target
/// (so that the caller can strip the whole thing before shlex sees it).
/// `target` is the unquoted target path.
#[derive(Debug, Clone)]
pub struct RedirMatch {
    pub start: usize,
    pub end: usize,
    pub target: String,
}

/// Find all shell output redirections in `cmd`, respecting single- and
/// double-quote state. Recognises `>`, `>>`, `2>`, `&>` (and any
/// `<digit>*>{1,2}` prefix). Skips fd-redirects like `2>&1`.
///
/// Returns matches in left-to-right order.
pub fn find_redirections(cmd: &str) -> Vec<RedirMatch> {
    let bytes = cmd.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape_next = false;

    while i < bytes.len() {
        let b = bytes[i];

        if escape_next {
            escape_next = false;
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single {
            escape_next = true;
            i += 1;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if in_single || in_double {
            i += 1;
            continue;
        }

        // Try to match a redirection operator starting at i.
        let op_start = i;
        let mut j = i;
        // optional leading digit(s): `2>`, `11>`, etc.
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        let had_digit = j > op_start;
        let op_match = if j < bytes.len() && bytes[j] == b'>' {
            // `>` or `>>`
            let mut k = j + 1;
            if k < bytes.len() && bytes[k] == b'>' {
                k += 1;
            }
            Some(k)
        } else if !had_digit
            && j + 1 < bytes.len()
            && bytes[j] == b'&'
            && bytes[j + 1] == b'>'
        {
            // `&>` only if we did not consume digits (those are fd refs).
            Some(j + 2)
        } else {
            None
        };

        let op_end = match op_match {
            Some(end) => end,
            None => {
                i += 1;
                continue;
            }
        };

        // Skip horizontal whitespace between operator and target.
        let mut t = op_end;
        while t < bytes.len() && (bytes[t] == b' ' || bytes[t] == b'\t') {
            t += 1;
        }
        if t >= bytes.len() {
            // Trailing redirect with no target — leave for shell to error.
            i = op_end;
            continue;
        }

        // Skip fd-redirects like `2>&1` or `>&2`.
        if bytes[t] == b'&'
            && t + 1 < bytes.len()
            && (bytes[t + 1].is_ascii_digit() || bytes[t + 1] == b'-')
        {
            // Advance past the `&<digits>` reference and continue.
            let mut k = t + 1;
            while k < bytes.len() && bytes[k].is_ascii_digit() {
                k += 1;
            }
            if t + 1 < bytes.len() && bytes[t + 1] == b'-' {
                k = t + 2;
            }
            i = k;
            continue;
        }

        // Parse a target token (bareword, 'single', "double", or mixed).
        let (target_end, target) = match parse_shell_token(cmd, t) {
            Some(v) => v,
            None => {
                i = op_end;
                continue;
            }
        };

        out.push(RedirMatch {
            start: op_start,
            end: target_end,
            target,
        });
        i = target_end;
    }

    out
}

/// Remove every redirection span found by `find_redirections` from `cmd`.
/// Used so shlex (which doesn't know about shell redirection) doesn't see
/// the redirect operator or its quoted target.
pub fn strip_redirections(cmd: &str) -> String {
    let matches = find_redirections(cmd);
    if matches.is_empty() {
        return cmd.to_string();
    }
    let mut out = String::with_capacity(cmd.len());
    let mut cursor = 0;
    for m in matches {
        out.push_str(&cmd[cursor..m.start]);
        // Leave a single space so token boundaries stay intact:
        // `echo hi>/tmp/x` must not collapse to `echohi`.
        out.push(' ');
        cursor = m.end;
    }
    out.push_str(&cmd[cursor..]);
    out
}

/// Parse a single shell token (possibly quoted or mixed quoted/bare)
/// starting at byte offset `start` of `cmd`, applying bash-style
/// tilde and `$HOME` expansion **based on the source-level quote
/// context**. Returns the byte offset after the token and the
/// bash-expanded literal.
///
/// Quote rules mirror bash:
/// - Inside `'...'`: everything is literal — `~`, `$HOME`, and `\`
///   do not expand/escape.
/// - Inside `"..."`: `$HOME` expands; `~` does NOT; `\` only escapes
///   `"`, `\\`, `$`, `` ` ``, and newline.
/// - Outside quotes: leading `~` expands (including `~<login-name>`);
///   `$HOME` expands wherever it appears; `\c` is literal `c`.
///
/// Stops at unquoted whitespace, `;`, `|`, `&`, `<`, `>`, `(`, `)`,
/// `` ` `` or `#`.
///
/// UTF-8 safe: all slicing is on char boundaries (quotes, escapes,
/// and terminators are ASCII, so non-ASCII bytes are copied through
/// as-is via `&cmd[..]` slicing).
fn parse_shell_token(cmd: &str, start: usize) -> Option<(usize, String)> {
    let bytes = cmd.as_bytes();
    if start >= bytes.len() {
        return None;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let mut out = String::new();
    let mut i = start;
    let mut started = false;
    // `at_word_start` governs leading-tilde expansion. Bash only
    // expands a tilde at the start of a word (or right after `=` /
    // `:` in certain assignments, which we don't care about for
    // redirection targets).
    let mut at_word_start = true;

    while i < bytes.len() {
        let b = bytes[i];
        // Word terminators (outside any quote state — this branch is
        // only reached in the top-level unquoted loop).
        if matches!(
            b,
            b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')' | b'`' | b'#'
        ) {
            break;
        }
        // Non-ASCII passes through.
        if b >= 0x80 {
            started = true;
            at_word_start = false;
            let char_len = utf8_char_len(b);
            let end = (i + char_len).min(bytes.len());
            out.push_str(&cmd[i..end]);
            i = end;
            continue;
        }
        match b {
            b'\'' => {
                // Single-quoted: pure literal pass-through.
                started = true;
                at_word_start = false;
                i += 1;
                let q_start = i;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
                out.push_str(&cmd[q_start..i]);
                if i < bytes.len() {
                    i += 1;
                }
            }
            b'"' => {
                // Double-quoted: `$HOME` expands; `\` escapes only a
                // limited set; `~` is literal (bash doesn't do tilde
                // expansion in double quotes).
                started = true;
                at_word_start = false;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    let bi = bytes[i];
                    if bi == b'\\' && i + 1 < bytes.len() {
                        let nb = bytes[i + 1];
                        if matches!(nb, b'"' | b'\\' | b'$' | b'`' | b'\n') {
                            // Escape consumed; emit just the escaped char.
                            let nlen = if nb >= 0x80 { utf8_char_len(nb) } else { 1 };
                            let ns = i + 1;
                            let ne = (ns + nlen).min(bytes.len());
                            out.push_str(&cmd[ns..ne]);
                            i = ne;
                        } else {
                            // Backslash is literal when followed by any other char.
                            out.push('\\');
                            let nlen = if nb >= 0x80 { utf8_char_len(nb) } else { 1 };
                            let ns = i + 1;
                            let ne = (ns + nlen).min(bytes.len());
                            out.push_str(&cmd[ns..ne]);
                            i = ne;
                        }
                    } else if bi == b'$' && cmd[i..].starts_with("$HOME") {
                        let after = i + "$HOME".len();
                        let complete = after >= bytes.len()
                            || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_');
                        if complete {
                            out.push_str(&home);
                            i = after;
                        } else {
                            out.push('$');
                            i += 1;
                        }
                    } else if bi >= 0x80 {
                        let nlen = utf8_char_len(bi);
                        let ne = (i + nlen).min(bytes.len());
                        out.push_str(&cmd[i..ne]);
                        i = ne;
                    } else {
                        out.push(bi as char);
                        i += 1;
                    }
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            b'\\' if i + 1 < bytes.len() => {
                // Unquoted backslash: next char literal, no expansion.
                started = true;
                at_word_start = false;
                let nb = bytes[i + 1];
                let nlen = if nb >= 0x80 { utf8_char_len(nb) } else { 1 };
                let ns = i + 1;
                let ne = (ns + nlen).min(bytes.len());
                out.push_str(&cmd[ns..ne]);
                i = ne;
            }
            b'~' if at_word_start => {
                // Leading unquoted tilde: apply bash tilde expansion.
                // The tilde-prefix extends to the next `/` or an
                // unquoted word boundary / quote character.
                started = true;
                let prefix_start = i + 1;
                let mut prefix_end = prefix_start;
                while prefix_end < bytes.len() {
                    let c = bytes[prefix_end];
                    if c == b'/'
                        || matches!(
                            c,
                            b' ' | b'\t' | b'\n' | b';' | b'|' | b'&'
                                | b'<' | b'>' | b'(' | b')' | b'`' | b'#'
                                | b'\'' | b'"' | b'\\'
                        )
                    {
                        break;
                    }
                    prefix_end += 1;
                }
                let tilde_prefix = &cmd[prefix_start..prefix_end];
                if tilde_prefix.is_empty() {
                    // Bare `~` or `~/...` or `~<word-break>`.
                    out.push_str(&home);
                    i = prefix_end;
                } else if is_valid_login_name(tilde_prefix) {
                    out.push_str(&tilde_user_home(tilde_prefix));
                    i = prefix_end;
                } else {
                    // Not a recognized login name — bash leaves the
                    // whole tilde-prefix literal (covers `~+`, `~-`,
                    // `~N`, etc.).
                    out.push('~');
                    i += 1;
                }
                at_word_start = false;
            }
            b'$' if cmd[i..].starts_with("$HOME") => {
                // Unquoted `$HOME` expansion.
                started = true;
                at_word_start = false;
                let after = i + "$HOME".len();
                let complete = after >= bytes.len()
                    || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_');
                if complete {
                    out.push_str(&home);
                    i = after;
                } else {
                    out.push('$');
                    i += 1;
                }
            }
            _ => {
                started = true;
                at_word_start = false;
                out.push(b as char);
                i += 1;
            }
        }
    }
    if !started {
        return None;
    }
    Some((i, out))
}

/// UTF-8 codepoint length given its leading byte.
fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b < 0xC0 {
        1 // stray continuation byte — treat as 1 to make progress
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
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
