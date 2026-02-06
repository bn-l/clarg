use crate::internalonly::{check_path_containment, resolve_target};
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

/// Analyze a full bash command string for paths outside the project root.
/// Returns Some(reason) if any violation is found.
pub fn analyze(command: &str, project_root: &Path) -> Option<String> {
    analyze_recursive(command, project_root, 0)
}

fn analyze_recursive(
    command: &str,
    project_root: &Path,
    depth: usize,
) -> Option<String> {
    if depth > MAX_RECURSION {
        return None;
    }

    // Phase 1: Check output redirections
    for cap in REDIRECT_RE.captures_iter(command) {
        let target = &cap[1];
        // Skip /dev/null and other special paths
        if target.starts_with("/dev/") {
            continue;
        }
        let resolved = resolve_target(target, project_root);
        if let Some(reason) = check_path_containment(
            &resolved,
            project_root,
            &format!("redirection target"),
        ) {
            return Some(reason);
        }
    }

    // Phase 2: Split on shell operators and analyze each sub-command
    let sub_commands = split_shell_operators(command);
    for sub_cmd in &sub_commands {
        let trimmed = sub_cmd.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(reason) =
            analyze_sub_command(trimmed, project_root, depth)
        {
            return Some(reason);
        }
    }

    None
}

/// Extract all filesystem paths referenced by a bash command.
/// Used by the router to check extracted paths against blocked_files rules.
pub fn extract_paths(command: &str) -> Vec<String> {
    let mut paths = Vec::new();
    extract_paths_recursive(command, &mut paths, 0);
    paths
}

fn extract_paths_recursive(command: &str, paths: &mut Vec<String>, depth: usize) {
    if depth > MAX_RECURSION {
        return;
    }

    // Collect redirection targets
    for cap in REDIRECT_RE.captures_iter(command) {
        let target = &cap[1];
        if !target.starts_with("/dev/") {
            paths.push(target.to_string());
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

fn extract_paths_from_sub_command(sub_cmd: &str, paths: &mut Vec<String>, depth: usize) {
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
            if let Some(target) = args.first() {
                if target != "-" {
                    paths.push(target.clone());
                }
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
                    paths.push(arg.clone());
                    break;
                }
            }
        }
        cmd if FILE_COMMANDS.contains(&cmd) => {
            for arg in args {
                if !arg.starts_with('-') {
                    paths.push(arg.clone());
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
                paths.push(arg.clone());
                i += 1;
            }
        }
        cmd if EXEC_COMMANDS.contains(&cmd) => {
            for arg in args {
                if !arg.starts_with('-') {
                    paths.push(arg.clone());
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
            // dd uses key=value syntax; extract values from if= and of=
            let path_keys = ["if", "of"];
            for arg in args {
                if let Some((key, value)) = arg.split_once('=') {
                    if path_keys.contains(&key) {
                        paths.push(value.to_string());
                    }
                }
            }
        }
        _ => {
            for arg in args {
                if !arg.starts_with('-') && looks_like_path(arg) {
                    paths.push(arg.clone());
                }
            }
        }
    }
}

/// Extract paths from download command arguments (for extract_paths).
fn extract_download_paths(args: &[String], cmd: &str, paths: &mut Vec<String>) {
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
                paths.push(path_arg.clone());
            }
            i += 2;
            continue;
        }
        if data_long_flags.contains(&arg.as_str()) || data_short_flags.contains(&arg.as_str()) {
            if let Some(data_arg) = args.get(i + 1) {
                if let Some(p) = extract_path_from_curl_data(data_arg) {
                    paths.push(p);
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
                        paths.push(p);
                    }
                } else {
                    paths.push(value.to_string());
                }
            }
        }
        // Handle concatenated short flags: -d@path, -T/path
        for flag in data_short_flags {
            if arg.starts_with(flag) && arg.len() > flag.len() {
                let value = &arg[flag.len()..];
                if let Some(p) = extract_path_from_curl_data(value) {
                    paths.push(p);
                }
            }
        }
        i += 1;
    }
}

/// Extract a path from a curl data argument (for extract_paths).
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

/// Extract paths from sed arguments (for extract_paths).
fn extract_sed_paths(args: &[String], paths: &mut Vec<String>) {
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
            paths.push(arg.clone());
        }
        i += 1;
    }
}

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

/// Analyze a single sub-command (no shell operators).
fn analyze_sub_command(
    sub_cmd: &str,
    project_root: &Path,
    depth: usize,
) -> Option<String> {
    // Strip the redirection parts from the command string before tokenizing,
    // since we already checked redirections in the outer function.
    let cleaned = REDIRECT_RE.replace_all(sub_cmd, "");
    let tokens = match shlex::split(&cleaned) {
        Some(t) => t,
        None => return None, // unparseable; we already checked redirections
    };
    if tokens.is_empty() {
        return None;
    }

    // Skip env var prefixes (KEY=value), sudo, env
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
        return None;
    }

    let cmd_name = &tokens[start];
    let args = &tokens[start + 1..];

    // Route by command name
    match cmd_name.as_str() {
        "cd" => check_cd(args, project_root),
        "eval" => check_eval(args, project_root, depth),
        "bash" | "sh" | "zsh" | "dash" => {
            check_shell_exec(args, cmd_name, project_root, depth)
        }
        cmd if FILE_COMMANDS.contains(&cmd) => {
            check_generic_file_cmd(args, project_root)
        }
        cmd if SEARCH_COMMANDS.contains(&cmd) => {
            check_search_cmd(args, project_root)
        }
        cmd if EXEC_COMMANDS.contains(&cmd) => {
            check_exec_cmd(args, cmd, project_root, depth)
        }
        cmd if DOWNLOAD_COMMANDS.contains(&cmd) => {
            check_download_cmd(args, cmd, project_root)
        }
        "sed" => check_sed(args, project_root),
        "dd" => check_dd(args, project_root),
        _ => check_unknown_cmd(args, project_root),
    }
}

/// Check `cd` command. Block if target is outside project, no args (-> $HOME), or `-`.
fn check_cd(args: &[String], project_root: &Path) -> Option<String> {
    if args.is_empty() {
        return Some(
            "Blocked by `clarg`: 'cd' with no arguments would navigate to $HOME, outside the project directory".to_string()
        );
    }
    let target = &args[0];
    if target == "-" {
        return Some(
            "Blocked by `clarg`: 'cd -' could navigate outside the project directory".to_string()
        );
    }
    let resolved = resolve_target(target, project_root);
    check_path_containment(
        &resolved,
        project_root,
        &format!("'cd {target}' would navigate to"),
    )
}

/// Check `eval "..."` — recursively analyze the evaluated string.
fn check_eval(
    args: &[String],
    project_root: &Path,
    depth: usize,
) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    let eval_cmd = args.join(" ");
    if let Some(reason) = analyze_recursive(&eval_cmd, project_root, depth + 1)
    {
        return Some(format!(
            "Blocked by `clarg`: 'eval \"{}\"' contains a command that {}",
            truncate(&eval_cmd, 80),
            extract_core_reason(&reason)
        ));
    }
    None
}

/// Check `bash -c "..."`, `sh -c "..."`, etc.
fn check_shell_exec(
    args: &[String],
    shell: &str,
    project_root: &Path,
    depth: usize,
) -> Option<String> {
    // Look for -c flag
    if let Some(pos) = args.iter().position(|t| t == "-c") {
        if let Some(inner_cmd) = args.get(pos + 1) {
            if let Some(reason) =
                analyze_recursive(inner_cmd, project_root, depth + 1)
            {
                return Some(format!(
                    "Blocked by `clarg`: '{shell} -c \"{}\"' contains a command that {}",
                    truncate(inner_cmd, 80),
                    extract_core_reason(&reason)
                ));
            }
            return None;
        }
    }
    // Otherwise treat as executing a script file
    check_exec_cmd(args, shell, project_root, depth)
}

/// Check file manipulation commands: skip flags, check remaining args as paths.
fn check_generic_file_cmd(args: &[String], project_root: &Path) -> Option<String> {
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        if looks_like_path(arg) {
            let resolved = resolve_target(arg, project_root);
            if let Some(reason) =
                check_path_containment(&resolved, project_root, "path")
            {
                return Some(reason);
            }
        }
    }
    None
}

/// Check search commands: skip flags and their arguments, check remaining as paths.
fn check_search_cmd(args: &[String], project_root: &Path) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if SEARCH_ARG_FLAGS.contains(&arg.as_str()) {
            i += 2; // skip flag and its argument
            continue;
        }
        // Handle --flag=value
        if arg.starts_with('-') && arg.contains('=') {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        // Non-flag argument — check if it's a path
        if looks_like_path(arg) {
            let resolved = resolve_target(arg, project_root);
            if let Some(reason) =
                check_path_containment(&resolved, project_root, "path")
            {
                return Some(reason);
            }
        }
        i += 1;
    }
    None
}

/// Check execute-like commands (python, node, etc.): check file arguments as paths.
/// For interpreters that support -c/-e, recursively analyze inline code strings.
fn check_exec_cmd(
    args: &[String],
    cmd: &str,
    project_root: &Path,
    depth: usize,
) -> Option<String> {
    // For interpreters that support -c/-e, scan inline code for external paths
    if INLINE_CODE_INTERPRETERS.contains(&cmd) {
        let code_flags: &[&str] = match cmd {
            "node" => &["-e", "--eval"],
            _ => &["-c", "-e"],
        };
        if let Some(pos) = args.iter().position(|t| code_flags.contains(&t.as_str())) {
            if let Some(code_arg) = args.get(pos + 1) {
                if let Some(reason) =
                    scan_code_for_paths(code_arg, cmd, &args[pos], project_root)
                {
                    return Some(reason);
                }
            }
            return None;
        }
    }

    // Otherwise check file path arguments
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        if looks_like_path(arg) {
            let resolved = resolve_target(arg, project_root);
            if let Some(reason) =
                check_path_containment(&resolved, project_root, "path")
            {
                return Some(reason);
            }
        }
        // Only check the first non-flag arg for exec commands
        break;
    }
    None
}

/// Check download commands: `curl -o <path>`, `wget -O <path>`, and upload flags.
fn check_download_cmd(
    args: &[String],
    cmd: &str,
    project_root: &Path,
) -> Option<String> {
    let output_flags: &[&str] = match cmd {
        "curl" => &["-o", "--output"],
        "wget" => &["-O", "--output-document"],
        _ => &[],
    };

    // Long flags whose next argument may reference a file path (via @path syntax)
    let data_long_flags: &[&str] = match cmd {
        "curl" => &[
            "--data", "--data-binary", "--data-raw", "--data-urlencode",
            "--form", "--upload-file",
        ],
        _ => &[],
    };

    // Short flags whose next argument (or concatenated value) may reference a file
    let data_short_flags: &[&str] = match cmd {
        "curl" => &["-d", "-F", "-T"],
        _ => &[],
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        // Check output flags (path is next arg)
        if output_flags.contains(&arg.as_str()) {
            if let Some(path_arg) = args.get(i + 1) {
                let resolved = resolve_target(path_arg, project_root);
                if let Some(reason) = check_path_containment(
                    &resolved,
                    project_root,
                    "download output path",
                ) {
                    return Some(reason);
                }
            }
            i += 2;
            continue;
        }

        // Check data/upload long flags as standalone tokens (next arg has value)
        if data_long_flags.contains(&arg.as_str()) {
            if let Some(data_arg) = args.get(i + 1) {
                if let Some(reason) = check_curl_data_path(data_arg, project_root) {
                    return Some(reason);
                }
            }
            i += 2;
            continue;
        }

        // Check data/upload short flags as standalone tokens (next arg has value)
        if data_short_flags.contains(&arg.as_str()) {
            if let Some(data_arg) = args.get(i + 1) {
                if let Some(reason) = check_curl_data_path(data_arg, project_root) {
                    return Some(reason);
                }
            }
            i += 2;
            continue;
        }

        // Handle --output=value
        for flag in output_flags {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                let resolved = resolve_target(value, project_root);
                if let Some(reason) = check_path_containment(
                    &resolved,
                    project_root,
                    "download output path",
                ) {
                    return Some(reason);
                }
            }
        }

        // Handle --data=@path, --form=field=@path, --upload-file=path, etc.
        for flag in data_long_flags {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if let Some(reason) = check_curl_data_path(value, project_root) {
                    return Some(reason);
                }
            }
        }

        // Handle concatenated short flags: -d@path, -Ffile=@path, -T/path
        for flag in data_short_flags {
            if arg.starts_with(flag) && arg.len() > flag.len() {
                let value = &arg[flag.len()..];
                if let Some(reason) = check_curl_data_path(value, project_root) {
                    return Some(reason);
                }
            }
        }

        i += 1;
    }
    None
}

/// Check a curl data argument for file path references.
/// Handles `@path`, `field=@path`, and direct paths (for -T/--upload-file).
fn check_curl_data_path(data_arg: &str, project_root: &Path) -> Option<String> {
    let path_str = if let Some(at_path) = data_arg.strip_prefix('@') {
        at_path
    } else if data_arg.contains("=@") {
        match data_arg.split_once("=@") {
            Some((_, path)) => path,
            None => return None,
        }
    } else if looks_like_path(data_arg) {
        data_arg
    } else {
        return None;
    };

    if path_str.is_empty() {
        return None;
    }

    let resolved = resolve_target(path_str, project_root);
    check_path_containment(&resolved, project_root, "upload/data file path")
}

/// Check `sed` specifically: it can take `-i` followed by a suffix, and filenames.
fn check_sed(args: &[String], project_root: &Path) -> Option<String> {
    let mut i = 0;
    let mut skip_next = false;
    while i < args.len() {
        if skip_next {
            skip_next = false;
            i += 1;
            continue;
        }
        let arg = &args[i];
        // -e and -f take an argument
        if arg == "-e" || arg == "-f" {
            skip_next = true;
            i += 1;
            continue;
        }
        // -i may have an optional suffix (no space on macOS, space on GNU)
        if arg == "-i" || arg.starts_with("-i") {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        // Non-flag: could be a sed expression or a file path
        // Heuristic: if it contains a path separator or looks like a path, check it
        if looks_like_path(arg) {
            let resolved = resolve_target(arg, project_root);
            if let Some(reason) =
                check_path_containment(&resolved, project_root, "path")
            {
                return Some(reason);
            }
        }
        i += 1;
    }
    None
}

/// Regex to extract absolute paths and home paths from inline code strings.
static PATH_IN_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:/[a-zA-Z0-9_.@-][a-zA-Z0-9_.@/-]*|~/[a-zA-Z0-9_.@/-]+|\$HOME/[a-zA-Z0-9_.@/-]+)"#).unwrap()
});

/// Scan an inline code string (from python -c, node -e, etc.) for external paths.
fn scan_code_for_paths(
    code: &str,
    cmd: &str,
    flag: &str,
    project_root: &Path,
) -> Option<String> {
    for mat in PATH_IN_CODE_RE.find_iter(code) {
        let path_str = mat.as_str();
        // Skip /dev/ paths
        if path_str.starts_with("/dev/") {
            continue;
        }
        let resolved = resolve_target(path_str, project_root);
        if let Some(_) = check_path_containment(&resolved, project_root, "path") {
            return Some(format!(
                "Blocked by `clarg`: '{cmd} {flag} \"{}\"' references external path '{}'",
                truncate(code, 80),
                path_str
            ));
        }
    }
    None
}

/// Check `dd` command: parse key=value arguments and check path values.
fn check_dd(args: &[String], project_root: &Path) -> Option<String> {
    let path_keys = ["if", "of"];
    for arg in args {
        if let Some((key, value)) = arg.split_once('=') {
            if path_keys.contains(&key) && looks_like_path(value) {
                let resolved = resolve_target(value, project_root);
                if let Some(reason) =
                    check_path_containment(&resolved, project_root, "path")
                {
                    return Some(reason);
                }
            }
        }
    }
    None
}

/// For unknown commands, check all non-flag tokens that look like paths.
fn check_unknown_cmd(args: &[String], project_root: &Path) -> Option<String> {
    for arg in args {
        if arg.starts_with('-') {
            // Check --flag=value patterns for embedded paths
            if let Some((_flag, value)) = arg.split_once('=') {
                if looks_like_path(value) {
                    let resolved = resolve_target(value, project_root);
                    if let Some(reason) =
                        check_path_containment(&resolved, project_root, "path")
                    {
                        return Some(reason);
                    }
                }
            }
            continue;
        }
        if looks_like_path(arg) {
            let resolved = resolve_target(arg, project_root);
            if let Some(reason) =
                check_path_containment(&resolved, project_root, "path")
            {
                return Some(reason);
            }
        }
    }
    None
}

/// Heuristic: does a token look like a filesystem path?
pub fn looks_like_path(token: &str) -> bool {
    token.contains('/')
        || token.starts_with('.')
        || token.starts_with('~')
        || token.starts_with("$HOME")
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..s.floor_char_boundary(max)]
    }
}

/// Extract the core reason from a full "Blocked by `clarg`: ..." message.
fn extract_core_reason(reason: &str) -> &str {
    reason
        .strip_prefix("Blocked by `clarg`: ")
        .unwrap_or(reason)
}
