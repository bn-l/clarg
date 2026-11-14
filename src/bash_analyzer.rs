use crate::internalonly::{
    check_path_containment, is_valid_login_name, resolve_literal_target, resolve_target,
    tilde_user_home,
};
use crate::shell_state::{ShellState, expand_vars, is_valid_name, parse_assignment};
use crate::system_paths::{contains_glob_meta, is_safe_device};
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

/// Regex to extract absolute paths and home paths from the inline-code scan surface.
static PATH_IN_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:/[a-zA-Z0-9_.@-][a-zA-Z0-9_.@/-]*|~/[a-zA-Z0-9_.@/-]+|\$HOME/[a-zA-Z0-9_.@/-]+)"#).unwrap()
});

// ============================================================================
// Extracted path types
// ============================================================================

/// A filesystem path extracted from a bash command, tagged with how it was referenced.
#[derive(Debug, Clone)]
pub struct ExtractedPath {
    /// The path as bash would see it. Relative paths that follow a `cd`
    /// in the same command are already joined onto that directory.
    pub raw: String,
    pub context: PathContext,
    /// True when `raw` contains a glob metacharacter (`*`, `?`, `[`)
    /// that the shell will expand — i.e. one that was neither quoted
    /// nor escaped. `'/*'` is a literal name; `/*` iterates `/`.
    pub unquoted_glob: bool,
}

impl ExtractedPath {
    pub fn new(raw: impl Into<String>, context: PathContext) -> Self {
        Self {
            raw: raw.into(),
            context,
            unquoted_glob: false,
        }
    }
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
///
/// The same quote masking also marks quoted / escaped glob characters
/// (`'/*'` is a literal name; see `ExtractedPath::unquoted_glob`) and
/// single-quoted `$`.
///
/// Relative paths after a `cd` in the same command are joined onto that
/// directory; relative paths before any `cd` are left as written.
pub fn extract_paths(command: &str) -> Vec<ExtractedPath> {
    extract_paths_from(command, None)
}

/// Like `extract_paths`, with `start_dir` — the shell's working directory
/// when the command starts — used to expand `$PWD`.
pub fn extract_paths_from(command: &str, start_dir: Option<&Path>) -> Vec<ExtractedPath> {
    let mut ex = Extraction::default();
    let mut state = ShellState::new(start_dir);
    walk(command, &mut ex, 0, &mut state, false);
    expand_brace_paths(ex.paths)
        .into_iter()
        .map(|mut ep| {
            // Masked (quoted / escaped) glob characters are sentinels,
            // so only globs the shell will expand are counted.
            ep.unquoted_glob = contains_glob_meta(&ep.raw);
            unmask_extracted_path(ep)
        })
        .collect()
}

/// Extract path-like references from inline interpreter source.
///
/// Static verification of arbitrary inline source remains impossible, so
/// `InlineCodeExecution` still denies under internal-only semantics. For the
/// narrower system-path and blocked-file rules, we scan a masked source surface:
/// comments and regex literals are blanked out, while strings and other literal
/// syntaxes stay visible. That catches obvious literal paths without confusing
/// JavaScript regex syntax like `/.{0,100}foo/g` with filesystem paths.
fn extract_inline_code_refs(code_arg: &str, interpreter: &str) -> Vec<String> {
    let scan_code = unmask_specials(code_arg);
    let scan_surface = inline_code_path_scan_surface(&scan_code, interpreter);
    let mut refs = Vec::new();

    for mat in PATH_IN_CODE_RE.find_iter(&scan_surface) {
        refs.push(widen_to_token(&scan_surface, mat.start(), mat.end()));
    }

    // PATH_IN_CODE_RE requires a character after `/`, so preserve the
    // bare-root guard for string literals like `os.chdir("/")`.
    if has_bare_root_target(&scan_surface, interpreter)
        || contains_bare_root_delimited_literal(&scan_surface, interpreter)
    {
        refs.push("/".to_string());
    }
    refs
}

/// A `PATH_IN_CODE_RE` match can start in the middle of a relative path:
/// `"../../"` matches `/../` and `"src/usr/lib"` matches `/usr/lib`.
/// Widen such a match to the whole token so it is resolved as the
/// relative path it is. `"//etc/passwd"` widens to itself and stays
/// absolute. After `$` or `}` (`$DIR/etc`, `${base}/etc`) the prefix is
/// unknowable, so the absolute fragment is kept (conservative).
fn widen_to_token(surface: &str, start: usize, end: usize) -> String {
    let bytes = surface.as_bytes();
    if bytes[start] != b'/' {
        return surface[start..end].to_string();
    }
    let is_path_byte =
        |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'@' | b'~' | b'/' | b'-');
    let mut k = start;
    while k > 0 && is_path_byte(bytes[k - 1]) {
        k -= 1;
    }
    let clear_boundary = k == 0
        || matches!(bytes[k - 1], b'\'' | b'"' | b'`' | b'(' | b',' | b'[' | b'=')
        || bytes[k - 1].is_ascii_whitespace();
    // Keep the absolute fragment when the prefix is unknowable (`$DIR/`,
    // `${base}/`, `%s/`) or a flag (`-C/etc`).
    if k == start || !clear_boundary || bytes[k] == b'-' {
        return surface[start..end].to_string();
    }
    surface[k..end].to_string()
}

/// String functions and methods: a `"/"` passed to one of these is a
/// separator or affix, not a filesystem target.
const STRING_FUNCS: &[&str] = &[
    "split", "rsplit", "join", "replace", "replaceAll", "startsWith", "endsWith",
    "startswith", "endswith", "includes", "indexOf", "lastIndexOf", "strip", "lstrip",
    "rstrip", "trim", "ltrim", "rtrim", "removeprefix", "removesuffix", "count", "find",
    "rfind", "index", "rindex", "partition", "rpartition", "sub", "gsub", "tr", "chomp",
    "explode", "implode", "str_replace", "strpos", "preg_split", "preg_replace",
    "start_with?", "end_with?", "include?",
];

/// Does the scan surface contain a bare `"/"` string literal that may be
/// a filesystem target (`os.chdir("/")`, `rmtree('/')`, `cwd="/"`)?
///
/// A literal is ignored only with positive evidence of string use: it is
/// the receiver of a method (`"/".join(…)`), an operand of `+`, `==`,
/// `!=`, `in`, `..` or `.`-concatenation, or an argument of a string
/// function (`x.split("/")`, `p.replace(/\\/g, "/")`).
fn has_bare_root_target(surface: &str, interpreter: &str) -> bool {
    let bytes = surface.as_bytes();
    // The call opened by each `(`; `None` for `[` / `{`.
    let mut open: Vec<Option<Call>> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(next) = skip_nonstandard_string(bytes, interpreter, i) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                let Some(end) = skip_ordinary_string(bytes, i) else {
                    break;
                };
                let q = bytes[i];
                let triple = q != b'`'
                    && bytes.get(i + 1) == Some(&q)
                    && bytes.get(i + 2) == Some(&q)
                    && end - i >= 6;
                let (cs, ce) = if triple { (i + 3, end - 3) } else { (i + 1, end - 1) };
                if &bytes[cs..ce] == b"/" && !is_string_use(bytes, i, end, &open) {
                    return true;
                }
                i = end;
                continue;
            }
            b'(' => open.push(callee_before(bytes, i)),
            b'[' | b'{' => open.push(None),
            b')' | b']' | b'}' => {
                open.pop();
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// A call opened by `(`: its name, and the receiver before `.` / `::`
/// (`path` in `os.path.join(`), if any.
struct Call {
    name: String,
    receiver: Option<String>,
}

/// Start of the identifier ending at `end` (exclusive).
fn ident_start(bytes: &[u8], end: usize) -> usize {
    let mut k = end;
    while k > 0 && (bytes[k - 1].is_ascii_alphanumeric() || matches!(bytes[k - 1], b'_' | b'?' | b'!')) {
        k -= 1;
    }
    k
}

/// The call whose `(` is at `paren` (`split` in `x.split(`).
fn callee_before(bytes: &[u8], paren: usize) -> Option<Call> {
    let start = ident_start(bytes, paren);
    if start == paren {
        return None;
    }
    let receiver_end = if start >= 1 && bytes[start - 1] == b'.' {
        Some(start - 1)
    } else if start >= 2 && &bytes[start - 2..start] == b"::" {
        Some(start - 2)
    } else {
        None
    };
    let receiver = receiver_end
        .map(|end| (ident_start(bytes, end), end))
        .filter(|(s, e)| s < e)
        .map(|(s, e)| String::from_utf8_lossy(&bytes[s..e]).into_owned());
    Some(Call {
        name: String::from_utf8_lossy(&bytes[start..paren]).into_owned(),
        receiver,
    })
}

/// Is `call` a string operation? `join` and `find` are also path
/// builders / directory walkers (`os.path.join("/")`, Perl `find(…, "/")`,
/// Ruby `Find.find("/")`), so their receiver decides.
fn is_string_function(call: &Call) -> bool {
    let receiver = call.receiver.as_deref();
    match call.name.as_str() {
        "join" => !matches!(
            receiver,
            Some("path" | "posixpath" | "ntpath" | "File" | "Path" | "PurePath" | "PosixPath")
        ),
        "find" => receiver.is_some_and(|r| !matches!(r, "Find" | "File")),
        name => STRING_FUNCS.contains(&name),
    }
}

/// Index of the previous non-whitespace byte before `idx`.
fn prev_non_ws(bytes: &[u8], idx: usize) -> Option<usize> {
    (0..idx).rev().find(|&k| !bytes[k].is_ascii_whitespace())
}

/// Is the string literal spanning `start..end` used as a string (see
/// `has_bare_root_target`)?
fn is_string_use(bytes: &[u8], start: usize, end: usize, open: &[Option<Call>]) -> bool {
    // After the literal: `.method` / `..`, `+`, `==`, `!=`, `in`.
    let mut j = end;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    let after = &bytes[j..];
    if after.starts_with(b".")
        || after.starts_with(b"+")
        || after.starts_with(b"==")
        || after.starts_with(b"!=")
        || after.starts_with(b"in ")
        || after.starts_with(b"not in")
    {
        return true;
    }

    // Before the literal (skipping a Python prefix like `r"/"`): `+`,
    // `.` / `..`, or a comparison / `+=`.
    let mut k = start;
    let mut letters = 0;
    while k > 0 && letters < 2 && matches!(bytes[k - 1], b'r' | b'R' | b'b' | b'B' | b'u' | b'U' | b'f' | b'F') {
        k -= 1;
        letters += 1;
    }
    if letters > 0 && k > 0 && (bytes[k - 1].is_ascii_alphanumeric() || bytes[k - 1] == b'_') {
        k = start; // part of an identifier, not a prefix
    }
    if let Some(p) = prev_non_ws(bytes, k) {
        match bytes[p] {
            b'+' | b'.' => return true,
            b'=' if p > 0 && matches!(bytes[p - 1], b'=' | b'!' | b'+') => return true,
            _ => {}
        }
    }

    // Argument of a string function.
    matches!(open.last(), Some(Some(call)) if is_string_function(call))
}

fn inline_code_path_scan_surface(code: &str, interpreter: &str) -> String {
    let bytes = code.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;

    while i < bytes.len() {
        if let Some(next) = skip_nonstandard_string(bytes, interpreter, i) {
            i = next;
            continue;
        }

        if let Some(next) = skip_ordinary_string(bytes, i) {
            i = next;
            continue;
        }

        if let Some(next) = skip_comment(bytes, interpreter, i) {
            mask_inline_code_range(&mut out, i, next);
            i = next;
            continue;
        }

        if should_skip_regex_literal(bytes, interpreter, i) {
            if let Some(next) = skip_regex_literal(bytes, i) {
                mask_inline_code_range(&mut out, i, next);
                i = next;
                continue;
            }
        }

        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn skip_nonstandard_string(bytes: &[u8], interpreter: &str, i: usize) -> Option<usize> {
    if interpreter == "ruby" && starts_ruby_percent_string(bytes, i) {
        return delimited_literal_end(bytes, i + 2);
    }

    if interpreter == "perl" {
        if let Some(delimiter_idx) = perl_q_delimiter_index(bytes, i) {
            return delimited_literal_end(bytes, delimiter_idx);
        }
    }

    if interpreter == "lua" {
        return skip_lua_long_bracket(bytes, i);
    }

    None
}

fn skip_ordinary_string(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = *bytes.get(start)?;
    if !matches!(quote, b'\'' | b'"' | b'`') {
        return None;
    }

    let triple = quote != b'`'
        && start + 2 < bytes.len()
        && bytes[start + 1] == quote
        && bytes[start + 2] == quote;
    let mut i = if triple { start + 3 } else { start + 1 };

    if triple {
        while i + 2 < bytes.len() {
            if bytes[i] == b'\\' {
                i = (i + 2).min(bytes.len());
                continue;
            }
            if bytes[i] == quote && bytes[i + 1] == quote && bytes[i + 2] == quote {
                return Some(i + 3);
            }
            i += 1;
        }
    } else {
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i = (i + 2).min(bytes.len());
                continue;
            }
            if bytes[i] == quote {
                return Some(i + 1);
            }
            i += 1;
        }
    }

    None
}

fn skip_comment(bytes: &[u8], interpreter: &str, start: usize) -> Option<usize> {
    let b = *bytes.get(start)?;

    if b == b'#' && matches!(interpreter, "python" | "python3" | "ruby" | "perl" | "php") {
        return Some(line_end(bytes, start));
    }

    if matches!(interpreter, "node" | "php") {
        if bytes.get(start..start + 2) == Some(b"//") {
            return Some(line_end(bytes, start));
        }
        if bytes.get(start..start + 2) == Some(b"/*") {
            return Some(block_comment_end(bytes, start + 2, b"*/"));
        }
    }

    if interpreter == "lua" && bytes.get(start..start + 2) == Some(b"--") {
        if bytes.get(start + 2) == Some(&b'[') {
            if let Some(end) = skip_lua_long_bracket(bytes, start + 2) {
                return Some(end);
            }
        }
        return Some(line_end(bytes, start));
    }

    None
}

fn line_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn block_comment_end(bytes: &[u8], mut i: usize, terminator: &[u8]) -> usize {
    while i + terminator.len() <= bytes.len() {
        if bytes.get(i..i + terminator.len()) == Some(terminator) {
            return i + terminator.len();
        }
        i += 1;
    }
    bytes.len()
}

fn skip_lua_long_bracket(bytes: &[u8], start: usize) -> Option<usize> {
    lua_long_bracket_parts(bytes, start).map(|(_, _, end)| end)
}

fn contains_bare_root_delimited_literal(scan_surface: &str, interpreter: &str) -> bool {
    let bytes = scan_surface.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if matches!(interpreter, "ruby" | "perl") {
            if starts_ruby_percent_string(bytes, i) {
                if delimited_literal_is_bare_root(bytes, i + 2) {
                    return true;
                }
            }

            if interpreter == "perl" {
                if let Some(delim_idx) = perl_q_delimiter_index(bytes, i) {
                    if delimited_literal_is_bare_root(bytes, delim_idx) {
                        return true;
                    }
                }
            }
        }

        if interpreter == "lua" {
            if let Some((content_start, content_end, literal_end)) = lua_long_bracket_parts(bytes, i) {
                if &bytes[content_start..content_end] == b"/" {
                    return true;
                }
                i = literal_end;
                continue;
            }
        }

        i += 1;
    }

    false
}

fn starts_ruby_percent_string(bytes: &[u8], i: usize) -> bool {
    matches!(bytes.get(i..i + 2), Some(b"%q" | b"%Q"))
}

fn perl_q_delimiter_index(bytes: &[u8], i: usize) -> Option<usize> {
    if !is_token_boundary(bytes, i) || bytes.get(i) != Some(&b'q') {
        return None;
    }

    let mut j = i + 1;
    if bytes.get(j) == Some(&b'q') {
        j += 1;
    } else if bytes.get(j) == Some(&b'r') {
        return None;
    }
    while bytes.get(j).is_some_and(|b| b.is_ascii_whitespace()) {
        j += 1;
    }
    bytes.get(j).map(|_| j)
}

fn is_token_boundary(bytes: &[u8], i: usize) -> bool {
    i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_'
}

fn delimited_literal_is_bare_root(bytes: &[u8], delimiter_idx: usize) -> bool {
    if let Some((content_start, content_end)) = delimited_literal_bounds(bytes, delimiter_idx) {
        return &bytes[content_start..content_end] == b"/";
    }
    false
}

fn delimited_literal_end(bytes: &[u8], delimiter_idx: usize) -> Option<usize> {
    delimited_literal_bounds(bytes, delimiter_idx).map(|(_, content_end)| content_end + 1)
}

fn delimited_literal_bounds(bytes: &[u8], delimiter_idx: usize) -> Option<(usize, usize)> {
    let open = *bytes.get(delimiter_idx)?;
    let close = match open {
        b'{' => b'}',
        b'(' => b')',
        b'[' => b']',
        b'<' => b'>',
        b if b.is_ascii_whitespace() || b.is_ascii_alphanumeric() => return None,
        b => b,
    };
    let content_start = delimiter_idx + 1;
    let mut i = content_start;

    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if bytes[i] == close {
            return Some((content_start, i));
        }
        i += 1;
    }

    None
}

fn lua_long_bracket_parts(bytes: &[u8], start: usize) -> Option<(usize, usize, usize)> {
    if bytes.get(start) != Some(&b'[') {
        return None;
    }

    let mut i = start + 1;
    while bytes.get(i) == Some(&b'=') {
        i += 1;
    }
    if bytes.get(i) != Some(&b'[') {
        return None;
    }
    let eq_count = i - start - 1;
    i += 1;
    let content_start = i;

    while i < bytes.len() {
        if bytes[i] == b']' {
            let mut j = i + 1;
            let mut n = 0;
            while n < eq_count && bytes.get(j) == Some(&b'=') {
                j += 1;
                n += 1;
            }
            if n == eq_count && bytes.get(j) == Some(&b']') {
                return Some((content_start, i, j + 1));
            }
        }
        i += 1;
    }

    Some((content_start, bytes.len(), bytes.len()))
}

fn mask_inline_code_range(out: &mut [u8], start: usize, end: usize) {
    for b in &mut out[start..end] {
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
}

fn should_skip_regex_literal(bytes: &[u8], interpreter: &str, slash_idx: usize) -> bool {
    if !matches!(interpreter, "node" | "ruby" | "perl" | "php") {
        return false;
    }
    if bytes.get(slash_idx) != Some(&b'/') || bytes.get(slash_idx + 1) == Some(&b'/') {
        return false;
    }

    match previous_non_whitespace_byte(bytes, slash_idx) {
        None => true,
        Some(
            b'=' | b'(' | b'[' | b'{' | b',' | b';' | b':' | b'!' | b'?' | b'&' | b'|'
            | b'~',
        ) => true,
        _ => false,
    }
}

fn previous_non_whitespace_byte(bytes: &[u8], idx: usize) -> Option<u8> {
    let mut i = idx;
    while i > 0 {
        i -= 1;
        if !bytes[i].is_ascii_whitespace() {
            return Some(bytes[i]);
        }
    }
    None
}

fn skip_regex_literal(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    let mut in_class = false;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i = (i + 2).min(bytes.len()),
            b'[' if !in_class => {
                in_class = true;
                i += 1;
            }
            b']' if in_class => {
                in_class = false;
                i += 1;
            }
            b'/' if !in_class => {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                    i += 1;
                }
                return Some(i);
            }
            b'\n' | b'\r' => return None,
            _ => i += 1,
        }
    }

    None
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
pub(crate) const SENTINEL_STAR: char = '\u{E003}';
pub(crate) const SENTINEL_QUESTION: char = '\u{E004}';
pub(crate) const SENTINEL_LBRACKET: char = '\u{E005}';
const SENTINEL_DOLLAR: char = '\u{E006}';
/// Opens a command-substitution placeholder: `SUBST_OPEN <index> SUBST_CLOSE`.
pub(crate) const SUBST_OPEN: char = '\u{E010}';
const SUBST_CLOSE: char = '\u{E011}';
/// Opens a heredoc / here-string marker: `HEREDOC_OPEN <index> SUBST_CLOSE`.
const HEREDOC_OPEN: char = '\u{E012}';

/// Sentinel for a character that is literal because of quoting.
fn sentinel_for(b: u8) -> Option<char> {
    match b {
        b'{' => Some(SENTINEL_LBRACE),
        b'}' => Some(SENTINEL_RBRACE),
        b',' => Some(SENTINEL_COMMA),
        b'*' => Some(SENTINEL_STAR),
        b'?' => Some(SENTINEL_QUESTION),
        b'[' => Some(SENTINEL_LBRACKET),
        b'$' => Some(SENTINEL_DOLLAR),
        _ => None,
    }
}

/// Replace characters whose shell meaning is suppressed by quoting with
/// private sentinel codepoints, so the analysis after shlex (which drops
/// quotes) can still tell literal from active:
///
/// * `{`, `}`, `,` — brace expansion (inside any quotes, or escaped);
/// * `*`, `?`, `[` — globbing (inside any quotes, or escaped);
/// * `$` — expansion (inside single quotes, or escaped).
///
/// Unquoted, unescaped characters are left intact.
fn mask_quoted_specials(cmd: &str) -> String {
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
                match sentinel_for(nb) {
                    // Inside double quotes bash drops the backslash of
                    // `\$`; emit the bare sentinel so shlex agrees.
                    Some(s) if in_double && nb == b'$' => {
                        out.push(s);
                        i += 2;
                    }
                    Some(s) => {
                        out.push('\\');
                        out.push(s);
                        i += 2;
                    }
                    None => {
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
            // `$` still expands inside double quotes.
            b'$' if in_single => {
                out.push(SENTINEL_DOLLAR);
                i += 1;
            }
            b'{' | b'}' | b',' | b'*' | b'?' | b'[' if in_single || in_double => {
                out.push(sentinel_for(b).unwrap());
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

fn is_private_marker(c: char) -> bool {
    ('\u{E000}'..='\u{E012}').contains(&c)
}

/// Restore masked characters to their original form.
///
/// * `keep_substitutions = true` keeps substitution placeholders intact
///   (used when re-feeding text to another parse level, e.g. `eval`).
/// * `false` renders each placeholder as `$(…)` for user-facing output.
fn unmask(s: &str, keep_substitutions: bool) -> String {
    if !s.chars().any(is_private_marker) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut in_subst = false;
    for c in s.chars() {
        if in_subst {
            if c == SUBST_CLOSE {
                in_subst = false;
                if keep_substitutions {
                    out.push(c);
                }
            } else if keep_substitutions {
                out.push(c);
            }
            continue;
        }
        match c {
            SENTINEL_LBRACE => out.push('{'),
            SENTINEL_RBRACE => out.push('}'),
            SENTINEL_COMMA => out.push(','),
            SENTINEL_STAR => out.push('*'),
            SENTINEL_QUESTION => out.push('?'),
            SENTINEL_LBRACKET => out.push('['),
            SENTINEL_DOLLAR => out.push('$'),
            SUBST_OPEN | HEREDOC_OPEN => {
                in_subst = true;
                if keep_substitutions {
                    out.push(c);
                } else if c == SUBST_OPEN {
                    out.push_str("$(…)");
                } else {
                    out.push_str("<<…");
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Restore every masked character (user-facing form).
fn unmask_specials(s: &str) -> String {
    unmask(s, false)
}

/// Unmask sentinels in `raw` and any embedded `code_snippet` so the
/// values we expose to users / downstream rules are byte-identical to
/// what bash would resolve.
fn unmask_extracted_path(mut ep: ExtractedPath) -> ExtractedPath {
    ep.raw = unmask_specials(&ep.raw);
    match &mut ep.context {
        PathContext::InlineCodeRef { code_snippet, .. }
        | PathContext::InlineCodeExecution { code_snippet, .. } => {
            *code_snippet = unmask_specials(code_snippet);
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
            out.push(ExtractedPath::new(
                expansions.into_iter().next().unwrap(),
                ep.context,
            ));
        } else {
            for exp in expansions {
                out.push(ExtractedPath::new(exp, ep.context.clone()));
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

/// Accumulated output of one `extract_paths` call.
#[derive(Default)]
struct Extraction {
    paths: Vec<ExtractedPath>,
    /// Bodies of command substitutions, indexed by their placeholder.
    /// Each body is taken (and walked) exactly once.
    substitutions: Vec<Option<String>>,
    /// Stdin text of heredocs / here-strings, indexed by their marker.
    heredocs: Vec<Option<String>>,
}

/// Walk one shell command string (the top-level command, or the inner
/// text of `eval`, `bash -c` or a command substitution).
///
/// Each level is processed from its *unmasked* text, so quoting is judged
/// by that level's own rules: `bash -c 'rm -rf /*'` globs at the inner
/// level even though the `*` was quoted at the outer one.
///
/// `feeds_args`: this level's output may become command arguments (it is
/// inside `$(…)`, or piped onward), so `echo` / `printf` text counts.
fn walk(command: &str, ex: &mut Extraction, depth: usize, state: &mut ShellState, feeds_args: bool) {
    if depth > MAX_RECURSION {
        return;
    }

    // Heredoc bodies, here-strings and comments are not commands. But
    // substitutions inside an unquoted-delimiter heredoc body or a
    // here-string do run, so walk those first.
    let spans = find_heredoc_spans(command);
    for span in &spans {
        let quote_aware = match span.kind {
            SpanKind::HeredocBody { expands: true } => false,
            SpanKind::HereString => true,
            _ => continue,
        };
        let mut bodies = Vec::new();
        scan_substitutions(&command[span.start..span.end], quote_aware, &mut bodies);
        for body in bodies.into_iter().flatten() {
            // The output becomes stdin data here, not arguments.
            walk(&body, ex, depth + 1, &mut state.clone(), false);
        }
    }
    let stripped = strip_spans_marking_heredocs(command, &spans, &mut ex.heredocs);

    // Replace `$(…)` / backticks / `<(…)` with placeholders so their
    // `;`, `|` and `)` can't split this level, then mask quoted specials.
    let replaced = scan_substitutions(&stripped, true, &mut ex.substitutions);
    let masked = mask_quoted_specials(&replaced);

    // Depth of `{ … }`, `( … )`, `if`/loops/`case`: their output may be
    // piped at the closing keyword (`done | xargs rm`), which we only see
    // later, so text inside them is treated as possibly feeding arguments.
    let mut compound_depth = 0usize;
    for (sub_cmd, sep) in split_shell_operators_with_ops(&masked) {
        let sub_cmd = sub_cmd.trim();
        if sub_cmd.is_empty() {
            continue;
        }
        let (opens, closes) = compound_boundaries(sub_cmd);
        let inside = compound_depth > 0 || (opens && !closes);
        compound_depth = (compound_depth + opens as usize).saturating_sub(closes as usize);
        let feeds = feeds_args || sep == Separator::Pipe || inside;
        // Substitutions run before the command, in a subshell.
        for idx in placeholder_indices(sub_cmd) {
            if let Some(body) = ex.substitutions.get_mut(idx).and_then(Option::take) {
                walk(&body, ex, depth + 1, &mut state.clone(), true);
            }
        }
        // Redirection targets (quote-aware; `> "/tmp/out.txt"` etc.).
        for r in find_redirections(sub_cmd) {
            let target = expand_vars(&r.target, state);
            emit(ex, state, target, PathContext::Redirection);
        }
        extract_paths_from_sub_command(sub_cmd, ex, depth, state, feeds);
    }
}

/// Does this sub-command open and/or close a compound command?
fn compound_boundaries(sub_cmd: &str) -> (bool, bool) {
    let first = sub_cmd.split_whitespace().next().unwrap_or("");
    let opens = matches!(first, "{" | "if" | "while" | "until" | "for" | "select" | "case")
        || first.starts_with('(');
    let closes = matches!(first, "}" | "fi" | "done" | "esac")
        || (sub_cmd.ends_with(')') && sub_cmd.matches(')').count() > sub_cmd.matches('(').count());
    (opens, closes)
}

/// Record one extracted path: join it onto the current directory, and
/// drop harmless device files (`/dev/null`, `/dev/stdout`, …).
fn emit(ex: &mut Extraction, state: &ShellState, raw: String, context: PathContext) {
    let raw = match context {
        PathContext::CdImplicitHome | PathContext::CdDash | PathContext::InlineCodeExecution { .. } => raw,
        PathContext::Redirection => state.join(&raw, true),
        _ => state.join(&raw, false),
    };
    if is_safe_device(&raw) {
        return;
    }
    ex.paths.push(ExtractedPath::new(raw, context));
}

/// Remove `spans` from `cmd`, leaving one space per span.
fn strip_spans(cmd: &str, spans: &[HeredocSpan]) -> String {
    if spans.is_empty() {
        return cmd.to_string();
    }
    let mut out = String::with_capacity(cmd.len());
    let mut cursor = 0;
    for span in spans {
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

/// Like `strip_spans`, but each heredoc operator and here-string becomes
/// a marker token `HEREDOC_OPEN <n> SUBST_CLOSE` on the command it feeds,
/// with its stdin text stored in `heredocs[n]`. A shell or interpreter
/// reading that stdin (`bash <<'EOF'`, `python3 - <<'EOF'`) runs it as
/// code; every other command ignores the marker.
fn strip_spans_marking_heredocs(
    cmd: &str,
    spans: &[HeredocSpan],
    heredocs: &mut Vec<Option<String>>,
) -> String {
    if spans.is_empty() {
        return cmd.to_string();
    }
    let mut out = String::with_capacity(cmd.len());
    let mut cursor = 0;
    // Heredoc bodies follow their operators in FIFO order.
    let mut pending: std::collections::VecDeque<usize> = Default::default();
    let marker = |out: &mut String, idx: usize| {
        out.push(HEREDOC_OPEN);
        out.push_str(&idx.to_string());
        out.push(SUBST_CLOSE);
    };
    for span in spans {
        if span.start > cursor {
            out.push_str(&cmd[cursor..span.start]);
        }
        out.push(' ');
        match span.kind {
            SpanKind::HeredocOp => {
                pending.push_back(heredocs.len());
                marker(&mut out, heredocs.len());
                heredocs.push(Some(String::new()));
                out.push(' ');
            }
            SpanKind::HeredocBody { .. } => {
                if let Some(idx) = pending.pop_front() {
                    heredocs[idx] = Some(cmd[span.start..span.content_end].to_string());
                }
            }
            SpanKind::HereString => {
                let word = cmd[span.start..span.end].trim_start_matches('<').trim_start();
                let text = shlex::split(word).map_or_else(|| word.to_string(), |w| w.join(" "));
                marker(&mut out, heredocs.len());
                heredocs.push(Some(text));
                out.push(' ');
            }
            SpanKind::Comment => {}
        }
        cursor = span.end;
    }
    if cursor < cmd.len() {
        out.push_str(&cmd[cursor..]);
    }
    out
}

/// The heredoc index of a marker token, if `token` is one.
fn heredoc_marker_index(token: &str) -> Option<usize> {
    token
        .strip_prefix(HEREDOC_OPEN)?
        .strip_suffix(SUBST_CLOSE)?
        .parse()
        .ok()
}

// ============================================================================
// Command substitution
// ============================================================================

/// Replace each command substitution in `cmd` — `$(…)`, `` `…` ``, `<(…)`,
/// `>(…)` — with a placeholder `SUBST_OPEN <n> SUBST_CLOSE`, storing its
/// body in `bodies[n]`. Arithmetic `$((…))` is left alone.
///
/// With `quote_aware`, nothing inside single quotes is a substitution and
/// process substitution is inactive inside double quotes. Without it (for
/// heredoc bodies, where quotes are literal), only `\` escapes apply.
/// An unclosed substitution runs to the end of `cmd` (fail closed).
fn scan_substitutions(cmd: &str, quote_aware: bool, bodies: &mut Vec<Option<String>>) -> String {
    let bytes = cmd.as_bytes();
    let mut out = String::with_capacity(cmd.len());
    let mut last = 0;
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && !in_single {
            i = advance_char(bytes, (i + 1).min(bytes.len()));
            continue;
        }
        if quote_aware && b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if quote_aware && b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if in_single {
            i = advance_char(bytes, i);
            continue;
        }

        let (body_start, body_end, span_end) = if b == b'$' && bytes.get(i + 1) == Some(&b'(') {
            if bytes.get(i + 2) == Some(&b'(') && is_arithmetic(cmd, i + 1) {
                // Arithmetic expansion — not a command.
                i = matching_paren(cmd, i + 1).map_or(bytes.len(), |c| c + 1);
                continue;
            }
            match matching_paren(cmd, i + 1) {
                Some(close) => (i + 2, close, close + 1),
                None => (i + 2, bytes.len(), bytes.len()),
            }
        } else if matches!(b, b'<' | b'>') && bytes.get(i + 1) == Some(&b'(') && !in_double {
            match matching_paren(cmd, i + 1) {
                Some(close) => (i + 2, close, close + 1),
                None => (i + 2, bytes.len(), bytes.len()),
            }
        } else if b == b'`' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'`' {
                j += if bytes[j] == b'\\' { 2 } else { 1 };
            }
            let j = j.min(bytes.len());
            (i + 1, j, (j + 1).min(bytes.len()))
        } else {
            i = advance_char(bytes, i);
            continue;
        };

        out.push_str(&cmd[last..i]);
        out.push(SUBST_OPEN);
        out.push_str(&bodies.len().to_string());
        out.push(SUBST_CLOSE);
        bodies.push(Some(cmd[body_start..body_end].to_string()));
        i = span_end;
        last = span_end;
    }
    out.push_str(&cmd[last..]);
    out
}

/// Index of the `)` matching the `(` at `open`.
///
/// Honours quotes, escapes, comments, nested `$((…))` / `((…))`
/// arithmetic, and heredoc bodies: in `"$(cat <<'EOF'⏎don't⏎EOF⏎)"` the
/// apostrophe is heredoc text, not a quote. Non-recursive, so deeply
/// nested input can't exhaust the stack.
fn matching_paren(cmd: &str, open: usize) -> Option<usize> {
    let bytes = cmd.as_bytes();
    // `P` = plain `(`, `A` = arithmetic `((`.
    let mut stack: Vec<u8> = vec![b'P'];
    let mut in_single = false;
    let mut in_double = false;
    let mut pending: Vec<(String, bool)> = Vec::new();
    let mut i = open + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if b == b'\\' {
            i += 2;
            continue;
        }
        if in_double {
            if b == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'\n' if !pending.is_empty() => {
                i = skip_heredoc_bodies(cmd, i + 1, std::mem::take(&mut pending));
                continue;
            }
            b'#' if is_comment_start(bytes, i) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'(' if bytes.get(i + 1) == Some(&b'(') => {
                stack.push(b'A');
                i += 2;
                continue;
            }
            b'(' => stack.push(b'P'),
            b')' => match stack.last() {
                Some(b'A') if bytes.get(i + 1) == Some(&b')') => {
                    stack.pop();
                    i += 2;
                    continue;
                }
                // `((cmd) )`: the inner `(` was a subshell, not arithmetic.
                Some(b'A') => *stack.last_mut().unwrap() = b'P',
                _ => {
                    stack.pop();
                    if stack.is_empty() {
                        return Some(i);
                    }
                }
            },
            b'<' if bytes.get(i + 1) == Some(&b'<') && !stack.contains(&b'A') => {
                if bytes.get(i + 2) == Some(&b'<') {
                    i += 3; // here-string
                    continue;
                }
                let mut j = i + 2;
                let strip_tabs = bytes.get(j) == Some(&b'-');
                if strip_tabs {
                    j += 1;
                }
                while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                    j += 1;
                }
                if let Some((end, delim)) = parse_heredoc_delim(cmd, j) {
                    pending.push((delim, strip_tabs));
                    i = end;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Skip heredoc bodies starting at `start` (just after the newline that
/// ends the operator line); returns the index after the last delimiter
/// line, or the end of input if one is unclosed.
fn skip_heredoc_bodies(cmd: &str, start: usize, pending: Vec<(String, bool)>) -> usize {
    let mut i = start;
    for (delim, strip_tabs) in pending {
        loop {
            let line_end = cmd[i..].find('\n').map_or(cmd.len(), |n| i + n);
            let line = &cmd[i..line_end];
            let candidate = if strip_tabs { line.trim_start_matches('\t') } else { line };
            i = (line_end + 1).min(cmd.len());
            if candidate == delim || line_end >= cmd.len() {
                break;
            }
        }
    }
    i
}

/// Is the `$((` / `((` whose first `(` is at `open` arithmetic? Bash
/// treats it as arithmetic only when the two parens close together as
/// `))`; `$((cmd) )` is a command substitution containing a subshell.
fn is_arithmetic(cmd: &str, open: usize) -> bool {
    match (matching_paren(cmd, open), matching_paren(cmd, open + 1)) {
        (Some(outer), Some(inner)) => inner + 1 == outer,
        _ => false,
    }
}

/// Placeholder indices (`SUBST_OPEN <n> SUBST_CLOSE`) appearing in `s`.
fn placeholder_indices(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == SUBST_OPEN {
            let digits: String = chars.by_ref().take_while(|&d| d != SUBST_CLOSE).collect();
            if let Ok(n) = digits.parse() {
                out.push(n);
            }
        }
    }
    out
}

/// Commands whose operands are never paths but whose flags take a
/// delimiter value that often looks like one (`cut -d /`, `awk -F '/'`).
const DELIMITER_FLAGS: &[(&str, &[&str])] = &[
    ("cut", &["-d"]),
    ("awk", &["-F"]),
    ("gawk", &["-F"]),
    ("sort", &["-t"]),
    ("paste", &["-d"]),
    ("join", &["-t"]),
    ("column", &["-s"]),
];

fn extract_paths_from_sub_command(
    sub_cmd: &str,
    ex: &mut Extraction,
    depth: usize,
    state: &mut ShellState,
    feeds: bool,
) {
    let cleaned = strip_redirections(sub_cmd);
    // Heredoc / here-string markers say what this command reads on stdin.
    let mut stdin_docs: Vec<usize> = Vec::new();
    let raw_tokens = match shlex::split(&cleaned) {
        Some(t) => strip_shell_syntax(
            t.into_iter()
                .filter(|tok| match heredoc_marker_index(tok) {
                    Some(idx) => {
                        stdin_docs.push(idx);
                        false
                    }
                    None => true,
                })
                .collect(),
        ),
        None => return,
    };
    if raw_tokens.is_empty() {
        return;
    }

    // Leading assignments and `sudo` / `env` wrappers.
    let mut start = 0;
    let mut prefix: Vec<(String, String)> = Vec::new();
    let mut wrapped = false;
    while start < raw_tokens.len() {
        let t = &raw_tokens[start];
        if t.contains('=') && !t.starts_with('-') && !t.starts_with('/') {
            if let Some((name, value, _)) = parse_assignment(t) {
                prefix.push((name.to_string(), value.to_string()));
            }
            start += 1;
        } else if t == "sudo" || t == "env" {
            wrapped = true;
            start += 1;
        } else {
            break;
        }
    }
    if start >= raw_tokens.len() {
        // Only assignments: they persist in the shell (`D=/etc; cat $D/x`).
        if !wrapped {
            for t in &raw_tokens {
                match parse_assignment(t) {
                    Some((name, _, true)) => state.mark_unknown(name),
                    Some((name, value, false)) => state.assign(name, value, false),
                    None => {}
                }
            }
        }
        return;
    }

    // Expand known variables. Prefix assignments don't apply here: bash
    // expands `$D` in `D=x cmd $D` with the old value.
    let raw_args = &raw_tokens[start..];
    let tokens: Vec<String> = raw_args.iter().map(|t| expand_vars(t, state)).collect();
    let cmd_name = tokens[0].as_str();
    let args = &tokens[1..];
    let mut found: Vec<(String, PathContext)> = Vec::new();

    match cmd_name {
        "cd" => {
            cd_command(args, ex, state);
            return;
        }
        "pushd" => {
            let operands: Vec<&String> = args
                .iter()
                .filter(|a| !a.starts_with('-') || is_dirstack_index(a))
                .collect();
            for a in &operands {
                if !is_dirstack_index(a) {
                    emit(ex, state, (*a).clone(), PathContext::CdTarget);
                }
            }
            match operands.first() {
                None => state.pushd_swap(),
                Some(a) if is_dirstack_index(a) => state.cd_unknown(),
                Some(a) => state.pushd(a),
            }
            return;
        }
        "popd" => {
            if args.iter().any(|a| is_dirstack_index(a)) {
                state.cd_unknown();
            } else {
                state.popd();
            }
            return;
        }
        "export" | "declare" | "typeset" | "local" | "readonly" => {
            // Use the unexpanded words: `assign` expands values itself.
            let exported = cmd_name == "export"
                || raw_args[1..].iter().any(|a| a.starts_with('-') && a.contains('x'));
            for a in &raw_args[1..] {
                match parse_assignment(a) {
                    Some((name, _, true)) => state.mark_unknown(name),
                    Some((name, value, false)) => state.assign(name, value, exported),
                    None if exported && is_valid_name(a) => state.export(a),
                    None => {}
                }
            }
            return;
        }
        "unset" => {
            for a in args.iter().filter(|a| is_valid_name(a)) {
                state.unset(a);
            }
            return;
        }
        "read" | "mapfile" | "readarray" => {
            for a in args.iter().filter(|a| is_valid_name(a)) {
                state.mark_unknown(a);
            }
            return;
        }
        "eval" => {
            if !args.is_empty() {
                // eval re-parses its (already expanded) arguments in the
                // current shell, so quoting from this level no longer
                // applies: `eval rm -rf '/*'` globs.
                let inner = unmask(&args.join(" "), true);
                if prefix.is_empty() {
                    walk(&inner, ex, depth + 1, state, feeds);
                } else {
                    walk(&inner, ex, depth + 1, &mut state.with_prefix(&prefix), feeds);
                }
            }
            return;
        }
        "bash" | "sh" | "zsh" | "dash" => {
            match shell_invocation(args) {
                ShellInvocation::Command(code) => {
                    let inner = unmask(code, true);
                    walk(&inner, ex, depth + 1, &mut state.child_shell(&prefix), feeds);
                }
                ShellInvocation::Script(script) if script != "-" => {
                    found.push((script.clone(), PathContext::ExecTarget));
                }
                // Commands on stdin: `bash <<'EOF'`, `sh -s <<< '…'`.
                ShellInvocation::Script(_) | ShellInvocation::Stdin => {
                    for idx in &stdin_docs {
                        if let Some(code) = ex.heredocs.get_mut(*idx).and_then(Option::take) {
                            walk(&code, ex, depth + 1, &mut state.child_shell(&prefix), feeds);
                        }
                    }
                }
            }
        }
        "for" | "select" => {
            // `for NAME in WORDS`: NAME is unknowable; the words are
            // still checked below (`for f in /etc/*`).
            if let Some(name) = args.first().filter(|n| is_valid_name(n)) {
                state.mark_unknown(name);
            }
            found.extend(unknown_command_args(cmd_name, args));
        }
        "echo" | "printf" | "tr" => {
            // Operands are text (printed, or tr's character sets), not
            // paths. They still matter when:
            // * they hold an unquoted glob — the shell lists a directory;
            // * echo/printf output may become arguments: inside `$(…)`,
            //   piped onward (`echo / | xargs rm -rf`), or inside a
            //   compound / `-c` / `eval` whose output may be piped;
            // * `printf -v NAME` stores the result in a variable.
            let printf_v = cmd_name == "printf" && args.iter().any(|a| a == "-v");
            if printf_v
                && let Some(pos) = args.iter().position(|a| a == "-v")
                && let Some(name) = args.get(pos + 1).filter(|n| is_valid_name(n))
            {
                state.mark_unknown(name);
            }
            let feeds_args = cmd_name != "tr" && (feeds || printf_v);
            for arg in args {
                if arg.starts_with('-') || !looks_like_path(arg) {
                    continue;
                }
                if feeds_args || contains_glob_meta(arg) {
                    found.push((arg.clone(), PathContext::UnknownCommandArg));
                }
            }
        }
        cmd if DIR_TARGET_COMMANDS.contains(&cmd) => {
            // Non-flag args are directories (mkdir, rmdir).
            // Emit CdTarget so directory-only blocked patterns fire via
            // `PathContext::implies_directory()` downstream.
            for arg in args {
                if !arg.starts_with('-') {
                    found.push((arg.clone(), PathContext::CdTarget));
                }
            }
        }
        cmd if FILE_COMMANDS.contains(&cmd) => {
            for arg in args {
                if !arg.starts_with('-') {
                    found.push((arg.clone(), PathContext::FileCommandArg));
                }
            }
        }
        "rg" | "grep" => {
            for p in pattern_search_paths(cmd_name, args) {
                found.push((p, PathContext::SearchCommandArg));
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
                if arg.starts_with('-') {
                    i += 1;
                    continue;
                }
                found.push((arg.clone(), PathContext::SearchCommandArg));
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
                        let context = |exec: bool| {
                            let interpreter = cmd.to_string();
                            let flag = args[pos].clone();
                            let code_snippet = code_arg.clone();
                            if exec {
                                PathContext::InlineCodeExecution { interpreter, flag, code_snippet }
                            } else {
                                PathContext::InlineCodeRef { interpreter, flag, code_snippet }
                            }
                        };
                        found.push((code_arg.clone(), context(true)));
                        // Defense-in-depth: literal paths still populate
                        // the list so no_root / no_system_dirs /
                        // blocked_files fire on obvious external references
                        // even when `-i` is not set.
                        for r in extract_inline_code_refs(code_arg, cmd) {
                            found.push((r, context(false)));
                        }
                        for (raw, ctx) in found {
                            emit(ex, state, raw, ctx);
                        }
                        return;
                    }
                }
                // Code on stdin: `python3 - <<'EOF'`, `node <<'EOF'`.
                let script = args.iter().find(|a| !a.starts_with('-') || *a == "-");
                if !stdin_docs.is_empty() && script.is_none_or(|s| s == "-") {
                    for idx in &stdin_docs {
                        let Some(code) = ex.heredocs.get_mut(*idx).and_then(Option::take) else {
                            continue;
                        };
                        let context = |exec: bool| {
                            let interpreter = cmd.to_string();
                            let flag = "<<".to_string();
                            let code_snippet = code.clone();
                            if exec {
                                PathContext::InlineCodeExecution { interpreter, flag, code_snippet }
                            } else {
                                PathContext::InlineCodeRef { interpreter, flag, code_snippet }
                            }
                        };
                        found.push((code.clone(), context(true)));
                        for r in extract_inline_code_refs(&code, cmd) {
                            found.push((r, context(false)));
                        }
                    }
                    for (raw, ctx) in found {
                        emit(ex, state, raw, ctx);
                    }
                    return;
                }
            }
            // Normal exec: first non-flag arg is the script path
            if let Some(arg) = args.iter().find(|a| !a.starts_with('-')) {
                found.push((arg.clone(), PathContext::ExecTarget));
            }
        }
        cmd if DOWNLOAD_COMMANDS.contains(&cmd) => {
            found.extend(extract_download_paths(args, cmd));
        }
        "sed" => {
            found.extend(extract_sed_paths(args));
        }
        "dd" => {
            let path_keys = ["if", "of"];
            for arg in args {
                if let Some((key, value)) = arg.split_once('=') {
                    if path_keys.contains(&key) {
                        found.push((value.to_string(), PathContext::DdPath));
                    }
                }
            }
        }
        _ => found.extend(unknown_command_args(cmd_name, args)),
    }

    for (raw, ctx) in found {
        emit(ex, state, raw, ctx);
    }
}

/// Reserved words and grouping that can precede a command.
const LEADING_SHELL_SYNTAX: &[&str] = &[
    "!", "{", "(", "((", "if", "then", "elif", "else", "while", "until", "do", "time",
];

/// Drop leading reserved words and grouping (`then cd /tmp`, `(cd /tmp`,
/// `do echo …`) so the real command is recognised, and the unbalanced
/// trailing `)` that closes a subshell (`rm -rf ../etc)`).
fn strip_shell_syntax(mut tokens: Vec<String>) -> Vec<String> {
    let mut start = 0;
    while let Some(t) = tokens.get(start) {
        if LEADING_SHELL_SYNTAX.contains(&t.as_str()) {
            start += 1;
            continue;
        }
        if t.starts_with('(') {
            let trimmed = t.trim_start_matches('(').to_string();
            if trimmed.is_empty() {
                start += 1;
                continue;
            }
            tokens[start] = trimmed;
        }
        break;
    }
    tokens.drain(..start);
    if let Some(last) = tokens.last_mut() {
        let mut excess = last.matches(')').count().saturating_sub(last.matches('(').count());
        while excess > 0 && last.ends_with(')') {
            last.pop();
            excess -= 1;
        }
        if last.is_empty() {
            tokens.pop();
        }
    }
    tokens
}

/// Path-like arguments of a command we don't model.
fn unknown_command_args(cmd_name: &str, args: &[String]) -> Vec<(String, PathContext)> {
    let delimiter_flags = DELIMITER_FLAGS
        .iter()
        .find(|(c, _)| *c == cmd_name)
        .map_or(&[][..], |(_, flags)| *flags);
    let mut found = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if delimiter_flags.contains(&arg.as_str()) {
            i += 2; // `cut -d /`: the value is a delimiter, not a path
            continue;
        }
        if arg.starts_with('-') {
            // Check --flag=value patterns for embedded paths
            if let Some((_flag, value)) = arg.split_once('=')
                && looks_like_path(value)
            {
                found.push((value.to_string(), PathContext::UnknownCommandArg));
            }
        } else if looks_like_path(arg) {
            found.push((arg.clone(), PathContext::UnknownCommandArg));
        }
        i += 1;
    }
    found
}

/// `cd [-L|-P|-e|-@]... [target]`. The target is recorded (and checked)
/// relative to the directory *before* the change.
fn cd_command(args: &[String], ex: &mut Extraction, state: &mut ShellState) {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| matches!(c, 'L' | 'P' | 'e' | '@')) {
            i += 1;
            continue;
        }
        break;
    }
    match args.get(i) {
        None => {
            emit(ex, state, String::new(), PathContext::CdImplicitHome);
            state.cd_home();
        }
        Some(t) if t == "-" => {
            emit(ex, state, "-".to_string(), PathContext::CdDash);
            state.cd_dash();
        }
        Some(t) => {
            emit(ex, state, t.clone(), PathContext::CdTarget);
            state.cd(t);
        }
    }
}

/// `+N` / `-N` directory-stack references of `pushd` / `popd`.
fn is_dirstack_index(a: &str) -> bool {
    a.len() > 1 && (a.starts_with('+') || a.starts_with('-')) && a[1..].chars().all(|c| c.is_ascii_digit())
}

enum ShellInvocation<'a> {
    /// `-c <code>` (also clustered: `-lc`, `-ec`).
    Command(&'a str),
    /// `bash script.sh` (`-` means stdin).
    Script(&'a String),
    /// No script, or `-s`: commands are read from stdin.
    Stdin,
}

/// Classify `bash`/`sh`/`zsh`/`dash` arguments. Options that take a value
/// (`-o pipefail`, `--rcfile f`) are skipped so their value isn't mistaken
/// for the command string or script.
fn shell_invocation(args: &[String]) -> ShellInvocation<'_> {
    let mut has_c = false;
    let mut has_s = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if matches!(a, "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file") {
            i += 2;
            continue;
        }
        if a.starts_with("--") {
            i += 1;
            continue;
        }
        if a.len() > 1 && (a.starts_with('-') || a.starts_with('+')) {
            has_c |= a.starts_with('-') && a[1..].contains('c');
            has_s |= a.starts_with('-') && a[1..].contains('s');
            i += 1;
            continue;
        }
        break;
    }
    match args.get(i) {
        Some(operand) if has_c => ShellInvocation::Command(operand),
        _ if has_s => ShellInvocation::Stdin,
        Some(operand) => ShellInvocation::Script(operand),
        None => ShellInvocation::Stdin,
    }
}

/// Short flags of `rg` / `grep` that take a value (next argument, or the
/// rest of the cluster). Only flags known to take a value are listed: a
/// missing one makes its value look like the pattern, which is the safe
/// direction (the real pattern is then checked as a path), whereas a
/// wrongly listed one would swallow the pattern and hide a path.
const RG_VALUE_SHORT: &str = "efgtTmABCdjEMr";
const GREP_VALUE_SHORT: &str = "efmABCdD";
const RG_VALUE_LONG: &[&str] = &[
    "regexp", "file", "glob", "iglob", "type", "type-not", "type-add", "type-clear",
    "max-count", "after-context", "before-context", "context", "max-depth", "threads",
    "encoding", "max-columns", "replace", "color", "colors", "sort", "sortr",
    "ignore-file", "path-separator", "pre", "pre-glob", "regex-size-limit",
    "dfa-size-limit", "max-filesize", "context-separator", "field-context-separator",
    "field-match-separator", "engine", "hostname-bin", "hyperlink-format", "generate",
];
const GREP_VALUE_LONG: &[&str] = &[
    "regexp", "file", "max-count", "after-context", "before-context", "label",
    "binary-files", "devices", "directories", "include", "exclude", "exclude-dir",
    "exclude-from",
];

/// Path operands of `rg` / `grep`. The first positional argument is the
/// pattern unless one was given with `-e` / `-f` / `--regexp` / `--file`
/// (or rg is listing files with `--files` / `--type-list`).
fn pattern_search_paths(cmd: &str, args: &[String]) -> Vec<String> {
    let (short_vals, long_vals) = if cmd == "rg" {
        (RG_VALUE_SHORT, RG_VALUE_LONG)
    } else {
        (GREP_VALUE_SHORT, GREP_VALUE_LONG)
    };
    let mut positional = Vec::new();
    let mut pattern_given = false;
    let mut options_done = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if options_done || !a.starts_with('-') || a == "-" {
            positional.push(a.clone());
            continue;
        }
        if a == "--" {
            options_done = true;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline_value) = match long.split_once('=') {
                Some((n, _)) => (n, true),
                None => (long, false),
            };
            if matches!(name, "regexp" | "file")
                || (cmd == "rg" && matches!(name, "files" | "type-list"))
            {
                pattern_given = true;
            }
            if !inline_value && long_vals.contains(&name) {
                i += 1;
            }
            continue;
        }
        let flags: Vec<char> = a[1..].chars().collect();
        for (k, c) in flags.iter().enumerate() {
            if short_vals.contains(*c) {
                pattern_given |= matches!(c, 'e' | 'f');
                if k + 1 == flags.len() {
                    i += 1; // value is the next argument
                }
                break; // otherwise the rest of the cluster is the value
            }
        }
    }
    if pattern_given {
        positional
    } else {
        positional.into_iter().skip(1).collect()
    }
}


/// Extract paths from download command arguments.
fn extract_download_paths(args: &[String], cmd: &str) -> Vec<(String, PathContext)> {
    let mut out = Vec::new();
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
                out.push((path_arg.clone(), PathContext::DownloadOutput));
            }
            i += 2;
            continue;
        }
        if data_long_flags.contains(&arg.as_str()) || data_short_flags.contains(&arg.as_str()) {
            if let Some(data_arg) = args.get(i + 1) {
                if let Some(p) = extract_path_from_curl_data(data_arg) {
                    out.push((p, PathContext::UploadData));
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
                out.push((path_arg.clone(), PathContext::HelperFile));
            }
            i += 2;
            continue;
        }
        // Handle --flag=value forms
        for flag in output_flags.iter().chain(data_long_flags) {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if data_long_flags.contains(flag) {
                    if let Some(p) = extract_path_from_curl_data(value) {
                        out.push((p, PathContext::UploadData));
                    }
                } else {
                    out.push((value.to_string(), PathContext::DownloadOutput));
                }
            }
        }
        // Helper-flag --flag=value forms.
        for flag in helper_long_flags {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if !value.is_empty() {
                    out.push((value.to_string(), PathContext::HelperFile));
                }
            }
        }
        // Handle concatenated short flags: -d@path, -T/path
        for flag in data_short_flags {
            if arg.starts_with(flag) && arg.len() > flag.len() {
                let value = &arg[flag.len()..];
                if let Some(p) = extract_path_from_curl_data(value) {
                    out.push((p, PathContext::UploadData));
                }
            }
        }
        // Concatenated short form for helper flags: -K/tmp/curlrc, -i/tmp/urls.
        for flag in helper_short_flags {
            if arg.starts_with(flag) && arg.len() > flag.len() {
                let value = &arg[flag.len()..];
                out.push((value.to_string(), PathContext::HelperFile));
            }
        }
        i += 1;
    }
    out
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
/// Without any `-e` / `-f`, the first operand is the script (POSIX), so
/// `sed '/etc/d' hosts.txt` only checks `hosts.txt`. An empty argument
/// right after `-i` is BSD's backup suffix (`sed -i '' …`), not the script.
///
/// `-i` / `-i<suffix>` (GNU in-place edit) have no separate argument;
/// `-l N` (GNU line length) takes one.
fn extract_sed_paths(args: &[String]) -> Vec<(String, PathContext)> {
    let mut out = Vec::new();
    let mut operands: Vec<&String> = Vec::new();
    let mut script_given = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;

        if arg == "--expression" {
            script_given = true;
            i += 1;
            continue;
        }
        if arg == "--file" {
            script_given = true;
            if let Some(next) = args.get(i) {
                out.push((next.clone(), PathContext::SedFile));
            }
            i += 1;
            continue;
        }
        if arg.starts_with("--expression=") {
            script_given = true;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--file=") {
            script_given = true;
            if !val.is_empty() {
                out.push((val.to_string(), PathContext::SedFile));
            }
            continue;
        }
        if arg.starts_with("--") || arg == "-" || !arg.starts_with('-') {
            if !arg.starts_with("--") {
                operands.push(arg);
            }
            continue;
        }

        // Short option cluster, e.g. `-n`, `-ne`, `-i.bak`, `-fscript.sed`.
        let flags: Vec<char> = arg[1..].chars().collect();
        for (k, c) in flags.iter().enumerate() {
            let rest: String = flags[k + 1..].iter().collect();
            match c {
                'i' => {
                    // The rest is the in-place suffix; BSD's `-i ''`
                    // passes an empty suffix as the next argument.
                    if rest.is_empty() && args.get(i).is_some_and(|a| a.is_empty()) {
                        i += 1;
                    }
                    break;
                }
                'e' => {
                    script_given = true;
                    if rest.is_empty() {
                        i += 1;
                    }
                    break;
                }
                'f' => {
                    script_given = true;
                    let path = if rest.is_empty() {
                        i += 1;
                        args.get(i - 1).cloned()
                    } else {
                        Some(rest)
                    };
                    if let Some(p) = path {
                        out.push((p, PathContext::SedFile));
                    }
                    break;
                }
                'l' => {
                    if rest.is_empty() {
                        i += 1;
                    }
                    break;
                }
                _ => {}
            }
        }
    }

    let mut files = operands.into_iter();
    if !script_given {
        files.next(); // the script (possibly empty: `sed '' file`)
    }
    for f in files.filter(|a| !a.is_empty()) {
        out.push((f.clone(), PathContext::SedFile));
    }
    out
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
//   * At each unquoted `#` that begins a word, strip the comment up to
//     (not including) the newline. Without this, an apostrophe in
//     `# don't` flips every downstream quote tracker, and `# cat <<EOF`
//     queues a heredoc that swallows the rest of the command.

/// What a `HeredocSpan` covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    /// The `<<[-]DELIM` operator.
    HeredocOp,
    /// A heredoc body including its closing delimiter line. `expands` is
    /// true when the delimiter was unquoted — bash then runs `$(…)` and
    /// backtick substitutions inside the body.
    HeredocBody { expands: bool },
    /// A `<<<` here-string operator plus its word.
    HereString,
    /// A `# …` comment, up to but not including the newline.
    Comment,
}

/// One byte span to be removed by `strip_heredocs`.
#[derive(Debug, Clone)]
pub struct HeredocSpan {
    pub start: usize,
    pub end: usize,
    pub kind: SpanKind,
    /// For heredoc bodies: where the content ends (the start of the
    /// closing delimiter line, or `end` if unclosed). Otherwise `end`.
    pub content_end: usize,
}

struct PendingHeredoc {
    delim: String,
    strip_tabs: bool,
    expands: bool,
}

/// Is the unquoted `#` at byte `i` the start of a shell comment? Bash
/// only treats `#` as a comment when it begins a word.
fn is_comment_start(bytes: &[u8], i: usize) -> bool {
    i == 0
        || matches!(
            bytes[i - 1],
            b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')'
        )
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
    // `A` = arithmetic `((`, `P` = plain `(`.
    let mut parens: Vec<u8> = Vec::new();
    let mut arith_depth = 0usize;

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
        // A command substitution inside double quotes is its own parse
        // context — `"$(cat <<'EOF'⏎don't⏎EOF⏎)"` — so skip it whole;
        // its heredoc and quotes are handled when its body is walked.
        if in_double && b == b'$' && bytes.get(i + 1) == Some(&b'(') {
            // Unclosed: bash treats the rest as its body, and so does
            // `scan_substitutions` (fail closed) — nothing left to scan.
            i = matching_paren(cmd, i + 1).map_or(bytes.len(), |c| c + 1);
            continue;
        }
        if in_single || in_double {
            i = advance_char(bytes, i);
            continue;
        }

        // Comment: everything up to the newline is inert, including
        // quotes (`# don't`) and heredoc operators (`# cat <<EOF`).
        // The newline itself is kept so it still ends the command and
        // still releases any pending heredoc.
        if b == b'#' && is_comment_start(bytes, i) {
            let mut j = i;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            out.push(HeredocSpan {
                start: i,
                end: j,
                content_end: j,
                kind: SpanKind::Comment,
            });
            i = j;
            continue;
        }

        // Newline outside quotes: drain any pending heredoc bodies.
        if b == b'\n' && !pending.is_empty() {
            i += 1;
            for heredoc in std::mem::take(&mut pending) {
                let body_start = i;
                let mut line_start = i;
                let body_end;
                let content_end;
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
                        content_end = line_start;
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
                        content_end = bytes.len();
                        break;
                    }
                    line_start = line_end + 1;
                }
                out.push(HeredocSpan {
                    start: body_start,
                    end: body_end,
                    content_end,
                    kind: SpanKind::HeredocBody {
                        expands: heredoc.expands,
                    },
                });
                i = body_end;
            }
            continue;
        }

        // Arithmetic `$((…))` / `((…))`: its `<<` is a bit shift, not a
        // heredoc (`echo $((1<<20))⏎rm -rf /` must not hide line two).
        // Tracked in one linear pass: `((cmd) )` turns out to be a
        // subshell when its first `)` isn't followed by another.
        match b {
            b'(' if bytes.get(i + 1) == Some(&b'(') => {
                parens.push(b'A');
                arith_depth += 1;
                i += 2;
                continue;
            }
            b'(' => {
                parens.push(b'P');
                i += 1;
                continue;
            }
            b')' => {
                match parens.last() {
                    Some(b'A') if bytes.get(i + 1) == Some(&b')') => {
                        parens.pop();
                        arith_depth -= 1;
                        i += 2;
                        continue;
                    }
                    Some(b'A') => {
                        *parens.last_mut().unwrap() = b'P';
                        arith_depth -= 1;
                    }
                    Some(_) => {
                        parens.pop();
                    }
                    None => {}
                }
                i += 1;
                continue;
            }
            _ => {}
        }
        let in_arithmetic = arith_depth > 0;

        if b == b'<' && i + 1 < bytes.len() && bytes[i + 1] == b'<' && !in_arithmetic {
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
                    content_end: end,
                    kind: SpanKind::HereString,
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
            // Any quoting in the delimiter word disables expansion in
            // the body (`<<'EOF'`, `<<"EOF"`, `<<\EOF`, `<<E"OF"`).
            let expands = !cmd[j..delim_end].contains(['\'', '"', '\\']);
            out.push(HeredocSpan {
                start: op_start,
                end: delim_end,
                content_end: delim_end,
                kind: SpanKind::HeredocOp,
            });
            pending.push(PendingHeredoc {
                delim,
                strip_tabs,
                expands,
            });
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

/// Replace every span returned by `find_heredoc_spans` (heredocs,
/// here-strings and `#` comments) with a single space, preserving token
/// boundaries on either side. Returns the original string unchanged when
/// none are present.
pub fn strip_heredocs(cmd: &str) -> String {
    if !cmd.contains("<<") && !cmd.contains('#') {
        return cmd.to_string();
    }
    strip_spans(cmd, &find_heredoc_spans(cmd))
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
            // `>`, `>>`, or `>|` (noclobber override)
            let mut k = j + 1;
            if k < bytes.len() && matches!(bytes[k], b'>' | b'|') {
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
        // `>& word` / `>&word`: same as `&> word` unless word is an fd.
        if bytes[t] == b'&' {
            t += 1;
            while t < bytes.len() && (bytes[t] == b' ' || bytes[t] == b'\t') {
                t += 1;
            }
            let word_end = (t..bytes.len())
                .find(|&k| matches!(bytes[k], b' ' | b'\t' | b'\n' | b';' | b'|' | b'&'))
                .unwrap_or(bytes.len());
            if t >= bytes.len()
                || cmd[t..word_end] == *"-"
                || (word_end > t && bytes[t..word_end].iter().all(u8::is_ascii_digit))
            {
                i = word_end.max(op_end);
                continue;
            }
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

/// How a sub-command produced by `split_shell_operators_with_ops` ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separator {
    /// `|` or `|&`: this command's output feeds the next command.
    Pipe,
    /// `;`, `&&`, `||`, background `&`, newline, or end of input.
    Other,
}

/// Split a command string on shell operators (`&&`, `||`, `;`, `|`,
/// `|&`, background `&`, and unquoted newlines) while respecting quotes.
pub fn split_shell_operators(command: &str) -> Vec<String> {
    split_shell_operators_with_ops(command)
        .into_iter()
        .map(|(part, _)| part)
        .collect()
}

/// Like `split_shell_operators`, but also reports the separator that
/// ended each part.
///
/// An unquoted, unescaped newline ends a command exactly like `;` —
/// without this, every line after the first would be parsed as
/// arguments of the first command (and e.g. `cd src⏎rm -rf /` would
/// only check `src`). A backslash-newline continuation is kept intact.
///
/// A single `&` (background) also ends a command, except in fd
/// redirections: `&>`, `&>>`, `>&N`, `2>&1`, `<&N`.
pub fn split_shell_operators_with_ops(command: &str) -> Vec<(String, Separator)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;
    // Previous unquoted, unescaped character, to tell the `&` of
    // `2>&1` / `<&0` (fd duplication) apart from a background `&`.
    let mut prev: Option<char> = None;

    while let Some(ch) = chars.next() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            prev = None;
            continue;
        }

        if ch == '\\' && !in_single_quote {
            escape_next = true;
            current.push(ch);
            prev = None;
            continue;
        }

        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            current.push(ch);
            prev = None;
            continue;
        }

        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            current.push(ch);
            prev = None;
            continue;
        }

        if in_single_quote || in_double_quote {
            current.push(ch);
            prev = None;
            continue;
        }

        match ch {
            '&' if chars.peek() == Some(&'&') => {
                chars.next(); // consume second '&'
                parts.push((std::mem::take(&mut current), Separator::Other));
            }
            '&' if chars.peek() == Some(&'>') || matches!(prev, Some('>' | '<')) => {
                // `&>` / `&>>` / `>&N` / `<&N`: part of a redirection.
                current.push(ch);
            }
            '&' => {
                // Background `&` ends the command.
                parts.push((std::mem::take(&mut current), Separator::Other));
            }
            '|' if prev == Some('>') => {
                // `>|` (noclobber override) is a redirection, not a pipe.
                current.push(ch);
            }
            '|' if chars.peek() == Some(&'|') => {
                chars.next(); // consume second '|'
                parts.push((std::mem::take(&mut current), Separator::Other));
            }
            '|' => {
                // Single pipe (or `|&`) — still a boundary for analysis.
                if chars.peek() == Some(&'&') {
                    chars.next();
                }
                parts.push((std::mem::take(&mut current), Separator::Pipe));
            }
            ';' | '\n' => {
                parts.push((std::mem::take(&mut current), Separator::Other));
            }
            _ => {
                current.push(ch);
            }
        }
        prev = Some(ch);
    }

    if !current.trim().is_empty() {
        parts.push((current, Separator::Other));
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
