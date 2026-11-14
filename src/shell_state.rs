//! Shell state tracked while walking one Bash command, so that later
//! sub-commands see the effects of earlier ones: `cd` / `pushd` / `popd`
//! and variable assignments.
//!
//! Without this, `cd /tmp && rm -rf ../etc` checks `../etc` against the
//! starting directory instead of `/tmp`, and `D=/etc; cat $D/passwd`
//! checks the literal relative path `$D/passwd`.

use crate::bash_analyzer::{SENTINEL_LBRACKET, SENTINEL_QUESTION, SENTINEL_STAR, SUBST_OPEN};
use crate::internalonly::expand_home;
use std::collections::HashMap;
use std::path::Path;

/// A directory as tracked by `ShellState`:
///
/// * `Some("")` — the starting directory (relative paths stay as written,
///   and the router resolves them against the hook's `cwd`);
/// * `Some(p)` — `p`, absolute or relative to the starting directory,
///   with `~` already expanded;
/// * `None` — unknown (e.g. after `cd "$UNSET"` or `cd $(…)`).
pub type Dir = Option<String>;

#[derive(Debug, Clone)]
struct Var {
    /// `None` when the value can't be determined statically.
    value: Option<String>,
    exported: bool,
}

#[derive(Debug, Clone)]
pub struct ShellState {
    /// Absolute starting directory, when known. Only used for `$PWD`.
    start: Option<String>,
    cwd: Dir,
    oldpwd: Dir,
    dir_stack: Vec<Dir>,
    vars: HashMap<String, Var>,
}

impl ShellState {
    pub fn new(start: Option<&Path>) -> Self {
        Self {
            start: start.map(|p| p.to_string_lossy().into_owned()),
            cwd: Some(String::new()),
            oldpwd: None,
            dir_stack: Vec::new(),
            vars: HashMap::new(),
        }
    }

    /// Join `raw` onto the current directory.
    ///
    /// Absolute paths are returned unchanged, and so are `~` / `$HOME`
    /// paths (the router expands those) — except for redirection targets,
    /// which were already tilde-expanded, so a leading `~` there is a
    /// literal file name. With an unknown directory the path is returned
    /// unchanged and falls back to the starting directory.
    pub fn join(&self, raw: &str, redirection: bool) -> String {
        if raw.is_empty() || raw.starts_with('/') {
            return raw.to_string();
        }
        if !redirection && (raw.starts_with('~') || raw.starts_with("$HOME")) {
            return raw.to_string();
        }
        match self.cwd.as_deref() {
            Some("") | None => raw.to_string(),
            Some(dir) => join_dir(dir, raw),
        }
    }

    fn resolve_dir(&self, target: &str) -> Dir {
        if is_unresolved(target) {
            return None;
        }
        let target = if target.starts_with('~') || target.starts_with("$HOME") {
            expand_home(target).to_string_lossy().into_owned()
        } else {
            target.to_string()
        };
        if target.starts_with('/') {
            return Some(target);
        }
        match self.cwd.as_deref() {
            Some("") => Some(target),
            Some(dir) => Some(join_dir(dir, &target)),
            None => None,
        }
    }

    /// `cd <target>`.
    pub fn cd(&mut self, target: &str) {
        let new = self.resolve_dir(target);
        self.oldpwd = std::mem::replace(&mut self.cwd, new);
    }

    /// `cd` with no target: go to `$HOME`.
    pub fn cd_home(&mut self) {
        let home = std::env::var("HOME").ok().filter(|h| !h.is_empty());
        self.oldpwd = std::mem::replace(&mut self.cwd, home);
    }

    /// `cd -`: swap with the previous directory.
    pub fn cd_dash(&mut self) {
        std::mem::swap(&mut self.cwd, &mut self.oldpwd);
    }

    /// A directory change we can't follow (e.g. `pushd +2`).
    pub fn cd_unknown(&mut self) {
        self.oldpwd = self.cwd.take();
    }

    /// `pushd <target>`.
    pub fn pushd(&mut self, target: &str) {
        self.dir_stack.push(self.cwd.clone());
        self.cd(target);
    }

    /// `pushd` with no target: swap the top two directories.
    pub fn pushd_swap(&mut self) {
        if let Some(top) = self.dir_stack.pop() {
            self.dir_stack.push(self.cwd.clone());
            self.oldpwd = std::mem::replace(&mut self.cwd, top);
        }
    }

    /// `popd`. With an empty stack bash errors and stays put.
    pub fn popd(&mut self) {
        if let Some(dir) = self.dir_stack.pop() {
            self.oldpwd = std::mem::replace(&mut self.cwd, dir);
        }
    }

    /// `NAME=value` (persisting assignment), `export NAME=value`, etc.
    /// `raw_value` is expanded against the current state first.
    pub fn assign(&mut self, name: &str, raw_value: &str, export: bool) {
        let value = expand_vars(raw_value, self);
        self.set(name, value, export);
    }

    fn set(&mut self, name: &str, mut value: String, export: bool) {
        // Bash tilde-expands unquoted assignment values.
        if value.starts_with('~') {
            value = expand_home(&value).to_string_lossy().into_owned();
        }
        let known = !is_unresolved(&value);
        let exported = export || self.is_exported(name);
        self.vars.insert(
            name.to_string(),
            Var {
                value: known.then_some(value),
                exported,
            },
        );
    }

    fn is_exported(&self, name: &str) -> bool {
        self.vars.get(name).is_some_and(|v| v.exported) || std::env::var_os(name).is_some()
    }

    /// The variable now holds something we can't know (`for NAME in`,
    /// `read NAME`, `NAME+=x`, `printf -v NAME`).
    pub fn mark_unknown(&mut self, name: &str) {
        let exported = self.is_exported(name);
        self.vars.insert(
            name.to_string(),
            Var {
                value: None,
                exported,
            },
        );
    }

    /// `unset NAME`: it now expands to nothing.
    pub fn unset(&mut self, name: &str) {
        self.vars.insert(
            name.to_string(),
            Var {
                value: Some(String::new()),
                exported: false,
            },
        );
    }

    /// `export NAME` (no value).
    pub fn export(&mut self, name: &str) {
        if let Some(var) = self.vars.get_mut(name) {
            var.exported = true;
        }
    }

    /// A copy with temporary `prefix` assignments applied
    /// (`D=/etc eval '…'`). Values are expanded against `self`.
    pub fn with_prefix(&self, prefix: &[(String, String)]) -> Self {
        let mut state = self.clone();
        for (name, raw) in prefix {
            let value = expand_vars(raw, self);
            state.set(name, value, true);
        }
        state
    }

    /// State for a new shell (`bash -c …`): same directory, exported
    /// variables only, plus the `prefix` assignments of that command.
    pub fn child_shell(&self, prefix: &[(String, String)]) -> Self {
        let mut child = Self {
            start: self.start.clone(),
            cwd: self.cwd.clone(),
            oldpwd: self.oldpwd.clone(),
            dir_stack: Vec::new(),
            vars: self
                .vars
                .iter()
                .filter(|(_, v)| v.exported)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        for (name, raw) in prefix {
            let value = expand_vars(raw, self);
            child.set(name, value, true);
        }
        child
    }

    fn lookup(&self, name: &str) -> Option<String> {
        match name {
            "PWD" => return self.absolute(&self.cwd),
            "OLDPWD" => return self.absolute(&self.oldpwd),
            _ => {}
        }
        if let Some(var) = self.vars.get(name) {
            return var.value.clone();
        }
        std::env::var(name).ok()
    }

    fn absolute(&self, dir: &Dir) -> Option<String> {
        let dir = dir.as_deref()?;
        if dir.starts_with('/') {
            return Some(dir.to_string());
        }
        let start = self.start.as_deref()?;
        Some(if dir.is_empty() {
            start.to_string()
        } else {
            join_dir(start, dir)
        })
    }
}

fn join_dir(dir: &str, rel: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), rel)
}

/// Does `s` still contain an expansion we couldn't resolve?
pub fn is_unresolved(s: &str) -> bool {
    s.contains('$') || s.contains('`') || s.contains(SUBST_OPEN)
}

/// `[A-Za-z_][A-Za-z0-9_]*`
pub fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Split `NAME=value` into its parts. `NAME+=value` (append) is reported
/// with `append = true`. Returns `None` for anything else.
pub fn parse_assignment(token: &str) -> Option<(&str, &str, bool)> {
    let (lhs, value) = token.split_once('=')?;
    if let Some(name) = lhs.strip_suffix('+') {
        return is_valid_name(name).then_some((name, value, true));
    }
    is_valid_name(lhs).then_some((lhs, value, false))
}

/// Expand `$NAME` and `${NAME}` references whose value is known.
/// Unknown references are left as written.
///
/// `s` is a masked token: a `$` that was single-quoted or escaped is a
/// sentinel, not `$`, so it is never expanded. Glob characters inside an
/// inserted value are made active, because bash pathname-expands the
/// result of an unquoted expansion (`D='/*'; rm -rf $D`).
pub fn expand_vars(s: &str, state: &ShellState) -> String {
    if !s.contains('$') {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$'
            && let Some((name, end)) = var_ref_at(&chars, i)
            && let Some(value) = state.lookup(&name)
        {
            out.push_str(&activate_globs(&value));
            i = end;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// `$NAME` or `${NAME}` at `chars[i]` → (name, index just past it).
fn var_ref_at(chars: &[char], i: usize) -> Option<(String, usize)> {
    match chars.get(i + 1) {
        Some('{') => {
            let close = chars[i + 2..].iter().position(|&c| c == '}')? + i + 2;
            let name: String = chars[i + 2..close].iter().collect();
            is_valid_name(&name).then_some((name, close + 1))
        }
        Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            Some((chars[i + 1..j].iter().collect(), j))
        }
        _ => None,
    }
}

fn activate_globs(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            SENTINEL_STAR => '*',
            SENTINEL_QUESTION => '?',
            SENTINEL_LBRACKET => '[',
            c => c,
        })
        .collect()
}
