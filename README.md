# clarg

Claude code argument guard. Uses the `PreToolUse` hook to block risky commands, arguments to commands, and/or file access.

## Install

With homebrew:

```bash
brew install bn-l/tap/clarg
```

Or cargo: clone this then:

```bash
cargo install --path .
```

## Hook setup (`.claude/settings.json`) example:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "clarg -b '.env,*.secret' -c 'rm -rf,sudo' -i --no-root --no-system-dirs"
          }
        ]
      }
    ]
  }
}
```

## Config (optional)

If a path to a config file is passed, all options will be ignored (the config overrides them).

```bash
clarg ./clarg.yaml
```

```yaml
block_access_to:
  - ".env"
commands_forbidden:
  - "rm -rf"
internal_access_only: true
special_flags:
  no_root: true
  no_system_dirs: true
  no_unknown_tools: true
```

### Special flags

Shortcuts for common safety guardrails. All default to `false`.

```yaml
special_flags:
  no_root: true          # block commands/tools targeting `/` (incl. /*, /**, /./*, /../*)
  no_system_dirs: true   # block access to OS system dirs (see list below)
  no_unknown_tools: true # deny any tool clarg does not explicitly recognize (incl. MCP tools)
  no_broad_search: true  # block searching or listing your home folder or anything above it
```

CLI equivalents: `--no-root`, `--no-system-dirs`, `--no-unknown-tools`, `--no-broad-search`.

**`no_root`** — blocks paths that lexically normalize to `/` (so `/./*`, `/../*`, `/tmp/../*` are all caught) and `/<glob>` forms that iterate root's direct children (`/*`, `/**`, `/?`, `/[abc]`, `/foo*`). Only *unquoted* glob characters count, as in bash: `rm -rf /*` is blocked, while `printf '/* comment */'` names a literal file and is allowed. Also catches a bare `"/"` passed to a filesystem call in `python -c`/`node -e`/etc. (`os.chdir("/")`, `rmtree("/")`, `cwd="/"`), but not one used as a string (`x.split("/")`, `"/".join(…)`, `p == "/"`).

**`no_system_dirs`** — blocks access to the following system directories and their descendants: `/bin`, `/boot`, `/etc`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/proc`, `/root`, `/sbin`, `/srv`, `/sys`, `/usr`, `/var`, `/System`, `/Library`, `/private`, `/Applications`, `/cores`, `/Network`, `/dev`. Intentionally *not* blocked: `/tmp`, `/opt`, `/home`, `/Users`, `/run`, `/mnt`, `/media`. Carved-out exceptions under blocked prefixes: `/private/tmp`, `/var/folders` and `/private/var/folders` (macOS `$TMPDIR`), `/var/tmp` and `/private/var/tmp`, `/usr/bin/log`, and the harmless devices `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`, `/dev/tty` and `/dev/fd/*` (so `> /dev/disk2` and `dd of=/dev/sda` are blocked). Paths inside the project root are exempt via an escape hatch (so projects living under e.g. `/var/www/site` keep working; both the raw and canonicalized roots are recognized to cover symlink aliases like macOS `/var` → `/private/var`).

**`no_broad_search`** — keeps the names in your home folder private. Nothing may search, list or glob-enumerate `$HOME` or anything above it (`/Users`, `/`):
- searches: `rg foo ~`, `fd x ~`, `find ~ …`, `grep -r foo ~`, `ag`, `ack`, including `fd --search-path ~`;
- listings and walkers: `ls ~`, `ls -R ~`, `tree ~`, `du -sh ~`, `eza ~`, `lsd ~`;
- globs the shell expands: `echo ~/*`, `du -sh ~/*`, `cat ~/.c*`;
- a search or listing of the current directory after `cd ~`;
- Claude Code's `Grep` / `Glob` tools rooted there (`Glob` with pattern `~/**/x`);
- best effort: inline code using the bare home path (`os.listdir("/Users/me")`).

Subfolders and known paths stay allowed: `rg x ~/projects`, `ls ~/.config`, `cat ~/.zshrc`, `ls -d ~`. The deny message suggests scoping the search, or `mdfind -name <name>` (Spotlight) to find a file by name.

With `internal_access_only`, every search root counts as a path, so no search can leave the project — including `fd --search-path` and an absolute `Glob` pattern.

**`no_unknown_tools`** — denies any tool clarg does not route (includes MCP tools like `mcp__filesystem__read_file`). Known tools — `Bash`, `Monitor`, `Read`, `Write`, `Edit`, `NotebookEdit`, `LSP`, `Glob`, `Grep`, `WebFetch`, `WebSearch`, `Task`/`Agent`, `AskUserQuestion`, `TodoWrite`, `Skill`, `SendMessage`, `TeamCreate`/`TeamDelete`, `EnterPlanMode`/`ExitPlanMode`, `TaskCreate`/`TaskGet`/`TaskUpdate`/`TaskList`/`TaskOutput`/`TaskStop`, `ToolSearch`, `SubagentHandback`, `ScheduleWakeup`, `ListAgents`, `CronCreate`/`CronDelete`/`CronList`, `EnterWorktree`/`ExitWorktree`, and the MCP resource tools — remain allowed. (`Monitor` runs shell commands, so its `command` is checked exactly like `Bash`; `LSP`'s `filePath` is checked like `Read`.)

### How Bash commands are analysed

clarg follows the shell's own rules when extracting the paths a command touches:

- **Command boundaries:** `;`, `&&`, `||`, `|`, background `&`, and newlines all separate commands, so every line of a multi-line command is checked. `#` comments, heredoc bodies and here-strings are not treated as commands.
- **Working directory:** relative paths are resolved from the hook's `cwd`, and `cd` / `pushd` / `popd` are followed through the command (`cd /tmp && rm -rf ../etc` is checked as `/etc`).
- **Variables:** assignments made earlier in the same command are expanded (`D=/etc; cat $D/passwd`), as are `$PWD` and variables from the environment. Single-quoted `$` is literal.
- **Nested code:** the bodies of `$(…)`, backticks, `<(…)`, `eval`, `bash -c` / `bash -lc`, and heredocs or here-strings fed to a shell (`bash <<'EOF'`) are checked as commands. Heredocs fed to `python3`/`node`/etc. (`python3 - <<'EOF'`) are treated like `python3 -c`.
- **Operands that aren't paths:** `echo`/`printf`/`tr` text (unless it holds an unquoted glob, or the output is piped on or substituted), `cut -d` / `awk -F` / `sort -t` delimiters, a `sed` script, and the pattern given to `rg` / `grep`.

What stays unknowable: the output of a command substitution, variables set by loops or `read`, and the directory after `cd` to such a value.

Unknown keys **inside** `special_flags` fail closed (typos are rejected), while unknown keys at the top level of the YAML are silently ignored as before.

### Pattern scope

Patterns in `block_access_to` use gitignore syntax and match anywhere by default — `.env` blocks both `<project>/.env` and `/Users/alice/.env`.

To restrict a pattern to the project, anchor it with a leading `/`:

```yaml
block_access_to:
  - /.env              # only <project>/.env
  - /secrets/**        # only <project>/secrets/**
```

Patterns starting with `~` or `$HOME` are home-expanded (e.g. `~/.ssh/**`).

## Logging

All tool evaluations are logged to a rotating file at:

```
$XDG_STATE_HOME/clarg/clarg.log
```

which defaults to `~/.local/state/clarg/clarg.log` (symlink to the current log file).

Logs rotate at 1 MB with 3 old files kept.

To override the log directory:

```bash
clarg -l /tmp/clarg-logs -b '.env' -i
```

Or in YAML config (a relative path is resolved against the project directory):

```yaml
log_dir: /tmp/clarg-logs
```

## Exit codes

- `0` allow
- `2` deny / internal error (fail closed)
    - This will provide a nice message as to why the command failed so the LLM can adjust.
