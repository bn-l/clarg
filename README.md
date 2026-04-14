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
```

CLI equivalents: `--no-root`, `--no-system-dirs`, `--no-unknown-tools`.

**`no_root`** — blocks paths that lexically normalize to `/` (so `/./*`, `/../*`, `/tmp/../*` are all caught) and `/<glob>` forms that iterate root's direct children (`/*`, `/**`, `/?`, `/[abc]`, `/foo*`). Also catches bare `/` inside `python -c`/`node -e`/etc. string literals.

**`no_system_dirs`** — blocks access to the following system directories and their descendants: `/bin`, `/boot`, `/etc`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/proc`, `/root`, `/sbin`, `/srv`, `/sys`, `/usr`, `/var`, `/System`, `/Library`, `/private`, `/Applications`, `/cores`, `/Network`. Intentionally *not* blocked: `/tmp`, `/opt`, `/dev`, `/home`, `/Users`, `/run`, `/mnt`, `/media`. Paths inside the project root are exempt via an escape hatch (so projects living under e.g. `/var/www/site` keep working; both the raw and canonicalized roots are recognized to cover symlink aliases like macOS `/var` → `/private/var`).

**`no_unknown_tools`** — denies any tool clarg does not route (includes MCP tools like `mcp__filesystem__read_file`). Known tools — `Bash`, `Read`, `Write`, `Edit`, `NotebookEdit`, `Glob`, `Grep`, `WebFetch`, `WebSearch`, `Task`, `AskUserQuestion`, `TodoWrite`, `Skill`, `SendMessage`, `TeamCreate`/`TeamDelete`, `EnterPlanMode`/`ExitPlanMode`, `TaskCreate`/`TaskGet`/`TaskUpdate`/`TaskList`/`TaskOutput`/`TaskStop` — remain allowed.

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

Or in YAML config:

```yaml
log_dir: /tmp/clarg-logs
```

## Exit codes

- `0` allow
- `2` deny / internal error (fail closed)
    - This will provide a nice message as to why the command failed so the LLM can adjust.
