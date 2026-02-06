# clarg

Claude Code `PreToolUse` hook to block risky file access and commands.

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
            "command": "clarg -b '.env,*.secret' -c 'rm -rf,sudo' -i"
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
```

## Exit codes

- `0` allow
- `2` deny / internal error (fail closed)
    - This will provide a nice message as to why the command failed so the LLM can adjust.
