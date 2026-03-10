**English** | [日本語](README.ja.md)

# guardrails

Code quality checker for Claude Code's PreToolCall hook. Combines external linters with custom rules to validate code and provide actionable fix suggestions.

## Features

- **oxlint integration** (priority): Lint rules from [oxc.rs](https://oxc.rs) with ESLint plugin compatibility
- **biome integration** (fallback): 300+ lint rules from [biomejs.dev](https://biomejs.dev)
- **Custom rules**: Security patterns external linters don't cover (JS/TS)
- **Claude-optimized output**: Actionable fix suggestions in stderr

## Installation

### Claude Code Plugin (Recommended)

Installs the binary and registers the hook automatically:

```bash
claude plugins marketplace add github:thkt/guardrails
claude plugins install guardrails
```

If the binary is not yet installed, run the bundled installer:

```bash
~/.claude/plugins/cache/guardrails/guardrails/*/hooks/install.sh
```

### Homebrew

```bash
brew install thkt/tap/guardrails
```

### From Release

Download the latest binary from [Releases](https://github.com/thkt/guardrails/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/thkt/guardrails/releases/latest/download/guardrails-aarch64-apple-darwin.tar.gz | tar xz
mv guardrails ~/.local/bin/
```

### From Source

```bash
cd /tmp
git clone https://github.com/thkt/guardrails.git
cd guardrails
cargo build --release
cp target/release/guardrails ~/.local/bin/
cd .. && rm -rf guardrails
```

## Usage

### As Claude Code Hook

When installed as a plugin, hooks are registered automatically. For manual setup, add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "guardrails",
            "timeout": 1000,
            "type": "command"
          }
        ],
        "matcher": "Write|Edit|MultiEdit"
      }
    ]
  }
}
```

## Requirements

Install at least one external linter (oxlint is preferred):

- [oxlint](https://oxc.rs) CLI installed (`npm i -g oxlint`) — **recommended**
- [biome](https://biomejs.dev) CLI installed (`brew install biome` or `npm i -g @biomejs/biome`) — fallback

### Linter Priority

guardrails uses **oxlint first**. If oxlint is not available, it falls back to biome. Only one runs per check.

| Condition                             | Linter used       |
| ------------------------------------- | ----------------- |
| oxlint installed                      | oxlint            |
| oxlint not installed, biome installed | biome             |
| Neither installed                     | Custom rules only |

Project config files (`oxlintrc.json`, `biome.json`) are automatically used when present.

## Custom Rules

See `src/rules/` for custom rules that complement external linters.

### Rules

| Rule               | Severity | Description                                     | When to disable                                  |
| ------------------ | -------- | ----------------------------------------------- | ------------------------------------------------ |
| `sensitiveFile`    | Critical | Blocks writes to .env, credentials.\*, \*.pem   | Never (security critical)                        |
| `cryptoWeak`       | High     | Detects MD5, SHA1, DES, RC4 usage               | Legacy system maintenance with known constraints |
| `sensitiveLogging` | High     | Detects password/token/secret in console.log    | Never (security critical)                        |
| `security`         | High     | XSS vectors, unsafe APIs, postMessage           | Never (security critical)                        |
| `architecture`     | High     | Layer violations (e.g., UI importing domain)    | Small projects, monoliths, or scripts            |
| `eval`             | High     | eval(), new Function(), indirect eval           | Never (security critical)                        |
| `hardcodedSecrets` | High     | API keys, tokens, passwords in source           | Never (security critical)                        |
| `openRedirect`     | High     | location.href/assign with user-controlled input | Non-web projects                                 |
| `rawHtml`          | High     | HTML concatenation with variables               | Non-web projects                                 |
| `httpResource`     | Medium   | HTTP (non-HTTPS) resource URLs                  | Development-only configs                         |
| `transaction`      | Medium   | Multiple writes without transaction wrapper     | Non-database projects                            |
| `domAccess`        | Medium   | Direct DOM manipulation in React (.tsx/.jsx)    | Non-React projects, or vanilla JS/TS             |
| `syncIo`           | Medium   | readFileSync, writeFileSync (blocks event loop) | CLI tools, build scripts, or sync-only contexts  |
| `bundleSize`       | Medium   | Full lodash/moment imports                      | Backend/Node.js (no bundle size concerns)        |
| `testAssertion`    | Medium   | Tests without expect() or assert calls          | Playwright, custom test frameworks               |
| `flakyTest`        | Low      | setTimeout, Math.random in tests                | Intentional timing/randomness tests              |
| `generatedFile`    | High     | Warns on \*.generated.\*, \*.g.ts edits         | No code generation in project                    |
| `testLocation`     | Medium   | Test files in src/ directory                    | Co-located test strategy (tests next to source)  |
| `naming`           | Mixed    | Naming conventions (hooks, components, types)   | Different naming conventions in team/project     |

## Exit Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | All checks passed                |
| 2    | Issues found (operation blocked) |

## Configuration

Add a `guardrails` key to `.claude/tools.json` at your project root. All fields are optional — only specify what you want to override.

> **Migration**: `.claude-guardrails.json` at the project root is still supported as a legacy fallback. If both exist, `.claude/tools.json` takes priority.

**Defaults** (no config file needed):

- All rules enabled
- Blocks on `critical` and `high` severity

### Schema

```json
{
  "guardrails": {
    "enabled": true,
    "rules": {
      "oxlint": true,
      "biome": true,
      "sensitiveFile": true,
      "cryptoWeak": true,
      "sensitiveLogging": true,
      "security": true,
      "architecture": true,
      "eval": true,
      "hardcodedSecrets": true,
      "openRedirect": true,
      "rawHtml": true,
      "httpResource": true,
      "transaction": true,
      "domAccess": true,
      "syncIo": true,
      "bundleSize": true,
      "testAssertion": true,
      "generatedFile": true,
      "testLocation": true,
      "naming": true,
      "flakyTest": true
    },
    "severity": {
      "blockOn": ["critical", "high"]
    }
  }
}
```

### Examples

**Minimal** (oxlint only, everything else default):

```json
{
  "guardrails": {
    "rules": {
      "oxlint": true
    }
  }
}
```

**Custom rules only** (disable external linters):

```json
{
  "guardrails": {
    "rules": {
      "oxlint": false,
      "biome": false
    }
  }
}
```

**Backend (Node.js/API)** — disable frontend-specific rules:

```json
{
  "guardrails": {
    "rules": {
      "domAccess": false,
      "bundleSize": false
    }
  }
}
```

**Block all severities**:

```json
{
  "guardrails": {
    "severity": {
      "blockOn": ["critical", "high", "medium", "low"]
    }
  }
}
```

**Disable guardrails for a project**:

```json
{
  "guardrails": {
    "enabled": false
  }
}
```

### Config Resolution

The config file is found by walking up from the target file to the nearest `.git` directory.

```text
project-root/
├── .claude/
│   └── tools.json     ← preferred (guardrails key)
├── .git/
├── src/
│   └── app.ts         ← file being checked → walks up to find config
└── .claude-guardrails.json  ← legacy fallback
```

## Using with Existing Linters

If you already run oxlint/biome via lefthook, husky, or lint-staged on commit, guardrails' linter checks may overlap. The two serve different purposes:

| Tool              | When                | Purpose                               |
| ----------------- | ------------------- | ------------------------------------- |
| guardrails (hook) | On every file write | Prevent issues before they're written |
| lefthook / husky  | On commit           | Final gate before code enters history |

To disable external linters in guardrails and rely on your commit hook instead:

```json
{
  "guardrails": {
    "rules": {
      "oxlint": false,
      "biome": false
    }
  }
}
```

This keeps guardrails' custom security rules (sensitiveFile, cryptoWeak, etc.) active while avoiding duplicate linter checks.

## Known Limitations

### Line-based rules (architecture, security, cryptoWeak, etc.)

These rules use `non_comment_lines()` which tracks `/* ... */` block comment state across lines and filters `//` line comments:

- **String literals containing `/*` or `*/`**: Comment markers inside string literals (e.g., `let s = "/* not a comment */";`) are treated as real comment boundaries, which may cause incorrect line filtering in rare cases.
- **Asterisk at line start**: Lines starting with `*` are treated as JSDoc continuations.

### Scanner-based rules (sensitiveLogging, testAssertion)

These rules use `StringScanner` which tracks comment state across lines:

- **JavaScript regex literals**: Patterns containing `//` or `/*` (e.g., `/https:\/\//`) may be misidentified as comment starts.

These trade-offs are acceptable for guardrails use cases where false positives are preferable to false negatives.

## Related Tools

| Tool | Hook | Timing | Role |
| --- | --- | --- | --- |
| **guardrails** | PreToolUse | Before Write/Edit | Lint + security checks |
| [formatter](https://github.com/thkt/formatter) | PostToolUse | After Write/Edit | Auto code formatting |
| [reviews](https://github.com/thkt/reviews) | PreToolUse | Review Skill execution | Static analysis context |
| [gates](https://github.com/thkt/gates) | Stop | Agent completion | Quality gates (knip, tsgo, madge) |

## License

MIT
