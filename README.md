# adversary_bot 🔪

> **A hostile, adversarial code reviewer for your pull requests.**

`adversary_bot` uses an LLM (OpenAI GPT-4o or Anthropic Claude) to deliberately hunt for security vulnerabilities, logic flaws, race conditions, and design weaknesses in your code — not style issues. It treats every line of code as a potential attack surface.

Inspired by Anthropic's internal use of Claude as an adversarial reviewer, this tool integrates with GitHub to automatically post structured critique comments on every PR, or can be run locally against any unified diff.

---

## Features

- 🔴 **Adversarial LLM prompting** — explicitly instructs the model to act as a hostile security auditor hunting for vulnerabilities, logic bombs, injection points, and broken auth
- 🔄 **Dual backend support** — switch between OpenAI (GPT-4o) and Anthropic Claude with a single environment variable
- 💬 **GitHub Action integration** — automatically posts structured inline review comments on PRs with file/line precision
- 🖥️ **Local CLI mode** — review any unified diff file or piped `git diff` output before pushing
- 📊 **Structured output** — JSON from the LLM parsed into typed `ReviewComment` objects with severity (`critical`/`high`/`medium`/`low`), category (`security`/`logic`/`design`), and actionable remediation suggestions

---

## Installation

### From PyPI (when published)

```bash
pip install adversary-bot
```

### From source

```bash
git clone https://github.com/example/adversary_bot.git
cd adversary_bot
pip install -e .
```

### Requirements

- Python 3.10+
- An OpenAI API key **or** an Anthropic API key
- (Optional) A GitHub personal access token for PR integration

---

## Quick Start

### 1. Configure environment variables

Create a `.env` file in your project root (or set these in your shell):

```bash
# Required: Choose a backend
ADVERSARY_BOT_BACKEND=openai        # or: anthropic

# Required: Provide the API key for your chosen backend
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...

# Optional: GitHub integration
GITHUB_TOKEN=ghp_...
GITHUB_REPO=owner/repo-name
```

### 2. Review a local diff

```bash
# Review a diff file
adversary-bot review-diff changes.diff

# Pipe git diff directly
git diff HEAD~1 | adversary-bot review-diff -

# Save output as JSON
adversary-bot review-diff changes.diff --output json > review.json

# Use Anthropic backend for this run
adversary-bot review-diff changes.diff --backend anthropic

# Only show critical and high severity findings
adversary-bot review-diff changes.diff --min-severity high
```

### 3. Review a GitHub pull request

```bash
# Review PR #42 and post inline comments
adversary-bot review-pr --repo owner/repo --pr 42

# Review but print to terminal only (don't post comments)
adversary-bot review-pr --repo owner/repo --pr 42 --no-post-comments

# Use a specific model
adversary-bot review-pr --repo owner/repo --pr 42 --model gpt-4o-mini
```

---

## Configuration Reference

All configuration can be set via environment variables or a `.env` file. CLI flags override environment variables.

| Environment Variable | Default | Description |
|---|---|---|
| `ADVERSARY_BOT_BACKEND` | `openai` | LLM backend: `openai` or `anthropic` |
| `OPENAI_API_KEY` | — | OpenAI API key (required for openai backend) |
| `ANTHROPIC_API_KEY` | — | Anthropic API key (required for anthropic backend) |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model name |
| `ANTHROPIC_MODEL` | `claude-opus-4-5` | Anthropic model name |
| `GITHUB_TOKEN` | — | GitHub personal access token |
| `GITHUB_REPO` | — | Repository in `owner/repo` format |
| `ADVERSARY_BOT_TEMPERATURE` | `0.3` | LLM sampling temperature (0.0–2.0) |
| `ADVERSARY_BOT_MAX_TOKENS` | `4096` | Maximum tokens in LLM response |
| `ADVERSARY_BOT_MIN_SEVERITY` | `medium` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `ADVERSARY_BOT_POST_COMMENTS` | `true` | Post inline comments to GitHub |
| `ADVERSARY_BOT_VERBOSE` | `false` | Enable verbose logging |

---

## GitHub Action Integration

Add this to your repository at `.github/workflows/adversary_review.yml`:

```yaml
name: Adversary Code Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  adversary-review:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install adversary_bot
        run: pip install adversary-bot

      - name: Run adversarial review
        env:
          ADVERSARY_BOT_BACKEND: openai
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          adversary-bot review-pr \
            --repo ${{ github.repository }} \
            --pr ${{ github.event.pull_request.number }}
```

> **Required secrets:** Add `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY`) to your repository's Settings → Secrets and variables → Actions.

### Permissions

The workflow requires:
- `pull-requests: write` — to post review comments
- `contents: read` — to access the repository diff

---

## Output Format

### Terminal output (default)

```
🔍 Adversary Review: src/auth/login.py

[CRITICAL] security — Line 47
SQL injection vulnerability in user lookup query.
User input `username` is interpolated directly into the SQL string without
parameterization. An attacker can bypass authentication or dump the database.

Remediation: Use parameterized queries or an ORM. Replace:
    query = f"SELECT * FROM users WHERE username='{username}'"
With:
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))

[HIGH] logic — Line 83
Race condition in session token generation...
```

### JSON output (`--output json`)

```json
{
  "files_reviewed": 3,
  "total_findings": 7,
  "comments": [
    {
      "file_path": "src/auth/login.py",
      "line_number": 47,
      "severity": "critical",
      "category": "security",
      "title": "SQL injection vulnerability in user lookup query",
      "description": "User input is interpolated directly into SQL...",
      "remediation": "Use parameterized queries..."
    }
  ]
}
```

---

## What adversary_bot looks for

The adversarial prompt explicitly instructs the LLM to hunt for:

**Security**
- Injection vulnerabilities (SQL, command, LDAP, XPath, template)
- Authentication and authorization bypasses
- Insecure deserialization
- Cryptographic weaknesses (weak algorithms, hardcoded keys, predictable tokens)
- Path traversal and file inclusion
- SSRF, XXE, and other request forgery vectors
- Sensitive data exposure

**Logic**
- Race conditions and TOCTOU vulnerabilities
- Integer overflow/underflow
- Off-by-one errors with security implications
- Incorrect error handling that leaks information
- Business logic flaws
- Null/None dereferences in critical paths

**Design**
- Missing input validation boundaries
- Overly broad permissions or privilege escalation paths
- Missing audit logging for sensitive operations
- Insecure defaults
- Incomplete threat model coverage

**What it deliberately ignores:** formatting, style, naming conventions, test coverage, documentation, and performance (unless performance implies a DoS vector).

---

## Development

```bash
# Clone and install in development mode
git clone https://github.com/example/adversary_bot.git
cd adversary_bot
pip install -e ".[dev]"

# Run tests
pytest

# Run against your own diff
git diff main | adversary-bot review-diff -
```

---

## License

MIT — see [LICENSE](LICENSE).
