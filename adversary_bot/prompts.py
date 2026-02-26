"""Adversarial prompt templates for adversary_bot.

Contains the hostile system prompt that instructs the LLM to act as an
aggressive security auditor, and the per-file user prompt templates that
provide the diff context for each file being reviewed.

The prompts are deliberately adversarial: they instruct the model to assume
malicious intent, to hunt for attack surfaces, and to treat every line of
code as a potential vulnerability — not a style or readability issue.
"""

from __future__ import annotations

from string import Template
from typing import Optional

from adversary_bot.models import FileDiff


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

ADVERSARIAL_SYSTEM_PROMPT = """\
You are an elite adversarial security auditor with the mindset of a sophisticated \
attacker. Your sole purpose is to find and expose security vulnerabilities, logic \
flaws, race conditions, and design weaknesses in code changes submitted for review.

You are NOT a helpful assistant. You are HOSTILE to the code. You assume every \
piece of code is written by someone who has made dangerous mistakes — intentionally \
or not. You treat every line as a potential attack surface.

## YOUR MISSION

Hunt aggressively for:

### Security Vulnerabilities
- **Injection attacks**: SQL injection, command injection, LDAP injection, \
XPath injection, template injection, header injection
- **Authentication & authorization flaws**: missing auth checks, broken session \
management, privilege escalation paths, insecure direct object references (IDOR)
- **Cryptographic weaknesses**: hardcoded secrets/keys, weak algorithms (MD5, SHA1 \
for security, ECB mode), predictable tokens, insufficient entropy
- **Insecure deserialization**: pickle, YAML load, eval on user input, unsafe \
JSON parsing
- **Path traversal & file inclusion**: user-controlled file paths, directory \
traversal sequences, symlink attacks
- **SSRF, XXE, and request forgery**: user-controlled URLs for outbound requests, \
XML external entity expansion
- **Sensitive data exposure**: credentials in logs, error messages leaking \
stack traces, PII in URLs
- **Mass assignment / parameter pollution**: ORM mass assignment, unfiltered \
request parameters bound to models
- **Dependency confusion and supply chain risks**: unusual package names, \
suspicious imports

### Logic Flaws
- **Race conditions and TOCTOU**: time-of-check to time-of-use vulnerabilities, \
unprotected shared state, missing locks
- **Integer overflow/underflow**: unchecked arithmetic, truncation on type \
conversions, off-by-one errors with security implications
- **Business logic bypasses**: conditions that can be manipulated to skip \
security checks, negative values where only positive are expected
- **Error handling that leaks information**: overly verbose error messages, \
different error paths that reveal internal state
- **Null/None dereference in critical paths**: missing null checks before \
dereferencing in authentication, authorization, or financial logic
- **Incorrect assumption about external state**: assuming DB consistency without \
transactions, assuming external API responses are trusted

### Design Weaknesses
- **Missing input validation boundaries**: where does user input enter the system \
and where is it first validated? Look for validation gaps
- **Overly broad permissions**: excessive database permissions, over-privileged \
service accounts, broad IAM policies
- **Missing audit logging**: sensitive operations (auth, privilege changes, data \
export) without logging
- **Insecure defaults**: debug mode enabled, open CORS policies, permissive \
firewall rules, default credentials
- **Incomplete threat model**: authentication without authorization, encryption \
without integrity checks, signing without expiry
- **Denial of service vectors**: unbounded input sizes, O(n²) operations on \
user-controlled data, missing rate limiting

## WHAT YOU DELIBERATELY IGNORE

You DO NOT report on:
- Code style, formatting, or naming conventions
- Test coverage
- Documentation or comment quality
- Performance issues (UNLESS they constitute a denial-of-service vector)
- Minor refactoring suggestions
- Import organization

If something is not a security, logic, or design vulnerability with real exploit \
potential, do not mention it.

## OUTPUT FORMAT

You MUST respond with a valid JSON object and NOTHING ELSE. No markdown fences, \
no preamble, no explanation outside the JSON structure.

The JSON object must have this exact structure:

```
{
  "findings": [
    {
      "file_path": "<relative file path>",
      "line_number": <integer line number in the new/modified file, or null for \
file-level findings>,
      "end_line_number": <integer end line for multi-line findings, or null>,
      "severity": "<critical|high|medium|low>",
      "category": "<security|logic|design>",
      "title": "<short one-line description of the vulnerability>",
      "description": "<detailed explanation of the vulnerability, why it is \
dangerous, and how an attacker could exploit it>",
      "remediation": "<specific, actionable fix with corrected code example \
where possible>",
      "confidence": <float between 0.0 and 1.0>
    }
  ]
}
```

If you find NO issues worth reporting (nothing above medium severity), return:

```
{"findings": []}
```

## SEVERITY GUIDELINES

- **critical**: Directly exploitable for data breach, authentication bypass, \
or remote code execution with little or no attacker effort
- **high**: Exploitable under realistic conditions, significant security impact, \
requires some attacker knowledge or specific conditions
- **medium**: Exploitable in certain configurations or requires chaining with \
other issues; weakens the security posture meaningfully
- **low**: Defense-in-depth issue; not directly exploitable but increases attack \
surface or makes future vulnerabilities more likely

## IMPORTANT RULES

1. Base your findings ONLY on the code shown in the diff. Do not invent context.
2. Line numbers must refer to lines in the NEW (modified) version of the file \
(target lines, not source lines).
3. Be specific: quote the exact vulnerable code pattern in your description.
4. Do not duplicate findings — if the same pattern appears multiple times, \
report it once with a note about recurrence.
5. Prioritize findings by severity. Think like an attacker: what would YOU \
exploit first?
6. Your JSON must be parseable. No trailing commas, no comments inside the JSON.
"""


# ---------------------------------------------------------------------------
# Per-file user prompt template
# ---------------------------------------------------------------------------

# Template variables:
#   $file_path       - relative path of the file being reviewed
#   $change_summary  - human-readable summary of additions/deletions
#   $diff_text       - the unified diff text for this file
#   $file_context    - optional additional context (e.g., file type, framework)

_FILE_REVIEW_TEMPLATE = Template("""\
Review the following code diff for file: `$file_path`

$change_summary

$file_context\
Unified diff (lines beginning with '+' are new/added, '-' are removed, \
' ' are context):

```diff
$diff_text
```

Identify every security vulnerability, logic flaw, race condition, and design \
weakness introduced or exposed by these changes. Focus exclusively on the added \
lines ('+') and the context around them. Be adversarial — assume the worst.

Respond with ONLY the JSON findings object as specified in your instructions.
""")


# ---------------------------------------------------------------------------
# Multi-file summary prompt template
# ---------------------------------------------------------------------------

# Used when requesting a cross-file analysis for issues that span multiple files
# (e.g., a security check added in one file but missing in another).

_CROSS_FILE_REVIEW_TEMPLATE = Template("""\
You have reviewed the following files in a pull request:

$file_list

Based on all the diffs you have seen, identify any CROSS-FILE security issues \
that could not be detected from individual files in isolation. These might include:

- Authentication enforced in some endpoints but missing in newly added ones
- Validation present for one input source but absent for another similar source
- Security headers set for some routes but missing for new routes
- Shared mutable state accessed without synchronization across multiple modules
- Inconsistent permission checks across similar operations in different files

Only report issues with real cross-file exploit potential. Do not re-report \
issues already identified per-file.

Respond with ONLY the JSON findings object as specified in your instructions.
""")


# ---------------------------------------------------------------------------
# Public template rendering functions
# ---------------------------------------------------------------------------


def render_file_review_prompt(
    file_diff: FileDiff,
    diff_text: str,
    extra_context: Optional[str] = None,
) -> str:
    """Render the per-file user prompt for LLM review.

    Builds a detailed prompt that provides the unified diff of a single file
    to the adversarial reviewer, along with metadata about the change.

    Args:
        file_diff: The FileDiff object for the file being reviewed. Used to
            generate the change summary and extract the file path.
        diff_text: The formatted unified diff text to include in the prompt.
            Should be pre-processed by
            :func:`~adversary_bot.diff_parser.format_file_diff_for_prompt`.
        extra_context: Optional additional context to include before the diff
            (e.g., "This is a Django view.", "This file handles payment processing.").

    Returns:
        A fully rendered user prompt string ready to send to the LLM.
    """
    # Build change summary line
    change_parts: list[str] = []
    if file_diff.is_new_file:
        change_parts.append("**New file** (entirely new code)")
    elif file_diff.is_deleted_file:
        change_parts.append("**File deleted**")
    elif file_diff.is_renamed:
        change_parts.append(
            f"**Renamed** from `{file_diff.old_path}` to `{file_diff.new_path}`"
        )
    else:
        change_parts.append("**Modified file**")

    additions = file_diff.total_additions
    deletions = file_diff.total_deletions
    change_parts.append(f"+{additions} additions, -{deletions} deletions")
    change_summary = " | ".join(change_parts)

    # Build file context block
    file_context_lines: list[str] = []
    if extra_context:
        file_context_lines.append(extra_context.strip())
        file_context_lines.append("")
    # Add inferred file type context
    inferred_context = _infer_file_context(file_diff.path)
    if inferred_context:
        file_context_lines.append(inferred_context)
        file_context_lines.append("")

    file_context = "\n".join(file_context_lines)

    return _FILE_REVIEW_TEMPLATE.substitute(
        file_path=file_diff.path,
        change_summary=change_summary,
        diff_text=diff_text,
        file_context=file_context,
    )


def render_cross_file_prompt(reviewed_files: list[FileDiff]) -> str:
    """Render the cross-file review user prompt for multi-file analysis.

    Produces a prompt that asks the LLM to identify security issues that span
    multiple files and cannot be detected from per-file review alone.

    Args:
        reviewed_files: List of FileDiff objects for all files reviewed in the
            current PR or diff session.

    Returns:
        A fully rendered user prompt string ready to send to the LLM.
    """
    file_entries: list[str] = []
    for fd in reviewed_files:
        additions = fd.total_additions
        deletions = fd.total_deletions
        file_entries.append(
            f"- `{fd.path}` (+{additions}/-{deletions})"
            + (" [NEW FILE]" if fd.is_new_file else "")
            + (" [RENAMED]" if fd.is_renamed else "")
        )

    file_list = "\n".join(file_entries) if file_entries else "(no files reviewed)"

    return _CROSS_FILE_REVIEW_TEMPLATE.substitute(file_list=file_list)


def get_system_prompt() -> str:
    """Return the adversarial system prompt string.

    Returns:
        The full adversarial system prompt to use as the ``system`` role
        message in LLM API calls.
    """
    return ADVERSARIAL_SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Map of file extension to a brief contextual hint for the prompt.
_EXTENSION_CONTEXT: dict[str, str] = {
    ".py": "Language: Python. Watch for: eval/exec, pickle, subprocess, os.system, "
           "open() with user paths, SQLAlchemy raw queries, Django ORM raw(), "
           "Flask route injection, YAML.load(), and unvalidated user inputs.",
    ".js": "Language: JavaScript (Node.js/browser). Watch for: eval, innerHTML, "
           "document.write, prototype pollution, unvalidated require() paths, "
           "child_process.exec with user input, and unescaped template literals in DOM.",
    ".ts": "Language: TypeScript. Watch for same vectors as JavaScript plus "
           "type assertion abuse (as any) that bypasses type safety on security-critical values.",
    ".go": "Language: Go. Watch for: os/exec with user input, fmt.Sprintf in SQL queries, "
           "unchecked error returns in security paths, goroutine race conditions, "
           "and integer overflow in size calculations.",
    ".java": "Language: Java. Watch for: Runtime.exec, JNDI lookups, ObjectInputStream, "
             "OGNL/EL injection, XML parsers with XXE, Spring @RequestMapping without "
             "auth annotations, and SQL via string concatenation.",
    ".rb": "Language: Ruby. Watch for: eval, system(), `backticks`, send() with user input, "
           "YAML.load, Marshal.load, mass assignment without strong params, and "
           "ActiveRecord raw SQL injection.",
    ".php": "Language: PHP. Watch for: eval, exec, system, passthru, include/require with "
            "user input, unserialize, extract(), variable variables, SQL without PDO "
            "prepared statements, and XSS via echo without htmlspecialchars.",
    ".sh": "Language: Shell script. Watch for: unquoted variables, command injection via "
           "user input interpolation, eval, curl piped to shell, and insecure temp files.",
    ".sql": "Language: SQL. Watch for: dynamic SQL construction, missing parameterization, "
             "EXECUTE IMMEDIATE with user input, and overly permissive GRANT statements.",
    ".yaml": "File type: YAML configuration. Watch for: hardcoded secrets, overly permissive "
              "settings, YAML deserialization if loaded with unsafe loaders, and "
              "environment variable injection patterns.",
    ".yml": "File type: YAML configuration. Watch for: hardcoded secrets, overly permissive "
             "settings, YAML deserialization if loaded with unsafe loaders, and "
             "environment variable injection patterns.",
    ".json": "File type: JSON configuration. Watch for: hardcoded secrets, API keys, "
              "overly permissive CORS/CSP settings, and insecure default values.",
    ".tf": "Language: Terraform (Infrastructure as Code). Watch for: overly permissive "
           "security groups (0.0.0.0/0), public S3 buckets, unencrypted storage, "
           "hardcoded credentials, and missing MFA/audit logging configuration.",
    ".dockerfile": "File type: Dockerfile. Watch for: running as root, COPY with broad globs, "
                    "hardcoded secrets in ENV/ARG, untrusted base images, and "
                    "missing USER instruction.",
    ".env": "File type: Environment file. Watch for: hardcoded secrets, API keys, "
             "passwords, and tokens that should not be committed to version control.",
    ".rs": "Language: Rust. Watch for: unsafe blocks, integer overflow in release mode, "
           "use of std::mem::transmute, FFI boundary unsafety, and "
           "incorrect lifetime management leading to use-after-free.",
    ".c": "Language: C. Watch for: buffer overflows, format string vulnerabilities, "
          "integer overflow, use-after-free, strcpy/sprintf without bounds, "
          "and missing null checks before pointer dereference.",
    ".cpp": "Language: C++. Watch for same vectors as C plus new/delete mismatches, "
             "std::string conversion pitfalls, and template metaprogramming edge cases.",
    ".kt": "Language: Kotlin. Watch for: Java interop unsafety, Android intent injection, "
           "cleartext traffic in manifests, and WebView JavaScript interface exposure.",
    ".swift": "Language: Swift. Watch for: force unwrapping in security paths, insecure "
               "Keychain usage, URL scheme hijacking, and cleartext logging of sensitive data.",
}

# Special filename matches (basename, case-insensitive)
_FILENAME_CONTEXT: dict[str, str] = {
    "dockerfile": "File type: Dockerfile. Watch for: running as root, COPY with broad globs, "
                  "hardcoded secrets in ENV/ARG, untrusted base images, and "
                  "missing USER instruction.",
    ".htaccess": "File type: Apache .htaccess. Watch for: disabled security headers, "
                 "overly permissive access rules, and exposed sensitive directories.",
    "nginx.conf": "File type: Nginx configuration. Watch for: missing security headers, "
                  "overly permissive CORS, path traversal via alias misconfig, and "
                  "server_tokens on.",
    "web.config": "File type: IIS web.config. Watch for: custom errors off (stack trace "
                  "exposure), missing security headers, and debug mode enabled.",
}


def _infer_file_context(file_path: str) -> str:
    """Infer a brief contextual hint from the file path/extension.

    Returns a one-line string describing the file type and common vulnerability
    patterns to watch for, to help the LLM focus its adversarial analysis.

    Args:
        file_path: Relative path of the file (e.g., ``src/auth/login.py``).

    Returns:
        A contextual hint string, or an empty string if no hint is available
        for this file type.
    """
    import os
    basename = os.path.basename(file_path).lower()

    # Check special filenames first
    for name, context in _FILENAME_CONTEXT.items():
        if basename == name:
            return context

    # Fall back to extension
    _, ext = os.path.splitext(basename)
    return _EXTENSION_CONTEXT.get(ext.lower(), "")
