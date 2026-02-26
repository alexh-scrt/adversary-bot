"""Core data models for adversary_bot.

Defines all typed dataclasses for ReviewComment, FileDiff, HunkLine, and
ReviewResult. These form the shared data contract used by all other modules
including the diff parser, LLM reviewer, and GitHub client.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Severity levels for adversarial review findings.

    Ordered from most to least severe. Used to filter findings by minimum
    severity threshold.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __lt__(self, other: object) -> bool:
        """Allow severity comparison by rank (critical > high > medium > low)."""
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_RANK[self] < _SEVERITY_RANK[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_RANK[self] <= _SEVERITY_RANK[other]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_RANK[self] > _SEVERITY_RANK[other]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_RANK[self] >= _SEVERITY_RANK[other]

    @property
    def rank(self) -> int:
        """Numeric rank where higher = more severe."""
        return _SEVERITY_RANK[self]


# Rank map: higher number = more severe
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Category(str, Enum):
    """Category of a review finding.

    Findings are classified into one of three broad buckets that map to the
    kinds of issues the adversarial reviewer hunts for.
    """

    SECURITY = "security"
    LOGIC = "logic"
    DESIGN = "design"


class LineType(str, Enum):
    """Type of a line within a diff hunk."""

    ADDED = "added"        # Lines beginning with '+'
    REMOVED = "removed"    # Lines beginning with '-'
    CONTEXT = "context"    # Unchanged context lines


# ---------------------------------------------------------------------------
# Diff representation models
# ---------------------------------------------------------------------------


@dataclass
class HunkLine:
    """A single line within a diff hunk.

    Attributes:
        line_type: Whether this line was added, removed, or is context.
        content: The raw line content (without the leading +/-/space character).
        source_line_no: Line number in the original (pre-change) file, or None
            for pure additions.
        target_line_no: Line number in the modified (post-change) file, or None
            for pure deletions.
    """

    line_type: LineType
    content: str
    source_line_no: Optional[int] = None
    target_line_no: Optional[int] = None

    def __str__(self) -> str:
        """Return the line with its diff prefix character."""
        prefix = {
            LineType.ADDED: "+",
            LineType.REMOVED: "-",
            LineType.CONTEXT: " ",
        }[self.line_type]
        return f"{prefix}{self.content}"

    @property
    def is_added(self) -> bool:
        """True if this line was added in the diff."""
        return self.line_type == LineType.ADDED

    @property
    def is_removed(self) -> bool:
        """True if this line was removed in the diff."""
        return self.line_type == LineType.REMOVED

    @property
    def is_context(self) -> bool:
        """True if this is an unchanged context line."""
        return self.line_type == LineType.CONTEXT


@dataclass
class DiffHunk:
    """A contiguous block of changes within a file diff.

    Represents one @@ ... @@ section of a unified diff, containing the
    surrounding context lines and the actual additions/deletions.

    Attributes:
        source_start: Starting line number in the source (original) file.
        source_length: Number of lines from the source file in this hunk.
        target_start: Starting line number in the target (modified) file.
        target_length: Number of lines from the target file in this hunk.
        section_heading: Optional text after the @@ marker (e.g., function name).
        lines: Ordered list of HunkLine objects in this hunk.
    """

    source_start: int
    source_length: int
    target_start: int
    target_length: int
    section_heading: str = ""
    lines: list[HunkLine] = field(default_factory=list)

    def __str__(self) -> str:
        """Reconstruct the hunk header line."""
        heading = f" {self.section_heading}" if self.section_heading else ""
        return (
            f"@@ -{self.source_start},{self.source_length} "
            f"+{self.target_start},{self.target_length} @@{heading}"
        )

    @property
    def added_lines(self) -> list[HunkLine]:
        """Return only the added lines in this hunk."""
        return [ln for ln in self.lines if ln.is_added]

    @property
    def removed_lines(self) -> list[HunkLine]:
        """Return only the removed lines in this hunk."""
        return [ln for ln in self.lines if ln.is_removed]

    def iter_changed_lines(self) -> Iterator[HunkLine]:
        """Iterate over all non-context (added or removed) lines."""
        for ln in self.lines:
            if not ln.is_context:
                yield ln

    def to_diff_text(self) -> str:
        """Reconstruct the full hunk as unified diff text."""
        lines = [str(self)]
        lines.extend(str(ln) for ln in self.lines)
        return "\n".join(lines)


@dataclass
class FileDiff:
    """Represents the diff for a single file.

    Captures all changed hunks for one file along with metadata about the
    type of change (modification, addition, deletion, rename, binary).

    Attributes:
        source_path: Path of the file before the change (a/... prefix stripped).
            For new files this is ``/dev/null``.
        target_path: Path of the file after the change (b/... prefix stripped).
            For deleted files this is ``/dev/null``.
        hunks: List of DiffHunk objects representing each change block.
        is_new_file: True if this file was newly created.
        is_deleted_file: True if this file was deleted.
        is_renamed: True if the file was renamed.
        is_binary: True if the file is binary (no textual diff available).
        old_path: Original path before rename (same as source_path if not renamed).
        new_path: New path after rename (same as target_path if not renamed).
    """

    source_path: str
    target_path: str
    hunks: list[DiffHunk] = field(default_factory=list)
    is_new_file: bool = False
    is_deleted_file: bool = False
    is_renamed: bool = False
    is_binary: bool = False
    old_path: Optional[str] = None
    new_path: Optional[str] = None

    def __post_init__(self) -> None:
        """Set old_path/new_path defaults from source/target paths."""
        if self.old_path is None:
            self.old_path = self.source_path
        if self.new_path is None:
            self.new_path = self.target_path

    @property
    def path(self) -> str:
        """Canonical path for this file (prefer target path for display)."""
        if self.target_path and self.target_path != "/dev/null":
            return self.target_path
        return self.source_path

    @property
    def total_additions(self) -> int:
        """Total number of added lines across all hunks."""
        return sum(len(h.added_lines) for h in self.hunks)

    @property
    def total_deletions(self) -> int:
        """Total number of removed lines across all hunks."""
        return sum(len(h.removed_lines) for h in self.hunks)

    @property
    def total_changes(self) -> int:
        """Total number of changed lines (additions + deletions)."""
        return self.total_additions + self.total_deletions

    def to_diff_text(self) -> str:
        """Reconstruct the file diff as unified diff text."""
        parts: list[str] = []
        parts.append(f"--- {self.source_path}")
        parts.append(f"+++ {self.target_path}")
        for hunk in self.hunks:
            parts.append(hunk.to_diff_text())
        return "\n".join(parts)

    def iter_all_lines(self) -> Iterator[HunkLine]:
        """Iterate over every HunkLine across all hunks in order."""
        for hunk in self.hunks:
            yield from hunk.lines

    def iter_changed_lines(self) -> Iterator[HunkLine]:
        """Iterate over all non-context changed lines across all hunks."""
        for hunk in self.hunks:
            yield from hunk.iter_changed_lines()


# ---------------------------------------------------------------------------
# Review output models
# ---------------------------------------------------------------------------


@dataclass
class ReviewComment:
    """A single adversarial review finding on a specific file location.

    Represents one issue identified by the LLM reviewer, with enough
    structured information to post as an inline GitHub review comment or
    render in terminal output.

    Attributes:
        file_path: Relative path of the file containing the issue.
        line_number: Line number in the target (post-change) file where the
            issue was identified. May be None for file-level findings.
        severity: How severe the finding is (critical/high/medium/low).
        category: The category of the finding (security/logic/design).
        title: Short one-line summary of the issue.
        description: Detailed description of the vulnerability or flaw,
            including why it is dangerous and how it could be exploited.
        remediation: Specific, actionable steps to fix the issue, ideally
            with a corrected code snippet.
        end_line_number: Optional end line for multi-line findings (for
            GitHub inline range comments).
        confidence: Optional 0.0–1.0 confidence score from the LLM.
    """

    file_path: str
    line_number: Optional[int]
    severity: Severity
    category: Category
    title: str
    description: str
    remediation: str
    end_line_number: Optional[int] = None
    confidence: Optional[float] = None

    def __post_init__(self) -> None:
        """Coerce string enum values to their Enum types if needed."""
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.lower().strip())
        if isinstance(self.category, str):
            self.category = Category(self.category.lower().strip())

    @property
    def severity_emoji(self) -> str:
        """Return an emoji indicator for the severity level."""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
        }[self.severity]

    @property
    def location_str(self) -> str:
        """Human-readable location string (file:line or file only)."""
        if self.line_number is not None:
            if self.end_line_number and self.end_line_number != self.line_number:
                return f"{self.file_path}:{self.line_number}-{self.end_line_number}"
            return f"{self.file_path}:{self.line_number}"
        return self.file_path

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary suitable for JSON output."""
        result: dict = {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
        }
        if self.end_line_number is not None:
            result["end_line_number"] = self.end_line_number
        if self.confidence is not None:
            result["confidence"] = self.confidence
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ReviewComment":
        """Deserialize a ReviewComment from a plain dictionary.

        Args:
            data: Dictionary with keys matching ReviewComment attributes.
                  ``severity`` and ``category`` may be raw strings.

        Returns:
            A fully constructed ReviewComment instance.

        Raises:
            KeyError: If a required field is missing from ``data``.
            ValueError: If severity or category values are invalid.
        """
        return cls(
            file_path=data["file_path"],
            line_number=data.get("line_number"),
            severity=Severity(data["severity"].lower().strip()),
            category=Category(data["category"].lower().strip()),
            title=data["title"],
            description=data["description"],
            remediation=data["remediation"],
            end_line_number=data.get("end_line_number"),
            confidence=data.get("confidence"),
        )

    def format_terminal(self) -> str:
        """Format this comment for human-readable terminal output.

        Returns:
            A multi-line string suitable for printing to stdout.
        """
        lines = [
            f"{self.severity_emoji} [{self.severity.value.upper()}] "
            f"{self.category.value} — {self.location_str}",
            f"  {self.title}",
            "",
        ]
        # Wrap description lines with indent
        for desc_line in self.description.strip().splitlines():
            lines.append(f"  {desc_line}")
        lines.append("")
        lines.append("  Remediation:")
        for rem_line in self.remediation.strip().splitlines():
            lines.append(f"  {rem_line}")
        return "\n".join(lines)

    def format_github_body(self) -> str:
        """Format this comment as a GitHub PR review comment body (Markdown).

        Returns:
            A Markdown-formatted string suitable for posting to the GitHub
            Reviews API.
        """
        severity_badge = (
            f"**{self.severity_emoji} {self.severity.value.upper()}** "
            f"| `{self.category.value}`"
        )
        lines = [
            f"### {severity_badge}: {self.title}",
            "",
            self.description.strip(),
            "",
            "**Remediation:**",
            "",
            self.remediation.strip(),
        ]
        if self.confidence is not None:
            lines += ["", f"*Confidence: {self.confidence:.0%}*"]
        return "\n".join(lines)


@dataclass
class ReviewResult:
    """The complete result of an adversarial review run.

    Aggregates all ReviewComment findings across all reviewed files, plus
    metadata about the review run itself.

    Attributes:
        comments: All findings from the adversarial review, across all files.
        files_reviewed: Number of files that were analysed.
        files_skipped: Number of files skipped (e.g. binary, no changes).
        backend_used: Name of the LLM backend that produced the review.
        model_used: Specific model name that produced the review.
        error: Optional error message if the review failed or was partial.
    """

    comments: list[ReviewComment] = field(default_factory=list)
    files_reviewed: int = 0
    files_skipped: int = 0
    backend_used: str = ""
    model_used: str = ""
    error: Optional[str] = None

    @property
    def total_findings(self) -> int:
        """Total number of findings across all files."""
        return len(self.comments)

    @property
    def has_critical(self) -> bool:
        """True if any finding has CRITICAL severity."""
        return any(c.severity == Severity.CRITICAL for c in self.comments)

    @property
    def has_high(self) -> bool:
        """True if any finding has HIGH severity."""
        return any(c.severity == Severity.HIGH for c in self.comments)

    def by_severity(self, severity: Severity) -> list[ReviewComment]:
        """Return all comments matching the given severity level.

        Args:
            severity: The exact severity level to filter for.

        Returns:
            List of matching ReviewComment objects.
        """
        return [c for c in self.comments if c.severity == severity]

    def by_category(self, category: Category) -> list[ReviewComment]:
        """Return all comments matching the given category.

        Args:
            category: The category to filter for.

        Returns:
            List of matching ReviewComment objects.
        """
        return [c for c in self.comments if c.category == category]

    def above_severity(self, min_severity: Severity) -> list[ReviewComment]:
        """Return all comments at or above the given minimum severity.

        Args:
            min_severity: The minimum severity threshold (inclusive).

        Returns:
            List of ReviewComment objects with severity >= min_severity.
        """
        return [c for c in self.comments if c.severity >= min_severity]

    def for_file(self, file_path: str) -> list[ReviewComment]:
        """Return all comments for a specific file.

        Args:
            file_path: The file path to filter for (exact match).

        Returns:
            List of ReviewComment objects for that file.
        """
        return [c for c in self.comments if c.file_path == file_path]

    def sorted_by_severity(self) -> list[ReviewComment]:
        """Return all comments sorted by severity (critical first).

        Returns:
            New list of ReviewComment objects, most severe first.
        """
        return sorted(self.comments, key=lambda c: c.severity.rank, reverse=True)

    def severity_summary(self) -> dict[str, int]:
        """Return a count of findings by severity level.

        Returns:
            Dictionary mapping severity name strings to counts.
        """
        summary: dict[str, int] = {s.value: 0 for s in Severity}
        for comment in self.comments:
            summary[comment.severity.value] += 1
        return summary

    def to_dict(self) -> dict:
        """Serialize this ReviewResult to a plain dictionary for JSON output.

        Returns:
            Dictionary representation suitable for json.dumps().
        """
        return {
            "files_reviewed": self.files_reviewed,
            "files_skipped": self.files_skipped,
            "total_findings": self.total_findings,
            "severity_summary": self.severity_summary(),
            "backend_used": self.backend_used,
            "model_used": self.model_used,
            "error": self.error,
            "comments": [c.to_dict() for c in self.comments],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize this ReviewResult to a JSON string.

        Args:
            indent: JSON indentation level.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "ReviewResult":
        """Deserialize a ReviewResult from a plain dictionary.

        Args:
            data: Dictionary as produced by to_dict().

        Returns:
            A fully constructed ReviewResult instance.
        """
        comments = [
            ReviewComment.from_dict(c)
            for c in data.get("comments", [])
        ]
        return cls(
            comments=comments,
            files_reviewed=data.get("files_reviewed", 0),
            files_skipped=data.get("files_skipped", 0),
            backend_used=data.get("backend_used", ""),
            model_used=data.get("model_used", ""),
            error=data.get("error"),
        )

    def format_terminal_summary(self, verbose: bool = False) -> str:
        """Format a human-readable summary for terminal output.

        Args:
            verbose: If True, include full detail for every comment.

        Returns:
            Multi-line string ready for printing to stdout.
        """
        lines: list[str] = []
        summary = self.severity_summary()

        lines.append("=" * 70)
        lines.append("🔪 ADVERSARY BOT — REVIEW COMPLETE")
        lines.append("=" * 70)
        lines.append(
            f"Files reviewed : {self.files_reviewed} "
            f"(skipped: {self.files_skipped})"
        )
        lines.append(f"Total findings : {self.total_findings}")
        lines.append(
            "Severity breakdown: "
            + "  ".join(
                f"{s.upper()}: {summary[s]}"
                for s in ["critical", "high", "medium", "low"]
            )
        )
        if self.model_used:
            lines.append(f"Model          : {self.backend_used}/{self.model_used}")
        if self.error:
            lines.append(f"⚠️  Error        : {self.error}")
        lines.append("")

        if not self.comments:
            lines.append("✅ No findings above the minimum severity threshold.")
            return "\n".join(lines)

        # Group by file for readability
        files_seen: list[str] = []
        file_order: dict[str, list[ReviewComment]] = {}
        for comment in self.sorted_by_severity():
            fp = comment.file_path
            if fp not in file_order:
                file_order[fp] = []
                files_seen.append(fp)
            file_order[fp].append(comment)

        for fp in files_seen:
            file_comments = file_order[fp]
            lines.append("-" * 70)
            lines.append(f"📄 {fp}  ({len(file_comments)} finding(s))")
            lines.append("")
            for comment in file_comments:
                if verbose:
                    lines.append(comment.format_terminal())
                else:
                    loc = (
                        f"line {comment.line_number}" if comment.line_number else "file"
                    )
                    lines.append(
                        f"  {comment.severity_emoji} [{comment.severity.value.upper()}] "
                        f"{comment.category.value} @ {loc}: {comment.title}"
                    )
            lines.append("")

        return "\n".join(lines)
