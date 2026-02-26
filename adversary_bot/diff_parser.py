"""Unified diff parser for adversary_bot.

Parses raw unified diff text into structured FileDiff, DiffHunk, and HunkLine
objects suitable for per-file adversarial review. Supports multi-file diffs,
new/deleted files, renames, and gracefully handles binary files.

Uses the ``unidiff`` library as the parsing backbone and maps its output to
the adversary_bot internal data models.
"""

from __future__ import annotations

import logging
from typing import Optional

from unidiff import PatchSet, PatchedFile, Hunk, LINE_TYPE_ADDED, LINE_TYPE_REMOVED, LINE_TYPE_CONTEXT
from unidiff.errors import UnidiffParseError

from adversary_bot.models import FileDiff, DiffHunk, HunkLine, LineType

logger = logging.getLogger(__name__)


class DiffParseError(ValueError):
    """Raised when the diff text cannot be parsed."""
    pass


def parse_diff(diff_text: str) -> list[FileDiff]:
    """Parse a unified diff string into a list of FileDiff objects.

    Each FileDiff corresponds to one file changed in the diff. The parser
    handles:

    - Standard file modifications (hunks with context, additions, deletions)
    - New file creation (``--- /dev/null``)
    - File deletion (``+++ /dev/null``)
    - File renames (``rename from`` / ``rename to`` git extended headers)
    - Binary files (no textual diff available)
    - Empty diffs (returns an empty list)

    Args:
        diff_text: Raw unified diff text, e.g. the output of ``git diff``.

    Returns:
        Ordered list of FileDiff objects, one per changed file. Binary files
        and files with no hunks are included but will have empty hunk lists
        and ``is_binary=True`` where appropriate.

    Raises:
        DiffParseError: If the diff text is malformed and cannot be parsed
            at all. Partial failures for individual files are logged as
            warnings and those files are skipped rather than raising.
    """
    if not diff_text or not diff_text.strip():
        return []

    try:
        patch_set = PatchSet(diff_text)
    except UnidiffParseError as exc:
        raise DiffParseError(f"Failed to parse diff: {exc}") from exc
    except Exception as exc:
        raise DiffParseError(f"Unexpected error parsing diff: {exc}") from exc

    file_diffs: list[FileDiff] = []

    for patched_file in patch_set:
        try:
            file_diff = _convert_patched_file(patched_file)
            file_diffs.append(file_diff)
        except Exception as exc:
            logger.warning(
                "Skipping file '%s' due to parse error: %s",
                getattr(patched_file, "path", "<unknown>"),
                exc,
            )

    return file_diffs


def parse_diff_from_file(path: str) -> list[FileDiff]:
    """Read a diff file from disk and parse it.

    A convenience wrapper around :func:`parse_diff` that handles file I/O.

    Args:
        path: Filesystem path to a ``.diff`` or ``.patch`` file.

    Returns:
        List of FileDiff objects parsed from the file.

    Raises:
        FileNotFoundError: If the specified path does not exist.
        DiffParseError: If the file contents cannot be parsed as a unified diff.
        OSError: If the file cannot be read.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        diff_text = fh.read()
    return parse_diff(diff_text)


def filter_reviewable_files(file_diffs: list[FileDiff]) -> list[FileDiff]:
    """Filter out files that should not be reviewed by the LLM.

    Excludes binary files (no textual content to review) and files with no
    changes (no hunks). Also excludes files that are purely deletions, as
    there is nothing new to audit in deleted code.

    Args:
        file_diffs: List of FileDiff objects to filter.

    Returns:
        Filtered list containing only files suitable for LLM review.
    """
    reviewable: list[FileDiff] = []
    for fd in file_diffs:
        if fd.is_binary:
            logger.debug("Skipping binary file: %s", fd.path)
            continue
        if fd.is_deleted_file:
            logger.debug("Skipping deleted file: %s", fd.path)
            continue
        if not fd.hunks:
            logger.debug("Skipping file with no hunks: %s", fd.path)
            continue
        reviewable.append(fd)
    return reviewable


def format_file_diff_for_prompt(file_diff: FileDiff, max_lines: int = 500) -> str:
    """Format a FileDiff as a compact diff text suitable for inclusion in an LLM prompt.

    Reconstructs the unified diff for the file, optionally truncating very
    long diffs to keep prompts within token limits. When truncated, a notice
    is appended.

    Args:
        file_diff: The FileDiff to format.
        max_lines: Maximum number of diff lines to include before truncating.
            Defaults to 500. Set to 0 or negative to disable truncation.

    Returns:
        A string containing the unified diff text for the file, possibly
        truncated with a truncation notice appended.
    """
    parts: list[str] = []

    # File header
    if file_diff.is_new_file:
        parts.append(f"--- /dev/null")
        parts.append(f"+++ b/{file_diff.target_path}")
    elif file_diff.is_deleted_file:
        parts.append(f"--- a/{file_diff.source_path}")
        parts.append(f"+++ /dev/null")
    elif file_diff.is_renamed:
        parts.append(f"--- a/{file_diff.old_path}")
        parts.append(f"+++ b/{file_diff.new_path}")
    else:
        parts.append(f"--- a/{file_diff.source_path}")
        parts.append(f"+++ b/{file_diff.target_path}")

    line_count = 0
    truncated = False

    for hunk in file_diff.hunks:
        hunk_lines = [str(hunk)]
        for line in hunk.lines:
            hunk_lines.append(str(line))

        if max_lines > 0 and line_count + len(hunk_lines) > max_lines:
            remaining = max_lines - line_count
            if remaining > 1:
                parts.extend(hunk_lines[:remaining])
            truncated = True
            break

        parts.extend(hunk_lines)
        line_count += len(hunk_lines)

    result = "\n".join(parts)

    if truncated:
        result += (
            f"\n\n[... diff truncated at {max_lines} lines. "
            "Review the visible portion only. ...]"
        )

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _convert_patched_file(patched_file: PatchedFile) -> FileDiff:
    """Convert a unidiff PatchedFile into an adversary_bot FileDiff.

    Args:
        patched_file: A PatchedFile instance from the unidiff library.

    Returns:
        A fully populated FileDiff object.
    """
    source_path = _strip_ab_prefix(patched_file.source_file)
    target_path = _strip_ab_prefix(patched_file.target_file)

    is_new = patched_file.is_added_file
    is_deleted = patched_file.is_removed_file
    is_renamed = patched_file.is_rename
    is_binary = patched_file.is_binary_file

    # Determine old/new paths for renames
    old_path: Optional[str] = source_path
    new_path: Optional[str] = target_path

    file_diff = FileDiff(
        source_path=source_path,
        target_path=target_path,
        is_new_file=is_new,
        is_deleted_file=is_deleted,
        is_renamed=is_renamed,
        is_binary=is_binary,
        old_path=old_path,
        new_path=new_path,
    )

    if not is_binary:
        for hunk in patched_file:
            converted_hunk = _convert_hunk(hunk)
            file_diff.hunks.append(converted_hunk)

    return file_diff


def _convert_hunk(hunk: Hunk) -> DiffHunk:
    """Convert a unidiff Hunk into an adversary_bot DiffHunk.

    Args:
        hunk: A Hunk instance from the unidiff library.

    Returns:
        A DiffHunk with all lines converted to HunkLine objects.
    """
    diff_hunk = DiffHunk(
        source_start=hunk.source_start,
        source_length=hunk.source_length,
        target_start=hunk.target_start,
        target_length=hunk.target_length,
        section_heading=hunk.section_header.strip() if hunk.section_header else "",
    )

    for line in hunk:
        line_type = _map_line_type(line.line_type)
        # unidiff line.value includes the trailing newline; strip it for storage
        content = line.value.rstrip("\n").rstrip("\r")
        hunk_line = HunkLine(
            line_type=line_type,
            content=content,
            source_line_no=line.source_line_no,
            target_line_no=line.target_line_no,
        )
        diff_hunk.lines.append(hunk_line)

    return diff_hunk


def _map_line_type(unidiff_type: str) -> LineType:
    """Map a unidiff line type constant to a LineType enum value.

    Args:
        unidiff_type: One of the LINE_TYPE_* constants from unidiff.

    Returns:
        The corresponding LineType enum member.
    """
    if unidiff_type == LINE_TYPE_ADDED:
        return LineType.ADDED
    if unidiff_type == LINE_TYPE_REMOVED:
        return LineType.REMOVED
    return LineType.CONTEXT


def _strip_ab_prefix(path: str) -> str:
    """Strip the leading ``a/`` or ``b/`` prefix from a diff path.

    Git unified diffs prefix source paths with ``a/`` and target paths with
    ``b/``. This function removes those prefixes for cleaner display.

    Args:
        path: The raw path string from the diff header.

    Returns:
        The path with any leading ``a/`` or ``b/`` removed. Special paths
        like ``/dev/null`` are returned unchanged.
    """
    if path in ("/dev/null", ""):
        return path
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path
