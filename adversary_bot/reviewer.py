"""Core adversarial review logic for adversary_bot.

Builds LLM prompts from parsed diff objects, calls OpenAI or Anthropic
backends, and parses the structured JSON critique output into typed
ReviewComment objects. Handles retry logic, token limits, and graceful
degradation when the LLM returns malformed output.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Optional

from adversary_bot.config import Config, LLMBackend, Severity
from adversary_bot.diff_parser import filter_reviewable_files, format_file_diff_for_prompt
from adversary_bot.models import Category, FileDiff, ReviewComment, ReviewResult
from adversary_bot.prompts import (
    get_system_prompt,
    render_cross_file_prompt,
    render_file_review_prompt,
)

logger = logging.getLogger(__name__)

# Maximum number of retries for transient LLM API errors
_MAX_RETRIES = 3

# Base delay (seconds) for exponential backoff
_RETRY_BASE_DELAY = 1.0

# Retryable HTTP status codes
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class ReviewerError(RuntimeError):
    """Raised when the LLM reviewer encounters an unrecoverable error."""

    pass


class LLMParseError(ValueError):
    """Raised when the LLM response cannot be parsed into ReviewComment objects."""

    pass


class AdversaryReviewer:
    """Adversarial code reviewer that orchestrates LLM-based review of diffs.

    Supports both OpenAI and Anthropic Claude backends. For each file in a
    diff it constructs an adversarial prompt, calls the configured LLM, and
    parses the JSON response into ReviewComment objects.

    Args:
        config: A validated Config instance specifying the backend, model,
            API keys, and other review parameters.

    Example::

        from adversary_bot.config import load_config
        from adversary_bot.reviewer import AdversaryReviewer

        config = load_config()
        reviewer = AdversaryReviewer(config)
        result = reviewer.review_diff(diff_text)
        print(result.format_terminal_summary())
    """

    def __init__(self, config: Config) -> None:
        """Initialise the reviewer with validated configuration.

        Args:
            config: Validated Config instance.

        Raises:
            ReviewerError: If the LLM client cannot be initialised (e.g. bad
                API key format or missing dependency).
        """
        self.config = config
        self._client = self._build_client()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def review_diff(
        self,
        diff_text: str,
        run_cross_file: bool = False,
    ) -> ReviewResult:
        """Review a unified diff string and return adversarial findings.

        Parses the diff into per-file objects, filters out non-reviewable
        files (binary, deleted, empty), then calls the LLM for each file.
        Optionally performs a cross-file pass to catch issues that span
        multiple files.

        Args:
            diff_text: Raw unified diff string (e.g., output of ``git diff``).
            run_cross_file: If True and multiple files are present, perform an
                additional cross-file review pass after per-file analysis.

        Returns:
            A ReviewResult aggregating all findings, metadata, and any errors.
        """
        from adversary_bot.diff_parser import parse_diff

        all_file_diffs = parse_diff(diff_text)
        reviewable = filter_reviewable_files(all_file_diffs)
        skipped = len(all_file_diffs) - len(reviewable)

        if not reviewable:
            logger.info("No reviewable files found in diff.")
            return ReviewResult(
                comments=[],
                files_reviewed=0,
                files_skipped=skipped,
                backend_used=self.config.llm_backend.value,
                model_used=self.config.active_model,
            )

        all_comments: list[ReviewComment] = []
        error_messages: list[str] = []

        for file_diff in reviewable:
            logger.info("Reviewing file: %s", file_diff.path)
            try:
                comments = self._review_file(file_diff)
                all_comments.extend(comments)
            except ReviewerError as exc:
                msg = f"Failed to review {file_diff.path}: {exc}"
                logger.error(msg)
                error_messages.append(msg)

        # Optional cross-file pass
        if run_cross_file and len(reviewable) > 1:
            logger.info("Running cross-file review pass for %d files.", len(reviewable))
            try:
                cross_comments = self._review_cross_file(reviewable)
                all_comments.extend(cross_comments)
            except ReviewerError as exc:
                msg = f"Cross-file review failed: {exc}"
                logger.warning(msg)
                error_messages.append(msg)

        # Apply severity filter
        min_sev = _config_severity_to_model_severity(self.config.min_severity)
        filtered = [c for c in all_comments if c.severity >= min_sev]

        error: Optional[str] = "; ".join(error_messages) if error_messages else None

        return ReviewResult(
            comments=filtered,
            files_reviewed=len(reviewable),
            files_skipped=skipped,
            backend_used=self.config.llm_backend.value,
            model_used=self.config.active_model,
            error=error,
        )

    def review_file_diff(
        self,
        file_diff: FileDiff,
        extra_context: Optional[str] = None,
    ) -> list[ReviewComment]:
        """Review a single FileDiff object and return findings.

        A lower-level API for callers that have already parsed the diff and
        want to review individual files without the full orchestration of
        :meth:`review_diff`.

        Args:
            file_diff: The FileDiff to review.
            extra_context: Optional extra context to pass to the prompt
                (e.g., "This is a Django authentication view.").

        Returns:
            List of ReviewComment findings for this file.

        Raises:
            ReviewerError: If the LLM call fails after all retries.
        """
        return self._review_file(file_diff, extra_context=extra_context)

    # ------------------------------------------------------------------
    # Internal review orchestration
    # ------------------------------------------------------------------

    def _review_file(
        self,
        file_diff: FileDiff,
        extra_context: Optional[str] = None,
    ) -> list[ReviewComment]:
        """Run the LLM review for a single file.

        Args:
            file_diff: The FileDiff to review.
            extra_context: Optional extra context string.

        Returns:
            Parsed list of ReviewComment objects.

        Raises:
            ReviewerError: If the LLM call or response parsing fails.
        """
        diff_text = format_file_diff_for_prompt(file_diff, max_lines=500)
        user_prompt = render_file_review_prompt(
            file_diff=file_diff,
            diff_text=diff_text,
            extra_context=extra_context,
        )
        system_prompt = get_system_prompt()

        raw_response = self._call_llm_with_retry(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        try:
            comments = _parse_llm_response(raw_response, default_file_path=file_diff.path)
        except LLMParseError as exc:
            logger.warning(
                "Failed to parse LLM response for %s: %s", file_diff.path, exc
            )
            if self.config.verbose:
                logger.debug("Raw LLM response:\n%s", raw_response)
            return []

        return comments

    def _review_cross_file(self, file_diffs: list[FileDiff]) -> list[ReviewComment]:
        """Run a cross-file review pass to detect multi-file security issues.

        Args:
            file_diffs: All reviewable FileDiff objects from the current run.

        Returns:
            Parsed list of ReviewComment objects for cross-file findings.

        Raises:
            ReviewerError: If the LLM call fails.
        """
        user_prompt = render_cross_file_prompt(file_diffs)
        system_prompt = get_system_prompt()

        raw_response = self._call_llm_with_retry(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        try:
            comments = _parse_llm_response(
                raw_response, default_file_path="<cross-file>"
            )
        except LLMParseError as exc:
            logger.warning("Failed to parse cross-file LLM response: %s", exc)
            return []

        return comments

    # ------------------------------------------------------------------
    # LLM backend dispatch
    # ------------------------------------------------------------------

    def _call_llm_with_retry(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """Call the configured LLM with exponential backoff retry logic.

        Args:
            system_prompt: The system/instructions prompt text.
            user_prompt: The user/content prompt text.

        Returns:
            The raw text response from the LLM.

        Raises:
            ReviewerError: If all retries are exhausted or a non-retryable
                error occurs.
        """
        last_exc: Optional[Exception] = None

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                if self.config.llm_backend == LLMBackend.OPENAI:
                    return self._call_openai(system_prompt, user_prompt)
                else:
                    return self._call_anthropic(system_prompt, user_prompt)
            except Exception as exc:
                last_exc = exc
                if not _is_retryable_error(exc):
                    raise ReviewerError(
                        f"Non-retryable LLM error ({type(exc).__name__}): {exc}"
                    ) from exc
                delay = _RETRY_BASE_DELAY * (2 ** (attempt - 1))
                logger.warning(
                    "LLM API error on attempt %d/%d: %s. Retrying in %.1fs…",
                    attempt,
                    _MAX_RETRIES,
                    exc,
                    delay,
                )
                time.sleep(delay)

        raise ReviewerError(
            f"LLM API failed after {_MAX_RETRIES} retries. "
            f"Last error: {last_exc}"
        ) from last_exc

    def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        """Call the OpenAI chat completions API.

        Args:
            system_prompt: System message content.
            user_prompt: User message content.

        Returns:
            Raw string content from the first choice.

        Raises:
            Various openai exceptions which are handled by _call_llm_with_retry.
        """
        from openai import OpenAI  # type: ignore[import]

        client: OpenAI = self._client  # type: ignore[assignment]
        response = client.chat.completions.create(
            model=self.config.openai_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            response_format={"type": "text"},
        )
        content = response.choices[0].message.content
        if content is None:
            raise ReviewerError("OpenAI returned an empty response content.")
        return content

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        """Call the Anthropic Messages API.

        Args:
            system_prompt: System message content.
            user_prompt: User message content.

        Returns:
            Raw string content from the first content block.

        Raises:
            Various anthropic exceptions which are handled by _call_llm_with_retry.
        """
        import anthropic  # type: ignore[import]

        client: anthropic.Anthropic = self._client  # type: ignore[assignment]
        response = client.messages.create(
            model=self.config.anthropic_model,
            max_tokens=self.config.max_tokens,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt},
            ],
            temperature=self.config.temperature,
        )
        if not response.content:
            raise ReviewerError("Anthropic returned an empty response.")
        block = response.content[0]
        if block.type != "text":
            raise ReviewerError(
                f"Anthropic returned unexpected content block type: {block.type}"
            )
        return block.text

    # ------------------------------------------------------------------
    # Client construction
    # ------------------------------------------------------------------

    def _build_client(self) -> object:
        """Build and return the appropriate LLM API client.

        Returns:
            An initialised OpenAI or Anthropic client instance.

        Raises:
            ReviewerError: If the client cannot be constructed.
        """
        if self.config.llm_backend == LLMBackend.OPENAI:
            try:
                from openai import OpenAI  # type: ignore[import]

                return OpenAI(api_key=self.config.openai_api_key)
            except ImportError as exc:
                raise ReviewerError(
                    "openai package is required for the OpenAI backend. "
                    "Install it with: pip install openai>=1.0"
                ) from exc
        else:
            try:
                import anthropic  # type: ignore[import]

                return anthropic.Anthropic(api_key=self.config.anthropic_api_key)
            except ImportError as exc:
                raise ReviewerError(
                    "anthropic package is required for the Anthropic backend. "
                    "Install it with: pip install anthropic>=0.20"
                ) from exc


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def _parse_llm_response(
    raw_response: str,
    default_file_path: str = "<unknown>",
) -> list[ReviewComment]:
    """Parse a raw LLM JSON response into a list of ReviewComment objects.

    The LLM is instructed to return a JSON object with a ``findings`` array.
    This function extracts the JSON (handling cases where the model wraps it
    in markdown fences despite instructions), validates the structure, and
    converts each finding into a ReviewComment.

    Args:
        raw_response: The raw string returned by the LLM.
        default_file_path: File path to use if a finding omits ``file_path``.

    Returns:
        List of ReviewComment objects. May be empty if the LLM found nothing.

    Raises:
        LLMParseError: If the response cannot be decoded as JSON or does not
            conform to the expected schema.
    """
    if not raw_response or not raw_response.strip():
        raise LLMParseError("LLM returned an empty response.")

    # Attempt to extract JSON from the response, handling markdown fences
    json_text = _extract_json(raw_response)

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise LLMParseError(
            f"LLM response is not valid JSON: {exc}. "
            f"First 200 chars: {json_text[:200]!r}"
        ) from exc

    if not isinstance(data, dict):
        raise LLMParseError(
            f"Expected a JSON object at the top level, got {type(data).__name__}."
        )

    findings = data.get("findings")
    if findings is None:
        raise LLMParseError(
            "LLM response JSON is missing the required 'findings' key."
        )
    if not isinstance(findings, list):
        raise LLMParseError(
            f"'findings' must be a JSON array, got {type(findings).__name__}."
        )

    comments: list[ReviewComment] = []
    for idx, finding in enumerate(findings):
        try:
            comment = _parse_finding(finding, default_file_path=default_file_path)
            if comment is not None:
                comments.append(comment)
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning(
                "Skipping malformed finding at index %d: %s — %r", idx, exc, finding
            )

    return comments


def _parse_finding(
    finding: dict,
    default_file_path: str,
) -> Optional[ReviewComment]:
    """Convert a single finding dictionary from the LLM into a ReviewComment.

    Args:
        finding: Dictionary representing one finding from the LLM JSON response.
        default_file_path: Fallback file path if the finding omits ``file_path``.

    Returns:
        A ReviewComment, or None if the finding should be skipped.

    Raises:
        KeyError: If a required field is absent.
        ValueError: If a field has an invalid value (e.g., unknown severity).
        TypeError: If a field has an unexpected type.
    """
    if not isinstance(finding, dict):
        raise TypeError(f"Finding must be a dict, got {type(finding).__name__}.")

    # Required fields
    severity_raw = finding.get("severity", "medium")
    category_raw = finding.get("category", "security")
    title = str(finding.get("title") or "").strip()
    description = str(finding.get("description") or "").strip()
    remediation = str(finding.get("remediation") or "").strip()

    if not title:
        raise ValueError("Finding has an empty 'title'.")
    if not description:
        raise ValueError("Finding has an empty 'description'.")

    # File path
    file_path = str(finding.get("file_path") or default_file_path).strip()
    if not file_path:
        file_path = default_file_path

    # Line numbers — accept int or null
    line_number_raw = finding.get("line_number")
    line_number: Optional[int] = None
    if line_number_raw is not None:
        try:
            line_number = int(line_number_raw)
            if line_number <= 0:
                line_number = None
        except (ValueError, TypeError):
            line_number = None

    end_line_raw = finding.get("end_line_number")
    end_line_number: Optional[int] = None
    if end_line_raw is not None:
        try:
            end_line_number = int(end_line_raw)
            if end_line_number <= 0:
                end_line_number = None
        except (ValueError, TypeError):
            end_line_number = None

    # Ensure end_line >= line_number
    if line_number is not None and end_line_number is not None:
        if end_line_number < line_number:
            end_line_number = line_number

    # Confidence — optional float 0..1
    confidence_raw = finding.get("confidence")
    confidence: Optional[float] = None
    if confidence_raw is not None:
        try:
            confidence = float(confidence_raw)
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = None

    # Severity — normalise and validate
    try:
        severity = Severity(str(severity_raw).lower().strip())
    except ValueError:
        logger.warning(
            "Unknown severity '%s' in finding '%s'; defaulting to 'medium'.",
            severity_raw,
            title,
        )
        severity = Severity.MEDIUM

    # Category — normalise and validate
    try:
        category = Category(str(category_raw).lower().strip())
    except ValueError:
        logger.warning(
            "Unknown category '%s' in finding '%s'; defaulting to 'security'.",
            category_raw,
            title,
        )
        category = Category.SECURITY

    # Convert config Severity to models Severity
    from adversary_bot.models import Severity as ModelSeverity
    model_severity = ModelSeverity(severity.value)

    return ReviewComment(
        file_path=file_path,
        line_number=line_number,
        severity=model_severity,
        category=category,
        title=title,
        description=description,
        remediation=remediation,
        end_line_number=end_line_number,
        confidence=confidence,
    )


def _extract_json(text: str) -> str:
    """Extract a JSON object from text, stripping markdown code fences if present.

    The LLM is instructed to return raw JSON, but may wrap it in triple-backtick
    fences. This function handles that gracefully.

    Args:
        text: The raw text from the LLM.

    Returns:
        The extracted JSON string, stripped of surrounding whitespace and fences.
    """
    stripped = text.strip()

    # Handle ```json ... ``` or ``` ... ``` fences
    fence_pattern = re.compile(
        r"```(?:json)?\s*\n?(.*?)\n?```",
        re.DOTALL | re.IGNORECASE,
    )
    match = fence_pattern.search(stripped)
    if match:
        return match.group(1).strip()

    # If the text starts with { or [ it's likely already raw JSON
    if stripped.startswith(("{", "[")):
        return stripped

    # Try to find the first { ... } block in the text
    brace_match = re.search(r"(\{.*\})", stripped, re.DOTALL)
    if brace_match:
        return brace_match.group(1).strip()

    # Return as-is and let json.loads report the error
    return stripped


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _is_retryable_error(exc: Exception) -> bool:
    """Determine whether an LLM API exception is worth retrying.

    Args:
        exc: The exception raised by the LLM client.

    Returns:
        True if the error is likely transient (rate limit, server error),
        False if it is a permanent failure (auth error, invalid request).
    """
    exc_type = type(exc).__name__
    exc_module = type(exc).__module__ or ""

    # OpenAI retryable errors
    retryable_names = {
        "RateLimitError",
        "APITimeoutError",
        "APIConnectionError",
        "InternalServerError",
        "ServiceUnavailableError",
    }
    if exc_type in retryable_names:
        return True

    # Anthropic retryable errors
    if "anthropic" in exc_module:
        retryable_anthropic = {
            "RateLimitError",
            "APITimeoutError",
            "APIConnectionError",
            "InternalServerError",
            "OverloadedError",
        }
        if exc_type in retryable_anthropic:
            return True

    # Check for HTTP status code attribute (both clients expose this)
    status_code = getattr(exc, "status_code", None)
    if status_code is not None and status_code in _RETRYABLE_STATUS_CODES:
        return True

    return False


def _config_severity_to_model_severity(config_severity: Severity) -> "ModelSeverity":
    """Convert a config.Severity to models.Severity.

    Both enums share the same string values; this function performs the
    explicit conversion to satisfy type checkers.

    Args:
        config_severity: A Severity enum value from adversary_bot.config.

    Returns:
        The equivalent Severity enum value from adversary_bot.models.
    """
    from adversary_bot.models import Severity as ModelSeverity  # noqa: F811

    return ModelSeverity(config_severity.value)
