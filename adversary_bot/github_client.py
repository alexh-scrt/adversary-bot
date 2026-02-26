"""GitHub API client wrapper for adversary_bot.

Provides a high-level interface around PyGithub for:

- Fetching the unified diff for a pull request
- Listing PR files and their change metadata
- Posting inline review comments back to a PR with file/line precision
- Creating a consolidated review (approve/comment/request-changes) with all
  findings summarised

All GitHub API calls respect rate limits via PyGithub's built-in handling and
include retry logic for transient server errors.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from github import Github, GithubException, RateLimitExceededException  # type: ignore[import]
from github.PullRequest import PullRequest  # type: ignore[import]
from github.Repository import Repository  # type: ignore[import]

from adversary_bot.models import ReviewComment, ReviewResult, Severity

logger = logging.getLogger(__name__)

# Maximum retries for transient GitHub API errors
_MAX_RETRIES = 3

# Base delay for exponential backoff (seconds)
_RETRY_BASE_DELAY = 2.0

# Delay when a rate limit is encountered (seconds)
_RATE_LIMIT_DELAY = 60.0

# Maximum body length for a single GitHub review comment (characters)
# GitHub's API enforces a 65536 character limit per comment body
_MAX_COMMENT_BODY_LEN = 65000

# The review event type to use when submitting the overall PR review
_REVIEW_EVENT_COMMENT = "COMMENT"


class GitHubClientError(RuntimeError):
    """Raised when a GitHub API operation fails unrecoverably."""

    pass


class GitHubRateLimitError(GitHubClientError):
    """Raised when the GitHub API rate limit is exceeded and cannot be recovered."""

    pass


class AdversaryGitHubClient:
    """High-level GitHub client for fetching PR diffs and posting review comments.

    Wraps PyGithub to provide adversary_bot-specific operations. Handles
    authentication, rate limiting, retry logic, and comment formatting.

    Args:
        github_token: A GitHub personal access token with ``repo`` scope
            (or ``pull-requests: write`` for fine-grained tokens).
        repo_name: Repository identifier in ``owner/repo`` format.

    Raises:
        GitHubClientError: If the client cannot authenticate or reach the
            specified repository.

    Example::

        client = AdversaryGitHubClient(
            github_token="ghp_...",
            repo_name="myorg/myrepo",
        )
        diff_text = client.get_pr_diff(pr_number=42)
        # ... run review ...
        client.post_review(pr_number=42, result=review_result)
    """

    def __init__(self, github_token: str, repo_name: str) -> None:
        """Initialise the GitHub client.

        Args:
            github_token: GitHub personal access token.
            repo_name: Repository in ``owner/repo`` format.

        Raises:
            GitHubClientError: If authentication fails or the repository
                cannot be found.
        """
        if not github_token:
            raise GitHubClientError(
                "A GitHub token is required for GitHub API access. "
                "Set GITHUB_TOKEN in your environment or .env file."
            )
        if not repo_name or "/" not in repo_name:
            raise GitHubClientError(
                f"repo_name must be in 'owner/repo' format, got: {repo_name!r}"
            )

        self._token = github_token
        self._repo_name = repo_name
        self._gh = Github(github_token)
        self._repo: Optional[Repository] = None  # lazy-loaded

    # ------------------------------------------------------------------
    # Repository access
    # ------------------------------------------------------------------

    @property
    def repo(self) -> Repository:
        """Return the PyGithub Repository object, loading it lazily.

        Returns:
            Authenticated Repository instance.

        Raises:
            GitHubClientError: If the repository cannot be accessed.
        """
        if self._repo is None:
            self._repo = self._get_repo()
        return self._repo

    def _get_repo(self) -> Repository:
        """Fetch the Repository object from GitHub.

        Returns:
            PyGithub Repository.

        Raises:
            GitHubClientError: On authentication failure or missing repo.
        """
        try:
            return self._gh.get_repo(self._repo_name)
        except GithubException as exc:
            if exc.status == 404:
                raise GitHubClientError(
                    f"Repository '{self._repo_name}' not found or not accessible "
                    f"with the provided token."
                ) from exc
            if exc.status == 401:
                raise GitHubClientError(
                    "GitHub authentication failed. Check your GITHUB_TOKEN."
                ) from exc
            raise GitHubClientError(
                f"Failed to access repository '{self._repo_name}': {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Fetching PR data
    # ------------------------------------------------------------------

    def get_pr_diff(self, pr_number: int) -> str:
        """Fetch the unified diff for a pull request.

        Downloads the raw diff via the GitHub REST API by requesting the PR
        with the ``application/vnd.github.v3.diff`` media type.

        Args:
            pr_number: The pull request number.

        Returns:
            The raw unified diff text for the PR.

        Raises:
            GitHubClientError: If the PR cannot be found or the diff cannot
                be retrieved.
        """
        pr = self._get_pull_request(pr_number)
        return self._fetch_pr_diff_text(pr)

    def get_pr_info(self, pr_number: int) -> dict:
        """Return basic metadata about a pull request.

        Args:
            pr_number: The pull request number.

        Returns:
            Dictionary with keys: ``number``, ``title``, ``author``,
            ``base_branch``, ``head_branch``, ``state``, ``url``,
            ``changed_files``, ``additions``, ``deletions``.

        Raises:
            GitHubClientError: If the PR cannot be found.
        """
        pr = self._get_pull_request(pr_number)
        return {
            "number": pr.number,
            "title": pr.title,
            "author": pr.user.login if pr.user else "unknown",
            "base_branch": pr.base.ref,
            "head_branch": pr.head.ref,
            "state": pr.state,
            "url": pr.html_url,
            "changed_files": pr.changed_files,
            "additions": pr.additions,
            "deletions": pr.deletions,
        }

    def get_pr_head_sha(self, pr_number: int) -> str:
        """Return the head commit SHA for a pull request.

        Args:
            pr_number: The pull request number.

        Returns:
            The full SHA string of the head commit.

        Raises:
            GitHubClientError: If the PR cannot be found.
        """
        pr = self._get_pull_request(pr_number)
        return pr.head.sha

    # ------------------------------------------------------------------
    # Posting review comments
    # ------------------------------------------------------------------

    def post_review(
        self,
        pr_number: int,
        result: ReviewResult,
        min_severity: Optional[Severity] = None,
    ) -> int:
        """Post a full PR review with inline comments for all findings.

        Creates a GitHub pull request review containing:
        - One inline comment per ReviewComment that has a valid line number
        - A review body summarising all findings (including file-level ones
          without line numbers)

        Only findings at or above ``min_severity`` are posted. If no findings
        qualify, a clean summary comment is posted instead.

        Args:
            pr_number: The pull request number to review.
            result: The ReviewResult from the adversarial review run.
            min_severity: Minimum severity for findings to post. Defaults to
                including all findings in ``result.comments``.

        Returns:
            The number of inline comments successfully posted.

        Raises:
            GitHubClientError: If the review cannot be posted.
        """
        pr = self._get_pull_request(pr_number)
        commit_sha = pr.head.sha

        # Filter by severity if requested
        comments_to_post = result.comments
        if min_severity is not None:
            comments_to_post = [c for c in comments_to_post if c.severity >= min_severity]

        # Separate inline-capable comments from file-level ones
        inline_comments = [c for c in comments_to_post if c.line_number is not None]
        file_level_comments = [c for c in comments_to_post if c.line_number is None]

        # Build the review body
        review_body = _build_review_body(result, file_level_comments)

        # Build the list of inline comment dicts for the GitHub API
        github_comments = [
            _build_inline_comment_dict(c) for c in inline_comments
        ]

        # Remove any comment dicts that failed construction
        github_comments = [gc for gc in github_comments if gc is not None]

        # Post the review via PyGithub
        posted_count = self._submit_pr_review(
            pr=pr,
            commit_sha=commit_sha,
            review_body=review_body,
            inline_comments=github_comments,
        )

        logger.info(
            "Posted review on PR #%d with %d inline comments.",
            pr_number,
            posted_count,
        )
        return posted_count

    def post_inline_comment(
        self,
        pr_number: int,
        comment: ReviewComment,
    ) -> bool:
        """Post a single inline review comment on a PR.

        This is a lower-level method for posting individual comments outside
        of a full review submission. Useful for streaming findings as they
        are discovered.

        Args:
            pr_number: The pull request number.
            comment: The ReviewComment to post.

        Returns:
            True if the comment was posted successfully, False otherwise.

        Raises:
            GitHubClientError: If the PR cannot be accessed.
        """
        if comment.line_number is None:
            logger.warning(
                "Cannot post inline comment for '%s' — no line number.",
                comment.title,
            )
            return False

        pr = self._get_pull_request(pr_number)
        commit_sha = pr.head.sha
        body = comment.format_github_body()
        if len(body) > _MAX_COMMENT_BODY_LEN:
            body = body[:_MAX_COMMENT_BODY_LEN] + "\n\n*[Comment truncated]*"

        try:
            self._api_call_with_retry(
                lambda: pr.create_review_comment(
                    body=body,
                    commit=self._repo.get_commit(commit_sha),  # type: ignore[union-attr]
                    path=comment.file_path,
                    line=comment.line_number,
                )
            )
            return True
        except GithubException as exc:
            logger.warning(
                "Failed to post inline comment on %s:%s — %s",
                comment.file_path,
                comment.line_number,
                exc,
            )
            return False

    def post_issue_comment(
        self,
        pr_number: int,
        body: str,
    ) -> None:
        """Post a plain issue comment (not inline) on a PR.

        Issue comments appear in the main PR timeline rather than on specific
        diff lines. Useful for summary comments or error notifications.

        Args:
            pr_number: The pull request number.
            body: The Markdown-formatted comment body.

        Raises:
            GitHubClientError: If the comment cannot be posted.
        """
        pr = self._get_pull_request(pr_number)
        if len(body) > _MAX_COMMENT_BODY_LEN:
            body = body[:_MAX_COMMENT_BODY_LEN] + "\n\n*[Comment truncated]*"
        try:
            self._api_call_with_retry(lambda: pr.create_issue_comment(body=body))
        except GithubException as exc:
            raise GitHubClientError(
                f"Failed to post issue comment on PR #{pr_number}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_pull_request(self, pr_number: int) -> PullRequest:
        """Fetch a PullRequest object from GitHub.

        Args:
            pr_number: The PR number.

        Returns:
            PyGithub PullRequest instance.

        Raises:
            GitHubClientError: If the PR is not found or cannot be accessed.
        """
        try:
            return self._api_call_with_retry(lambda: self.repo.get_pull(pr_number))
        except GithubException as exc:
            if exc.status == 404:
                raise GitHubClientError(
                    f"Pull request #{pr_number} not found in '{self._repo_name}'."
                ) from exc
            raise GitHubClientError(
                f"Failed to fetch PR #{pr_number}: {exc}"
            ) from exc

    def _fetch_pr_diff_text(self, pr: PullRequest) -> str:
        """Download the raw unified diff for a PR using the GitHub API.

        PyGithub does not expose the raw diff directly, so we use the
        underlying PyGithub requester to make the API call with the
        appropriate media type header.

        Args:
            pr: The PyGithub PullRequest object.

        Returns:
            Raw unified diff text string.

        Raises:
            GitHubClientError: If the diff cannot be fetched.
        """
        try:
            # Use PyGithub's internal requester to fetch the diff
            # The diff is available at the PR URL with a specific Accept header
            requester = self.repo._requester  # type: ignore[attr-defined]
            headers, data = requester.requestBlobAndCheck(
                "GET",
                pr.url,
                headers={"Accept": "application/vnd.github.v3.diff"},
            )
            if isinstance(data, bytes):
                return data.decode("utf-8", errors="replace")
            return str(data)
        except GithubException as exc:
            raise GitHubClientError(
                f"Failed to fetch diff for PR #{pr.number}: {exc}"
            ) from exc
        except Exception as exc:
            # Fall back to fetching files and reconstructing a minimal diff
            logger.warning(
                "Could not fetch raw diff for PR #%d via blob endpoint (%s). "
                "Falling back to files API.",
                pr.number,
                exc,
            )
            return self._fetch_diff_from_files(pr)

    def _fetch_diff_from_files(self, pr: PullRequest) -> str:
        """Construct a diff-like representation from PR file patches.

        Falls back to the PR files API (which returns per-file patch text)
        when the raw diff endpoint is unavailable.

        Args:
            pr: The PyGithub PullRequest object.

        Returns:
            A concatenated string of per-file unified diff text.

        Raises:
            GitHubClientError: If the files cannot be fetched.
        """
        try:
            files = list(self._api_call_with_retry(lambda: pr.get_files()))
        except GithubException as exc:
            raise GitHubClientError(
                f"Failed to fetch PR files for PR #{pr.number}: {exc}"
            ) from exc

        parts: list[str] = []
        for f in files:
            patch = getattr(f, "patch", None)
            if not patch:
                continue
            # Reconstruct a minimal unified diff header
            previous_name = getattr(f, "previous_filename", None) or f.filename
            parts.append(f"diff --git a/{previous_name} b/{f.filename}")
            if f.status == "added":
                parts.append("new file mode 100644")
                parts.append("--- /dev/null")
            else:
                parts.append(f"--- a/{previous_name}")
            if f.status == "removed":
                parts.append("+++ /dev/null")
            else:
                parts.append(f"+++ b/{f.filename}")
            parts.append(patch)

        return "\n".join(parts)

    def _submit_pr_review(
        self,
        pr: PullRequest,
        commit_sha: str,
        review_body: str,
        inline_comments: list[dict],
    ) -> int:
        """Submit a PR review with optional inline comments.

        Attempts to create a review with all inline comments in one API call.
        If the batch submission fails (e.g., some line numbers are invalid),
        falls back to posting each comment individually.

        Args:
            pr: The PyGithub PullRequest object.
            commit_sha: The commit SHA to attach the review to.
            review_body: The overall review body text (Markdown).
            inline_comments: List of comment dicts with keys:
                ``path``, ``line``, ``body``.

        Returns:
            Number of inline comments successfully posted.

        Raises:
            GitHubClientError: If the review body itself cannot be posted.
        """
        commit = self.repo.get_commit(commit_sha)

        if inline_comments:
            try:
                self._api_call_with_retry(
                    lambda: pr.create_review(
                        commit=commit,
                        body=review_body,
                        event=_REVIEW_EVENT_COMMENT,
                        comments=inline_comments,
                    )
                )
                return len(inline_comments)
            except GithubException as exc:
                logger.warning(
                    "Batch review submission failed (%s). "
                    "Falling back to individual comment posting.",
                    exc,
                )
                # Fall through to individual posting

        # Post the review body as a plain issue comment first
        try:
            self._api_call_with_retry(
                lambda: pr.create_review(
                    commit=commit,
                    body=review_body,
                    event=_REVIEW_EVENT_COMMENT,
                    comments=[],
                )
            )
        except GithubException as exc:
            raise GitHubClientError(
                f"Failed to post review body on PR #{pr.number}: {exc}"
            ) from exc

        # Post inline comments individually
        posted = 0
        for comment_dict in inline_comments:
            try:
                self._api_call_with_retry(
                    lambda cd=comment_dict: pr.create_review_comment(
                        body=cd["body"],
                        commit=commit,
                        path=cd["path"],
                        line=cd["line"],
                    )
                )
                posted += 1
            except GithubException as exc:
                logger.warning(
                    "Failed to post inline comment on %s:%s — %s",
                    comment_dict.get("path"),
                    comment_dict.get("line"),
                    exc,
                )

        return posted

    def _api_call_with_retry(self, fn, *args, **kwargs):
        """Execute a GitHub API call with retry logic.

        Retries on rate limit errors (waiting for reset) and transient server
        errors (with exponential backoff).

        Args:
            fn: Callable that performs the GitHub API call.
            *args: Positional arguments to pass to ``fn``.
            **kwargs: Keyword arguments to pass to ``fn``.

        Returns:
            The return value of ``fn``.

        Raises:
            GitHubRateLimitError: If rate limit cannot be recovered within
                the retry budget.
            GitHubClientError: If the call fails after all retries.
        """
        last_exc: Optional[Exception] = None

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                return fn(*args, **kwargs)
            except RateLimitExceededException as exc:
                last_exc = exc
                logger.warning(
                    "GitHub rate limit exceeded on attempt %d/%d. "
                    "Waiting %.0fs before retry…",
                    attempt,
                    _MAX_RETRIES,
                    _RATE_LIMIT_DELAY,
                )
                if attempt == _MAX_RETRIES:
                    raise GitHubRateLimitError(
                        "GitHub rate limit exceeded and retry budget exhausted."
                    ) from exc
                time.sleep(_RATE_LIMIT_DELAY)
            except GithubException as exc:
                last_exc = exc
                if exc.status in {401, 403, 404, 422}:
                    # Non-retryable: auth error, permission denied, not found,
                    # or unprocessable entity (e.g., invalid line number)
                    raise
                if exc.status in {500, 502, 503, 504}:
                    delay = _RETRY_BASE_DELAY * (2 ** (attempt - 1))
                    logger.warning(
                        "GitHub server error %d on attempt %d/%d. "
                        "Retrying in %.1fs…",
                        exc.status,
                        attempt,
                        _MAX_RETRIES,
                        delay,
                    )
                    if attempt == _MAX_RETRIES:
                        raise GitHubClientError(
                            f"GitHub API failed after {_MAX_RETRIES} retries: {exc}"
                        ) from exc
                    time.sleep(delay)
                else:
                    raise

        raise GitHubClientError(
            f"GitHub API call failed after {_MAX_RETRIES} retries. "
            f"Last error: {last_exc}"
        ) from last_exc


# ---------------------------------------------------------------------------
# Comment formatting helpers
# ---------------------------------------------------------------------------


def _build_review_body(result: ReviewResult, file_level_comments: list[ReviewComment]) -> str:
    """Build the overall PR review body markdown summarising the findings.

    Args:
        result: The full ReviewResult from the adversarial review.
        file_level_comments: Comments without line numbers that cannot be
            posted inline, to be included in the review body.

    Returns:
        Markdown-formatted review body string.
    """
    lines: list[str] = []
    severity_summary = result.severity_summary()

    lines.append("## 🔪 Adversary Bot — Adversarial Code Review")
    lines.append("")
    lines.append(
        f"Reviewed **{result.files_reviewed}** file(s) using "
        f"`{result.backend_used}/{result.model_used}`."
    )
    if result.files_skipped:
        lines.append(f"Skipped **{result.files_skipped}** file(s) (binary or deleted).")
    lines.append("")

    if result.total_findings == 0:
        lines.append("✅ **No security findings above the minimum severity threshold.**")
        lines.append("")
        lines.append(
            "*This review was performed adversarially — "
            "the bot was instructed to hunt for vulnerabilities and found none.*"
        )
        return "\n".join(lines)

    # Severity summary table
    lines.append("### Findings Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev_name in ["critical", "high", "medium", "low"]:
        count = severity_summary.get(sev_name, 0)
        if count > 0:
            sev = Severity(sev_name)
            emoji = _severity_emoji(sev)
            lines.append(f"| {emoji} {sev_name.upper()} | {count} |")
    lines.append("")

    lines.append(
        f"**Total findings: {result.total_findings}** "
        f"(inline comments below for specific line references)"
    )

    # Include file-level comments (no line number) in the review body
    if file_level_comments:
        lines.append("")
        lines.append("### File-Level Findings")
        lines.append("")
        lines.append(
            "*These findings apply to the file as a whole and are not tied to a specific line.*"
        )
        lines.append("")
        for comment in file_level_comments:
            lines.append(comment.format_github_body())
            lines.append("")
            lines.append("---")
            lines.append("")

    if result.error:
        lines.append("")
        lines.append(f"⚠️ **Review error:** {result.error}")

    body = "\n".join(lines)
    if len(body) > _MAX_COMMENT_BODY_LEN:
        body = body[:_MAX_COMMENT_BODY_LEN] + "\n\n*[Review body truncated due to length]*"
    return body


def _build_inline_comment_dict(comment: ReviewComment) -> Optional[dict]:
    """Build a GitHub API-compatible inline comment dictionary.

    Args:
        comment: A ReviewComment with a valid line_number.

    Returns:
        A dictionary with ``path``, ``line``, and ``body`` keys suitable for
        passing to PyGithub's create_review(), or None if the comment cannot
        be represented as an inline comment.
    """
    if comment.line_number is None:
        return None

    body = comment.format_github_body()
    if len(body) > _MAX_COMMENT_BODY_LEN:
        body = body[:_MAX_COMMENT_BODY_LEN] + "\n\n*[Comment truncated]*"

    result: dict = {
        "path": comment.file_path,
        "body": body,
        "line": comment.line_number,
    }

    # GitHub supports multi-line range comments via start_line/line
    if (
        comment.end_line_number is not None
        and comment.end_line_number > comment.line_number
    ):
        result["start_line"] = comment.line_number
        result["line"] = comment.end_line_number

    return result


def _severity_emoji(severity: Severity) -> str:
    """Return an emoji for a Severity level.

    Args:
        severity: The Severity enum value.

    Returns:
        An emoji string.
    """
    return {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
    }.get(severity, "⚪")
