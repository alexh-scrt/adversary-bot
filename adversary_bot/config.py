"""Configuration loading and validation for adversary_bot.

Loads settings from environment variables and optional .env files.
All configuration values are validated at load time with clear error messages.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


class LLMBackend(str, Enum):
    """Supported LLM backend providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class Severity(str, Enum):
    """Severity levels for review findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Model defaults per backend
DEFAULT_OPENAI_MODEL = "gpt-4o"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-5"

# Default temperature for adversarial review (slightly creative to surface edge cases)
DEFAULT_TEMPERATURE = 0.3

# Maximum tokens for LLM response
DEFAULT_MAX_TOKENS = 4096

# Minimum severity to report (findings below this are suppressed)
DEFAULT_MIN_SEVERITY = Severity.MEDIUM


@dataclass
class Config:
    """Validated configuration for adversary_bot.

    Attributes:
        llm_backend: Which LLM provider to use (openai or anthropic).
        openai_api_key: API key for OpenAI (required if backend is openai).
        anthropic_api_key: API key for Anthropic (required if backend is anthropic).
        openai_model: OpenAI model name to use.
        anthropic_model: Anthropic model name to use.
        github_token: Personal access token for GitHub API access.
        github_repo: Repository in owner/repo format (for PR review mode).
        temperature: LLM sampling temperature.
        max_tokens: Maximum tokens in LLM response.
        min_severity: Minimum severity level to include in output.
        post_comments: Whether to post inline comments back to GitHub.
        verbose: Enable verbose logging output.
    """

    llm_backend: LLMBackend = LLMBackend.OPENAI
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    openai_model: str = DEFAULT_OPENAI_MODEL
    anthropic_model: str = DEFAULT_ANTHROPIC_MODEL
    github_token: Optional[str] = None
    github_repo: Optional[str] = None
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS
    min_severity: Severity = DEFAULT_MIN_SEVERITY
    post_comments: bool = True
    verbose: bool = False

    @property
    def active_model(self) -> str:
        """Return the model name for the currently selected backend."""
        if self.llm_backend == LLMBackend.OPENAI:
            return self.openai_model
        return self.anthropic_model

    @property
    def active_api_key(self) -> Optional[str]:
        """Return the API key for the currently selected backend."""
        if self.llm_backend == LLMBackend.OPENAI:
            return self.openai_api_key
        return self.anthropic_api_key

    def validate(self) -> None:
        """Validate the configuration, raising ConfigError on invalid state.

        Raises:
            ConfigError: If required configuration values are missing or invalid.
        """
        # Validate backend-specific API key
        if self.llm_backend == LLMBackend.OPENAI:
            if not self.openai_api_key:
                raise ConfigError(
                    "OPENAI_API_KEY is required when using the OpenAI backend. "
                    "Set it in your environment or .env file."
                )
        elif self.llm_backend == LLMBackend.ANTHROPIC:
            if not self.anthropic_api_key:
                raise ConfigError(
                    "ANTHROPIC_API_KEY is required when using the Anthropic backend. "
                    "Set it in your environment or .env file."
                )

        # Validate temperature range
        if not 0.0 <= self.temperature <= 2.0:
            raise ConfigError(
                f"Temperature must be between 0.0 and 2.0, got {self.temperature}."
            )

        # Validate max_tokens
        if self.max_tokens < 256:
            raise ConfigError(
                f"max_tokens must be at least 256, got {self.max_tokens}."
            )
        if self.max_tokens > 32768:
            raise ConfigError(
                f"max_tokens must be at most 32768, got {self.max_tokens}."
            )

        # Validate github_repo format if provided
        if self.github_repo and "/" not in self.github_repo:
            raise ConfigError(
                f"GITHUB_REPO must be in 'owner/repo' format, got '{self.github_repo}'."
            )


class ConfigError(ValueError):
    """Raised when configuration is invalid or missing required values."""

    pass


def load_config(
    env_file: Optional[Path] = None,
    override_backend: Optional[str] = None,
    override_model: Optional[str] = None,
    override_github_repo: Optional[str] = None,
    override_github_token: Optional[str] = None,
    override_min_severity: Optional[str] = None,
    override_temperature: Optional[float] = None,
    override_max_tokens: Optional[int] = None,
    override_post_comments: Optional[bool] = None,
    override_verbose: Optional[bool] = None,
    validate: bool = True,
) -> Config:
    """Load and return a validated Config object from the environment.

    Reads configuration from environment variables, optionally loading a .env
    file first. Any ``override_*`` keyword arguments take precedence over
    environment variables, allowing CLI flags to override env config.

    Environment variables recognized:
        - ``ADVERSARY_BOT_BACKEND``: ``openai`` or ``anthropic`` (default: ``openai``)
        - ``OPENAI_API_KEY``: API key for OpenAI
        - ``ANTHROPIC_API_KEY``: API key for Anthropic
        - ``OPENAI_MODEL``: OpenAI model name (default: ``gpt-4o``)
        - ``ANTHROPIC_MODEL``: Anthropic model name (default: ``claude-opus-4-5``)
        - ``GITHUB_TOKEN``: GitHub personal access token
        - ``GITHUB_REPO``: Repository in ``owner/repo`` format
        - ``ADVERSARY_BOT_TEMPERATURE``: Sampling temperature (default: ``0.3``)
        - ``ADVERSARY_BOT_MAX_TOKENS``: Max response tokens (default: ``4096``)
        - ``ADVERSARY_BOT_MIN_SEVERITY``: Minimum severity (default: ``medium``)
        - ``ADVERSARY_BOT_POST_COMMENTS``: Post GitHub comments (default: ``true``)
        - ``ADVERSARY_BOT_VERBOSE``: Verbose output (default: ``false``)

    Args:
        env_file: Path to a .env file to load. If None, searches for .env in
            the current directory and its parents.
        override_backend: Override the LLM backend selection.
        override_model: Override the model name for the selected backend.
        override_github_repo: Override the GitHub repository.
        override_github_token: Override the GitHub token.
        override_min_severity: Override the minimum severity filter.
        override_temperature: Override the LLM temperature.
        override_max_tokens: Override the max tokens limit.
        override_post_comments: Override whether to post GitHub comments.
        override_verbose: Override the verbose flag.
        validate: Whether to call config.validate() before returning.

    Returns:
        A fully populated and (if validate=True) validated Config instance.

    Raises:
        ConfigError: If required configuration is missing or invalid and
            validate=True.
    """
    # Load .env file - explicit path takes precedence, otherwise auto-discover
    if env_file is not None:
        load_dotenv(dotenv_path=env_file, override=False)
    else:
        # Search upward from cwd for .env file
        _load_dotenv_from_cwd()

    # Resolve backend
    raw_backend = override_backend or os.environ.get("ADVERSARY_BOT_BACKEND", "openai")
    try:
        backend = LLMBackend(raw_backend.lower().strip())
    except ValueError:
        raise ConfigError(
            f"Unknown LLM backend '{raw_backend}'. Valid options: "
            + ", ".join(b.value for b in LLMBackend)
        )

    # Resolve API keys
    openai_api_key = os.environ.get("OPENAI_API_KEY") or None
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY") or None

    # Resolve model names
    openai_model = os.environ.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL)
    anthropic_model = os.environ.get("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL)

    # Apply override_model to the active backend's model
    if override_model:
        if backend == LLMBackend.OPENAI:
            openai_model = override_model
        else:
            anthropic_model = override_model

    # Resolve GitHub settings
    github_token = override_github_token or os.environ.get("GITHUB_TOKEN") or None
    github_repo = override_github_repo or os.environ.get("GITHUB_REPO") or None

    # Resolve temperature
    if override_temperature is not None:
        temperature = override_temperature
    else:
        raw_temp = os.environ.get("ADVERSARY_BOT_TEMPERATURE", str(DEFAULT_TEMPERATURE))
        try:
            temperature = float(raw_temp)
        except ValueError:
            raise ConfigError(
                f"ADVERSARY_BOT_TEMPERATURE must be a float, got '{raw_temp}'."
            )

    # Resolve max_tokens
    if override_max_tokens is not None:
        max_tokens = override_max_tokens
    else:
        raw_max = os.environ.get("ADVERSARY_BOT_MAX_TOKENS", str(DEFAULT_MAX_TOKENS))
        try:
            max_tokens = int(raw_max)
        except ValueError:
            raise ConfigError(
                f"ADVERSARY_BOT_MAX_TOKENS must be an integer, got '{raw_max}'."
            )

    # Resolve min_severity
    if override_min_severity is not None:
        raw_severity = override_min_severity
    else:
        raw_severity = os.environ.get(
            "ADVERSARY_BOT_MIN_SEVERITY", DEFAULT_MIN_SEVERITY.value
        )
    try:
        min_severity = Severity(raw_severity.lower().strip())
    except ValueError:
        raise ConfigError(
            f"Unknown severity '{raw_severity}'. Valid options: "
            + ", ".join(s.value for s in Severity)
        )

    # Resolve post_comments
    if override_post_comments is not None:
        post_comments = override_post_comments
    else:
        post_comments = _parse_bool(
            os.environ.get("ADVERSARY_BOT_POST_COMMENTS", "true"),
            "ADVERSARY_BOT_POST_COMMENTS",
        )

    # Resolve verbose
    if override_verbose is not None:
        verbose = override_verbose
    else:
        verbose = _parse_bool(
            os.environ.get("ADVERSARY_BOT_VERBOSE", "false"),
            "ADVERSARY_BOT_VERBOSE",
        )

    config = Config(
        llm_backend=backend,
        openai_api_key=openai_api_key,
        anthropic_api_key=anthropic_api_key,
        openai_model=openai_model,
        anthropic_model=anthropic_model,
        github_token=github_token,
        github_repo=github_repo,
        temperature=temperature,
        max_tokens=max_tokens,
        min_severity=min_severity,
        post_comments=post_comments,
        verbose=verbose,
    )

    if validate:
        config.validate()

    return config


def _load_dotenv_from_cwd() -> None:
    """Search for a .env file starting from cwd, walking up to the filesystem root."""
    current = Path.cwd()
    for directory in [current, *current.parents]:
        candidate = directory / ".env"
        if candidate.is_file():
            load_dotenv(dotenv_path=candidate, override=False)
            return
    # If no .env found, that's fine — not all setups use one


def _parse_bool(value: str, var_name: str) -> bool:
    """Parse a string as a boolean value.

    Accepts: true/false, yes/no, 1/0, on/off (case-insensitive).

    Args:
        value: The string to parse.
        var_name: The environment variable name (for error messages).

    Returns:
        The parsed boolean value.

    Raises:
        ConfigError: If the value cannot be interpreted as a boolean.
    """
    normalized = value.lower().strip()
    if normalized in ("true", "yes", "1", "on"):
        return True
    if normalized in ("false", "no", "0", "off"):
        return False
    raise ConfigError(
        f"{var_name} must be a boolean value (true/false/yes/no/1/0/on/off), "
        f"got '{value}'."
    )
