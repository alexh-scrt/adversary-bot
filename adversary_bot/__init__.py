"""adversary_bot - A hostile, adversarial code reviewer for pull requests.

This package provides a CLI tool and library for performing aggressive,
security-focused code reviews using LLMs (OpenAI GPT-4o or Anthropic Claude).
It hunts for security vulnerabilities, logic flaws, race conditions, and design
weaknesses — not style issues.

Typical usage::

    # Review a local diff
    adversary-bot review-diff path/to/changes.diff

    # Review a GitHub pull request
    adversary-bot review-pr --repo owner/repo --pr 42

Or programmatically::

    from adversary_bot.config import load_config
    from adversary_bot.reviewer import AdversaryReviewer

    config = load_config()
    reviewer = AdversaryReviewer(config)
    result = reviewer.review_diff(diff_text)
"""

__version__ = "0.1.0"
__author__ = "adversary_bot contributors"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
