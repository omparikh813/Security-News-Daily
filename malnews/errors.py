"""Pipeline errors that map to distinct process exit codes."""


class MalNewsError(Exception):
    exit_code = 1


class ConfigError(MalNewsError):
    """Bad configuration or environment (FR-11). Raised before any network use."""

    exit_code = 2


class RateLimitStop(MalNewsError):
    """HTTP 429 or a quota error from the model provider (FR-14). Publish nothing."""

    exit_code = 3


class BudgetExceeded(MalNewsError):
    """The per-run request cap was hit (FR-14). Publish nothing."""

    exit_code = 4


class AllSourcesFailed(MalNewsError):
    """Every news source failed (FR-3)."""

    exit_code = 5


class AIAuthError(MalNewsError):
    """The provider rejected the API key. Fail loudly instead of printing excerpts."""

    exit_code = 6
