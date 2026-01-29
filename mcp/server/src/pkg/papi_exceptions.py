"""Exception classes for XSIAM PAPI client."""


class PAPIClientError(Exception):
    """Base exception for PAPI client errors."""


class PAPIConnectionError(PAPIClientError):
    """Raised when connection to PAPI fails."""


class PAPIResponseError(PAPIClientError):
    """Raised when response parsing fails."""


class PAPIAuthenticationError(PAPIClientError):
    """Raised when authentication fails (401/403)."""


class PAPIServerError(PAPIClientError):
    """Raised when server returns 5xx error."""


class PAPIClientRequestError(PAPIClientError):
    """Raised when client request is invalid (4xx)."""
