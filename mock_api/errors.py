"""The error envelope: {"error": {"code", "message", "request_id"}}."""

from __future__ import annotations

CODES = {
    400: "invalid_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "idempotency_conflict",
    429: "rate_limited",
}


class ApiError(Exception):
    """An HTTP error the mock answers with. 5xx statuses map to `server_error`."""

    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}

    @property
    def code(self) -> str:
        return CODES.get(self.status, "server_error")


def error_body(code: str, message: str, request_id: str) -> dict[str, dict[str, str]]:
    return {"error": {"code": code, "message": message, "request_id": request_id}}
