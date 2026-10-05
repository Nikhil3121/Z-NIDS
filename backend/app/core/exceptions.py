"""Consistent API error model.

Every error leaving the API has the shape::

    {"error": {"code": "RESOURCE_NOT_FOUND", "message": "...", "request_id": "..."}}

Unexpected exceptions are logged with their traceback server-side and returned
to the client as a generic INTERNAL_ERROR — stack traces never leave the process.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_var

logger = logging.getLogger(__name__)


class AppError(Exception):
    status_code = 400
    code = "BAD_REQUEST"

    def __init__(self, message: str, *, code: str | None = None, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details


class NotFoundError(AppError):
    status_code = 404
    code = "RESOURCE_NOT_FOUND"


class AuthenticationError(AppError):
    status_code = 401
    code = "AUTHENTICATION_FAILED"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "PERMISSION_DENIED"


class ConflictError(AppError):
    status_code = 409
    code = "CONFLICT"


class ValidationFailedError(AppError):
    status_code = 422
    code = "VALIDATION_ERROR"


class RateLimitedError(AppError):
    status_code = 429
    code = "RATE_LIMITED"

    def __init__(self, message: str = "Too many requests", retry_after: int = 60) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ServiceUnavailableError(AppError):
    status_code = 503
    code = "SERVICE_UNAVAILABLE"


class InvalidStateTransitionError(AppError):
    status_code = 409
    code = "INVALID_STATE_TRANSITION"


_STATUS_CODES = {
    400: "BAD_REQUEST",
    401: "AUTHENTICATION_FAILED",
    403: "PERMISSION_DENIED",
    404: "RESOURCE_NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    413: "PAYLOAD_TOO_LARGE",
    429: "RATE_LIMITED",
}


def error_body(code: str, message: str, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message, "request_id": request_id_var.get()}
    if details is not None:
        body["details"] = details
    return {"error": body}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        headers = {}
        if isinstance(exc, RateLimitedError):
            headers["Retry-After"] = str(exc.retry_after)
        if isinstance(exc, AuthenticationError):
            headers["WWW-Authenticate"] = "Bearer"
        log = logger.warning if exc.status_code >= 500 or exc.status_code in (401, 403, 429) else logger.info
        log("request failed", extra={"error_code": exc.code, "status": exc.status_code})
        return JSONResponse(
            error_body(exc.code, exc.message, exc.details), status_code=exc.status_code, headers=headers
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {"loc": [str(p) for p in err.get("loc", ())], "msg": err.get("msg"), "type": err.get("type")}
            for err in exc.errors()
        ]
        return JSONResponse(error_body("VALIDATION_ERROR", "Request validation failed", details), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "HTTP_ERROR")
        message = exc.detail if isinstance(exc.detail, str) else code.replace("_", " ").title()
        return JSONResponse(error_body(code, message), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled exception", exc_info=exc)
        return JSONResponse(error_body("INTERNAL_ERROR", "An internal error occurred"), status_code=500)
