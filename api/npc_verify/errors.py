"""Fail-closed error shapes for the Verification API.

Rules (from DESIGN v1 §3):
- Unknown subject -> 404 with {"verdict": "unknown"}. Never a fabricated verdict.
- Malformed input -> 400, never a 500 for client mistakes.
- Auth problems -> 401 / 403 with no information about what exists.
- Rate limits -> 429 with retry guidance.
- Bodies are small, fixed-shape, and signed like every other response.
"""
from http import HTTPStatus


def unknown():
    """Unknown subject. Fail closed: no verdict is fabricated."""
    return HTTPStatus.NOT_FOUND, {"verdict": "unknown"}


def not_found():
    """Unknown route."""
    return HTTPStatus.NOT_FOUND, {"error": "not_found", "verdict": "unknown"}


def bad_request(detail):
    return HTTPStatus.BAD_REQUEST, {"error": "bad_request", "detail": detail}


def unauthorized():
    return HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"}


def forbidden(detail="insufficient role for this operation"):
    return HTTPStatus.FORBIDDEN, {"error": "forbidden", "detail": detail}


def rate_limited(retry_after):
    return HTTPStatus.TOO_MANY_REQUESTS, {
        "error": "rate_limited",
        "detail": "slow down",
        "retry_after_seconds": retry_after,
    }


def conflict(detail):
    return HTTPStatus.CONFLICT, {"error": "conflict", "detail": detail}


def unprocessable(detail):
    return HTTPStatus.UNPROCESSABLE_ENTITY, {
        "error": "unprocessable", "detail": detail}
