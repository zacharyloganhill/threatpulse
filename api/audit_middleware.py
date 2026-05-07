"""
FedRAMP 20x — Audit logging middleware.
Logs every API request (method, path, status code, user, duration).
Skips static files and health checks to avoid noise.
"""

import time
import logging

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Paths that don't need audit logging
_SKIP_PREFIXES = ("/docs", "/openapi", "/redoc", "/static", "/favicon")
_SKIP_EXTENSIONS = (".html", ".js", ".css", ".png", ".ico", ".map")


def _should_audit(path: str) -> bool:
    if any(path.startswith(p) for p in _SKIP_PREFIXES):
        return False
    if any(path.endswith(ext) for ext in _SKIP_EXTENSIONS):
        return False
    if path in ("/", "/health"):
        return False
    return True


def _extract_client_id(path: str) -> str | None:
    """Best-effort extraction of client_id from path like /api/v1/clients/{id}/..."""
    parts = path.split("/")
    try:
        idx = parts.index("clients")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    except ValueError:
        pass
    return None


def _extract_username(request: Request) -> tuple[str | None, str | None]:
    """Extract user info from Authorization header (JWT) without full validation."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        try:
            import base64, json as _json
            # Decode JWT payload (no signature check — just for logging)
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = _json.loads(base64.b64decode(payload_b64))
            return payload.get("sub"), payload.get("user_id")
        except Exception:
            pass
    return None, None


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        if not _should_audit(request.url.path):
            return await call_next(request)

        start = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = (time.monotonic() - start) * 1000

        try:
            from db.audit_log import log_event
            username, user_id = _extract_username(request)
            client_id = _extract_client_id(request.url.path)
            ip = request.client.host if request.client else None
            await log_event(
                event_type="api_request",
                user_id=user_id,
                username=username,
                client_id=client_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                ip_address=ip,
                user_agent=request.headers.get("user-agent", "")[:200],
                duration_ms=round(duration_ms, 2),
            )
        except Exception as exc:
            logger.debug("Audit log error: %s", exc)

        return response
