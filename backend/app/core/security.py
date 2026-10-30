"""Security utilities, rate limiting, and audit logging for SENTINEL X."""

import time
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse
from fastapi import Request, HTTPException, status
from app.config import settings
from app.firebase import get_firestore_client

logger = logging.getLogger("sentinel.security")


class InMemoryRateLimiter:
    """
    Sliding window in-memory rate limiter per IP address.
    Suitable for single-worker or prototype instances.
    Production multi-worker deployments should configure Redis or API Gateway.
    """
    def __init__(self, requests_per_minute: int = 60):
        self.rate_limit = requests_per_minute
        self.window_seconds = 60
        self.requests: Dict[str, List[float]] = {}

    def is_rate_limited(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        client_history = self.requests.get(client_ip, [])

        # Filter out timestamps older than the window
        client_history = [t for t in client_history if t > cutoff]
        self.requests[client_ip] = client_history

        if len(client_history) >= self.rate_limit:
            return True

        client_history.append(now)
        return False

    def reset(self):
        """Reset all rate limit counters (for testing)."""
        self.requests.clear()


rate_limiter = InMemoryRateLimiter(requests_per_minute=settings.RATE_LIMIT_PER_MINUTE)


def check_rate_limit(request: Request):
    """Dependency that checks if client IP has exceeded the allowed rate limit."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    if rate_limiter.is_rate_limited(client_ip):
        logger.warning("Rate limit exceeded for IP: %s", client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait before making more requests.",
            headers={"Retry-After": "60"},
        )


async def record_audit_log(
    action: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    severity: str = "Low",
    details: Optional[dict] = None,
):
    """
    Record an immutable security event into Firestore audit_logs collection.
    """
    try:
        db = get_firestore_client()
        audit_ref = db.collection("audit_logs")
        event_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        log_entry = {
            "id": event_id,
            "action": action,
            "user_id": user_id or "system",
            "ip_address": ip_address or "unknown",
            "severity": severity,
            "details": details or {},
            "timestamp": now_iso,
        }
        audit_ref.document(event_id).set(log_entry)
        logger.info("Audit log recorded: action=%s user=%s severity=%s", action, user_id, severity)
    except Exception as exc:
        logger.error("Failed to record audit log: %s", exc)


def is_safe_url(url: str) -> bool:
    """
    Ensure URL is syntactically valid and uses safe HTTP/HTTPS schemes.
    Explicitly rejects dangerous schemes (javascript:, data:, file:, etc.).
    """
    if not url or len(url) > 2048:
        return False
    lower = url.strip().lower()
    dangerous_schemes = ("javascript:", "data:", "file:", "vbscript:", "about:", "blob:")
    if any(lower.startswith(s) for s in dangerous_schemes):
        return False

    try:
        parsed = urlparse(url)
        if parsed.scheme:
            return parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)
        # If no scheme was provided, verify with http:// prefix
        parsed_with_scheme = urlparse("http://" + url)
        return parsed_with_scheme.scheme.lower() in ("http", "https") and bool(parsed_with_scheme.netloc)
    except Exception:
        return False
