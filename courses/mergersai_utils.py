"""
Mergers.AI HMAC token generation for embedded video search widget.

Generates short-lived (15-min) HMAC-SHA256 signed tokens that allow
users to search course videos without exposing email in plaintext.
"""
import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Optional

from django.conf import settings

logger = logging.getLogger(__name__)


def mergersai_make_token(email: str, course_slug: Optional[str] = None) -> str:
    """
    Generate an HMAC-signed token for embedding Mergers.AI video widget.

    Token format (URL-safe base64):
        payload   = { "email": "...", "course": "...", "exp": <unix-ts> }
        token     = base64url(payload) + "." + base64url(HMAC-SHA256(secret, payload))

    Args:
        email: User's email (must match Moodle email)
        course_slug: Optional Moodle course shortname

    Returns:
        URL-safe base64 encoded token (safe for query strings)

    Raises:
        ValueError: If MERGERSAI_EMBED_SECRET is not configured
    """
    secret = settings.MERGERSAI_EMBED_SECRET
    if not secret:
        raise ValueError(
            "MERGERSAI_EMBED_SECRET not configured. "
            "Set it in .env or Django settings before using Mergers.AI widget."
        )

    payload = {
        "email": email,
        "course": course_slug,
        "exp": int(time.time()) + 900,  # 15 minutes from now
    }

    # Encode payload as URL-safe base64 (no padding)
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")

    # HMAC-SHA256 signature
    signature = hmac.new(
        secret.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    token = f"{payload_b64}.{sig_b64}"
    logger.debug(
        "Generated Mergers.AI token for user=%s course=%s exp=%s",
        email,
        course_slug,
        payload["exp"],
    )
    return token


def build_mergersai_widget_url(token: str, course_slug: Optional[str] = None) -> str:
    """
    Build the full iframe src URL for Mergers.AI widget.

    Args:
        token: HMAC token from mergersai_make_token()
        course_slug: Optional course shortname to scope search

    Returns:
        Full URL safe for <iframe src="">
    """
    base_url = getattr(
        settings,
        "MERGERSAI_WIDGET_URL",
        "https://app.mergers.ai/embed/widget",
    )

    params = [f"token={token}"]
    if course_slug:
        params.append(f"course={course_slug}")

    query_string = "&".join(params)
    url = f"{base_url}?{query_string}"

    logger.debug("Built Mergers.AI widget URL for course=%s", course_slug)
    return url
