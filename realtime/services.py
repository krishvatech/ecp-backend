"""
CPaaS integration services.

This module defines a minimal service layer for interacting with a
cloud communications platform as a service (CPaaS).  In the first
iteration of the project we integrate with Agora, an industry‑leading
provider of audio/video streaming.  The service class encapsulates
token generation using the application credentials stored in the
environment.  If you choose a different provider later (e.g. Twilio),
you can create another service class here with the same interface.

Since external network calls are not available in this development
environment, the token generator implemented here uses a simple
base64 encoding scheme.  In a production deployment you should
replace the implementation with Agora's official `RtcTokenBuilder` or
similar.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta
from typing import Tuple

from django.conf import settings


class AgoraService:
    """Service for generating short‑lived Agora stream tokens.

    Attributes:
        app_id: The Agora application ID.
        app_certificate: The Agora application certificate (secret).
        expire_seconds: Number of seconds until the token expires.
    """

    def __init__(self, app_id: str | None = None, app_certificate: str | None = None, *, expire_seconds: int | None = None) -> None:
        # Allow overriding credentials for easier testing; fall back to
        # settings if not provided.
        self.app_id = app_id or getattr(settings, "AGORA_APP_ID", "")
        self.app_certificate = app_certificate or getattr(settings, "AGORA_APP_CERTIFICATE", "")
        # Default expiry of one hour, override from settings or argument.
        self.expire_seconds = expire_seconds or getattr(settings, "AGORA_EXPIRE_SECONDS", 3600)

    def generate_token(self, channel_name: str, user_id: int, role: str = "publisher") -> Tuple[str, datetime]:
        """Generate a pseudo‑token for a channel and user.

        In a production setup this method would use Agora's SDK to
        build a secure token.  Here we construct a base64‑encoded
        string containing the channel name, user ID, role and expiry.

        Args:
            channel_name: The unique channel/event slug used as
                Agora channel.
            user_id: The numeric ID of the Django user requesting the
                token.  Agora tokens typically include a UID; using
                the user ID ensures tokens are scoped to a single
                participant.
            role: Either ``"publisher"`` (speaker) or ``"audience"`` (listener).
                Roles may be ignored by the token builder; they are
                included for future compatibility.

        Returns:
            A tuple of the generated token string and its expiry
            timestamp.
        """
        # Calculate expiry timestamp
        expire_at = datetime.utcnow() + timedelta(seconds=int(self.expire_seconds))
        expire_ts = int(expire_at.timestamp())
        # Concatenate parts into a plain string; this is not secure and
        # should be replaced with official token builder for real use.
        payload = f"{self.app_id}:{channel_name}:{user_id}:{role}:{expire_ts}:{self.app_certificate}"
        token_bytes = base64.urlsafe_b64encode(payload.encode("utf-8"))
        token = token_bytes.decode("ascii")
        return token, expire_at
