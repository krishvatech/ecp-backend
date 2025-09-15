# services.py
from datetime import datetime, timedelta, timezone
from django.conf import settings

try:
    # Only needed when App Certificate is ENABLED
    from agora_token_builder import RtcTokenBuilder
except Exception:
    RtcTokenBuilder = None


class AgoraService:
    def __init__(self, app_id: str | None = None, app_certificate: str | None = None, *, expire_seconds: int | None = None) -> None:
        self.app_id = (app_id or getattr(settings, "AGORA_APP_ID", "")).strip()
        self.app_certificate = (app_certificate or getattr(settings, "AGORA_APP_CERTIFICATE", "")).strip()
        self.expire_seconds = int(expire_seconds or getattr(settings, "AGORA_EXPIRE_SECONDS", 3600))

    @property
    def certificate_enabled(self) -> bool:
        # If there's a certificate configured, assume enabled in console.
        return bool(self.app_certificate)

    def generate_token(self, channel_name: str, role: str = "audience", uid: int = 0):
        """
        Returns (token: str|None, expires_at: datetime).
        - If certificate is enabled -> return a real RTC token.
        - If disabled -> return None (client must join with null token).
        """
        expire_at = datetime.now(timezone.utc) + timedelta(seconds=self.expire_seconds)

        if not self.certificate_enabled:
            # Mode B: App Certificate disabled -> no token
            return None, expire_at

        if not RtcTokenBuilder:
            raise RuntimeError("agora-token-builder not installed. pip install agora-token-builder")

        agora_role = 1 if role == "publisher" else 2  # 1: publisher, 2: audience/subscriber
        expire_ts = int(expire_at.timestamp())

        token = RtcTokenBuilder.buildTokenWithUid(
            self.app_id,
            self.app_certificate,
            channel_name,
            uid or 0,
            agora_role,
            expire_ts,
        )
        return token, expire_at
