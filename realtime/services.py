# realtime/services.py
import os
import time
import random
from dataclasses import dataclass
from typing import Literal, Tuple

from agora_token_builder import RtcTokenBuilder
from agora_token_builder.RtcTokenBuilder import Role_Publisher, Role_Subscriber

Role = Literal["publisher", "audience"]

@dataclass
class AgoraConfig:
    app_id: str
    app_certificate: str
    token_ttl: int = 3600  # seconds

    @classmethod
    def from_env(cls) -> "AgoraConfig":
        app_id = (os.getenv("AGORA_APP_ID", "")).strip()
        app_certificate = (os.getenv("AGORA_APP_CERTIFICATE", "")).strip()
        # Support either var name
        ttl = int(os.getenv("AGORA_TOKEN_TTL") or os.getenv("AGORA_EXPIRE_SECONDS", "3600"))
        if not app_id:
            raise ValueError("AGORA_APP_ID not set")
        if not app_certificate:
            raise ValueError("AGORA_APP_CERTIFICATE not set (and certificate must be enabled in Agora Console)")
        return cls(app_id=app_id, app_certificate=app_certificate, token_ttl=ttl)


class AgoraService:
    def __init__(self, cfg: AgoraConfig):
        self.cfg = cfg

    def _channel_for_event(self, event_id: int) -> str:
        return f"event-{event_id}"

    def build_uid_token(self, *, event_id: int, role: Role, uid: int | None) -> Tuple[str, int, int, str]:
        channel = self._channel_for_event(event_id)
        final_uid = int(uid) if uid is not None else random.randint(10_000_000, 2_000_000_000)
        agora_role = Role_Publisher if role == "publisher" else Role_Subscriber

        now = int(time.time())
        expires_at = now + int(self.cfg.token_ttl)

        token = RtcTokenBuilder.buildTokenWithUid(
            self.cfg.app_id,
            self.cfg.app_certificate,
            channel,
            final_uid,
            agora_role,
            expires_at,
        )
        return token, final_uid, expires_at, channel

    def diagnostic_sample(self) -> dict:
        try:
            token, uid, exp, ch = self.build_uid_token(event_id=86, role="publisher", uid=123456789)
            return {"ok": True, "len": len(token), "uid": uid, "channel": ch, "exp": exp}
        except Exception as e:
            return {"error": str(e)}
