# ecp_backend/common/querystring_jwt.py
from urllib.parse import parse_qs
from django.conf import settings
from django.contrib.auth import get_user_model
from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
import jwt

User = get_user_model()

@database_sync_to_async
def get_user(uid: int):
    try:
        return User.objects.get(id=uid)
    except User.DoesNotExist:
        return None

class QueryStringJWTAuthMiddleware(BaseMiddleware):
    """
    Reads ?token=<JWT> from the WS URL and sets scope['user'] if valid.
    This lets browsers authenticate WebSockets without Authorization headers.
    """
    async def __call__(self, scope, receive, send):
        try:
            qs = parse_qs(scope.get("query_string", b"").decode() or "")
            token = (qs.get("token") or [None])[0]
            if token:
                SIGNING_KEY = getattr(settings, "SIMPLE_JWT", {}).get("SIGNING_KEY", settings.SECRET_KEY)
                ALGO = getattr(settings, "SIMPLE_JWT", {}).get("ALGORITHM", "HS256")
                payload = jwt.decode(token, SIGNING_KEY, algorithms=[ALGO])
                uid = payload.get("user_id") or payload.get("sub")
                if uid:
                    user = await get_user(uid)
                    if user:
                        scope["user"] = user
        except Exception as e:
            # Keep user anonymous on any error, but don't break the handshake
            print("WS JWT error:", e)
        return await super().__call__(scope, receive, send)
