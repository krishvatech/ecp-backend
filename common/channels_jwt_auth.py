"""
Custom JWT authentication middleware for Django Channels.

This middleware extracts a JWT token either from the WebSocket's
`Authorization: Bearer <token>` header or from a `token` query parameter.
It validates the token using SimpleJWT and populates `scope['user']` with
the corresponding Django user instance.  Anonymous users will see
`scope['user']` set to an `AnonymousUser` if authentication fails.
"""
# common/channels_jwt_auth.py
import urllib.parse
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from channels.db import database_sync_to_async

from rest_framework_simplejwt.settings import api_settings as sj_settings
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.exceptions import InvalidToken


async def _get_user_by_id(user_id: int):
    User = get_user_model()
    return await database_sync_to_async(User.objects.get)(pk=user_id)


class JWTAuthMiddleware:
    """
    Extract JWT from:
      - Authorization: Bearer <token>
      - ?token=<token> / ?access_token=<token>
      - Cookie: access=<token> or Authorization=Bearer <token>
      - Sec-WebSocket-Protocol: Bearer, <token>
    Decode with SimpleJWT and set scope['user'].
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # defaults
        scope["user"] = AnonymousUser()
        scope["user_id"] = None
        scope["anon"] = True

        token = None
        headers = {k.lower(): v for k, v in scope.get("headers", [])}

        # 1) Authorization header
        auth_raw = headers.get(b"authorization")
        if auth_raw:
            try:
                scheme, value = auth_raw.decode().split(" ", 1)
                if scheme.lower() == "bearer":
                    token = value.strip()
            except Exception:
                pass

        # 2) query string
        if not token:
            raw_qs = scope.get("query_string", b"").decode()
            qs = urllib.parse.parse_qs(raw_qs)
            token = (qs.get("token", [None])[0] or
                     qs.get("access_token", [None])[0])

        # 3) cookie
        if not token:
            cookie = headers.get(b"cookie")
            if cookie:
                cookies = {}
                for kv in cookie.decode().split(";"):
                    if "=" in kv:
                        k, v = kv.strip().split("=", 1)
                        cookies[k.lower()] = v
                token = cookies.get("access") or None
                if not token and "authorization" in cookies:
                    try:
                        scheme, value = cookies["authorization"].split(" ", 1)
                        if scheme.lower() == "bearer":
                            token = value
                    except Exception:
                        pass

        # 4) subprotocol
        if not token:
            subproto = headers.get(b"sec-websocket-protocol")
            if subproto:
                parts = [p.strip() for p in subproto.decode().split(",")]
                if len(parts) >= 2 and parts[0].lower() == "bearer":
                    token = parts[1]
                elif len(parts) == 1 and parts[0]:
                    token = parts[0]

        if token:
            try:
                alg = sj_settings.ALGORITHM
                signing_key = sj_settings.SIGNING_KEY or settings.SECRET_KEY
                verifying_key = sj_settings.VERIFYING_KEY
                payload = TokenBackend(
                    algorithm=alg,
                    signing_key=signing_key,
                    verifying_key=verifying_key,
                ).decode(token, verify=True)

                uid = payload.get("user_id")
                if uid:
                    try:
                        user = await _get_user_by_id(uid)
                        scope["user"] = user
                        scope["user_id"] = uid
                        scope["anon"] = False
                    except Exception:
                        # user id in token but no matching user -> anonymous
                        scope["user"] = AnonymousUser()
                        scope["user_id"] = None
                        scope["anon"] = True
            except InvalidToken:
                # invalid/expired -> anonymous
                pass

        return await self.app(scope, receive, send)


def JWTAuthMiddlewareStack(inner):
    return JWTAuthMiddleware(inner)
