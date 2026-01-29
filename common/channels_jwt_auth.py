"""
Custom JWT authentication middleware for Django Channels.

This middleware extracts a JWT token either from the WebSocket's
`Authorization: Bearer <token>` header or from a `token` query parameter.
It validates the token using SimpleJWT and populates `scope['user']` with
the corresponding Django user instance.  Anonymous users will see
`scope['user']` set to an `AnonymousUser` if authentication fails.
"""

import json
import time
import urllib.parse
from urllib.request import urlopen
from typing import Callable

from channels.auth import AuthMiddlewareStack
from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.db import close_old_connections

import jwt
from jwt.algorithms import RSAAlgorithm


User = get_user_model()

_JWKS_CACHE = {"keys": None, "fetched_at": 0}
_JWKS_TTL = 60 * 60  # 1 hour


def _issuer():
    region = getattr(settings, "COGNITO_REGION", None) or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", None) or ""
    if not region or not pool_id:
        return ""
    return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"


def _jwks_url():
    iss = _issuer()
    if not iss:
        return ""
    return f"{iss}/.well-known/jwks.json"


def _get_jwks():
    now = int(time.time())
    if _JWKS_CACHE["keys"] and (now - _JWKS_CACHE["fetched_at"] < _JWKS_TTL):
        return _JWKS_CACHE["keys"]

    url = _jwks_url()
    if not url:
        raise ValueError("Cognito not configured (missing region/pool id)")

    with urlopen(url) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    _JWKS_CACHE["keys"] = data["keys"]
    _JWKS_CACHE["fetched_at"] = now
    return data["keys"]


def _get_public_key(kid: str):
    keys = _get_jwks()
    jwk = next((k for k in keys if k.get("kid") == kid), None)
    if not jwk:
        raise ValueError("Invalid token (kid not found)")
    return RSAAlgorithm.from_jwk(json.dumps(jwk))


def _get_cognito_user(token):
    issuer = _issuer()
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        iss = unverified.get("iss", "")
    except Exception:
        return "not_cognito", None

    if not issuer or iss != issuer:
        return "not_cognito", None

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            return "cognito_failed", None

        public_key = _get_public_key(kid)

        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_aud": False},
            issuer=issuer,
        )

        token_use = claims.get("token_use")  # "id" or "access"
        client_id = getattr(settings, "COGNITO_APP_CLIENT_ID", "") or ""

        if token_use == "id":
            if client_id and claims.get("aud") != client_id:
                return "cognito_failed", None
        elif token_use == "access":
            if client_id and claims.get("client_id") != client_id:
                return "cognito_failed", None
        else:
            return "cognito_failed", None

        sub = (claims.get("sub") or "").strip()
        if not sub:
            return "cognito_failed", None

        from users.models import CognitoIdentity

        identity = (
            CognitoIdentity.objects.select_related("user", "user__profile")
            .filter(cognito_sub=sub)
            .first()
        )
        if identity:
            return "cognito_valid", identity.user
        return "cognito_valid", None
    except Exception:
        return "cognito_failed", None


def _is_user_suspended(user):
    """Check if user is suspended/fake/deceased."""
    if not user:
        return False
    BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")
    profile = getattr(user, "profile", None)
    return profile and profile.profile_status in BLOCKED_PROFILE_STATUSES


@database_sync_to_async
def get_user_from_token(token):
    """Validate token and return user (sync function wrapped for async use)."""
    try:
        status, cognito_user = _get_cognito_user(token)
        if status == "cognito_valid":
            # Check suspension status for Cognito users
            if _is_user_suspended(cognito_user):
                return None  # Treat suspended users as unauthenticated
            return cognito_user

        # Validate token
        UntypedToken(token)

        # Decode token to get user_id
        from rest_framework_simplejwt.backends import TokenBackend
        from rest_framework_simplejwt.settings import api_settings

        backend = TokenBackend(
            algorithm=api_settings.ALGORITHM,
            signing_key=api_settings.SIGNING_KEY
        )
        payload = backend.decode(token, verify=True)
        user_id = payload.get('user_id')

        if user_id:
            user = User.objects.select_related("profile").get(pk=user_id)
            # Check suspension status
            if _is_user_suspended(user):
                return None  # Treat suspended users as unauthenticated
            return user
    except (InvalidToken, TokenError, User.DoesNotExist, Exception):
        pass

    return None


class _JWTMiddleware(BaseMiddleware):
    """Low-level middleware to handle JWT tokens in a WebSocket scope."""

    async def __call__(self, scope, receive, send):
        # Normalize headers to dict for easier lookup
        headers = dict(scope.get("headers", []))
        token = None

        # Check Authorization header for Bearer token
        auth_header = headers.get(b"authorization", b"").decode()
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()

        # Fallback: check query string for token parameter
        if not token:
            qs = scope.get("query_string", b"").decode()
            params = urllib.parse.parse_qs(qs)
            token = params.get("token", [None])[0]

        scope["user"] = AnonymousUser()

        if token:
            user = await get_user_from_token(token)
            if user:
                scope["user"] = user

        # Close old database connections to prevent leaks
        close_old_connections()
        return await super().__call__(scope, receive, send)


def JWTAuthMiddlewareStack(inner: Callable):
    """Entry point for the middleware stack used by Channels routing."""
    return _JWTMiddleware(AuthMiddlewareStack(inner))
