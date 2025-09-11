"""
Custom JWT authentication middleware for Django Channels.

This middleware extracts a JWT token either from the WebSocket's
`Authorization: Bearer <token>` header or from a `token` query parameter.
It validates the token using SimpleJWT and populates `scope['user']` with
the corresponding Django user instance.  Anonymous users will see
`scope['user']` set to an `AnonymousUser` if authentication fails.
"""
import urllib.parse
from typing import Callable

from channels.auth import AuthMiddlewareStack
from channels.middleware import BaseMiddleware
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db import close_old_connections


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
            token = (params.get("token", [None])[0])

        scope["user"] = AnonymousUser()

        if token:
            try:
                # Validate token signature and expiration
                UntypedToken(token)
                authenticator = JWTAuthentication()
                validated = authenticator.get_validated_token(token)
                user = authenticator.get_user(validated)
                scope["user"] = user
            except Exception:
                # leave user as anonymous on failure
                scope["user"] = AnonymousUser()

        # Close old database connections to prevent leaks
        close_old_connections()
        return await super().__call__(scope, receive, send)


def JWTAuthMiddlewareStack(inner: Callable):
    """Entry point for the middleware stack used by Channels routing."""
    return _JWTMiddleware(AuthMiddlewareStack(inner))