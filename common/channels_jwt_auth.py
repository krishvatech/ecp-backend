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
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.db import close_old_connections


User = get_user_model()


@database_sync_to_async
def get_user_from_token(token):
    """Validate token and return user (sync function wrapped for async use)."""
    try:
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
            return User.objects.get(pk=user_id)
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