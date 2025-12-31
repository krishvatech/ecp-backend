import json
import time
from urllib.request import urlopen

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

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
        raise AuthenticationFailed("Cognito not configured (missing region/pool id)")

    with urlopen(url) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    _JWKS_CACHE["keys"] = data["keys"]
    _JWKS_CACHE["fetched_at"] = now
    return data["keys"]


def _get_public_key(kid: str):
    keys = _get_jwks()
    jwk = next((k for k in keys if k.get("kid") == kid), None)
    if not jwk:
        raise AuthenticationFailed("Invalid token (kid not found)")
    return RSAAlgorithm.from_jwk(json.dumps(jwk))


class CognitoJWTAuthentication(BaseAuthentication):
    """
    Accepts: Authorization: Bearer <Cognito JWT>
    Supports both id token and access token.
    Auto-creates a local Django user on first login.
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).decode("utf-8")
        if not auth or not auth.lower().startswith("bearer "):
            return None

        token = auth.split(" ", 1)[1].strip()
        if not token:
            return None

        # If token isn't Cognito, don't block SimpleJWT; just return None.
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            iss = unverified.get("iss", "")
            if iss and iss != _issuer():
                return None
        except Exception:
            return None

        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            public_key = _get_public_key(kid)

            iss = _issuer()
            if not iss:
                raise AuthenticationFailed("Cognito not configured")

            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
                issuer=iss,
            )
            request.cognito_claims = claims

            token_use = claims.get("token_use")  # "id" or "access"
            client_id = getattr(settings, "COGNITO_APP_CLIENT_ID", "") or ""

            if token_use == "id":
                if client_id and claims.get("aud") != client_id:
                    raise AuthenticationFailed("Invalid token audience")
            elif token_use == "access":
                if client_id and claims.get("client_id") != client_id:
                    raise AuthenticationFailed("Invalid token client_id")
            else:
                raise AuthenticationFailed("Invalid token_use")

           # Access token usually has "username"
            # ID token usually has "cognito:username"
            username = claims.get("cognito:username") or claims.get("username") or ""
            email = (claims.get("email") or "").lower().strip()
            first_name = claims.get("given_name") or ""
            last_name = claims.get("family_name") or ""
            # --- Global roles from Cognito groups ---
            raw_groups = claims.get("cognito:groups") or []
            if isinstance(raw_groups, str):
                raw_groups = [raw_groups]

            groups = {str(g).strip().lower() for g in raw_groups if g}

            is_platform_admin = "platform_admin" in groups
            is_staff_role = is_platform_admin or ("staff" in groups)
            # ----------------------------------------

            if not username:
                # fallback (still must be stable)
                username = email.split("@")[0] if email else ""
            if not username:
                raise AuthenticationFailed("Token missing username/email")

            user, created = User.objects.get_or_create(
                username=username,
                defaults={"email": email, "first_name": first_name, "last_name": last_name},
            )

            # keep basic fields in sync
            updated = False
            if email and user.email != email:
                user.email = email
                updated = True
            if first_name and user.first_name != first_name:
                user.first_name = first_name
                updated = True
            if last_name and user.last_name != last_name:
                user.last_name = last_name
                updated = True
            if updated:
                user.save(update_fields=["email", "first_name", "last_name"])

            return (user, token)

        except AuthenticationFailed:
            raise
        except Exception as e:
            raise AuthenticationFailed(f"Cognito auth failed: {str(e)}")
