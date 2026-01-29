import json
import time
import logging
from urllib.request import urlopen

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from django.db import transaction
from django.utils.crypto import get_random_string

from .models import CognitoIdentity

import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)

User = get_user_model()

_JWKS_CACHE = {"keys": None, "fetched_at": 0}
_JWKS_TTL = 60 * 60  # 1 hour

def _unique_username(base: str):
    base = (base or "user").strip().lower()
    if not base:
        base = "user"

    username = base
    while User.objects.filter(username__iexact=username).exists():
        username = f"{base}{get_random_string(4).lower()}"
    return username


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

def _truthy(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v != 0
        if isinstance(v, str):
            return v.strip().lower() in {"true", "1", "yes"}
        return False

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
            provider_username = claims.get("cognito:username") or claims.get("username") or ""
            sub = (claims.get("sub") or "").strip()

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

            if not sub:
                raise AuthenticationFailed("Token missing sub")

            # ✅ 1) Always try to resolve user via Cognito sub (stable)
            identity = CognitoIdentity.objects.select_related("user", "user__profile").filter(cognito_sub=sub).first()
            if identity:
                user = identity.user
            else:
                user = None
                email_verified = _truthy(claims.get("email_verified"))

                # ✅ 2) If verified email exists, reuse existing DB user (best merge path)
                if email and email_verified:
                    user = (
                        User.objects.filter(email__iexact=email).order_by("id").first()
                        or User.objects.filter(username__iexact=email).order_by("id").first()  # handles old callback users
                    )

                # ✅ 3) Backward compatibility: if we previously stored provider_username as DB username
                if not user and provider_username:
                    user = User.objects.filter(username__iexact=provider_username).order_by("id").first()

                # ✅ 4) If still not found, create a new DB user
                if not user:
                    base = email.split("@")[0] if email else (provider_username or "user")
                    user = User.objects.create(
                        username=_unique_username(base),
                        email=email or "",
                        first_name=first_name,
                        last_name=last_name,
                    )

                # ✅ 5) Create mapping: sub -> user (prevents future duplicates)
                try:
                    with transaction.atomic():
                        CognitoIdentity.objects.create(
                            user=user,
                            cognito_sub=sub,
                            email=email or "",
                            email_verified=email_verified,
                            provider="cognito",
                        )
                except Exception:
                    # If a concurrent request created it first, fetch it
                    identity = CognitoIdentity.objects.select_related("user").filter(cognito_sub=sub).first()
                    if identity:
                        user = identity.user

            # --- Check suspension status before allowing authentication ---
            BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")
            profile = getattr(user, "profile", None)

            logger.info(
                f"Cognito auth check for user_id={user.id}, username={user.username}, "
                f"profile_exists={profile is not None}, "
                f"profile_status={profile.profile_status if profile else 'NO_PROFILE'}"
            )

            if profile and profile.profile_status in BLOCKED_PROFILE_STATUSES:
                status = profile.profile_status
                logger.warning(
                    f"Rejecting authentication for user_id={user.id} with status={status}"
                )
                if status == "suspended":
                    raise AuthenticationFailed(
                        "Your account has been suspended. Please contact support for assistance.",
                        code="account_suspended"
                    )
                elif status == "deceased":
                    raise AuthenticationFailed(
                        "This account has been memorialized.",
                        code="account_memorialized"
                    )
                elif status == "fake":
                    raise AuthenticationFailed(
                        "This account has been disabled due to policy violations.",
                        code="account_disabled"
                    )
            # ---------------------------------------------------------------

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

            # --- ECP <-> Saleor Sync (Synchronous) ---
            from .saleor_sync import sync_user_to_saleor_sync
            try:
                sync_user_to_saleor_sync(user)
            except Exception as e:
                # Log but don't fail login if sync fails
                print(f"Sync error during login: {e}")
            # -----------------------------------------

            return (user, token)


        except AuthenticationFailed:
            raise
        except Exception as e:
            raise AuthenticationFailed(f"Cognito auth failed: {str(e)}")
