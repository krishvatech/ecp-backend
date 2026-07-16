import json
import time
import logging
import re
import boto3
from urllib.request import urlopen

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from django.db import transaction
from django.db import IntegrityError
from django.utils.crypto import get_random_string
from django.utils import timezone

from .models import CognitoIdentity

import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)

User = get_user_model()

_JWKS_CACHE = {"keys": None, "fetched_at": 0}
_JWKS_TTL = 60 * 60  # 1 hour
_FEDERATED_PASSWORD_SYNCED_SUBS = set()

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


def _provider_from_claims(claims: dict, provider_username: str) -> str:
    """
    Infer identity provider for CognitoIdentity.provider.
    - Native Cognito users -> "cognito"
    - Federated users -> normalized provider key (e.g. "google", "linkedin")
    """
    identities = claims.get("identities")
    if isinstance(identities, str):
        try:
            identities = json.loads(identities)
        except Exception:
            identities = None

    if isinstance(identities, list) and identities:
        first = identities[0] or {}
        provider_name = str(first.get("providerName") or "").strip().lower()
        if provider_name:
            return re.sub(r"[^a-z0-9_\-]", "", provider_name) or "cognito"

    # Fallback: cognito usernames for federated users often look like "Google_xxx"
    raw = str(provider_username or "")
    if "_" in raw:
        prefix = raw.split("_", 1)[0].strip().lower()
        if prefix and prefix not in {"cognito", "username"}:
            return re.sub(r"[^a-z0-9_\-]", "", prefix) or "cognito"

    return "cognito"


def _extract_email_from_provider_username(provider_username: str) -> str:
    """
    Some OIDC/SAML providers return Cognito usernames such as
    "IMAAWordPress_user@example.com" even when the email claim is missing.
    Use this only as a fallback so Cognito can still link the correct local user.
    """
    raw = str(provider_username or "").strip()
    if "_" in raw:
        raw = raw.split("_", 1)[1]
    match = re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", raw, re.I)
    return match.group(0).lower().strip() if match else ""


def _skip_local_password_provider(provider: str) -> bool:
    skipped = getattr(settings, "COGNITO_SKIP_LOCAL_PASSWORD_PROVIDERS", set()) or set()
    return str(provider or "").strip().lower() in skipped


def _random_cognito_password(length: int = 20) -> str:
    """Generate a strong random password compatible with common Cognito policies."""
    # Ensure upper/lower/digit/special are present.
    core = get_random_string(max(8, length - 4))
    return f"Aa1!{core}"


def _enable_federated_user_password(provider_username: str, provider: str = "") -> bool:
    """
    For federated Cognito users (e.g. Google_xxx), set a permanent local password.
    This enables Cognito ForgotPassword OTP delivery for that account.

    IMAA WordPress OAuth/OIDC users should keep WordPress as the password owner,
    so they can be excluded through COGNITO_SKIP_LOCAL_PASSWORD_PROVIDERS.
    """
    if _skip_local_password_provider(provider):
        logger.info("Skipping local Cognito password enablement for provider: %s", provider)
        return False

    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""
    if not region or not pool_id or not provider_username:
        return False

    try:
        client = boto3.client("cognito-idp", region_name=region)
        client.admin_set_user_password(
            UserPoolId=pool_id,
            Username=provider_username,
            Password=_random_cognito_password(),
            Permanent=True,
        )
        logger.info("Enabled local password for federated Cognito user: %s", provider_username)
        return True
    except Exception as exc:
        logger.warning(
            "Could not enable local password for federated user %s: %s",
            provider_username,
            exc,
        )
        return False

class CognitoJWTAuthentication(BaseAuthentication):
    """
    Accepts: Authorization: Bearer <Cognito JWT>
    Supports both id token and access token.
    Auto-creates a local Django user on first login.
    """

    def authenticate_header(self, request):
        return "Bearer"

    def authenticate(self, request):
        auth = get_authorization_header(request).decode("utf-8")
        if not auth or not auth.lower().startswith("bearer "):
            # logger.debug("CognitoAuth: No Bearer token found in header")
            return None

        token = auth.split(" ", 1)[1].strip()
        if not token:
            # logger.debug("CognitoAuth: Empty token")
            return None

        # If token isn't Cognito, don't block SimpleJWT; just return None.
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            iss = unverified.get("iss", "")
            
            expected_iss = _issuer()
            if iss and iss != expected_iss:
                logger.error(f"CognitoAuth: Issuer mismatch. Got '{iss}', expected '{expected_iss}'")
                return None

        except Exception as e:
            # logger.error(f"CognitoAuth: Failed to decode token headers (unverified step): {e}")
            return None

        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")

            # If no 'kid' in header, this is not a Cognito token (e.g., WordPress sync tokens)
            # Let other authenticators handle it
            if not kid:
                logger.debug("CognitoAuth: No 'kid' in token header, not a Cognito token")
                return None

            public_key = _get_public_key(kid)

            iss = _issuer()
            if not iss:
                raise AuthenticationFailed("Cognito not configured")

            # Validate the token
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
                issuer=iss,
                leeway=60,  # Fix for "The token is not yet valid (iat)" due to clock skew
            )
            request.cognito_claims = claims

            token_use = claims.get("token_use")  # "id" or "access"
            client_id = getattr(settings, "COGNITO_APP_CLIENT_ID", "") or ""

            if token_use == "id":
                if client_id and claims.get("aud") != client_id:
                    # logger.error(f"CognitoAuth: Invalid aud. Got {claims.get('aud')}, expected {client_id}")
                    raise AuthenticationFailed("Invalid token audience")
            elif token_use == "access":
                if client_id and claims.get("client_id") != client_id:
                    # logger.error(f"CognitoAuth: Invalid client_id. Got {claims.get('client_id')}, expected {client_id}")
                    raise AuthenticationFailed("Invalid token client_id")
            else:
                raise AuthenticationFailed("Invalid token_use")

            # Access token usually has "username"
            # ID token usually has "cognito:username"
            provider_username = claims.get("cognito:username") or claims.get("username") or ""
            provider = _provider_from_claims(claims, provider_username)
            sub = (claims.get("sub") or "").strip()

            email = (claims.get("email") or "").lower().strip()
            if not email and provider != "cognito":
                email = _extract_email_from_provider_username(provider_username)
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
                if identity.provider != "cognito" and sub not in _FEDERATED_PASSWORD_SYNCED_SUBS:
                    if _enable_federated_user_password(provider_username, provider):
                        _FEDERATED_PASSWORD_SYNCED_SUBS.add(sub)
            else:
                user = None
                email_verified = _truthy(claims.get("email_verified"))

                # ✅ 2) If verified email exists, reuse existing DB user ATOMICALLY
                if email and email_verified:
                    user, created = User.objects.get_or_create(
                        email__iexact=email,
                        defaults={
                            "username": _unique_username(email.split("@")[0]),
                            "email": email,
                            "first_name": first_name,
                            "last_name": last_name,
                        }
                    )
                    if created:
                        if provider != "cognito":
                            user.set_unusable_password()
                            user.save(update_fields=["password"])
                        logger.info(f"Created new user for verified email {email}")

                # ✅ 3) Backward compatibility: if we previously stored provider_username as DB username
                if not user and provider_username:
                    user = User.objects.filter(username__iexact=provider_username).order_by("id").first()

                # ✅ 4) If still not found, create a new DB user (atomic)
                if not user:
                    base = email.split("@")[0] if email else (provider_username or "user")
                    username = _unique_username(base)

                    try:
                        with transaction.atomic():
                            # Double-check inside transaction to prevent race condition
                            user = User.objects.filter(email__iexact=email).first() if email else None

                            if not user:
                                user = User(
                                    username=username,
                                    email=email or "",
                                    first_name=first_name,
                                    last_name=last_name,
                                )
                                if provider != "cognito":
                                    user.set_unusable_password()
                                user.save()
                                logger.info(f"Created new user {user.id} with email {email}")
                    except Exception as e:
                        logger.warning(f"Error creating user for {email}: {e}")
                        # Final fallback: try to get existing user
                        user = User.objects.filter(email__iexact=email).first() if email else None
                        if not user:
                            raise AuthenticationFailed(f"Failed to create user: {str(e)}")

                # ✅ 5) Create mapping: sub -> user (prevents future duplicates)
                if not identity:
                    try:
                        with transaction.atomic():
                            # Use get_or_create to handle race condition
                            identity, created = CognitoIdentity.objects.get_or_create(
                                cognito_sub=sub,
                                defaults={
                                    "user": user,
                                    "email": email or "",
                                    "email_verified": email_verified,
                                    "provider": provider,
                                }
                            )

                            if created:
                                logger.info(f"Created CognitoIdentity {sub} -> user {user.id}")
                                if provider != "cognito":
                                    if _enable_federated_user_password(provider_username, provider):
                                        _FEDERATED_PASSWORD_SYNCED_SUBS.add(sub)
                            else:
                                if identity.user_id != user.id:
                                    logger.warning(
                                        f"CognitoIdentity {sub} linked to different user "
                                        f"(expected {user.id}, got {identity.user_id})"
                                    )
                                    user = identity.user

                    except IntegrityError as e:
                        # Common recovery path:
                        # same verified (email, provider) already exists with an older/different sub.
                        recovered = None
                        if email and email_verified:
                            recovered = (
                                CognitoIdentity.objects
                                .select_related("user")
                                .filter(email__iexact=email, provider=provider, email_verified=True)
                                .order_by("id")
                                .first()
                            )

                        if recovered:
                            old_sub = recovered.cognito_sub
                            recovered.cognito_sub = sub
                            recovered.user = user
                            recovered.email = email or recovered.email
                            recovered.email_verified = email_verified
                            recovered.provider = provider or recovered.provider
                            recovered.save(update_fields=[
                                "cognito_sub",
                                "user",
                                "email",
                                "email_verified",
                                "provider",
                                "updated_at",
                            ])
                            identity = recovered
                            user = recovered.user
                            logger.info(
                                "Re-linked CognitoIdentity by email/provider (%s, %s): %s -> %s",
                                email,
                                provider,
                                old_sub,
                                sub,
                            )
                        else:
                            logger.error(f"Error creating CognitoIdentity for {sub}: {e}")
                    except Exception as e:
                        logger.error(f"Error creating CognitoIdentity for {sub}: {e}")

            # --- Check suspension status before allowing authentication ---
            BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased", "deleted")
            profile = getattr(user, "profile", None)

            # logger.info(
            #     f"Cognito auth check for user_id={user.id}, username={user.username}, "
            #     f"profile_exists={profile is not None}, "
            #     f"profile_status={profile.profile_status if profile else 'NO_PROFILE'}"
            # )

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
                elif status == "deleted":
                    raise AuthenticationFailed(
                        "This account has been deactivated by an administrator. Please contact support.",
                        code="account_deleted"
                    )

            if not user.is_active:
                raise AuthenticationFailed(
                    "This account has been deactivated by an administrator. Please contact support.",
                    code="account_inactive",
                )
            # ---------------------------------------------------------------

            # keep basic fields in sync
            updated = False
            # Never downgrade a real email to WordPress placeholder from Cognito claims.
            if email and user.email != email:
                current_is_placeholder = (user.email or "").lower().endswith("@wordpress.local")
                incoming_is_placeholder = email.endswith("@wordpress.local")
                if not incoming_is_placeholder or current_is_placeholder:
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

            # Keep profile full_name in sync with user's first_name + last_name
            profile = getattr(user, "profile", None)
            if profile:
                full_name = f"{user.first_name} {user.last_name}".strip()
                if full_name and profile.full_name != full_name:
                    profile.full_name = full_name
                    if profile.pk:
                        profile.save(update_fields=["full_name"])
                    else:
                        profile.save()

            # --- Update last_login on successful authentication ---
            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])
            # ---------------------------------------------------

            # --- ECP <-> Saleor Sync (Async Background Task) ---
            from .tasks import sync_user_to_saleor_async
            try:
                sync_user_to_saleor_async.delay(user.id)
            except Exception as e:
                logger.warning(f"Failed to queue Saleor sync task: {e}")
            # -------------------------------------------------------

            return (user, token)


        except AuthenticationFailed:
            raise
        except Exception as e:
            # logger.error(f"Cognito auth failed: {e}")
            raise AuthenticationFailed(f"Cognito auth failed: {str(e)}")


def create_cognito_user_from_guest(
    guest,
    password: str,
    first_name: str = "",
    last_name: str = "",
    email: str = "",
):
    """
    Convert a GuestAttendee into a regular Django user account.

    Note: this helper creates a local user account used by existing auth flows.
    """
    first_name = (first_name or getattr(guest, "first_name", "") or "").strip()
    last_name = (last_name or getattr(guest, "last_name", "") or "").strip()
    email = (email or getattr(guest, "email", "") or "").strip().lower()

    if not email:
        raise ValueError("Email is required.")

    existing = User.objects.filter(email__iexact=email).first()
    if existing:
        raise ValueError("An account with this email already exists. Please sign in.")

    base_username = email.split("@")[0] if "@" in email else f"guest{getattr(guest, 'id', '')}"
    username = _unique_username(base_username)

    with transaction.atomic():
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )
        user.set_password(password)
        user.save()

        from .models import UserProfile

        profile, _ = UserProfile.objects.get_or_create(user=user)
        full_name = f"{first_name} {last_name}".strip() or username
        update_fields = []
        if profile.full_name != full_name:
            profile.full_name = full_name
            update_fields.append("full_name")
        if getattr(guest, "job_title", "") and not profile.job_title:
            profile.job_title = guest.job_title
            update_fields.append("job_title")
        if getattr(guest, "company", "") and not profile.company:
            profile.company = guest.company
            update_fields.append("company")
        if update_fields:
            profile.save(update_fields=update_fields)

    return user