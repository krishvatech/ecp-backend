import base64
import hashlib
import json
import logging
from urllib.parse import parse_qs, urlparse

import requests
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core import signing
from django.utils import timezone

from .models import SaleorUserConnection

logger = logging.getLogger(__name__)

SALEOR_OIDC_PLUGIN_ID = "mirumee.authentication.openidconnect"
STATE_MAX_AGE_SECONDS = 10 * 60


class SaleorConnectionError(Exception):
    pass


def _fernet():
    raw_key = getattr(settings, "SALEOR_TOKEN_ENCRYPTION_KEY", "") or getattr(settings, "SECRET_KEY", "")
    if not raw_key:
        raise SaleorConnectionError("SALEOR_TOKEN_ENCRYPTION_KEY is not configured.")

    try:
        return Fernet(raw_key.encode("utf-8"))
    except Exception:
        digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_value(value):
    if not value:
        return ""
    return _fernet().encrypt(str(value).encode("utf-8")).decode("utf-8")


def decrypt_value(value):
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise SaleorConnectionError("Stored Saleor token could not be decrypted.") from exc


def _saleor_graphql(query, variables=None, token=None, timeout=20):
    saleor_api_url = getattr(settings, "SALEOR_API_URL", None)
    if not saleor_api_url:
        raise SaleorConnectionError("SALEOR_API_URL is not configured.")

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = requests.post(
        saleor_api_url,
        json={"query": query, "variables": variables or {}},
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    if data.get("errors"):
        raise SaleorConnectionError("Saleor GraphQL request failed.")
    return data.get("data") or {}


def _callback_url(request):
    configured = getattr(settings, "SALEOR_ECP_CALLBACK_URL", "")
    if configured:
        return configured
    return request.build_absolute_uri("/api/auth/saleor/callback/")


def _state_cache_key(state):
    digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
    return f"saleor-connection-state:{digest}"


def _remember_saleor_state(state, user):
    cache.set(
        _state_cache_key(state),
        signing.dumps({"user_id": user.pk}, salt="saleor-connection-user"),
        timeout=STATE_MAX_AGE_SECONDS,
    )


def _load_user_id_for_saleor_state(state):
    signed_user = cache.get(_state_cache_key(state))
    if not signed_user:
        raise SaleorConnectionError("Invalid or expired Saleor SSO state.")
    try:
        data = signing.loads(signed_user, salt="saleor-connection-user", max_age=STATE_MAX_AGE_SECONDS)
        return data["user_id"]
    except signing.BadSignature as exc:
        raise SaleorConnectionError("Invalid or expired Saleor SSO state.") from exc


def build_saleor_sso_url(user, request):
    mutation = """
    mutation GetExternalAuthUrl($pluginId: String!, $input: JSONString!) {
      externalAuthenticationUrl(pluginId: $pluginId, input: $input) {
        authenticationData
        errors {
          field
          message
          code
        }
      }
    }
    """
    input_payload = {
        "redirectUri": _callback_url(request),
    }
    data = _saleor_graphql(
        mutation,
        {
            "pluginId": SALEOR_OIDC_PLUGIN_ID,
            "input": json.dumps(input_payload),
        },
    )
    payload = data.get("externalAuthenticationUrl") or {}
    if payload.get("errors"):
        raise SaleorConnectionError("Saleor OIDC init failed.")

    raw_auth_data = payload.get("authenticationData")
    if not raw_auth_data:
        raise SaleorConnectionError("Saleor did not return authenticationData.")

    try:
        auth_data = json.loads(raw_auth_data)
        authorization_url = auth_data["authorizationUrl"]
    except Exception as exc:
        raise SaleorConnectionError("Invalid authenticationData returned by Saleor.") from exc

    saleor_state = parse_qs(urlparse(authorization_url).query).get("state", [""])[0]
    if not saleor_state:
        raise SaleorConnectionError("Saleor did not return an SSO state.")
    _remember_saleor_state(saleor_state, user)
    return authorization_url


def _extract_permissions(user_data):
    permissions = set()
    for permission in user_data.get("userPermissions") or []:
        code = permission.get("code") if isinstance(permission, dict) else None
        if code:
            permissions.add(code)
    for group in user_data.get("permissionGroups") or []:
        for permission in group.get("permissions") or []:
            code = permission.get("code") if isinstance(permission, dict) else None
            if code:
                permissions.add(code)
    return sorted(permissions)


def verify_saleor_user(token):
    query = """
    query SaleorConnectionMe {
      me {
        id
        email
        userPermissions {
          code
        }
        permissionGroups {
          permissions {
            code
          }
        }
      }
    }
    """
    data = _saleor_graphql(query, token=token)
    user_data = data.get("me")
    if not user_data:
        raise SaleorConnectionError("Saleor did not return the connected user.")
    return {
        "id": user_data.get("id") or "",
        "email": user_data.get("email") or "",
        "permissions": _extract_permissions(user_data),
    }


def handle_saleor_callback(request):
    error = request.GET.get("error")
    if error:
        raise SaleorConnectionError(error)

    code = request.GET.get("code")
    state = request.GET.get("state")
    if not code or not state:
        raise SaleorConnectionError("Saleor callback is missing code or state.")

    user_id = _load_user_id_for_saleor_state(state)
    user = get_user_model().objects.get(pk=user_id)

    mutation = """
    mutation ExternalObtainAccessTokens($pluginId: String!, $input: JSONString!) {
      externalObtainAccessTokens(pluginId: $pluginId, input: $input) {
        token
        refreshToken
        csrfToken
        user {
          id
          email
        }
        errors {
          field
          message
          code
        }
      }
    }
    """
    input_payload = {
        "code": code,
        "state": state,
        "redirectUri": _callback_url(request),
    }
    data = _saleor_graphql(
        mutation,
        {
            "pluginId": SALEOR_OIDC_PLUGIN_ID,
            "input": json.dumps(input_payload),
        },
    )
    payload = data.get("externalObtainAccessTokens") or {}
    if payload.get("errors"):
        raise SaleorConnectionError("Saleor token exchange failed.")

    access_token = payload.get("token")
    refresh_token = payload.get("refreshToken")
    csrf_token = payload.get("csrfToken")
    if not access_token:
        raise SaleorConnectionError("Saleor did not return an access token.")

    verified = verify_saleor_user(access_token)
    now = timezone.now()
    connection, _ = SaleorUserConnection.objects.get_or_create(user=user)
    connection.saleor_user_id = verified["id"] or (payload.get("user") or {}).get("id", "")
    connection.saleor_email = verified["email"] or (payload.get("user") or {}).get("email", "")
    connection.access_token_encrypted = encrypt_value(access_token)
    connection.refresh_token_encrypted = encrypt_value(refresh_token)
    connection.csrf_token_encrypted = encrypt_value(csrf_token)
    connection.permissions = verified["permissions"]
    connection.is_valid = True
    connection.connected_at = now
    connection.last_verified_at = now
    connection.last_error = "" if "MANAGE_STAFF" in connection.permissions else "Connected Saleor user is missing MANAGE_STAFF."
    connection.save()
    return connection


def refresh_saleor_token(connection):
    refresh_token = decrypt_value(connection.refresh_token_encrypted)
    if not refresh_token:
        connection.is_valid = False
        connection.last_error = "Missing Saleor refresh token."
        connection.save(update_fields=["is_valid", "last_error"])
        return None

    mutation = """
    mutation ExternalRefresh($pluginId: String!, $input: JSONString!) {
      externalRefresh(pluginId: $pluginId, input: $input) {
        token
        refreshToken
        csrfToken
        user {
          id
          email
        }
        errors {
          field
          message
          code
        }
      }
    }
    """
    try:
        data = _saleor_graphql(
            mutation,
            {
                "pluginId": SALEOR_OIDC_PLUGIN_ID,
                "input": json.dumps({"refreshToken": refresh_token}),
            },
        )
        payload = data.get("externalRefresh") or {}
        if payload.get("errors") or not payload.get("token"):
            raise SaleorConnectionError("Saleor token refresh failed.")

        verified = verify_saleor_user(payload["token"])
        connection.access_token_encrypted = encrypt_value(payload["token"])
        if payload.get("refreshToken"):
            connection.refresh_token_encrypted = encrypt_value(payload["refreshToken"])
        if payload.get("csrfToken"):
            connection.csrf_token_encrypted = encrypt_value(payload["csrfToken"])
        connection.saleor_user_id = verified["id"] or connection.saleor_user_id
        connection.saleor_email = verified["email"] or connection.saleor_email
        connection.permissions = verified["permissions"]
        connection.is_valid = True
        connection.last_verified_at = timezone.now()
        connection.last_error = ""
        connection.save()
        return payload["token"]
    except Exception as exc:
        connection.is_valid = False
        connection.last_error = str(exc)
        connection.save(update_fields=["is_valid", "last_error"])
        return None


def get_valid_saleor_token_for_user(user, required_permissions=None):
    required_permissions = set(required_permissions or [])
    try:
        connection = user.saleor_connection
    except SaleorUserConnection.DoesNotExist:
        return None

    if not connection.is_valid:
        return None

    try:
        token = decrypt_value(connection.access_token_encrypted)
        verified = verify_saleor_user(token)
    except Exception:
        token = refresh_saleor_token(connection)
        if not token:
            return None
        try:
            verified = verify_saleor_user(token)
        except Exception:
            return None

    connection.saleor_user_id = verified["id"] or connection.saleor_user_id
    connection.saleor_email = verified["email"] or connection.saleor_email
    connection.permissions = verified["permissions"]
    connection.last_verified_at = timezone.now()
    connection.last_error = ""
    connection.is_valid = True
    if not required_permissions.issubset(set(connection.permissions)):
        connection.last_error = "Connected Saleor user is missing required permissions."
    connection.save()
    if not required_permissions.issubset(set(connection.permissions)):
        return None
    return token


def disconnect_saleor_user(user):
    SaleorUserConnection.objects.filter(user=user).delete()
