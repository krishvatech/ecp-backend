"""
Secure Cognito session endpoints (Phase 1 foundation, disabled by default).

    POST /api/auth/secure-session/establish/   Cognito Bearer + refresh_token -> cookie
    POST /api/auth/secure-session/refresh/     cookie -> fresh Cognito ID token
    POST /api/auth/secure-session/logout/      cookie -> Cognito revoke + clear cookie

While SECURE_AUTH_SESSION_ENABLED is False every endpoint returns 404 before any
authentication, throttling or database work runs. No existing view, auth class
or frontend code depends on these endpoints.
"""

import logging

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.http import Http404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_variables
from rest_framework import status
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

from ecp_backend.sentry_scrubbing import protect_current_request

from . import secure_session as svc
from .cognito_auth import CognitoJWTAuthentication
from .models import CognitoSecureSession

logger = logging.getLogger(__name__)


class SecureSessionMisconfigured(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Secure session service is not available."
    default_code = "secure_session_misconfigured"


class SecureSessionThrottle(SimpleRateThrottle):
    scope = "secure_auth_session"

    def get_rate(self):
        return getattr(settings, "SECURE_AUTH_SESSION_THROTTLE_RATE", None)

    def get_cache_key(self, request, view):
        # Deliberately not DRF's get_ident(): with NUM_PROXIES unset it keys on
        # the raw, client-supplied X-Forwarded-For header.
        return self.cache_format % {"scope": self.scope, "ident": svc.throttle_identity(request)}


class _SecureSessionBaseView(APIView):
    throttle_classes = [SecureSessionThrottle]

    def initial(self, request, *args, **kwargs):
        # Runs before DRF authentication, permissions and throttling, so a
        # disabled or misconfigured feature has no side effects at all.
        if not svc.is_enabled():
            raise Http404()
        # Scrub this request's raw credentials from any Sentry event it produces.
        self.sensitive = protect_current_request()
        self.sensitive.add(request.COOKIES.get(svc.cookie_name(), ""))
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header[:7].lower() == "bearer ":
            self.sensitive.add(auth_header[7:])
        try:
            svc.validate_configuration()
        except ImproperlyConfigured as exc:
            logger.error("[SECURE_SESSION] misconfigured: %s", exc)
            raise SecureSessionMisconfigured()
        problem = svc.request_origin_problem(request)
        if problem:
            logger.warning("[SECURE_SESSION] request rejected reason=%s path=%s", problem, request.path)
            raise PermissionDenied(detail="Request not allowed.", code=problem)
        super().initial(request, *args, **kwargs)

    @staticmethod
    def _error(code, http_status, clear_cookie=False):
        response = Response({"detail": code, "code": code}, status=http_status)
        response["Cache-Control"] = "no-store"
        if clear_cookie:
            svc.clear_session_cookie(response)
        return response

    @staticmethod
    def _token_response(id_token, claims, extra=None):
        body = {
            # Same semantics as today's localStorage "access_token": the Cognito
            # ID token used as the API Bearer credential.
            "access_token": id_token,
            "token_type": "Bearer",
            "expires_in": svc.seconds_until_expiry(claims),
        }
        body.update(extra or {})
        response = Response(body, status=status.HTTP_200_OK)
        response["Cache-Control"] = "no-store"
        return response

    @staticmethod
    def _revoke_row(session):
        session.revoked_at = timezone.now()
        session.encrypted_refresh_token = ""
        session.save(update_fields=["revoked_at", "encrypted_refresh_token"])

    @staticmethod
    def _active_session_for_cookie(request):
        handle = request.COOKIES.get(svc.cookie_name(), "")
        if not handle:
            return None, False
        session = (
            CognitoSecureSession.objects.select_related("user", "user__profile")
            .filter(handle_hash=svc.hash_session_handle(handle))
            .first()
        )
        return session, True


class SecureSessionEstablishView(_SecureSessionBaseView):
    # Cognito member tokens only: guest JWTs, SimpleJWT and Django sessions
    # are not accepted because no other authentication class is listed.
    authentication_classes = [CognitoJWTAuthentication]
    permission_classes = [IsAuthenticated]

    @method_decorator(sensitive_variables())
    def post(self, request):
        claims = getattr(request, "cognito_claims", None) or {}
        bearer_sub = (claims.get("sub") or "").strip()
        if not bearer_sub or getattr(request.user, "is_guest", False):
            return self._error("cognito_member_required", status.HTTP_403_FORBIDDEN)

        refresh_token = request.data.get("refresh_token") if hasattr(request.data, "get") else None
        self.sensitive.add(refresh_token)
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            return self._error("refresh_token_required", status.HTTP_400_BAD_REQUEST)
        refresh_token = refresh_token.strip()
        if len(refresh_token) > svc.MAX_REFRESH_TOKEN_LENGTH:
            return self._error("refresh_token_invalid", status.HTTP_400_BAD_REQUEST)

        cognito_username = claims.get("cognito:username") or claims.get("username") or ""
        try:
            result = svc.cognito_refresh(refresh_token, cognito_username)
            self.sensitive.add(result.id_token)
            self.sensitive.add(result.rotated_refresh_token)
            id_claims = svc.verify_id_token(result.id_token)
        except svc.CognitoRefreshRejected:
            logger.info("[SECURE_SESSION] establish refresh rejected user_id=%s", request.user.id)
            return self._error("refresh_token_rejected", status.HTTP_401_UNAUTHORIZED)
        except svc.TokenVerificationFailed:
            logger.warning("[SECURE_SESSION] establish id token verification failed user_id=%s", request.user.id)
            return self._error("token_verification_failed", status.HTTP_401_UNAUTHORIZED)
        except svc.CognitoUnavailable as exc:
            logger.warning("[SECURE_SESSION] establish cognito unavailable user_id=%s code=%s", request.user.id, exc.code)
            return self._error("cognito_unavailable", status.HTTP_502_BAD_GATEWAY)

        refreshed_sub = id_claims["sub"].strip()
        if refreshed_sub != bearer_sub or svc.user_id_for_cognito_sub(refreshed_sub) != request.user.id:
            logger.warning("[SECURE_SESSION] establish identity mismatch user_id=%s", request.user.id)
            return self._error("identity_mismatch", status.HTTP_403_FORBIDDEN)

        stored_refresh = result.rotated_refresh_token or refresh_token
        handle = svc.new_session_handle()
        self.sensitive.add(handle)
        session = CognitoSecureSession.objects.create(
            user=request.user,
            handle_hash=svc.hash_session_handle(handle),
            encrypted_refresh_token=svc.encrypt_refresh_token(stored_refresh),
            cognito_sub=refreshed_sub,
            cognito_username=cognito_username,
            last_used_at=timezone.now(),
            expires_at=svc.session_expiry(),
        )
        logger.info("[SECURE_SESSION] established session_id=%s user_id=%s", session.pk, request.user.id)

        response = self._token_response(result.id_token, id_claims, {"session_established": True})
        svc.set_session_cookie(response, handle, session.expires_at)
        return response


class SecureSessionRefreshView(_SecureSessionBaseView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @method_decorator(sensitive_variables())
    def post(self, request):
        session, had_cookie = self._active_session_for_cookie(request)
        if not had_cookie:
            return self._error("session_missing", status.HTTP_401_UNAUTHORIZED)
        if session is None:
            return self._error("session_invalid", status.HTTP_401_UNAUTHORIZED, clear_cookie=True)
        if session.revoked_at is not None:
            return self._error("session_revoked", status.HTTP_401_UNAUTHORIZED, clear_cookie=True)
        if session.expires_at <= timezone.now():
            self._revoke_row(session)
            logger.info("[SECURE_SESSION] expired session_id=%s user_id=%s", session.pk, session.user_id)
            return self._error("session_expired", status.HTTP_401_UNAUTHORIZED, clear_cookie=True)
        if not svc.user_can_hold_session(session.user):
            self._revoke_row(session)
            logger.warning("[SECURE_SESSION] blocked user session_id=%s user_id=%s", session.pk, session.user_id)
            return self._error("account_unavailable", status.HTTP_401_UNAUTHORIZED, clear_cookie=True)

        try:
            refresh_token = svc.decrypt_refresh_token(session.encrypted_refresh_token)
            self.sensitive.add(refresh_token)
        except svc.SecureSessionError as exc:
            self._revoke_row(session)
            logger.error("[SECURE_SESSION] credential unusable session_id=%s code=%s", session.pk, exc.code)
            return self._error("session_invalid", status.HTTP_401_UNAUTHORIZED, clear_cookie=True)

        try:
            result = svc.cognito_refresh(refresh_token, session.cognito_username)
            self.sensitive.add(result.id_token)
            self.sensitive.add(result.rotated_refresh_token)
            id_claims = svc.verify_id_token(result.id_token)
        except svc.CognitoRefreshRejected:
            # Revoked/expired at Cognito (e.g. admin global sign-out).
            self._revoke_row(session)
            logger.info("[SECURE_SESSION] cognito rejected refresh session_id=%s user_id=%s", session.pk, session.user_id)
            return self._error("session_revoked", status.HTTP_401_UNAUTHORIZED, clear_cookie=True)
        except svc.TokenVerificationFailed:
            logger.warning("[SECURE_SESSION] refresh id token verification failed session_id=%s", session.pk)
            return self._error("token_verification_failed", status.HTTP_401_UNAUTHORIZED)
        except svc.CognitoUnavailable as exc:
            # Transient: keep the session so the client can retry.
            logger.warning("[SECURE_SESSION] refresh cognito unavailable session_id=%s code=%s", session.pk, exc.code)
            return self._error("cognito_unavailable", status.HTTP_502_BAD_GATEWAY)

        refreshed_sub = id_claims["sub"].strip()
        if refreshed_sub != session.cognito_sub or svc.user_id_for_cognito_sub(refreshed_sub) != session.user_id:
            self._revoke_row(session)
            logger.warning("[SECURE_SESSION] refresh identity mismatch session_id=%s user_id=%s", session.pk, session.user_id)
            return self._error("identity_mismatch", status.HTTP_401_UNAUTHORIZED, clear_cookie=True)

        with transaction.atomic():
            locked = CognitoSecureSession.objects.select_for_update().get(pk=session.pk)
            if locked.revoked_at is not None:
                # Logged out concurrently; do not hand out a token for it.
                return self._error("session_revoked", status.HTTP_401_UNAUTHORIZED, clear_cookie=True)
            update_fields = ["last_used_at"]
            locked.last_used_at = timezone.now()
            if result.rotated_refresh_token and result.rotated_refresh_token != refresh_token:
                locked.encrypted_refresh_token = svc.encrypt_refresh_token(result.rotated_refresh_token)
                update_fields.append("encrypted_refresh_token")
            locked.save(update_fields=update_fields)

        logger.info(
            "[SECURE_SESSION] refreshed session_id=%s user_id=%s rotated=%s",
            session.pk,
            session.user_id,
            "encrypted_refresh_token" in update_fields,
        )
        return self._token_response(result.id_token, id_claims)


class SecureSessionLogoutView(_SecureSessionBaseView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @method_decorator(sensitive_variables())
    def post(self, request):
        session, _ = self._active_session_for_cookie(request)
        if session is not None and session.revoked_at is None:
            revoked_at_cognito = False
            if session.encrypted_refresh_token:
                try:
                    refresh_token = svc.decrypt_refresh_token(session.encrypted_refresh_token)
                    self.sensitive.add(refresh_token)
                    revoked_at_cognito = svc.cognito_revoke(refresh_token)
                except svc.SecureSessionError:
                    revoked_at_cognito = False
            # The row is always revoked locally, even if Cognito revocation fails,
            # so this handle can never mint tokens again.
            self._revoke_row(session)
            logger.info(
                "[SECURE_SESSION] logout session_id=%s user_id=%s cognito_revoked=%s",
                session.pk,
                session.user_id,
                revoked_at_cognito,
            )

        response = Response({"logged_out": True}, status=status.HTTP_200_OK)
        response["Cache-Control"] = "no-store"
        svc.clear_session_cookie(response)
        return response
