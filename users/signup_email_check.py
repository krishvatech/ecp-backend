"""Public signup preflight: is this email acceptable for a NEW account?

The frontend creates accounts directly in Cognito, so this endpoint only gives
early, friendly feedback. Real enforcement is the Cognito Pre Sign-up Lambda
(deploy/cognito_pre_signup/) plus the backend guards on account creation.

The response depends only on the email's domain. It never touches the user
table, so it cannot reveal whether an account exists.
"""
from django.conf import settings
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from .disposable_email import INVALID_EMAIL_CODE, check_signup_email


class SignupEmailCheckThrottle(AnonRateThrottle):
    scope = "signup_email_check"

    def get_rate(self):
        return getattr(settings, "SIGNUP_EMAIL_CHECK_THROTTLE_RATE", "30/min")


class ValidateSignupEmailView(APIView):
    """
    POST /api/auth/validate-signup-email/  {"email": "..."}

    200 {"allowed": true,  "code": "allowed", "message": ""}
    200 {"allowed": false, "code": "disposable_email_domain", "message": "..."}
    400 {"allowed": false, "code": "invalid_email", "message": "..."}
    """

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [SignupEmailCheckThrottle]

    def post(self, request):
        email = request.data.get("email") if hasattr(request.data, "get") else None
        result = check_signup_email(email)
        response_status = (
            status.HTTP_400_BAD_REQUEST if result.code == INVALID_EMAIL_CODE else status.HTTP_200_OK
        )
        response = Response(
            {"allowed": result.allowed, "code": result.code, "message": result.message},
            status=response_status,
        )
        response["Cache-Control"] = "no-store"
        return response
