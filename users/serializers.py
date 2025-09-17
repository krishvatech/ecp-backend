"""
Serializers for the users app.

Defines serializers for listing users, registering new users with nested
profiles, password management, forgot/reset password, and email-based login
that returns JWT refresh/access tokens.
"""
from __future__ import annotations

import re
import pytz

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email as django_validate_email
from django.core.validators import URLValidator

from rest_framework.validators import UniqueValidator
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


from .validators import (
    validate_email_smart,      # kept for direct use if needed
    validate_email_strict,     # new shared validator used below
)

from .models import UserProfile

User = get_user_model()


# ---------------------------
# Helpers
# ---------------------------
def _looks_like_email(value: str) -> bool:
    """Return True if value passes Django's simple email validator."""
    try:
        django_validate_email(value)
        return True
    except DjangoValidationError:
        return False


# ---------------------------
# Serializers
# ---------------------------
    
class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for the UserProfile model."""

    class Meta:
        model = UserProfile
        fields = [
            "full_name",
            "timezone",
            "bio",
            "job_title",
            "company",
            "location",
            "headline",
            "skills",
            "links",
        ]

    # Timezone validation (IANA / pytz name)
    def validate_timezone(self, value: str) -> str:
        if value not in pytz.all_timezones:
            raise serializers.ValidationError(
                "Invalid timezone. Please use a valid timezone like 'Asia/Kolkata' or 'UTC'."
            )
        return value
    
    def validate_full_name(self, value: str) -> str:
        v = (value or "").strip()
        if v.isdigit():
            raise serializers.ValidationError("Full name cannot be only numbers.")
        if re.search(r"\d", v):
            raise serializers.ValidationError("Full name cannot contain digits.")
        if not re.match(r"^[A-Za-z\s]+$", v):
            raise serializers.ValidationError("Full name must contain only letters and spaces.")
        return v

    def validate_links(self, value):
        if not value:
            return {}
        if not isinstance(value, dict):
            raise serializers.ValidationError("Links must be a mapping of site name to URL.")
        validator = URLValidator()
        validated_links = {}
        for key, url in value.items():
            if not isinstance(url, str) or not url:
                raise serializers.ValidationError({key: "URL must be a non-empty string."})
            try:
                validator(url)
            except DjangoValidationError:
                raise serializers.ValidationError({key: "Invalid URL."})
            validated_links[key] = url
        return validated_links


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the Django User model with nested profile."""
    profile = UserProfileSerializer()
    username = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ["id", "username", "email", "profile", "is_active", "date_joined"]
        read_only_fields = ["id", "is_active", "date_joined"]

    # username must not be numeric-only
    def validate_username(self, value: str) -> str:
        if value and value.isdigit():
            raise serializers.ValidationError("Username cannot be only numbers.")
        return value

    # reuse shared email validator (strict) – applies on update too
    def validate_email(self, value: str) -> str:
        return validate_email_strict(value, instance=self.instance)

    # support nested profile writes
    def update(self, instance, validated_data):
        profile_data = validated_data.pop("profile", None)

        # update basic user fields
        for attr, val in validated_data.items():
            setattr(instance, attr, val)
        instance.save()

        # update profile if provided
        if profile_data:
            prof = instance.profile
            for attr, val in profile_data.items():
                if hasattr(prof, attr):
                    setattr(prof, attr, val)
            prof.save()

        return instance


class RegisterSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        label="Username",
        min_length=3,
        max_length=150,
        validators=[
            UnicodeUsernameValidator(),                     # letters, digits, @/./+/-/_
            UniqueValidator(queryset=User.objects.all()),   # unique
        ],
    )
    email = serializers.EmailField(
        label="Email",
        validators=[
            UniqueValidator(queryset=User.objects.all()),
            validate_email_smart,                           # base syntax/DNS (also done in strict)
        ],
    )
    password = serializers.CharField(
        label="Password",
        write_only=True,
        style={"input_type": "password"},
    )
    password2 = serializers.CharField(
        label="Confirm password",
        write_only=True,
        style={"input_type": "password"},
    )
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = User
        fields = ["username", "email", "password", "password2", "profile"]

    # username rules: not all digits, and must NOT look like an email
    def validate_username(self, value: str) -> str:
        if value.isdigit():
            raise serializers.ValidationError("Username cannot be only numbers.")
        if _looks_like_email(value):
            raise serializers.ValidationError("Username cannot be an email address.")
        return value

    # use the same strict email validator as updates
    def validate_email(self, value: str) -> str:
        return validate_email_strict(value)

    def validate(self, attrs):
        # confirm passwords match
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        # Run Django's password validators with user context so similarity checks work
        pseudo_user = User(username=attrs.get("username"), email=attrs.get("email"))
        validate_password(attrs["password"], user=pseudo_user)

        return attrs

    def create(self, validated_data):
        profile_data = validated_data.pop("profile", {})
        validated_data.pop("password2")
        password = validated_data.pop("password")

        # email already normalized by validate_email_strict
        user = User(**validated_data)
        user.set_password(password)
        user.save()

        if profile_data:
            for k, v in profile_data.items():
                setattr(user.profile, k, v)
            user.profile.save()
        return user


class EmailTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Login using email + password and return SimpleJWT refresh/access tokens.
    POST body: {"email": "...", "password": "..."}
    """
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove the parent-added username field so the browsable form shows only Email + Password.
        self.fields.pop(self.username_field, None)  # typically 'username'

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        # Find user by email (case-insensitive)
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise AuthenticationFailed("No active account found with the given credentials")

        if not user.is_active:
            raise AuthenticationFailed("User account is disabled")

        if not user.check_password(password):
            raise AuthenticationFailed("No active account found with the given credentials")

        refresh = self.get_token(user)
        return {"refresh": str(refresh), "access": str(refresh.access_token)}


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)
    confirm_new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_new_password"]:
            raise serializers.ValidationError({"confirm_new_password": "Passwords do not match."})
        # Run Django’s password validators (length, common, numeric, etc.) with the real user
        validate_password(attrs["new_password"], self.context["request"].user)
        return attrs


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = (attrs["email"] or "").strip().lower()
        try:
            attrs["user"] = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            # Do not reveal if email exists – still behave as success
            attrs["user"] = None
        return attrs


class ResetPasswordSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)
    confirm_new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_new_password"]:
            raise serializers.ValidationError({"confirm_new_password": "Passwords do not match."})

        # Decode uid and fetch user
        try:
            uid_int = force_str(urlsafe_base64_decode(attrs["uid"]))
            user = User.objects.get(pk=uid_int)
        except Exception:
            raise serializers.ValidationError({"uid": "Invalid user id."})

        # Check token
        token_gen = PasswordResetTokenGenerator()
        if not token_gen.check_token(user, attrs["token"]):
            raise serializers.ValidationError({"token": "Invalid or expired token."})

        # Run Django password validators
        validate_password(attrs["new_password"], user)
        attrs["user"] = user
        return attrs
