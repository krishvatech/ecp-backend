"""
Serializers for the users app.

Defines serializers for listing users, registering new users with nested
profiles, password management, forgot/reset password, and email-based login
that returns JWT refresh/access tokens.
"""
from __future__ import annotations

import re
import pytz
from django.conf import settings
from urllib.parse import urljoin
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from .models import User as UserModel, UserProfile, Experience, Education
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email as django_validate_email

from rest_framework.validators import UniqueValidator
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Education, Experience

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

class EducationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Education
        fields = (
            "id", "school", "degree", "field_of_study",
            "start_date", "end_date", "grade", "description",
            # no "user" field exposed → bound from request.user
        )

class ExperienceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Experience
        fields = (
            "id", "community_name", "position",
            "start_date", "end_date", "currently_work_here",
            "location", "description",
        )

class UserProfileMiniSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("full_name", "job_title", "headline", "company", "location")
        
class UserRosterSerializer(serializers.ModelSerializer):
    profile = UserProfileMiniSerializer(read_only=True)

    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "email", "profile")

class UserProfileSerializer(serializers.ModelSerializer):
    user_image_url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = UserProfile
        fields = [
            "full_name","timezone","bio","headline","job_title","company",
            "location","links","user_image","user_image_url","skills",
        ]

    def get_user_image_url(self, obj):
        request = self.context.get("request")

        # 1) prefer the real field you have:
        if getattr(obj, "user_image", None):
            try:
                url = obj.user_image.url
                return request.build_absolute_uri(url) if request else url
            except Exception:
                pass

        # 2) fallback to other common names (kept from your code)
        for attr in ["image", "avatar", "profile_image", "profile_pic", "photo", "picture"]:
            f = getattr(obj, attr, None)
            if f:
                try:
                    url = f.url
                    return request.build_absolute_uri(url) if request else url
                except Exception:
                    pass

        # 3) last resort: check related User
        user = getattr(obj, "user", None)
        if user:
            for attr in ["avatar", "image", "profile_image", "photo", "picture"]:
                f = getattr(user, attr, None)
                if f:
                    try:
                        url = f.url
                        return request.build_absolute_uri(url) if request else url
                    except Exception:
                        pass
        return None


    def validate_timezone(self, value: str) -> str:
        if value and value not in pytz.all_timezones:
            raise serializers.ValidationError("Invalid timezone. Use a valid IANA zone like 'Asia/Kolkata' or 'UTC'.")
        return value

    def validate_links(self, value):
        if value in (None, ""):
            return {}
        if not isinstance(value, dict):
            raise serializers.ValidationError("Links must be a JSON object.")
        return value

    def validate_skills(self, value):
        if value in (None, ""):
            return []
        if not isinstance(value, list) or not all(isinstance(s, str) for s in value):
            raise serializers.ValidationError("Skills must be a list of strings.")
        return [s.strip() for s in value if isinstance(s, str) and s.strip()]
    

class UserSerializer(serializers.ModelSerializer):
    """Serializer for the Django User model with nested profile."""
    profile = UserProfileSerializer()
    username = serializers.CharField(required=False, allow_blank=True)
    educations = EducationSerializer(many=True, read_only=True)
    experiences = ExperienceSerializer(many=True, read_only=True)


    class Meta:
        model = User
        fields = ["id", "username", "email", "profile", "first_name", "is_active","is_staff", "date_joined","educations", "experiences"]
        read_only_fields = ["id", "is_active","is_staff",  "date_joined"]

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

class UserRosterSerializer(serializers.ModelSerializer):
    profile = UserProfileMiniSerializer(read_only=True)
    avatar_url = serializers.SerializerMethodField()
    company_from_experience = serializers.SerializerMethodField()
    position_from_experience = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id", "first_name", "last_name", "email", "profile",
            "company_from_experience", "position_from_experience", "avatar_url",
        )

    def get_avatar_url(self, obj):
        prof = getattr(obj, "profile", None)

        # include your real field name
        candidates = [
            getattr(prof, "user_image", None),   # profile user_image (ImageField/FileField)
            getattr(obj,  "user_image", None),   # if ever on User
            getattr(obj,  "avatar", None),
            getattr(obj,  "avatar_url", None),
            getattr(prof, "avatar", None),
            getattr(prof, "photo", None),
            getattr(prof, "image", None),
            getattr(prof, "image_url", None),
        ]

        url = next((c for c in candidates if c), None)
        if not url:
            return ""

        # If it's a File/ImageField object, use its .url
        if hasattr(url, "url"):
            url = url.url

        # Now url is a string. Handle 3 cases cleanly.
        if not isinstance(url, str) or not url:
            return ""

        # 1) Already absolute -> return as-is (prevents "https://s3/...https://s3/..." bug)
        if url.startswith(("http://", "https://")):
            return url

        # 2) Absolute path -> build absolute with request (e.g. "/media/avatars/x.jpg")
        if url.startswith("/"):
            request = self.context.get("request")
            return request.build_absolute_uri(url) if request else url

        # 3) Bare filename/relative path -> join with MEDIA_URL (works whether MEDIA_URL is /media/ or S3 URL)
        media_url = getattr(settings, "MEDIA_URL", "/media/")
        if not media_url.endswith("/"):
            media_url += "/"
        full = urljoin(media_url, url)

        return full

    def _best_experience(self, obj):
        # use prefetched related if present; fall back to query
        qs = getattr(obj, "experiences", None)
        if hasattr(qs, "all"):
            qs = qs.all()
        else:
            qs = Experience.objects.filter(user=obj)
        return qs.order_by("-currently_work_here", "-end_date", "-start_date", "-id").first()

    def get_company_from_experience(self, obj):
        ex = self._best_experience(obj)
        return ex.community_name if ex else ""

    def get_position_from_experience(self, obj):
        ex = self._best_experience(obj)
        return ex.position if ex else ""

class ExperiencePublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Experience
        fields = ("id", "position", "community_name",
                  "start_date", "end_date", "currently_work_here")

class EducationPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Education
        fields = ("id", "school", "degree", "field_of_study",
                  "start_date", "end_date")


class UserMiniSerializer(serializers.ModelSerializer):
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name", "avatar_url")

    def _pick_image_field(self, user):
        prof = getattr(user, "profile", None)
        # your DB column comes first:
        for cand in (
            getattr(prof, "user_image", None),   # <-- your real column
            getattr(prof, "avatar", None),
            getattr(prof, "photo", None),
            getattr(prof, "image", None),
            getattr(user, "avatar", None),
        ):
            if cand:
                return cand
        return None

    def get_avatar_url(self, obj):
        url = self._pick_image_field(obj)
        if not url:
            return ""

        # If it's a File/ImageField
        if hasattr(url, "url"):
            url = url.url

        url = str(url).strip()
        # Already absolute? return as-is (prevents “double S3”)
        if url.startswith("http://") or url.startswith("https://"):
            return url

        media = (settings.MEDIA_URL or "").strip()
        # MEDIA_URL absolute (S3 style)
        if media.startswith("http://") or media.startswith("https://"):
            if url.startswith("/"):
                url = url[1:]
            return media + url

        # local dev: build full URL
        req = self.context.get("request")
        if req:
            if not url.startswith("/"):
                url = "/" + url
            return req.build_absolute_uri(url)
        return url

class PublicProfileSerializer(serializers.Serializer):
    user = UserMiniSerializer()
    profile = UserProfileMiniSerializer(allow_null=True)
    experiences = ExperiencePublicSerializer(many=True)
    educations = EducationPublicSerializer(many=True)