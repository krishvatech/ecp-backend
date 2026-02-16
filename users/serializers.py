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
from .models import User as UserModel, UserProfile, Experience, Education, NameChangeRequest, EducationDocument, UserSkill, EscoSkill, LanguageCertificate, IsoLanguage, UserLanguage, ProfileTraining, ProfileCertification, ProfileMembership
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email as django_validate_email

from rest_framework.validators import UniqueValidator
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from .models import Education, Experience
from .esco_client import fetch_skill_details
from .validators import (
    validate_email_smart,      # kept for direct use if needed
    validate_email_strict,     # new shared validator used below
)

from .models import UserProfile

User = get_user_model()
import logging

logger = logging.getLogger(__name__)


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
            "location", "description","sector",
            "industry",
            "number_of_employees",
            # NEW fields:
            "employment_type",
            "work_schedule",
            "relationship_to_org",
            "career_stage",
            "work_arrangement",
            "exit_reason",
        )
        # Let optional selects accept blank ("") from the UI
        extra_kwargs = {
            "employment_type": {"required": True},
            "work_schedule": {"required": False, "allow_blank": True},
            "relationship_to_org": {"required": False, "allow_blank": True},
            "career_stage": {"required": False, "allow_blank": True},
            "work_arrangement": {"required": False, "allow_blank": True},
            "exit_reason": {"required": False, "allow_blank": True},
            "sector": {"required": False, "allow_blank": True},
            "industry": {"required": False, "allow_blank": True},
            "number_of_employees": {"required": False, "allow_blank": True},
        }

class EmailChangeInitSerializer(serializers.Serializer):
    """
    Validates a request to change the primary email checks uniqueness.
    """
    new_email = serializers.EmailField()

    def validate_new_email(self, value):
        value = value.lower().strip()
        # Ensure it's not already the user's current email
        user = self.context["request"].user
        if user.email == value:
            raise serializers.ValidationError("This is already your primary email.")

        # Ensure unique across all users
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use by another account.")
        return value

class EmailChangeConfirmSerializer(serializers.Serializer):
    """
    Validates the OTP code for email change.
    """
    code = serializers.CharField(min_length=6, max_length=6)
    new_email = serializers.EmailField()

class UserProfileMiniSerializer(serializers.ModelSerializer):
    is_online = serializers.ReadOnlyField()
    
    class Meta:
        model = UserProfile
        fields = (
            "full_name",
            "job_title",
            "headline",
            "company",
            "location",
            "links",              # Added for contact information (emails, phones, etc.)
            "last_activity_at",   # read-only field
            "is_online",          # computed
            "kyc_status",         # Verification status
            "directory_hidden",   # NEW: privacy status
        )
        read_only_fields = ("last_activity_at", "is_online")

    def get_is_online(self, obj):
        # Uses the @property is_online from UserProfile
        return getattr(obj, "is_online", False)
        


class UserProfileSerializer(serializers.ModelSerializer):
    user_image_url = serializers.SerializerMethodField(read_only=True)
    is_online = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = UserProfile
        fields = [
            "full_name", "timezone", "bio", "headline", "job_title", "company",
            "location", "links", "user_image", "user_image_url", "skills",
            "last_activity_at", "is_online","kyc_decline_reason",
            "kyc_status", "legal_name_locked", "legal_name_verified_at",
            "directory_hidden",
        ]
        read_only_fields = ("last_activity_at", "is_online", "kyc_status",
                            "legal_name_locked", "legal_name_verified_at")


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
    
    def get_is_online(self, obj):
        return getattr(obj, "is_online", False)


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
        fields = ["id", "username", "email", "profile", "first_name", "last_name","is_active", "is_superuser", "is_staff", "date_joined","educations", "experiences"]
        read_only_fields = ["id", "is_active","is_superuser", "is_staff",  "date_joined","first_name", "last_name",]

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
            UnicodeUsernameValidator(),
            UniqueValidator(queryset=User.objects.all()),
        ],
    )

    first_name = serializers.CharField(
        label="First name",
        min_length=2,
        max_length=150,
    )
    last_name = serializers.CharField(
        label="Last name",
        min_length=2,
        max_length=150,
    )

    email = serializers.EmailField(
        label="Email",
        validators=[
            UniqueValidator(queryset=User.objects.all()),
            validate_email_smart,
        ],
    )

    password = serializers.CharField(
        label="Password",
        write_only=True,
        style={"input_type": "password"},
        trim_whitespace=False,
    )
    password2 = serializers.CharField(
        label="Confirm password",
        write_only=True,
        style={"input_type": "password"},
        trim_whitespace=False,
    )

    # optional nested profile payload
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "password",
            "password2",
            "first_name",
            "last_name",
            "profile",
        ]

    # username rules
    def validate_username(self, value: str) -> str:
        v = (value or "").strip()
        if v.isdigit():
            raise serializers.ValidationError("Username cannot be only numbers.")
        if _looks_like_email(v):
            raise serializers.ValidationError("Username cannot be an email address.")
        return v

    # strict email validator
    def validate_email(self, value: str) -> str:
        return validate_email_strict(value)

    def validate(self, attrs):
        # confirm passwords match
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        # Run Django's password validators with a pseudo user
        pseudo_user = User(
            username=attrs.get("username"),
            email=attrs.get("email"),
        )
        validate_password(attrs["password"], user=pseudo_user)
        return attrs

    def create(self, validated_data):
        # pull out profile + names BEFORE we construct User
        profile_data = validated_data.pop("profile", {}) or {}

        first_name = (validated_data.pop("first_name", "") or "").strip()
        last_name  = (validated_data.pop("last_name", "") or "").strip()

        # handle password fields
        validated_data.pop("password2", None)
        raw_password = validated_data.pop("password")

        # create the user
        user = User(**validated_data)
        user.first_name = first_name
        user.last_name = last_name
        user.set_password(raw_password)
        user.save()

        # create/update profile directly (do not rely on signals)
        profile_obj, _ = UserProfile.objects.get_or_create(user=user)

        # full_name priority:
        #   1) profile.full_name from payload
        #   2) "<first_name> <last_name>"
        #   3) username
        submitted_full_name = (profile_data.get("full_name") or "").strip()
        computed_full_name = f"{first_name} {last_name}".strip()

        if submitted_full_name:
            profile_obj.full_name = submitted_full_name
        elif computed_full_name:
            profile_obj.full_name = computed_full_name
        else:
            profile_obj.full_name = user.username

        # copy over any other profile fields (bio, headline, etc.)
        for key, value in profile_data.items():
            if key == "full_name":
                continue
            if hasattr(profile_obj, key):
                setattr(profile_obj, key, value)

        profile_obj.save()
        return user

class EmailTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Login using email + password and return SimpleJWT refresh/access tokens.
    POST body: {"email": "...", "password": "..."}
    """
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, trim_whitespace=False)
    timezone = serializers.CharField(required=False, allow_blank=True)

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

        # Check suspension status before issuing tokens
        BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")
        profile = getattr(user, "profile", None)
        if profile and profile.profile_status in BLOCKED_PROFILE_STATUSES:
            status_messages = {
                "suspended": "Your account has been suspended. Please contact support for assistance.",
                "deceased": "This account has been memorialized.",
                "fake": "This account has been disabled due to policy violations.",
            }
            raise AuthenticationFailed(
                status_messages.get(profile.profile_status, "Account is not accessible.")
            )

        request = self.context.get("request")
        tz_value = attrs.get("timezone") or ""
        if request is not None:
            tz_value = tz_value or request.data.get("timezone") or ""
            tz_value = tz_value or request.headers.get("X-Timezone") or ""
            tz_value = tz_value or request.headers.get("X-User-Timezone") or ""
        tz_value = (tz_value or "").strip()
        if tz_value:
            try:
                ZoneInfo(tz_value)
            except ZoneInfoNotFoundError:
                tz_value = ""
        if tz_value:
            profile, _ = UserProfile.objects.get_or_create(user=user)
            if profile.timezone != tz_value:
                profile.timezone = tz_value
                profile.save(update_fields=["timezone"])

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
    email = serializers.SerializerMethodField()  # Override to add privacy filtering
    company_from_experience = serializers.SerializerMethodField()
    position_from_experience = serializers.SerializerMethodField()
    industry_from_experience = serializers.SerializerMethodField()
    number_of_employees_from_experience = serializers.SerializerMethodField()
    

    class Meta:
        model = User
        fields = (
            "id", "first_name", "last_name", "email", "profile",
            "company_from_experience", "position_from_experience", "avatar_url","industry_from_experience","number_of_employees_from_experience","is_superuser",
        )
        read_only_fields = ("is_superuser",)

    def get_email(self, obj):
        """
        Return email only if:
        1. Requester is staff/admin, OR
        2. Viewing own profile, OR
        3. Email visibility is set to "public"
        
        Otherwise return empty string to hide the email.
        """
        request = self.context.get("request")
        if not request or not request.user:
            return ""
        
        requester = request.user
        
        # 1. Staff/Admin can see all emails
        if requester.is_staff or requester.is_superuser:
            return obj.email or ""
        
        # 2. Users can see their own email
        if requester.id == obj.id:
            return obj.email or ""
        
        # 3. Check privacy setting in profile.links.contact.main_email.visibility
        profile = getattr(obj, "profile", None)
        if not profile:
            # No profile, hide email by default
            return ""
        
        links = profile.links or {}
        contact = links.get("contact", {})
        main_email = contact.get("main_email", {})
        visibility = main_email.get("visibility", "private")  # Default to private
        
        # Show email only if visibility is "public"
        if visibility == "public":
            return obj.email or ""
        
        # Otherwise hide the email
        return ""

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
    
    def get_industry_from_experience(self, obj):
        ex = self._best_experience(obj)
        return ex.industry if ex else ""

    def get_number_of_employees_from_experience(self, obj):
        ex = self._best_experience(obj)
        return ex.number_of_employees if ex else ""

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
    kyc_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name", "avatar_url", "kyc_status")

    def get_kyc_status(self, obj):
        return getattr(obj.profile, "kyc_status", None) if hasattr(obj, "profile") else None

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

class StaffUserSerializer(serializers.ModelSerializer):
    # Allow full editing for admin provisioning
    is_staff = serializers.BooleanField(required=False)
    is_active = serializers.BooleanField(required=False)
    is_superuser = serializers.BooleanField(required=False)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    
    profile = UserProfileMiniSerializer(read_only=True)
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id", "username", "first_name", "last_name",
            "email", "is_active", "is_superuser",
            "is_staff", "date_joined", "last_login",
            "profile", "avatar_url",
        )
        read_only_fields = (
            "id", "date_joined", "last_login",
            # username is auto-generated if omitted, but can be read-only for now
            # as we'll handle it in the view if missing.
        )
        extra_kwargs = {
            "username": {"required": False, "allow_blank": True},
        }

    def validate_email(self, value):
        # Allow updating existing user, but check uniqueness for new ones?
        # unique validator on model handles it, checking here is good too.
        return value


    def get_avatar_url(self, obj):
        prof = getattr(obj, "profile", None)
        # prioritized list of where the image helps
        candidates = [
            getattr(prof, "user_image", None),
            getattr(prof, "avatar", None),
            getattr(prof, "image", None),
            getattr(obj, "avatar", None),
        ]
        url = next((c for c in candidates if c), None)
        
        if hasattr(url, "url"):
            url = url.url
            
        if not url:
            return ""
            
        url = str(url).strip()
        if url.startswith("http"):
            return url
            
        request = self.context.get("request")
        if request and not url.startswith("/"):
             return request.build_absolute_uri(url) if request else url
             
        media = (settings.MEDIA_URL or "").strip()
        if media.startswith("http"):
             if url.startswith("/"):
                 url = url[1:]
             return media + url
             
        # local dev fallback
        if request:
            if not url.startswith("/"):
                 url = "/" + url
            return request.build_absolute_uri(url)
        return url

class MonthYearField(serializers.DateField):
    """
    Accepts 'YYYY-MM' or 'YYYY-MM-DD' and stores as date (YYYY-MM-01).
    Returns 'YYYY-MM' in API responses.
    """
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("format", "%Y-%m")
        kwargs.setdefault("input_formats", ["%Y-%m", "%Y-%m-%d"])
        super().__init__(*args, **kwargs)


class ProfileTrainingSerializer(serializers.ModelSerializer):
    start_date = MonthYearField(required=False, allow_null=True)
    end_date = MonthYearField(required=False, allow_null=True)

    class Meta:
        model = ProfileTraining
        fields = (
            "id",
            "program_title",
            "provider",
            "start_date",
            "end_date",
            "currently_ongoing",
            "description",
            "credential_url",
        )

    def validate(self, attrs):
        ongoing = attrs.get("currently_ongoing")
        if ongoing is True:
            attrs["end_date"] = None
        return attrs


class ProfileCertificationSerializer(serializers.ModelSerializer):
    issue_date = MonthYearField(required=False, allow_null=True)
    expiration_date = MonthYearField(required=False, allow_null=True)

    class Meta:
        model = ProfileCertification
        fields = (
            "id",
            "certification_name",
            "issuing_organization",
            "issue_date",
            "expiration_date",
            "no_expiration",
            "credential_id",
            "credential_url",
        )

    def validate(self, attrs):
        if attrs.get("no_expiration") is True:
            attrs["expiration_date"] = None
        return attrs


class ProfileMembershipSerializer(serializers.ModelSerializer):
    start_date = MonthYearField(required=False, allow_null=True)
    end_date = MonthYearField(required=False, allow_null=True)

    class Meta:
        model = ProfileMembership
        fields = (
            "id",
            "organization_name",
            "role_type",
            "start_date",
            "end_date",
            "ongoing",
            "membership_url",
        )

    def validate(self, attrs):
        if attrs.get("ongoing") is True:
            attrs["end_date"] = None
        return attrs


class PublicProfileSerializer(serializers.Serializer):
    user = UserMiniSerializer()
    profile = UserProfileMiniSerializer(allow_null=True)
    experiences = ExperiencePublicSerializer(many=True)
    educations = EducationPublicSerializer(many=True)
    trainings = ProfileTrainingSerializer(many=True)
    certifications = ProfileCertificationSerializer(many=True)
    memberships = ProfileMembershipSerializer(many=True)
    
    
class NameChangeRequestSerializer(serializers.ModelSerializer):
    # ✅ 1. Add these lines to expose user details
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)

    class Meta:
        model = NameChangeRequest
        fields = (
            "id", "user", "username", "email",
            "first_name", "last_name",
            "old_first_name", "old_middle_name", "old_last_name",
            "new_first_name", "new_middle_name", "new_last_name",
            "reason",
            "status",
            "didit_status",     # NEW
            "created_at", "decided_at", "admin_note",
            "didit_session_id",
            "doc_full_name", "doc_first_name", "doc_last_name",
            "name_match_passed", "auto_approved", "name_match_debug",

        )
        read_only_fields = (
            "id", "user", "old_first_name", "old_middle_name", "old_last_name",
            "status", "didit_status",      # NEW
            "created_at", "decided_at", "admin_note",
            "didit_session_id",
            "doc_full_name", "doc_first_name", "doc_last_name",
            "name_match_passed", "auto_approved", "name_match_debug",
        )


class AdminKYCSerializer(serializers.ModelSerializer):
    """Serializer for admin KYC verification management."""
    # User fields
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    
    # Profile image
    user_image_url = serializers.SerializerMethodField(read_only=True)

    kyc_manual_approved_by_username = serializers.CharField(source="kyc_manual_approved_by.username", read_only=True, allow_null=True)
    kyc_manual_approved_by_full_name = serializers.CharField(source="kyc_manual_approved_by.profile.full_name", read_only=True, allow_null=True)

    class Meta:
        model = UserProfile
        fields = (
            "user_id", "username", "email", "first_name", "last_name",
            "full_name", "middle_name",
            "user_image_url",
            "kyc_status", "kyc_decline_reason",
            "kyc_last_session_id",
            "kyc_didit_last_webhook_at",
            "legal_name_locked", "legal_name_verified_at",
            "kyc_didit_raw_payload",
            # Manual KYC
            "kyc_manual_proof", "kyc_manual_reason",
            "kyc_manual_approved_by", "kyc_manual_approved_at",
            "kyc_manual_approved_by_username", "kyc_manual_approved_by_full_name",
        )
        read_only_fields = (
            "user_id", "username", "email", "first_name", "last_name",
            "full_name", "middle_name", "user_image_url",
            "kyc_last_session_id", "kyc_didit_last_webhook_at",
            "legal_name_locked", "legal_name_verified_at",
            "kyc_didit_raw_payload",
            "kyc_manual_proof", "kyc_manual_reason",
            "kyc_manual_approved_by", "kyc_manual_approved_at",
            "kyc_manual_approved_by_username", "kyc_manual_approved_by_full_name",
        )

    def get_user_image_url(self, obj):
        request = self.context.get("request")
        if getattr(obj, "user_image", None):
            try:
                url = obj.user_image.url
                return request.build_absolute_uri(url) if request else url
            except Exception:
                pass
        return None


    def validate(self, attrs):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            raise serializers.ValidationError("Authentication required.")

        # Only one pending request at a time
        if NameChangeRequest.objects.filter(
            user=user,
            status="pending", # Ensure string matches model choice
        ).exists():
            raise serializers.ValidationError(
                "You already have a pending name change request."
            )
        return attrs

    def create(self, validated_data):
        request = self.context.get("request")
        user = request.user

        validated_data["user"] = user
        validated_data["old_first_name"] = user.first_name or ""
        validated_data["old_last_name"] = user.last_name or ""

        # ✅ 6. Improved: Try to fetch the real middle name from profile if it exists
        profile = getattr(user, 'profile', None)
        # Use getattr to safely get middle_name, defaulting to empty string if it doesn't exist
        validated_data["old_middle_name"] = getattr(profile, "middle_name", "") if profile else ""

        # strip spaces
        for key in ("new_first_name", "new_middle_name", "new_last_name"):
            val = validated_data.get(key)
            if isinstance(val, str):
                validated_data[key] = val.strip()

        return super().create(validated_data)
    

class EducationDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = EducationDocument
        fields = ["id", "file", "filename", "uploaded_at"]


class EducationSerializer(serializers.ModelSerializer):
    # Add this nested field (read-only) so we can see files in the list
    documents = EducationDocumentSerializer(many=True, read_only=True)

    class Meta:
        model = Education
        fields = (
            "id", "school", "degree", "field_of_study",
            "start_date", "end_date", "grade", "description",
            "documents", # Add "documents" to fields
        )

class EscoSkillSerializer(serializers.ModelSerializer):
    class Meta:
        model = EscoSkill
        fields = [
            "uri",
            "preferred_label",
            "alt_labels",
            "description",
            "skill_type",
            "esco_version",
        ]
        read_only_fields = fields

class UserSkillSerializer(serializers.ModelSerializer):
    skill = EscoSkillSerializer(read_only=True)
    skill_uri = serializers.CharField(write_only=True)
    preferred_label = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = UserSkill
        fields = [
            "id",
            "skill",            # nested read-only ESCO data
            "skill_uri",        # for create/update
            "preferred_label",  # for initial ESCO insert
            "proficiency_level",
            "assessment_type",
            "notes",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "skill", "created_at", "updated_at"]

    def validate_proficiency_level(self, value):
        if not 1 <= value <= 5:
            raise serializers.ValidationError("proficiency_level must be between 1 and 5.")
        return value

    def create(self, validated_data):
        user = self.context["request"].user
        skill_uri = validated_data.pop("skill_uri")
        preferred_label = validated_data.pop("preferred_label", "").strip() or skill_uri

        logger.info(
            "[UserSkillSerializer.create] Incoming payload for user=%s skill_uri=%s",
            getattr(user, "id", None), skill_uri
        )

        # 1. Get or Create the EscoSkill locally
        esco_skill, created_esco = EscoSkill.objects.get_or_create(
            uri=skill_uri,
            defaults={"preferred_label": preferred_label},
        )

        # 2. FETCH DETAILS IF MISSING
        # If we just created it, OR if it exists but has no description/type, try to fetch info.
        if created_esco or not esco_skill.description:
            logger.info("[UserSkillSerializer] Fetching rich details for skill %s", skill_uri)
            details = fetch_skill_details(skill_uri)
            
            if details:
                esco_skill.description = details.get('description', '')
                esco_skill.skill_type = details.get('skill_type', '')
                
                # Ensure we strictly save a list for ArrayField
                alt_labels = details.get('alternative_labels', [])
                if isinstance(alt_labels, list):
                    esco_skill.alt_labels = alt_labels
                
                esco_skill.save()
                logger.info("[UserSkillSerializer] Updated EscoSkill details successfully.")

        # 3. Link to User
        user_skill, created_user_skill = UserSkill.objects.update_or_create(
            user=user,
            skill=esco_skill,
            defaults=validated_data,
        )

        return user_skill



class IsoLanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = IsoLanguage
        fields = ["iso_639_1", "iso_639_3", "english_name", "native_name"]
        read_only_fields = fields


class LanguageCertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = LanguageCertificate
        fields = ["id", "user_language", "file", "filename", "test_name", "score", "verified", "uploaded_at"]
        read_only_fields = ["id", "filename", "verified", "uploaded_at"]


class UserLanguageSerializer(serializers.ModelSerializer):
    language = IsoLanguageSerializer(read_only=True)

    # write-only inputs for master creation
    iso_639_1 = serializers.CharField(write_only=True)
    iso_639_3 = serializers.CharField(write_only=True, required=False, allow_blank=True)
    english_name = serializers.CharField(write_only=True, required=False, allow_blank=True)
    native_name = serializers.CharField(write_only=True, required=False, allow_blank=True)

    certificates = LanguageCertificateSerializer(many=True, read_only=True)

    class Meta:
        model = UserLanguage
        fields = [
            "id",
            "language",
            "iso_639_1",
            "iso_639_3",
            "english_name",
            "native_name",
            "primary_dialect",
            "proficiency_cefr",
            "acquisition_context",
            "assessment_type",
            "notes",
            "certificates",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "language", "certificates", "created_at", "updated_at"]

    def validate_iso_639_1(self, value):
        value = (value or "").strip()
        if len(value) != 2:
            raise serializers.ValidationError("iso_639_1 must be a 2-letter code.")
        return value.lower()

    def create(self, validated_data):
        user = self.context["request"].user

        iso_639_1 = validated_data.pop("iso_639_1")
        iso_639_3 = validated_data.pop("iso_639_3", "").strip()
        english_name = validated_data.pop("english_name", "").strip() or iso_639_1.upper()
        native_name = validated_data.pop("native_name", "").strip()

        lang, _ = IsoLanguage.objects.get_or_create(
            iso_639_1=iso_639_1,
            defaults={
                "iso_639_3": iso_639_3,
                "english_name": english_name,
                "native_name": native_name,
            },
        )

        # keep master up-to-date if new data arrives later
        dirty = False
        if iso_639_3 and not lang.iso_639_3:
            lang.iso_639_3 = iso_639_3
            dirty = True
        if english_name and (not lang.english_name or lang.english_name == iso_639_1.upper()):
            lang.english_name = english_name
            dirty = True
        if native_name and not lang.native_name:
            lang.native_name = native_name
            dirty = True
        if dirty:
            lang.save()

        primary_dialect = validated_data.get("primary_dialect", "")

        obj, _ = UserLanguage.objects.update_or_create(
            user=user,
            language=lang,
            primary_dialect=primary_dialect,
            defaults=validated_data,
        )
        return obj
    
