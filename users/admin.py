"""
Admin configuration for the users app.

This module unregisters the default `User` admin and re-registers it with
an inline profile form so that user profiles are editable via the Django
admin.  Fields displayed on the list include username, email, active
status, and join date.
"""
import logging

import boto3
from django.conf import settings
from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.utils.crypto import get_random_string
from .models import UserProfile, ProfileTraining, ProfileCertification, ProfileMembership
from .models import Education, Experience
from .task import send_speaker_credentials_task
from .email_utils import generate_temporary_password


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    fk_name = "user"


class SpeakerCreationForm(UserCreationForm):
    """
    Custom form for creating speaker accounts with auto-generated username.
    Only requires email; username is auto-generated from email.
    """
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("email", "first_name", "last_name")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Hide password fields since we'll generate them
        if "password1" in self.fields:
            self.fields["password1"].required = False
            self.fields["password1"].widget.attrs["style"] = "display:none;"
        if "password2" in self.fields:
            self.fields["password2"].required = False
            self.fields["password2"].widget.attrs["style"] = "display:none;"

    def clean_username(self):
        # Auto-generate username from email if not provided
        return self.cleaned_data.get("username") or self._generate_username()

    def _generate_username(self):
        """Generate unique username from email."""
        email = self.cleaned_data.get("email", "").lower().strip()
        if not email:
            raise ValueError("Email is required to generate username")

        base = email.split("@")[0]
        username = base
        counter = 1
        while User.objects.filter(username__iexact=username).exists():
            username = f"{base}{counter}"
            counter += 1
        return username

    def save(self, commit=True):
        user = super().save(commit=False)
        # Auto-generate username from email
        email = self.cleaned_data.get("email", "").lower().strip()
        if email and not user.username:
            base = email.split("@")[0]
            user.username = base
            counter = 1
            while User.objects.filter(username__iexact=user.username).exists():
                user.username = f"{base}{counter}"
                counter += 1

        # Set a random password (will be replaced when sending credentials)
        user.set_password(generate_temporary_password())

        if commit:
            user.save()
        return user


class UserAdmin(admin.ModelAdmin):
    inlines = [UserProfileInline]
    list_display = ("username", "email", "is_active", "is_staff", "date_joined")
    list_filter = ("is_staff", "is_active", "date_joined")
    search_fields = ("username", "email", "first_name", "last_name")
    actions = ["send_speaker_credentials"]
    add_form = SpeakerCreationForm

    def get_form(self, request, obj=None, **kwargs):
        """Use custom form for adding new users to simplify speaker creation."""
        if not obj:  # Adding new user
            return self.add_form
        return super().get_form(request, obj, **kwargs)

    @admin.action(description="Send speaker credentials to selected users")
    def send_speaker_credentials(self, request, queryset):
        """
        Admin action to send password reset links to selected users.
        Useful for pre-registered speakers who need account access.
        """
        sent_count = 0
        failed_count = 0

        for user in queryset:
            if not user.email:
                self.message_user(
                    request,
                    f"Skipped {user.username}: No email address",
                    level='warning'
                )
                failed_count += 1
                continue

            # Send email asynchronously via Celery
            try:
                send_speaker_credentials_task.delay(user.id)
                sent_count += 1
            except Exception as e:
                self.message_user(
                    request,
                    f"Failed to queue email for {user.username}: {e}",
                    level='error'
                )
                failed_count += 1

        # Success message
        if sent_count > 0:
            self.message_user(
                request,
                f"Successfully queued {sent_count} credential email(s). Users will receive password reset links shortly.",
                level='success'
            )

        if failed_count > 0:
            self.message_user(
                request,
                f"{failed_count} email(s) could not be sent. Check user email addresses.",
                level='warning'
            )

    def save_model(self, request, obj, form, change):
        old_is_staff = None
        if change and obj.pk:
            try:
                old_is_staff = User.objects.filter(pk=obj.pk).values_list("is_staff", flat=True).first()
            except Exception:
                old_is_staff = None

        if "password" in form.changed_data:
            raw = obj.password or ""
            # Only hash if it looks like plaintext (not already hashed)
            if not raw.startswith(("pbkdf2_", "argon2", "bcrypt", "scrypt")):
                obj.set_password(raw)
        super().save_model(request, obj, form, change)

        # Sync is_staff -> Cognito group membership.
        if old_is_staff is None and not obj.is_staff:
            return
        if old_is_staff is not None and old_is_staff == obj.is_staff:
            return

        region = getattr(settings, "COGNITO_REGION", "") or ""
        pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""
        group = getattr(settings, "COGNITO_STAFF_GROUP", "staff") or "staff"
        if not region or not pool_id:
            return

        try:
            client = boto3.client("cognito-idp", region_name=region)
            if obj.is_staff:
                client.admin_add_user_to_group(
                    UserPoolId=pool_id,
                    Username=obj.username,
                    GroupName=group,
                )
            else:
                client.admin_remove_user_from_group(
                    UserPoolId=pool_id,
                    Username=obj.username,
                    GroupName=group,
                )
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Cognito staff sync failed for user=%s group=%s: %s",
                obj.username,
                group,
                exc,
            )

@admin.register(Education)
class EducationAdmin(admin.ModelAdmin):
    list_display = ("user", "school", "degree", "field_of_study", "start_date", "end_date")
    list_filter = ("school", "degree")
    search_fields = ("school", "degree", "field_of_study", "user__username", "user__email")

@admin.register(Experience)
class ExperienceAdmin(admin.ModelAdmin):
    list_display = ("user", "community_name", "position", "currently_work_here", "start_date", "end_date")
    list_filter = ("community_name", "position", "currently_work_here")
    search_fields = ("community_name", "position", "user__username", "user__email")

@admin.register(ProfileTraining)
class ProfileTrainingAdmin(admin.ModelAdmin):
    list_display = ("user", "program_title", "provider", "start_date", "end_date", "currently_ongoing")
    search_fields = ("program_title", "provider", "user__username", "user__email")


@admin.register(ProfileCertification)
class ProfileCertificationAdmin(admin.ModelAdmin):
    list_display = ("user", "certification_name", "issuing_organization", "issue_date", "expiration_date", "no_expiration")
    search_fields = ("certification_name", "issuing_organization", "user__username", "user__email")


@admin.register(ProfileMembership)
class ProfileMembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "organization_name", "role_type", "start_date", "end_date", "ongoing")
    search_fields = ("organization_name", "role_type", "user__username", "user__email")


# Unregister the default User admin and register the customized one
admin.site.unregister(User)
admin.site.register(User, UserAdmin)
