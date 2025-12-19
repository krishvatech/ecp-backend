"""
Admin configuration for the users app.

This module unregisters the default `User` admin and re-registers it with
an inline profile form so that user profiles are editable via the Django
admin.  Fields displayed on the list include username, email, active
status, and join date.
"""
from django.contrib import admin
from django.contrib.auth.models import User
from .models import UserProfile, ProfileTraining, ProfileCertification, ProfileMembership
from .models import Education, Experience


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False


class UserAdmin(admin.ModelAdmin):
    inlines = [UserProfileInline]
    list_display = ("username", "email", "is_active", "date_joined")
    def save_model(self, request, obj, form, change):
        if "password" in form.changed_data:
            raw = obj.password or ""
            # Only hash if it looks like plaintext (not already hashed)
            if not raw.startswith(("pbkdf2_", "argon2", "bcrypt", "scrypt")):
                obj.set_password(raw)
        super().save_model(request, obj, form, change)

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