"""
Admin configuration for the users app.

This module unregisters the default `User` admin and re-registers it with
an inline profile form so that user profiles are editable via the Django
admin.  Fields displayed on the list include username, email, active
status, and join date.
"""
from django.contrib import admin
from django.contrib.auth.models import User
from .models import UserProfile


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

# Unregister the default User admin and register the customized one
admin.site.unregister(User)
admin.site.register(User, UserAdmin)