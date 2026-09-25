from types import SimpleNamespace

from django.contrib.auth.models import AnonymousUser, Group, User
from django.test import TestCase

from users.permissions import IsPlatformAdminForOpenAPIDocs


class OpenAPIDocsPermissionTests(TestCase):
    def setUp(self):
        self.permission = IsPlatformAdminForOpenAPIDocs()

    def _request(self, user, claims=None):
        return SimpleNamespace(
            user=user,
            cognito_claims=claims or {},
        )

    def test_anonymous_user_is_denied(self):
        request = self._request(AnonymousUser())
        self.assertFalse(self.permission.has_permission(request, view=None))

    def test_normal_user_is_denied(self):
        user = User.objects.create_user(username="openapi-normal")
        request = self._request(user)
        self.assertFalse(self.permission.has_permission(request, view=None))

    def test_staff_user_without_platform_admin_role_is_denied(self):
        user = User.objects.create_user(
            username="openapi-staff",
            is_staff=True,
            is_superuser=False,
        )
        request = self._request(user)
        self.assertFalse(self.permission.has_permission(request, view=None))

    def test_django_platform_admin_group_is_allowed(self):
        user = User.objects.create_user(username="openapi-platform-admin")
        group, _ = Group.objects.get_or_create(name="platform_admin")
        user.groups.add(group)

        request = self._request(user)
        self.assertTrue(self.permission.has_permission(request, view=None))

    def test_cognito_platform_admin_claim_is_allowed(self):
        user = User.objects.create_user(username="openapi-cognito-admin")
        request = self._request(
            user,
            claims={"cognito:groups": ["platform_admin"]},
        )
        self.assertTrue(self.permission.has_permission(request, view=None))

    def test_existing_superuser_fallback_is_allowed(self):
        user = User.objects.create_user(
            username="openapi-superuser",
            is_staff=True,
            is_superuser=True,
        )
        request = self._request(user)
        self.assertTrue(self.permission.has_permission(request, view=None))
