from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import Group, User
from django.test import TestCase
from rest_framework.test import APIClient


class OpenAPIDocsSessionTests(TestCase):
    endpoint = "/api/auth/openapi/session/"

    def _post_as(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        response = client.post(self.endpoint, {}, format="json")
        return client, response

    def test_anonymous_user_cannot_create_docs_session(self):
        response = APIClient().post(self.endpoint, {}, format="json")
        self.assertIn(response.status_code, {401, 403})

    def test_normal_user_is_forbidden(self):
        user = User.objects.create_user(username="openapi-session-normal")
        client, response = self._post_as(user)

        self.assertEqual(response.status_code, 403)
        self.assertNotIn(SESSION_KEY, client.session)

    def test_staff_only_user_is_forbidden(self):
        user = User.objects.create_user(
            username="openapi-session-staff",
            is_staff=True,
            is_superuser=False,
        )
        client, response = self._post_as(user)

        self.assertEqual(response.status_code, 403)
        self.assertNotIn(SESSION_KEY, client.session)

    def test_platform_admin_group_can_create_docs_session_without_staff_mutation(self):
        user = User.objects.create_user(
            username="openapi-session-platform-admin",
            is_staff=False,
            is_superuser=False,
        )
        group, _ = Group.objects.get_or_create(name="platform_admin")
        user.groups.add(group)

        client, response = self._post_as(user)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"detail": "openapi_session_created"})
        self.assertEqual(client.session.get(SESSION_KEY), str(user.pk))

        user.refresh_from_db()
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_existing_superuser_fallback_can_create_docs_session(self):
        user = User.objects.create_user(
            username="openapi-session-superuser",
            is_staff=True,
            is_superuser=True,
        )
        client, response = self._post_as(user)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.session.get(SESSION_KEY), str(user.pk))
