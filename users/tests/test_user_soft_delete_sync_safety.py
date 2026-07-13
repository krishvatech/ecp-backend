from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from groups.models import Group, GroupMembership, WordPressGroupSource
from groups.wordpress_group_sync import _get_or_create_connect_user_from_wordpress_member
from users.models import UserProfile
from users.suspension import soft_delete_user_account
from users.wordpress_sync import WordPressProfileSyncService


@override_settings(COGNITO_REGION="", COGNITO_USER_POOL_ID="", SALEOR_ENABLED=False)
class UserSoftDeleteSyncSafetyTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="admin",
            email="admin@example.com",
            password="password",
        )
        self.user = User.objects.create_user(
            username="member",
            email="member@example.com",
            password="password",
        )
        self.profile = self.user.profile
        self.profile.wordpress_id = 501
        self.profile.wordpress_email = self.user.email
        self.profile.wordpress_sync_status = UserProfile.WORDPRESS_SYNC_STATUS_SYNCED
        self.profile.save()

    @patch("users.suspension.cognito_global_signout", return_value=True)
    def test_soft_delete_preserves_user_and_sync_identifiers(self, _signout):
        result = soft_delete_user_account(
            self.user.id,
            reason="Requested by admin",
            performed_by=self.admin.id,
        )

        self.assertTrue(result["success"])
        self.user.refresh_from_db()
        self.profile.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertEqual(self.profile.profile_status, UserProfile.PROFILE_STATUS_DELETED)
        self.assertEqual(self.profile.wordpress_id, 501)
        self.assertEqual(self.profile.wordpress_sync_status, UserProfile.WORDPRESS_SYNC_STATUS_SYNCED)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    @patch("users.suspension.cognito_global_signout", return_value=True)
    def test_group_sync_does_not_reactivate_soft_deleted_user(self, _signout):
        soft_delete_user_account(self.user.id, performed_by=self.admin.id)

        synced_user, created, reason = _get_or_create_connect_user_from_wordpress_member(
            {
                "id": 501,
                "email": "member@example.com",
                "name": "Member Example",
                "slug": "member",
            },
            {
                "id": 501,
                "email": "member@example.com",
                "name": "Member Example",
                "slug": "member",
            },
        )

        self.assertFalse(created)
        self.assertEqual(reason, "ok")
        synced_user.refresh_from_db()
        self.assertFalse(synced_user.is_active)
        self.assertEqual(synced_user.profile.profile_status, UserProfile.PROFILE_STATUS_DELETED)

    @patch.object(WordPressProfileSyncService, "_ensure_cognito_user_exists")
    def test_wordpress_profile_sync_updates_metadata_without_reprovisioning_login(self, ensure_cognito):
        soft_delete_user_account(self.user.id, performed_by=self.admin.id)
        service = WordPressProfileSyncService()

        synced_user, created = service.sync_user_from_wordpress(
            {
                "id": 501,
                "email": "member@example.com",
                "name": "Updated Member",
                "slug": "member",
            }
        )

        self.assertFalse(created)
        self.assertEqual(synced_user.id, self.user.id)
        synced_user.refresh_from_db()
        self.assertFalse(synced_user.is_active)
        self.assertEqual(synced_user.profile.profile_status, UserProfile.PROFILE_STATUS_DELETED)
        ensure_cognito.assert_not_called()

    @override_settings(MANDA_SYNC_DEFAULT_USER_ID=None, WP_SYNC_SERVICE_ACCOUNT_ID=None)
    @patch("users.suspension.cognito_global_signout", return_value=True)
    def test_admin_deactivate_endpoint_keeps_group_membership(self, _signout):
        group = Group.objects.create(
            name="Synced Group",
            slug="synced-group",
            source=Group.SOURCE_WORDPRESS,
            source_group_id="99",
            owner=self.admin,
            created_by=self.admin,
        )
        source = WordPressGroupSource.objects.create(
            wp_group_id=99,
            name="Synced Group",
            linked_group=group,
            sync_enabled=True,
        )
        membership = GroupMembership.objects.create(
            group=group,
            user=self.user,
            status=GroupMembership.STATUS_ACTIVE,
            source=GroupMembership.SOURCE_WORDPRESS,
            source_user_id="501",
        )

        client = APIClient()
        client.force_authenticate(self.admin)
        response = client.post(
            f"/api/auth/admin/users/{self.user.id}/deactivate/",
            {"reason": "UI test"},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(User.objects.filter(pk=self.user.id).exists())
        self.assertTrue(Group.objects.filter(pk=group.id).exists())
        self.assertTrue(WordPressGroupSource.objects.filter(pk=source.id, linked_group=group).exists())
        self.assertTrue(GroupMembership.objects.filter(pk=membership.id, user=self.user).exists())

    @override_settings(MANDA_SYNC_DEFAULT_USER_ID=None, WP_SYNC_SERVICE_ACCOUNT_ID=None)
    def test_configured_sync_service_account_cannot_be_deactivated(self):
        client = APIClient()
        client.force_authenticate(self.admin)
        with override_settings(WP_SYNC_SERVICE_ACCOUNT_ID=self.user.id):
            response = client.post(
                f"/api/auth/admin/users/{self.user.id}/deactivate/",
                {},
                format="json",
            )
        self.assertEqual(response.status_code, 409, response.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
