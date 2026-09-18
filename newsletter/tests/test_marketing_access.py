"""Marketing Access: eligibility, provisioning, lifecycle and enforcement.

The contract under test:

* only an **active ECP superuser** may hold Marketing access (staff may not)
* using the Marketing Hub additionally needs an **active** Mautic mapping
* managing other people's access needs superuser only, so an unmapped superuser
  can still grant access
* a superuser may not change their own access
* provisioning creates the Mautic human on the **service account**, never with
  the target's own assertion (that identity does not exist yet)

The flag is pinned explicitly in every class, so these never depend on the
developer's live ``ECP_MAUTIC_PER_USER_EXECUTION_ENABLED`` setting.
"""

import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status as http_status
from rest_framework.test import APIClient

from newsletter.marketing_access_services import (
    MarketingState,
    candidate_usernames,
    grant_marketing_access,
    has_marketing_hub_access,
    is_marketing_eligible,
)
from newsletter.models import MauticIdentityAuditLog, MauticUserConnection
from newsletter.tests.test_mautic_per_user_execution import PER_USER_OFF, PER_USER_ON

User = get_user_model()

LIST_URL = reverse("newsletter-admin-marketing-access-list")
ME_URL = reverse("newsletter-marketing-access-me")
COMPANY_LIST_URL = reverse("newsletter-admin-company-list")
CONNECTION_LIST_URL = reverse("newsletter-admin-mautic-connection-list")


def add_url(user_id):
    return reverse("newsletter-admin-marketing-access-add", args=[user_id])


def remove_url(user_id):
    return reverse("newsletter-admin-marketing-access-remove", args=[user_id])


def _provider_user(user_id=41, username="ecp-target-2", email="target@example.test"):
    return {
        "id": user_id,
        "username": username,
        "email": email,
        "firstName": "Target",
        "lastName": "Superuser",
        "isPublished": True,
        "role": {"id": 1, "name": "Administrator"},
    }


class _MarketingFixtures:
    """Distinct ECP roles, so no test can silently rely on the wrong one."""

    def setUp(self):
        self.manager = User.objects.create_user(
            username="marketing-manager",
            email="marketing-manager@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        self.target = User.objects.create_user(
            username="marketing-target",
            email="marketing-target@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        self.staff = User.objects.create_user(
            username="marketing-staff",
            email="marketing-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal = User.objects.create_user(
            username="marketing-normal",
            email="marketing-normal@example.test",
            password="test-password",
        )
        self.client = APIClient()

    def as_(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def _connection(self, user, mautic_user_id=41, is_active=True, **kwargs):
        return MauticUserConnection.objects.create(
            user=user,
            mautic_user_id=mautic_user_id,
            mautic_username=kwargs.pop("mautic_username", "ecp-target-2"),
            mautic_role_name=kwargs.pop("mautic_role_name", "Administrator"),
            status=(
                MauticUserConnection.Status.ACTIVE
                if is_active
                else MauticUserConnection.Status.DISABLED
            ),
            is_active=is_active,
            **kwargs,
        )

    def _provisioning_client(self, created_id=41, existing_by_email=None):
        """A service-account client whose provider calls are all recorded."""
        client = Mock(name="MauticClient")
        client.find_users_by_email.return_value = existing_by_email or []
        client.get_role_by_name.return_value = {"id": 1, "name": "Administrator"}
        client.find_user_by_username.return_value = None
        client.create_user.return_value = _provider_user(user_id=created_id)
        return client


@override_settings(**PER_USER_OFF)
class MarketingAccessManagementAuthorizationTests(_MarketingFixtures, TestCase):
    def test_superuser_can_list_marketing_access(self):
        response = self.as_(self.manager).get(LIST_URL)

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertIn("results", response.data)

    def test_staff_cannot_manage_marketing_access(self):
        self.assertEqual(
            self.as_(self.staff).get(LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )
        self.assertEqual(
            self.as_(self.staff).post(add_url(self.target.pk)).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )

    def test_normal_user_cannot_manage_marketing_access(self):
        self.assertEqual(
            self.as_(self.normal).get(LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )

    def test_unauthenticated_request_is_denied(self):
        self.assertIn(
            APIClient().get(LIST_URL).status_code,
            (http_status.HTTP_401_UNAUTHORIZED, http_status.HTTP_403_FORBIDDEN),
        )

    def test_unmapped_superuser_can_still_manage_marketing_access(self):
        # The bootstrap case: nobody could ever be granted access otherwise.
        self.assertFalse(has_marketing_hub_access(self.manager))

        response = self.as_(self.manager).get(LIST_URL)

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    def test_mapped_superuser_can_manage_marketing_access(self):
        self._connection(self.manager, mautic_user_id=7)

        response = self.as_(self.manager).get(LIST_URL)

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    def test_inactive_superuser_manager_is_denied(self):
        self.manager.is_active = False
        self.manager.save(update_fields=["is_active"])

        self.assertIn(
            self.as_(self.manager).get(LIST_URL).status_code,
            (http_status.HTTP_401_UNAUTHORIZED, http_status.HTTP_403_FORBIDDEN),
        )


@override_settings(**PER_USER_OFF)
class MarketingAccessTargetEligibilityTests(_MarketingFixtures, TestCase):
    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_active_superuser_target_is_accepted(self, provisioning_cls, verify_cls):
        provisioning_cls.return_value = self._provisioning_client()
        verify_cls.return_value.get_user.return_value = _provider_user()

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertEqual(response.data["marketing_state"], MarketingState.ACTIVE)

    def test_staff_target_is_rejected(self):
        response = self.as_(self.manager).post(add_url(self.staff.pk))

        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], "target_not_marketing_eligible")
        self.assertFalse(MauticUserConnection.objects.filter(user=self.staff).exists())

    def test_normal_user_target_is_rejected(self):
        response = self.as_(self.manager).post(add_url(self.normal.pk))

        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], "target_not_marketing_eligible")

    def test_inactive_superuser_target_is_rejected(self):
        self.target.is_active = False
        self.target.save(update_fields=["is_active"])

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], "target_not_marketing_eligible")

    def test_unknown_target_is_not_found(self):
        response = self.as_(self.manager).post(add_url(999999))

        self.assertEqual(response.status_code, http_status.HTTP_404_NOT_FOUND)

    def test_self_add_is_rejected(self):
        response = self.as_(self.manager).post(add_url(self.manager.pk))

        self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["code"], "marketing_self_management_not_allowed")
        self.assertFalse(MauticUserConnection.objects.filter(user=self.manager).exists())

    def test_self_remove_is_rejected(self):
        self._connection(self.manager, mautic_user_id=7)

        response = self.as_(self.manager).post(remove_url(self.manager.pk))

        self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["code"], "marketing_self_management_not_allowed")
        self.assertTrue(
            MauticUserConnection.objects.get(user=self.manager).is_active,
            "a refused self-removal must not change the mapping",
        )

    def test_self_reactivate_is_rejected(self):
        self._connection(self.manager, mautic_user_id=7, is_active=False)

        response = self.as_(self.manager).post(add_url(self.manager.pk))

        self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["code"], "marketing_self_management_not_allowed")
        self.assertFalse(MauticUserConnection.objects.get(user=self.manager).is_active)


@override_settings(**PER_USER_OFF)
class MarketingAccessProvisioningTests(_MarketingFixtures, TestCase):
    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_add_provisions_mautic_user_and_activates_mapping(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client(created_id=55)
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user(user_id=55)

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        provider.create_user.assert_called_once()
        self.assertEqual(response.data["outcome"], "provisioned")
        self.assertEqual(response.data["mautic_user_id"], 55)
        self.assertTrue(response.data["has_marketing_access"])

        connection = MauticUserConnection.objects.get(user=self.target)
        self.assertEqual(connection.mautic_user_id, 55)
        self.assertTrue(connection.is_active)
        self.assertEqual(connection.status, MauticUserConnection.Status.ACTIVE)

    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_provisioning_uses_service_account_not_the_target_assertion(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client()
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user()

        with patch(
            "newsletter.mautic.identity_assertion.issue_identity_assertion"
        ) as signer:
            response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        # The identity being created cannot assert itself, so no assertion is
        # minted for anybody during provisioning.
        signer.assert_not_called()
        # Plain construction = service-account client, no assertion provider.
        provisioning_cls.assert_called_with()

    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_generated_username_uses_stable_ecp_id_scheme(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client()
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user()

        self.as_(self.manager).post(add_url(self.target.pk))

        username = provider.create_user.call_args.kwargs["username"]
        self.assertEqual(username, f"ecp-marketing-target-{self.target.pk}")
        self.assertIn(str(self.target.pk), username)
        self.assertNotIn("@", username)

    def test_username_candidates_are_deterministic_and_collision_safe(self):
        first = list(candidate_usernames(self.target))[:3]

        self.assertEqual(first[0], f"ecp-marketing-target-{self.target.pk}")
        self.assertEqual(first[1], f"ecp-marketing-target-{self.target.pk}-2")
        self.assertEqual(first, list(candidate_usernames(self.target))[:3])

    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_username_collision_falls_back_deterministically(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client()
        taken = f"ecp-marketing-target-{self.target.pk}"
        provider.find_user_by_username.side_effect = (
            lambda name: {"id": 9, "username": name} if name == taken else None
        )
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user()

        self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(
            provider.create_user.call_args.kwargs["username"], f"{taken}-2"
        )

    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_generated_password_never_leaves_the_provider_call(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client()
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user()

        with self.assertLogs("newsletter", level="DEBUG") as logs:
            response = self.as_(self.manager).post(add_url(self.target.pk))

        password = provider.create_user.call_args.kwargs["password"]
        self.assertTrue(password)

        body = json.dumps(response.data, default=str)
        self.assertNotIn(password, body)
        self.assertNotIn("password", body.lower())

        self.assertNotIn(password, "\n".join(logs.output))

        connection = MauticUserConnection.objects.get(user=self.target)
        row = json.dumps(
            {
                field.name: str(getattr(connection, field.name))
                for field in MauticUserConnection._meta.fields
            }
        )
        self.assertNotIn(password, row)

        audit = json.dumps(list(MauticIdentityAuditLog.objects.values()), default=str)
        self.assertNotIn(password, audit)

    @override_settings(
        ECP_MAUTIC_MARKETING_ROLE_NAME="ECP Marketing Manager",
        ECP_MAUTIC_MARKETING_ROLE_ID="",
    )
    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_configured_role_is_resolved_by_name_not_hard_coded(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client()
        provider.get_role_by_name.return_value = {"id": 9, "name": "ECP Marketing Manager"}
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user()

        self.as_(self.manager).post(add_url(self.target.pk))

        provider.get_role_by_name.assert_called_once_with("ECP Marketing Manager")
        self.assertEqual(provider.create_user.call_args.kwargs["role_id"], 9)

    @override_settings(ECP_MAUTIC_MARKETING_ROLE_NAME="Nonexistent Role")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_unresolvable_role_fails_closed_without_creating_a_user(
        self, provisioning_cls
    ):
        provider = self._provisioning_client()
        provider.get_role_by_name.return_value = None
        provisioning_cls.return_value = provider

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_502_BAD_GATEWAY)
        self.assertEqual(response.data["code"], "marketing_provisioning_failed")
        provider.create_user.assert_not_called()
        self.assertFalse(MauticUserConnection.objects.filter(user=self.target).exists())


@override_settings(**PER_USER_OFF)
class MarketingAccessExistingMappingTests(_MarketingFixtures, TestCase):
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_add_when_already_active_is_rejected_without_provisioning(
        self, provisioning_cls
    ):
        provider = self._provisioning_client()
        provisioning_cls.return_value = provider
        self._connection(self.target, mautic_user_id=41)

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_409_CONFLICT)
        self.assertEqual(response.data["code"], "marketing_access_already_active")
        provider.create_user.assert_not_called()
        self.assertEqual(MauticUserConnection.objects.filter(user=self.target).count(), 1)

    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_inactive_mapping_reactivates_the_same_provider_identity(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client()
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user(user_id=41)
        existing = self._connection(self.target, mautic_user_id=41, is_active=False)

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertEqual(response.data["outcome"], "reactivated")
        self.assertEqual(response.data["mautic_user_id"], 41)

        provider.create_user.assert_not_called()
        self.assertEqual(MauticUserConnection.objects.filter(user=self.target).count(), 1)
        existing.refresh_from_db()
        self.assertTrue(existing.is_active)
        self.assertEqual(existing.mautic_user_id, 41)


@override_settings(**PER_USER_OFF)
class MarketingAccessEmailConflictTests(_MarketingFixtures, TestCase):
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_existing_provider_email_is_a_conflict_not_a_silent_link(
        self, provisioning_cls
    ):
        provider = self._provisioning_client(
            existing_by_email=[_provider_user(user_id=77, email=self.target.email)]
        )
        provisioning_cls.return_value = provider

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_409_CONFLICT)
        self.assertEqual(response.data["code"], "marketing_identity_conflict")

        self.assertFalse(MauticUserConnection.objects.filter(user=self.target).exists())
        provider.create_user.assert_not_called()
        provider.set_user_published.assert_not_called()
        # Nothing about the discovered account is touched.
        self.assertEqual(
            [name for name, *_ in provider.method_calls if name.startswith("create")],
            [],
        )

    @patch("newsletter.marketing_access_services.MauticClient")
    def test_conflict_is_audited_against_the_manager(self, provisioning_cls):
        provisioning_cls.return_value = self._provisioning_client(
            existing_by_email=[_provider_user(user_id=77, email=self.target.email)]
        )

        self.as_(self.manager).post(add_url(self.target.pk))

        entry = MauticIdentityAuditLog.objects.latest("id")
        self.assertEqual(entry.ecp_user_id, self.manager.pk)
        self.assertEqual(entry.error_code, "marketing_identity_conflict")
        self.assertIn(f"target_ecp_user_id={self.target.pk}", entry.detail)


@override_settings(**PER_USER_OFF)
class MarketingAccessRemovalTests(_MarketingFixtures, TestCase):
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_remove_deactivates_mapping_and_keeps_everything_else(
        self, provisioning_cls
    ):
        provider = self._provisioning_client()
        provisioning_cls.return_value = provider
        connection = self._connection(self.target, mautic_user_id=41)
        audit_before = MauticIdentityAuditLog.objects.count()

        response = self.as_(self.manager).post(remove_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertFalse(response.data["has_marketing_access"])
        self.assertEqual(response.data["marketing_state"], MarketingState.INACTIVE)

        connection.refresh_from_db()
        self.assertFalse(connection.is_active)
        # The mapping row and its provider id survive: history is not rewritten.
        self.assertEqual(connection.mautic_user_id, 41)

        # The Mautic user itself is never deleted or disabled by a removal.
        self.assertEqual(provider.method_calls, [])

        self.target.refresh_from_db()
        self.assertTrue(self.target.is_superuser)
        self.assertTrue(self.target.is_active)
        self.assertGreater(MauticIdentityAuditLog.objects.count(), audit_before)

    def test_remove_without_active_access_is_rejected(self):
        response = self.as_(self.manager).post(remove_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    def test_removed_user_loses_marketing_hub_access(self):
        connection = self._connection(self.target, mautic_user_id=41)
        self.assertTrue(has_marketing_hub_access(self.target))

        self.as_(self.manager).post(remove_url(self.target.pk))

        self.target.refresh_from_db()
        self.assertFalse(has_marketing_hub_access(self.target))
        self.assertEqual(
            self.as_(self.target).get(COMPANY_LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )
        connection.refresh_from_db()
        self.assertFalse(connection.is_active)


@override_settings(**PER_USER_OFF)
class MarketingAccessFailureCompensationTests(_MarketingFixtures, TestCase):
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_provider_creation_failure_leaves_no_mapping(self, provisioning_cls):
        from newsletter.mautic import PermanentMauticError

        provider = self._provisioning_client()
        provider.create_user.side_effect = PermanentMauticError("rejected")
        provisioning_cls.return_value = provider

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_502_BAD_GATEWAY)
        self.assertEqual(response.data["code"], "marketing_provisioning_failed")
        self.assertFalse(MauticUserConnection.objects.filter(user=self.target).exists())

        entry = MauticIdentityAuditLog.objects.latest("id")
        self.assertEqual(entry.ecp_user_id, self.manager.pk)
        self.assertEqual(entry.error_code, "marketing_provisioning_failed")

    @patch("newsletter.marketing_access_services.connect_mautic_user")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_mapping_failure_after_provisioning_disables_the_provider_user(
        self, provisioning_cls, connect
    ):
        provider = self._provisioning_client(created_id=61)
        provisioning_cls.return_value = provider
        connect.side_effect = RuntimeError("database gone")

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(response.status_code, http_status.HTTP_502_BAD_GATEWAY)
        self.assertEqual(response.data["code"], "marketing_provisioning_failed")
        # No orphaned enabled Mautic human is left behind.
        provider.set_user_published.assert_called_once_with(61, False)
        self.assertFalse(MauticUserConnection.objects.filter(user=self.target).exists())


@override_settings(**PER_USER_OFF)
class MarketingAccessIdempotencyTests(_MarketingFixtures, TestCase):
    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_second_add_cannot_create_a_second_identity(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client(created_id=55)
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user(user_id=55)

        first = self.as_(self.manager).post(add_url(self.target.pk))
        second = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertEqual(first.status_code, http_status.HTTP_200_OK)
        self.assertEqual(second.status_code, http_status.HTTP_409_CONFLICT)
        self.assertEqual(second.data["code"], "marketing_access_already_active")

        self.assertEqual(provider.create_user.call_count, 1)
        self.assertEqual(
            MauticUserConnection.objects.filter(user=self.target, is_active=True).count(),
            1,
        )

    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_one_provider_identity_cannot_serve_two_ecp_users(
        self, provisioning_cls, verify_cls
    ):
        provider = self._provisioning_client(created_id=41)
        provisioning_cls.return_value = provider
        verify_cls.return_value.get_user.return_value = _provider_user(user_id=41)
        self._connection(self.manager, mautic_user_id=41)

        response = self.as_(self.manager).post(add_url(self.target.pk))

        self.assertGreaterEqual(response.status_code, 400)
        self.assertFalse(
            MauticUserConnection.objects.filter(
                user=self.target, is_active=True
            ).exists()
        )

    def test_database_enforces_one_active_mapping_per_user(self):
        from django.db import IntegrityError, transaction

        self._connection(self.target, mautic_user_id=41)

        with self.assertRaises(IntegrityError), transaction.atomic():
            self._connection(self.target, mautic_user_id=42)


@override_settings(**PER_USER_OFF)
class MarketingAccessAuditTests(_MarketingFixtures, TestCase):
    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_grant_audit_records_manager_as_actor_and_target_separately(
        self, provisioning_cls, verify_cls
    ):
        provisioning_cls.return_value = self._provisioning_client(created_id=55)
        verify_cls.return_value.get_user.return_value = _provider_user(user_id=55)

        self.as_(self.manager).post(add_url(self.target.pk))

        entry = MauticIdentityAuditLog.objects.filter(
            action=MauticIdentityAuditLog.Action.CONNECTION_CREATE
        ).latest("id")
        self.assertEqual(entry.ecp_user_id, self.manager.pk)
        self.assertEqual(entry.ecp_user_label, self.manager.get_username())
        self.assertNotEqual(entry.ecp_user_id, self.target.pk)
        self.assertEqual(entry.mautic_user_id, 55)
        self.assertEqual(entry.resource, "mautic_user_connection")
        self.assertIn(f"target_ecp_user_id={self.target.pk}", entry.detail)
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)

        connection = MauticUserConnection.objects.get(user=self.target)
        self.assertEqual(entry.resource_id, str(connection.pk))

    @patch("newsletter.mautic_identity_services.MauticClient")
    @patch("newsletter.marketing_access_services.MauticClient")
    def test_reactivation_audits_activate_with_manager_as_actor(
        self, provisioning_cls, verify_cls
    ):
        provisioning_cls.return_value = self._provisioning_client()
        verify_cls.return_value.get_user.return_value = _provider_user(user_id=41)
        self._connection(self.target, mautic_user_id=41, is_active=False)

        self.as_(self.manager).post(add_url(self.target.pk))

        entry = MauticIdentityAuditLog.objects.filter(
            action=MauticIdentityAuditLog.Action.CONNECTION_ACTIVATE
        ).latest("id")
        self.assertEqual(entry.ecp_user_id, self.manager.pk)
        self.assertIn(f"target_ecp_user_id={self.target.pk}", entry.detail)

    def test_removal_audits_deactivate_with_manager_as_actor(self):
        self._connection(self.target, mautic_user_id=41)

        self.as_(self.manager).post(remove_url(self.target.pk))

        entry = MauticIdentityAuditLog.objects.filter(
            action=MauticIdentityAuditLog.Action.CONNECTION_DEACTIVATE
        ).latest("id")
        self.assertEqual(entry.ecp_user_id, self.manager.pk)
        self.assertEqual(entry.mautic_user_id, 41)
        self.assertIn(f"target_ecp_user_id={self.target.pk}", entry.detail)


@override_settings(**PER_USER_OFF)
class MarketingHubAccessPermissionTests(_MarketingFixtures, TestCase):
    """The permission matrix, on a representative Marketing feature endpoint."""

    @patch("newsletter.company_views.list_admin_companies")
    def test_active_mapped_superuser_is_allowed(self, list_companies):
        list_companies.return_value = {"count": 0, "results": []}
        self._connection(self.target, mautic_user_id=41)

        response = self.as_(self.target).get(COMPANY_LIST_URL)

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    def test_superuser_without_mapping_is_denied(self):
        self.assertEqual(
            self.as_(self.target).get(COMPANY_LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )

    def test_superuser_with_inactive_mapping_is_denied(self):
        self._connection(self.target, mautic_user_id=41, is_active=False)

        self.assertEqual(
            self.as_(self.target).get(COMPANY_LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )

    def test_staff_with_a_stale_mapping_is_still_denied(self):
        # A mapping cannot smuggle a non-superuser into the Marketing Hub.
        MauticUserConnection.objects.create(
            user=self.staff,
            mautic_user_id=91,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
        )

        self.assertEqual(
            self.as_(self.staff).get(COMPANY_LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )

    def test_staff_without_mapping_is_denied(self):
        self.assertEqual(
            self.as_(self.staff).get(COMPANY_LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )

    def test_normal_user_is_denied(self):
        self.assertEqual(
            self.as_(self.normal).get(COMPANY_LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )

    def test_unauthenticated_is_denied(self):
        self.assertIn(
            APIClient().get(COMPANY_LIST_URL).status_code,
            (http_status.HTTP_401_UNAUTHORIZED, http_status.HTTP_403_FORBIDDEN),
        )

    def test_eligibility_helper_matches_the_permission(self):
        self.assertTrue(is_marketing_eligible(self.target))
        self.assertFalse(is_marketing_eligible(self.staff))
        self.assertFalse(is_marketing_eligible(self.normal))


@override_settings(**PER_USER_ON)
class MarketingStatusEndpointTests(_MarketingFixtures, TestCase):
    def test_staff_can_read_status_and_sees_not_eligible(self):
        response = self.as_(self.staff).get(ME_URL)

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertFalse(response.data["eligible"])
        self.assertFalse(response.data["has_marketing_access"])
        self.assertFalse(response.data["can_manage_marketing_access"])
        self.assertEqual(response.data["marketing_state"], MarketingState.NOT_ELIGIBLE)

    def test_unmapped_superuser_is_eligible_without_access(self):
        response = self.as_(self.target).get(ME_URL)

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertTrue(response.data["eligible"])
        self.assertFalse(response.data["has_marketing_access"])
        self.assertTrue(response.data["can_manage_marketing_access"])
        self.assertEqual(
            response.data["marketing_state"], MarketingState.ELIGIBLE_NOT_ADDED
        )

    def test_mapped_superuser_has_access_and_asserted_auth_mode(self):
        self._connection(self.target, mautic_user_id=41)

        response = self.as_(self.target).get(ME_URL)

        self.assertTrue(response.data["eligible"])
        self.assertTrue(response.data["has_marketing_access"])
        self.assertTrue(response.data["connection_active"])
        self.assertEqual(response.data["mautic_user_id"], 41)
        self.assertEqual(response.data["auth_mode"], "asserted_user")

    def test_removed_superuser_reports_inactive_state(self):
        self._connection(self.target, mautic_user_id=41, is_active=False)

        response = self.as_(self.target).get(ME_URL)

        self.assertTrue(response.data["eligible"])
        self.assertFalse(response.data["has_marketing_access"])
        self.assertFalse(response.data["connection_active"])
        self.assertEqual(response.data["marketing_state"], MarketingState.INACTIVE)

    def test_status_never_exposes_credentials(self):
        self._connection(self.target, mautic_user_id=41)

        body = json.dumps(self.as_(self.target).get(ME_URL).data, default=str).lower()

        for secret in ("password", "token", "secret", "private_key", "assertion"):
            self.assertNotIn(secret, body)

    def test_normal_user_can_read_own_status(self):
        response = self.as_(self.normal).get(ME_URL)

        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertFalse(response.data["eligible"])

    def test_unauthenticated_status_is_denied(self):
        self.assertIn(
            APIClient().get(ME_URL).status_code,
            (http_status.HTTP_401_UNAUTHORIZED, http_status.HTTP_403_FORBIDDEN),
        )


@override_settings(**PER_USER_OFF)
class LowLevelConnectionApiEligibilityTests(_MarketingFixtures, TestCase):
    """The low-level admin API must honour the same eligibility rule."""

    @patch("newsletter.mautic_identity_services.MauticClient")
    def test_staff_target_cannot_be_mapped_directly(self, verify_cls):
        verify_cls.return_value.get_user.return_value = _provider_user(user_id=41)

        response = self.as_(self.manager).post(
            CONNECTION_LIST_URL,
            {"ecp_user_id": self.staff.pk, "mautic_user_id": 41},
            format="json",
        )

        self.assertGreaterEqual(response.status_code, 400)
        self.assertFalse(MauticUserConnection.objects.filter(user=self.staff).exists())

    @patch("newsletter.mautic_identity_services.MauticClient")
    def test_superuser_target_can_be_mapped_directly(self, verify_cls):
        verify_cls.return_value.get_user.return_value = _provider_user(user_id=41)

        response = self.as_(self.manager).post(
            CONNECTION_LIST_URL,
            {"ecp_user_id": self.target.pk, "mautic_user_id": 41},
            format="json",
        )

        self.assertEqual(response.status_code, http_status.HTTP_201_CREATED)
        connection = MauticUserConnection.objects.get(user=self.target)
        self.assertTrue(connection.is_active)
        self.assertEqual(connection.mautic_user_id, 41)

    def test_staff_cannot_use_the_low_level_api(self):
        self.assertEqual(
            self.as_(self.staff).get(CONNECTION_LIST_URL).status_code,
            http_status.HTTP_403_FORBIDDEN,
        )


@override_settings(**PER_USER_OFF)
class MarketingAccessListingTests(_MarketingFixtures, TestCase):
    def test_listing_reports_state_per_user_without_credentials(self):
        self._connection(self.target, mautic_user_id=41)

        response = self.as_(self.manager).get(LIST_URL)
        rows = {row["ecp_user_id"]: row for row in response.data["results"]}

        self.assertEqual(rows[self.target.pk]["marketing_state"], MarketingState.ACTIVE)
        self.assertEqual(rows[self.target.pk]["mautic_user_id"], 41)
        self.assertEqual(
            rows[self.manager.pk]["marketing_state"], MarketingState.ELIGIBLE_NOT_ADDED
        )
        # Staff are not listed as candidates at all.
        self.assertNotIn(self.staff.pk, rows)
        self.assertNotIn("password", json.dumps(response.data, default=str).lower())

    def test_user_who_lost_superuser_is_still_listed_for_revocation(self):
        self._connection(self.target, mautic_user_id=41)
        self.target.is_superuser = False
        self.target.save(update_fields=["is_superuser"])

        response = self.as_(self.manager).get(LIST_URL)
        rows = {row["ecp_user_id"]: row for row in response.data["results"]}

        self.assertIn(self.target.pk, rows)
        self.assertEqual(
            rows[self.target.pk]["marketing_state"], MarketingState.NOT_ELIGIBLE
        )
        self.assertFalse(rows[self.target.pk]["eligible"])


@override_settings(**PER_USER_ON)
class MarketingAccessServiceLayerTests(_MarketingFixtures, TestCase):
    """Service-level checks that do not need the HTTP layer."""

    def test_grant_requires_a_manager(self):
        from newsletter.mautic.exceptions import MarketingAccessNotEligibleError

        with self.assertRaises(MarketingAccessNotEligibleError):
            grant_marketing_access(self.target, actor=self.staff)

    def test_grant_refuses_self_management(self):
        from newsletter.mautic.exceptions import MarketingSelfManagementError

        with self.assertRaises(MarketingSelfManagementError):
            grant_marketing_access(self.manager, actor=self.manager)

    def test_has_marketing_hub_access_requires_both_halves(self):
        self.assertFalse(has_marketing_hub_access(self.target))

        connection = self._connection(self.target, mautic_user_id=41)
        self.assertTrue(has_marketing_hub_access(self.target))

        connection.is_active = False
        connection.status = MauticUserConnection.Status.DISABLED
        connection.save(update_fields=["is_active", "status"])
        self.target.refresh_from_db()
        self.assertFalse(has_marketing_hub_access(self.target))
