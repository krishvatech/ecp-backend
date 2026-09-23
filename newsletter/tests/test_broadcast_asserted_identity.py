"""Asserted-user execution for interactive Email Broadcast draft mutations.

Interactive create/update/delete of a broadcast draft must execute as the
mapped human Mautic user, while the background send path must keep executing as
the service account no matter how the feature flag is set.
"""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.campaign_services import (
    delete_draft_campaign,
    sync_campaign_for_worker_delivery,
    sync_campaign_to_mautic,
)
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticBridgeRejectedError
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    EMAIL_CREATE,
    EMAIL_DELETE,
    EMAIL_UPDATE,
)
from newsletter.models import (
    MauticIdentityAuditLog,
    MauticUserConnection,
    NewsletterCampaign,
    NewsletterCategory,
)
from newsletter.tests.test_mautic_user_identity import IDENTITY_SETTINGS


User = get_user_model()

PER_USER_ON = {
    **IDENTITY_SETTINGS,
    "MAUTIC_SYNC_ENABLED": True,
    "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": True,
}

MAUTIC_SETTINGS = {
    "MAUTIC_BASE_URL": "http://mautic.local",
    "MAUTIC_USERNAME": "api-user",
    "MAUTIC_PASSWORD": "secret",
    "MAUTIC_REQUEST_TIMEOUT": 12,
}


def response(status_code=200, payload=None):
    result = Mock()
    result.status_code = status_code
    result.json.return_value = {} if payload is None else payload
    return result


# ----------------------------------------------------------------------------
# Operation catalogue
# ----------------------------------------------------------------------------


class BroadcastOperationTests(SimpleTestCase):
    def test_email_operations_are_assertable(self):
        for operation in (EMAIL_CREATE, EMAIL_UPDATE, EMAIL_DELETE):
            self.assertIn(operation, ASSERTABLE_OPERATIONS)

    def test_operation_strings_match_the_bridge_contract(self):
        self.assertEqual(EMAIL_CREATE, "email.create")
        self.assertEqual(EMAIL_UPDATE, "email.update")
        self.assertEqual(EMAIL_DELETE, "email.delete")

    def test_broadcast_operations_are_distinct_from_templates_and_campaigns(self):
        from newsletter.mautic.operations import (
            CAMPAIGN_CREATE,
            TEMPLATE_CREATE,
        )

        self.assertNotIn(EMAIL_CREATE, {TEMPLATE_CREATE, CAMPAIGN_CREATE})


# ----------------------------------------------------------------------------
# Client routing
# ----------------------------------------------------------------------------


@override_settings(**MAUTIC_SETTINGS)
class BroadcastEmailClientRoutingTests(SimpleTestCase):
    def make_client(self, result, *, asserted):
        session = Mock()
        session.request.return_value = result
        if not asserted:
            return MauticClient(session=session), session, None

        provider = Mock(return_value="signed-assertion")
        client = MauticClient(
            session=session,
            assertion_provider=provider,
            correlation_id="corr-1",
        )
        return client, session, provider

    # --- create -------------------------------------------------------------

    def test_asserted_create_uses_the_broadcast_bridge_route(self):
        client, session, provider = self.make_client(
            response(201, {"email": {"id": 42, "emailType": "list"}}),
            asserted=True,
        )

        email = client.create_email({"name": "B", "emailType": "list"})

        self.assertEqual(email["id"], 42)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/ecp/bridge/emails/new"),
        )
        provider.assert_called_once_with(EMAIL_CREATE)
        headers = session.request.call_args.kwargs["headers"]
        self.assertEqual(headers["X-ECP-Identity-Assertion"], "signed-assertion")
        self.assertEqual(headers["X-ECP-Correlation-Id"], "corr-1")

    def test_service_account_create_keeps_the_native_route(self):
        client, session, _ = self.make_client(
            response(201, {"email": {"id": 42}}),
            asserted=False,
        )

        client.create_email({"name": "B", "emailType": "list"})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/emails/new"),
        )
        self.assertNotIn("headers", session.request.call_args.kwargs)

    # --- update -------------------------------------------------------------

    def test_asserted_update_uses_the_broadcast_bridge_route(self):
        client, session, provider = self.make_client(
            response(200, {"email": {"id": 42, "emailType": "list"}}),
            asserted=True,
        )

        client.update_email(42, {"subject": "New"})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/ecp/bridge/emails/42/edit"),
        )
        provider.assert_called_once_with(EMAIL_UPDATE)

    def test_service_account_update_keeps_the_native_route(self):
        client, session, _ = self.make_client(
            response(200, {"email": {"id": 42}}),
            asserted=False,
        )

        client.update_email(42, {"subject": "New"})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/emails/42/edit"),
        )

    # --- delete -------------------------------------------------------------

    def test_asserted_delete_uses_the_broadcast_bridge_route(self):
        client, session, provider = self.make_client(
            response(200, {"email": {"id": 42}}),
            asserted=True,
        )

        client.delete_email(42)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/ecp/bridge/emails/42/delete"),
        )
        provider.assert_called_once_with(EMAIL_DELETE)

    def test_service_account_delete_keeps_the_native_route(self):
        client, session, _ = self.make_client(
            response(200, {"email": {"id": 42}}),
            asserted=False,
        )

        client.delete_email(42)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/emails/42/delete"),
        )

    # --- separation from templates ------------------------------------------

    def test_template_mutations_still_use_the_template_bridge(self):
        client, session, provider = self.make_client(
            response(201, {"email": {"id": 7, "emailType": "template"}}),
            asserted=True,
        )

        client.create_email_template({"name": "T"})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/ecp/bridge/templates/new"),
        )
        self.assertEqual(provider.call_args.args[0], "template.create")

    def test_bridge_rejection_is_classified_for_the_identity_layer(self):
        client, session, _ = self.make_client(
            response(403, {"errors": [{"message": "Access denied."}]}),
            asserted=True,
        )

        with self.assertRaises(MauticBridgeRejectedError):
            client.create_email({"name": "B"})


# ----------------------------------------------------------------------------
# Service layer
# ----------------------------------------------------------------------------


class BroadcastFixtureMixin:
    def build_campaign(self, *, mautic_email_id=""):
        category = NewsletterCategory.objects.create(
            name=f"Broadcast List {mautic_email_id or 'new'}",
            slug=f"broadcast-list-{mautic_email_id or 'new'}",
            mautic_segment_id="501",
        )
        campaign = NewsletterCampaign.objects.create(
            name="Asserted Broadcast",
            subject="Subject",
            from_name="ECP",
            from_email="news@example.test",
            html_content="<p>Hello</p>",
            mautic_email_id=mautic_email_id,
        )
        campaign.audiences.set([category])
        return campaign


@override_settings(MAUTIC_SYNC_ENABLED=True)
class BroadcastSyncClientInjectionTests(BroadcastFixtureMixin, TestCase):
    def test_injected_client_is_used_for_create(self):
        campaign = self.build_campaign()
        client = Mock()
        client.create_email.return_value = {"id": "77"}

        with patch("newsletter.campaign_services.MauticClient") as fallback:
            sync_campaign_to_mautic(campaign, client=client)

        fallback.assert_not_called()
        client.create_email.assert_called_once()
        client.update_email.assert_not_called()
        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_email_id, "77")

    def test_injected_client_is_used_for_update_and_keeps_the_id(self):
        campaign = self.build_campaign(mautic_email_id="77")
        client = Mock()

        with patch("newsletter.campaign_services.MauticClient") as fallback:
            sync_campaign_to_mautic(campaign, client=client)

        fallback.assert_not_called()
        client.update_email.assert_called_once()
        client.create_email.assert_not_called()
        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_email_id, "77")

    def test_without_an_injected_client_the_service_account_is_used(self):
        campaign = self.build_campaign()

        with patch("newsletter.campaign_services.MauticClient") as service:
            service.return_value.create_email.return_value = {"id": "88"}
            sync_campaign_to_mautic(campaign)

        service.assert_called_once_with()

    def test_injected_client_is_used_for_delete(self):
        campaign = self.build_campaign(mautic_email_id="77")
        client = Mock()

        with patch("newsletter.campaign_services.MauticClient") as fallback:
            delete_draft_campaign(campaign, client=client)

        fallback.assert_not_called()
        client.delete_email.assert_called_once_with("77")
        self.assertFalse(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )


# ----------------------------------------------------------------------------
# Background safety
# ----------------------------------------------------------------------------


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=True,
)
class BackgroundStaysServiceAccountTests(BroadcastFixtureMixin, TestCase):
    """The worker path must never impersonate a human, flag on or not."""

    def test_worker_sync_uses_a_plain_service_client(self):
        campaign = self.build_campaign(mautic_email_id="77")

        with patch("newsletter.campaign_services.MauticClient") as service:
            sync_campaign_for_worker_delivery(campaign)

        # No actor, no assertion provider, no correlation id.
        service.assert_called_once_with()

    def test_worker_sync_accepts_no_client_injection_point(self):
        """Structural guard: an interactive client cannot be threaded in."""
        import inspect

        signature = inspect.signature(sync_campaign_for_worker_delivery)
        self.assertNotIn("client", signature.parameters)

    def test_worker_sync_ignores_the_actor_for_execution_identity(self):
        actor = User.objects.create_user(
            username="worker-actor",
            email="worker-actor@example.test",
            password="pw",
        )
        campaign = self.build_campaign(mautic_email_id="77")

        with patch("newsletter.campaign_services.MauticClient") as service:
            sync_campaign_for_worker_delivery(campaign, actor=actor)

        # actor only stamps NewsletterCampaign.updated_by; the Mautic client is
        # still built with no identity arguments at all.
        service.assert_called_once_with()
        campaign.refresh_from_db()
        self.assertEqual(campaign.updated_by_id, actor.pk)

    def test_send_processor_never_mints_an_assertion(self):
        from newsletter import campaign_send_processor

        source = campaign_send_processor.__file__
        with open(source, encoding="utf-8") as handle:
            body = handle.read()

        for forbidden in (
            "get_mautic_client",
            "run_interactive_mutation",
            "interactive_mautic_client",
            "assertion_provider",
        ):
            self.assertNotIn(
                forbidden,
                body,
                msg=f"{forbidden} must not appear in the background send path",
            )


# ----------------------------------------------------------------------------
# API + audit
# ----------------------------------------------------------------------------


@override_settings(**PER_USER_ON)
class BroadcastSyncApiIdentityTests(BroadcastFixtureMixin, TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_superuser(
            username="broadcast-admin",
            email="broadcast-admin@example.test",
            password="pw",
        )
        self.connection = MauticUserConnection.objects.create(
            user=self.user,
            mautic_user_id=6,
            mautic_display_name="Ecp DevProof",
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
            connected_at=timezone.now(),
        )
        self.client.force_authenticate(user=self.user)

    def sync_url(self, campaign):
        return reverse(
            "newsletter-admin-campaign-sync",
            kwargs={"uuid": campaign.uuid},
        )

    def test_create_sync_audits_email_create_as_asserted_user(self):
        campaign = self.build_campaign()

        def fake_sync(campaign_arg, *, actor=None, client=None, **kwargs):
            campaign_arg.mautic_email_id = "77"
            campaign_arg.save(update_fields=["mautic_email_id"])
            return campaign_arg

        with patch(
            "newsletter.admin_views.sync_campaign_draft_to_mautic",
            side_effect=fake_sync,
        ):
            resp = self.client.post(self.sync_url(campaign))

        self.assertEqual(resp.status_code, 200)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.EMAIL_CREATE)
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)
        self.assertEqual(entry.ecp_user_id, self.user.pk)
        self.assertEqual(entry.mautic_user_id, 6)
        self.assertEqual(entry.auth_mode, "asserted_user")
        self.assertEqual(entry.resource_id, str(campaign.uuid))
        self.assertTrue(entry.correlation_id)

    def test_update_sync_audits_email_update(self):
        campaign = self.build_campaign(mautic_email_id="77")

        with patch(
            "newsletter.admin_views.sync_campaign_draft_to_mautic",
            side_effect=lambda c, **kwargs: c,
        ):
            resp = self.client.post(self.sync_url(campaign))

        self.assertEqual(resp.status_code, 200)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.EMAIL_UPDATE)
        self.assertEqual(entry.auth_mode, "asserted_user")

    def test_missing_mapping_fails_closed_without_touching_mautic(self):
        """No active mapping fails closed at the permission layer.

        HasMarketingHubAccess requires an active MauticUserConnection, so the
        request is refused before the view runs. That is stricter than failing
        inside the identity layer: no Mautic call is attempted, and there is no
        identity audit row because no asserted execution was ever begun.
        """
        self.connection.is_active = False
        self.connection.status = MauticUserConnection.Status.DISABLED
        self.connection.save(update_fields=["is_active", "status"])
        campaign = self.build_campaign()

        with patch(
            "newsletter.admin_views.sync_campaign_draft_to_mautic"
        ) as sync:
            resp = self.client.post(self.sync_url(campaign))

        self.assertEqual(resp.status_code, 403)
        sync.assert_not_called()
        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_email_id, "")
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_IDENTITY_PRIVATE_KEY": ""})
    def test_missing_signing_config_fails_closed(self):
        campaign = self.build_campaign()

        with patch(
            "newsletter.admin_views.sync_campaign_draft_to_mautic"
        ) as sync:
            resp = self.client.post(self.sync_url(campaign))

        self.assertGreaterEqual(resp.status_code, 400)
        sync.assert_not_called()

    def test_bridge_denial_is_audited_and_does_not_fall_back(self):
        campaign = self.build_campaign()

        with patch(
            "newsletter.admin_views.sync_campaign_draft_to_mautic",
            side_effect=MauticBridgeRejectedError("Access denied. (HTTP 403)"),
        ):
            resp = self.client.post(self.sync_url(campaign))

        self.assertGreaterEqual(resp.status_code, 400)
        entry = MauticIdentityAuditLog.objects.order_by("-id").first()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.EMAIL_CREATE)
        self.assertIn(
            entry.status,
            {
                MauticIdentityAuditLog.Status.DENIED,
                MauticIdentityAuditLog.Status.FAILED,
            },
        )
        self.assertEqual(entry.auth_mode, "asserted_user")
        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_email_id, "")

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": False})
    def test_flag_off_still_syncs_without_asserted_identity(self):
        campaign = self.build_campaign()

        with patch(
            "newsletter.admin_views.sync_campaign_draft_to_mautic",
            side_effect=lambda c, **kwargs: c,
        ) as sync:
            resp = self.client.post(self.sync_url(campaign))

        self.assertEqual(resp.status_code, 200)
        sync.assert_called_once()
        entry = MauticIdentityAuditLog.objects.order_by("-id").first()
        if entry is not None:
            self.assertNotEqual(entry.auth_mode, "asserted_user")


@override_settings(**PER_USER_ON)
class BroadcastDeleteApiIdentityTests(BroadcastFixtureMixin, TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_superuser(
            username="broadcast-deleter",
            email="broadcast-deleter@example.test",
            password="pw",
        )
        MauticUserConnection.objects.create(
            user=self.user,
            mautic_user_id=6,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
            connected_at=timezone.now(),
        )
        self.client.force_authenticate(user=self.user)

    def detail_url(self, campaign):
        return reverse(
            "newsletter-admin-campaign-detail",
            kwargs={"uuid": campaign.uuid},
        )

    def test_linked_draft_delete_is_asserted_and_audited(self):
        campaign = self.build_campaign(mautic_email_id="77")

        with patch(
            "newsletter.admin_views.delete_draft_campaign",
            side_effect=lambda c, **kwargs: c.delete(),
        ) as deleter:
            resp = self.client.delete(self.detail_url(campaign))

        self.assertEqual(resp.status_code, 204)
        self.assertIn("client", deleter.call_args.kwargs)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.EMAIL_DELETE)
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)
        self.assertEqual(entry.auth_mode, "asserted_user")
        self.assertEqual(entry.mautic_user_id, 6)

    def test_local_only_draft_delete_writes_no_identity_audit(self):
        campaign = self.build_campaign()

        resp = self.client.delete(self.detail_url(campaign))

        self.assertEqual(resp.status_code, 204)
        self.assertFalse(MauticIdentityAuditLog.objects.exists())
        self.assertFalse(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )

    def test_denied_delete_keeps_the_local_campaign(self):
        campaign = self.build_campaign(mautic_email_id="77")

        with patch(
            "newsletter.admin_views.delete_draft_campaign",
            side_effect=MauticBridgeRejectedError("Access denied. (HTTP 403)"),
        ):
            resp = self.client.delete(self.detail_url(campaign))

        self.assertGreaterEqual(resp.status_code, 400)
        self.assertTrue(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )
        entry = MauticIdentityAuditLog.objects.order_by("-id").first()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.EMAIL_DELETE)
        self.assertIn(
            entry.status,
            {
                MauticIdentityAuditLog.Status.DENIED,
                MauticIdentityAuditLog.Status.FAILED,
            },
        )


# ----------------------------------------------------------------------------
# Audit domain classification
# ----------------------------------------------------------------------------


class BroadcastAuditDomainTests(SimpleTestCase):
    def test_email_actions_classify_as_email_broadcasts(self):
        from newsletter.marketing_audit_views import domain_for_action

        for action in (EMAIL_CREATE, EMAIL_UPDATE, EMAIL_DELETE):
            self.assertEqual(domain_for_action(action), "Email Broadcasts")

    def test_existing_domains_are_unchanged(self):
        from newsletter.marketing_audit_views import domain_for_action

        self.assertEqual(domain_for_action("campaign.create"), "Campaigns")
        self.assertEqual(domain_for_action("template.create"), "Templates")
        self.assertEqual(domain_for_action("newsletter.test_send"), "Delivery")
        self.assertEqual(domain_for_action("segment.create"), "Segments")
        self.assertEqual(domain_for_action("unknown.thing"), "Other")
