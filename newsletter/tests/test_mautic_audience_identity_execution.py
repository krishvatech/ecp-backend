from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic.exceptions import (
    MauticBridgeRejectedError,
    MauticUserConnectionMissingError,
)
from newsletter.mautic.identity import (
    MauticAuthMode,
    MauticExecutionContext,
    MauticExecutionIdentity,
)
from newsletter.mautic.operations import (
    CONTACT_CREATE,
    CONTACT_TAG_ADD,
    CONTACT_TAG_REMOVE,
    CONTACT_UPDATE,
    FIELD_CREATE,
    FIELD_DELETE,
    FIELD_UPDATE,
    SEGMENT_CONTACT_ADD,
    SEGMENT_CONTACT_REMOVE,
    SEGMENT_CREATE,
    SEGMENT_DELETE,
    SEGMENT_UPDATE,
    TAG_CREATE,
    TAG_DELETE,
    TAG_UPDATE,
)
from newsletter.mautic_identity_execution import run_interactive_mutation
from newsletter.models import MauticIdentityAuditLog


User = get_user_model()


class AudienceIdentityEndpointTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="audience-identity-staff",
            email="audience-identity-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)

    def _provider_read_client(self):
        client = Mock()
        client.get_segment.return_value = {"id": 22, "name": "Static", "filters": []}
        client.get_contact.return_value = {"id": 51}
        client.get_segment_filter_metadata.return_value = {"objects": [], "fields": []}
        return client

    def _patch_provider_reads(self):
        return patch("newsletter.admin_views.MauticClient", return_value=self._provider_read_client())

    def _run_case(self, *, method, url, helper_target, action, result=None, data=None):
        result = {} if result is None else result
        with patch(helper_target, return_value=(result, None)) as identity_helper:
            with self._patch_provider_reads():
                response = getattr(self.client, method)(url, data=data or {}, format="json")

        self.assertLess(response.status_code, 400, response.data)
        identity_helper.assert_called_once()
        self.assertEqual(identity_helper.call_args.kwargs["action"], action)
        self.assertIs(identity_helper.call_args.args[0].user, self.staff)

    def test_audience_mutation_endpoints_use_exact_identity_actions(self):
        cases = [
            {
                "method": "post",
                "url": reverse("newsletter-admin-mautic-segment-list"),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": SEGMENT_CREATE,
                "data": {"name": "QA Segment"},
                "result": {"id": 22, "name": "QA Segment", "filters": []},
            },
            {
                "method": "patch",
                "url": reverse("newsletter-admin-mautic-segment-detail", args=["22"]),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": SEGMENT_UPDATE,
                "data": {"name": "QA Segment 2"},
                "result": {"id": 22, "name": "QA Segment 2", "filters": []},
            },
            {
                "method": "delete",
                "url": reverse("newsletter-admin-mautic-segment-detail", args=["22"]),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": SEGMENT_DELETE,
            },
            {
                "method": "post",
                "url": reverse("newsletter-admin-mautic-segment-contact-list", args=["22"]),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": SEGMENT_CONTACT_ADD,
                "data": {"contact_id": "51"},
            },
            {
                "method": "delete",
                "url": reverse(
                    "newsletter-admin-mautic-segment-contact-detail",
                    args=["22", "51"],
                ),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": SEGMENT_CONTACT_REMOVE,
            },
            {
                "method": "post",
                "url": reverse("newsletter-admin-contact-list"),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": CONTACT_CREATE,
                "data": {"email": "qa@example.test"},
                "result": {"mautic_contact_id": "51"},
            },
            {
                "method": "patch",
                "url": reverse("newsletter-admin-contact-detail", args=["51"]),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": CONTACT_UPDATE,
                "data": {"firstname": "QA"},
                "result": {"mautic_contact_id": "51"},
            },
            {
                "method": "post",
                "url": reverse("newsletter-admin-contact-tags", args=["51"]),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": CONTACT_TAG_ADD,
                "data": {"tag": "qa-tag"},
                "result": {"mautic_contact_id": "51", "tags": ["qa-tag"]},
            },
            {
                "method": "delete",
                "url": reverse("newsletter-admin-contact-tag-detail", args=["51", "qa-tag"]),
                "helper_target": "newsletter.admin_views.run_interactive_mutation",
                "action": CONTACT_TAG_REMOVE,
                "result": {"mautic_contact_id": "51", "tags": []},
            },
            {
                "method": "post",
                "url": reverse("newsletter-admin-tag-directory"),
                "helper_target": "newsletter.tag_views.run_interactive_mutation",
                "action": TAG_CREATE,
                "data": {"tag": "qa-tag"},
                "result": {"id": 33, "tag": "qa-tag"},
            },
            {
                "method": "patch",
                "url": reverse("newsletter-admin-tag-detail", args=["33"]),
                "helper_target": "newsletter.tag_views.run_interactive_mutation",
                "action": TAG_UPDATE,
                "data": {"tag": "qa-tag-2"},
                "result": {"id": 33, "tag": "qa-tag-2"},
            },
            {
                "method": "delete",
                "url": reverse("newsletter-admin-tag-detail", args=["33"]),
                "helper_target": "newsletter.tag_views.run_interactive_mutation",
                "action": TAG_DELETE,
                "result": {"id": None, "tag": "qa-tag-2"},
            },
            {
                "method": "post",
                "url": reverse("newsletter-admin-field-list", args=["contact"]),
                "helper_target": "newsletter.field_views.run_interactive_mutation",
                "action": FIELD_CREATE,
                "data": {"label": "QA Field", "alias": "qa_field", "type": "text"},
                "result": {"id": 44, "label": "QA Field", "alias": "qa_field"},
            },
            {
                "method": "patch",
                "url": reverse("newsletter-admin-field-detail", args=["contact", "44"]),
                "helper_target": "newsletter.field_views.run_interactive_mutation",
                "action": FIELD_UPDATE,
                "data": {"label": "QA Field 2"},
                "result": {"id": 44, "label": "QA Field 2", "alias": "qa_field"},
            },
            {
                "method": "delete",
                "url": reverse("newsletter-admin-field-detail", args=["contact", "44"]),
                "helper_target": "newsletter.field_views.run_interactive_mutation",
                "action": FIELD_DELETE,
                "result": {"id": None},
            },
        ]

        for case in cases:
            with self.subTest(action=case["action"]):
                self._run_case(**case)


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=True)
class AudienceIdentityExecutionHelperTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.staff = User.objects.create_user(
            username="audience-helper-staff",
            email="audience-helper-staff@example.test",
            password="test-password",
            is_staff=True,
        )

    def _request(self):
        request = self.factory.post("/newsletter/admin/mautic/segments/")
        request.user = self.staff
        return request

    def _identity_client(self):
        client = Mock()
        client.execution_identity = MauticExecutionIdentity(
            context=MauticExecutionContext.INTERACTIVE,
            auth_mode=MauticAuthMode.ASSERTED_USER,
            actor_id=self.staff.id,
            mautic_user_id=6,
        )
        client.last_assertion_jti = "jti-audience-test"
        return client

    @patch("newsletter.mautic_identity_execution.get_mautic_client")
    def test_success_uses_request_user_and_records_asserted_audit(self, get_client):
        identity_client = self._identity_client()
        get_client.return_value = identity_client
        mutate = Mock(return_value={"id": 22})

        result, response = run_interactive_mutation(
            self._request(),
            action=SEGMENT_CREATE,
            resource="segment",
            resource_id="22",
            mutate=mutate,
        )

        self.assertIsNone(response)
        self.assertEqual(result, {"id": 22})
        mutate.assert_called_once_with(identity_client)
        get_client.assert_called_once()
        self.assertEqual(get_client.call_args.kwargs["actor"], self.staff)
        self.assertEqual(get_client.call_args.kwargs["purpose"], MauticExecutionContext.INTERACTIVE)
        audit = MauticIdentityAuditLog.objects.get()
        self.assertEqual(audit.action, SEGMENT_CREATE)
        self.assertEqual(audit.status, MauticIdentityAuditLog.Status.SUCCEEDED)
        self.assertEqual(audit.auth_mode, MauticAuthMode.ASSERTED_USER)
        self.assertEqual(audit.mautic_user_id, 6)
        self.assertEqual(audit.assertion_jti, "jti-audience-test")

    @patch("newsletter.mautic_identity_execution.get_mautic_client")
    def test_missing_mapping_fails_closed_before_mutation(self, get_client):
        get_client.side_effect = MauticUserConnectionMissingError("missing")
        mutate = Mock()

        result, response = run_interactive_mutation(
            self._request(),
            action=SEGMENT_CREATE,
            resource="segment",
            mutate=mutate,
        )

        self.assertIsNone(result)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "mautic_user_not_connected")
        mutate.assert_not_called()
        audit = MauticIdentityAuditLog.objects.get()
        self.assertEqual(audit.action, SEGMENT_CREATE)
        self.assertEqual(audit.status, MauticIdentityAuditLog.Status.DENIED)
        self.assertEqual(audit.assertion_jti, "")

    @patch("newsletter.mautic_identity_execution.get_mautic_client")
    def test_bridge_permission_denial_records_denied_audit(self, get_client):
        identity_client = self._identity_client()
        get_client.return_value = identity_client

        def mutate(_client):
            raise MauticBridgeRejectedError("Mautic API request failed (HTTP 403)")

        result, response = run_interactive_mutation(
            self._request(),
            action=CONTACT_TAG_REMOVE,
            resource="contact_tag",
            resource_id="51",
            mutate=mutate,
        )

        self.assertIsNone(result)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["code"], "mautic_permission_denied")
        audit = MauticIdentityAuditLog.objects.get()
        self.assertEqual(audit.action, CONTACT_TAG_REMOVE)
        self.assertEqual(audit.status, MauticIdentityAuditLog.Status.DENIED)
        self.assertEqual(audit.auth_mode, MauticAuthMode.ASSERTED_USER)
        self.assertEqual(audit.assertion_jti, "jti-audience-test")
