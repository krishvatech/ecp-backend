"""Asserted-user execution for Contact Notes, Contact DNC and Stages.

These are human-initiated Marketing Hub mutations, so with per-user execution on
they must run as the mapped Mautic human, be bound to their exact operation, and
be audited. Reads around them (contact lookups, stage lookups, the refreshed
contact returned after a DNC change) stay on the service account.

The bulk stage endpoint gets one freshly minted assertion per contact: reusing
one assertion across contacts would be a replay, which the bridge refuses by
design.
"""

from unittest.mock import Mock, call, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic.client import ECP_IDENTITY_ASSERTION_HEADER, MauticClient
from newsletter.mautic.exceptions import MauticBridgeRejectedError
from newsletter.mautic.identity import (
    MauticAuthMode,
    MauticExecutionContext,
    MauticExecutionIdentity,
)
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    CONTACT_DNC_ADD,
    CONTACT_DNC_REMOVE,
    CONTACT_NOTE_CREATE,
    STAGE_CONTACT_ADD,
    STAGE_CONTACT_REMOVE,
    STAGE_CREATE,
    STAGE_DELETE,
    STAGE_UPDATE,
)
from newsletter.models import MauticIdentityAuditLog, MauticUserConnection
from newsletter.tests.test_mautic_per_user_execution import PER_USER_OFF, PER_USER_ON

User = get_user_model()

MAUTIC_USER_ID = 17


def _contact(stage=None):
    contact = {"id": 51, "fields": {"core": {}, "professional": {}}}
    if stage is not None:
        contact["stage"] = stage
    return contact


class _ContactStageFixtures:
    """An authorized Marketing actor: active superuser WITH an active mapping."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="contact-stage-actor",
            email="contact-stage-actor@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        self.connection = MauticUserConnection.objects.create(
            user=self.staff,
            mautic_user_id=MAUTIC_USER_ID,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
        )
        self.client.force_authenticate(user=self.staff)

        self.notes_url = reverse("newsletter-admin-contact-notes", args=["51"])
        self.dnc_url = reverse("newsletter-admin-contact-dnc", args=["51"])
        self.dnc_detail_url = reverse(
            "newsletter-admin-contact-dnc-detail", args=["51", "email"]
        )
        self.contact_stage_url = reverse("newsletter-admin-contact-stage", args=["51"])
        self.stage_list_url = reverse("newsletter-admin-stage-list")
        self.stage_detail_url = reverse("newsletter-admin-stage-detail", args=["7"])
        self.bulk_url = reverse("newsletter-admin-contact-bulk-stage")

    def _provider(self, *, stage=None):
        """A stub Mautic client for both the reads and the mutation."""
        client = Mock(name="MauticClient")
        client.get_contact.return_value = _contact(stage)
        client.get_stage.return_value = {"id": 7, "name": "Qualified", "weight": 3}
        client.create_note.return_value = {
            "id": 9,
            "text": "QA note",
            "type": "general",
        }
        client.create_stage.return_value = {"id": 7, "name": "Qualified", "weight": 3}
        client.update_stage.return_value = {"id": 7, "name": "Renamed", "weight": 4}
        client.delete_stage.return_value = {}
        client.add_contact_to_stage.return_value = None
        client.remove_contact_from_stage.return_value = None
        return client

    def _patch_client(self, client):
        """Both bindings the views construct clients through."""
        return patch("newsletter.admin_views.MauticClient", return_value=client), patch(
            "newsletter.contact_services.MauticClient", return_value=client
        )


@override_settings(**PER_USER_ON)
class ContactStageOperationBindingTests(_ContactStageFixtures, TestCase):
    """Each endpoint must name its own exact operation, and nothing else."""

    def _assert_action(self, *, method, url, action, data=None, stage=None):
        client = self._provider(stage=stage)
        view_patch, service_patch = self._patch_client(client)
        with patch(
            "newsletter.admin_views.run_interactive_mutation",
            return_value=({"id": 7, "name": "Qualified", "weight": 3}, None),
        ) as helper:
            with view_patch, service_patch:
                response = getattr(self.client, method)(url, data=data or {}, format="json")

        self.assertLess(response.status_code, 400, getattr(response, "data", None))
        helper.assert_called_once()
        self.assertEqual(helper.call_args.kwargs["action"], action)
        self.assertIs(helper.call_args.args[0].user, self.staff)

    def test_every_contact_and_stage_mutation_uses_its_exact_operation(self):
        cases = [
            ("post", self.notes_url, CONTACT_NOTE_CREATE, {"text": "QA note"}, None),
            ("post", self.dnc_url, CONTACT_DNC_ADD, {"channel": "email", "reason": 3}, None),
            ("delete", self.dnc_detail_url, CONTACT_DNC_REMOVE, None, None),
            ("post", self.stage_list_url, STAGE_CREATE, {"name": "Qualified"}, None),
            ("patch", self.stage_detail_url, STAGE_UPDATE, {"name": "Renamed"}, None),
            ("delete", self.stage_detail_url, STAGE_DELETE, None, None),
            ("post", self.contact_stage_url, STAGE_CONTACT_ADD, {"stage_id": "7"}, None),
            (
                "delete",
                self.contact_stage_url,
                STAGE_CONTACT_REMOVE,
                None,
                {"id": 7, "name": "Qualified"},
            ),
        ]
        for method, url, action, data, stage in cases:
            with self.subTest(action=action):
                self._assert_action(
                    method=method, url=url, action=action, data=data, stage=stage
                )

    def test_new_operations_are_registered_as_assertable(self):
        for action in (
            CONTACT_NOTE_CREATE,
            CONTACT_DNC_ADD,
            CONTACT_DNC_REMOVE,
            STAGE_CREATE,
            STAGE_UPDATE,
            STAGE_DELETE,
            STAGE_CONTACT_ADD,
            STAGE_CONTACT_REMOVE,
        ):
            with self.subTest(action=action):
                self.assertIn(action, ASSERTABLE_OPERATIONS)
                self.assertIn(action, MauticIdentityAuditLog.Action.values)


@override_settings(**PER_USER_ON)
class ContactStageBridgeRoutingTests(TestCase):
    """The client must send each operation to its own bridge route."""

    def _asserted_client(self, session, status_code=200, payload=None):
        response = Mock(status_code=status_code)
        response.json.return_value = payload if payload is not None else {}
        session.request.return_value = response
        identity = MauticExecutionIdentity(
            context=MauticExecutionContext.INTERACTIVE,
            auth_mode=MauticAuthMode.ASSERTED_USER,
            actor_id=1,
            mautic_user_id=MAUTIC_USER_ID,
        )
        provider = Mock(return_value="assertion-token")
        provider.last_jti = "jti-1"
        return MauticClient(
            session=session,
            execution_identity=identity,
            assertion_provider=provider,
        ), provider

    def _sent(self, session):
        args, kwargs = session.request.call_args
        return args[0], args[1], kwargs

    @override_settings(MAUTIC_BASE_URL="https://mautic.test", MAUTIC_USERNAME="u", MAUTIC_PASSWORD="p")
    def test_each_mutation_targets_its_own_bridge_route_and_operation(self):
        cases = [
            (
                lambda c: c.create_note({"lead": "51", "text": "hi", "type": "general"}),
                "POST",
                "ecp/bridge/notes/new",
                CONTACT_NOTE_CREATE,
                {"note": {"id": 9, "text": "hi"}},
            ),
            (
                lambda c: c.add_contact_dnc("51", "email", reason=3, comments=""),
                "POST",
                "ecp/bridge/contacts/51/dnc/email/add",
                CONTACT_DNC_ADD,
                {"contact": {"id": 51}},
            ),
            (
                lambda c: c.remove_contact_dnc("51", "email"),
                "POST",
                "ecp/bridge/contacts/51/dnc/email/remove",
                CONTACT_DNC_REMOVE,
                {"contact": {"id": 51}},
            ),
            (
                lambda c: c.create_stage({"name": "Qualified"}),
                "POST",
                "ecp/bridge/stages/new",
                STAGE_CREATE,
                {"stage": {"id": 7, "name": "Qualified"}},
            ),
            (
                lambda c: c.update_stage("7", {"name": "Renamed"}),
                "PATCH",
                "ecp/bridge/stages/7/edit",
                STAGE_UPDATE,
                {"stage": {"id": 7, "name": "Renamed"}},
            ),
            (
                lambda c: c.delete_stage("7"),
                "DELETE",
                "ecp/bridge/stages/7/delete",
                STAGE_DELETE,
                {"stage": {"id": 7}},
            ),
            (
                lambda c: c.add_contact_to_stage("7", "51"),
                "POST",
                "ecp/bridge/stages/7/contact/51/add",
                STAGE_CONTACT_ADD,
                {},
            ),
            (
                lambda c: c.remove_contact_from_stage("7", "51"),
                "POST",
                "ecp/bridge/stages/7/contact/51/remove",
                STAGE_CONTACT_REMOVE,
                {},
            ),
        ]
        for invoke, method, path, operation, payload in cases:
            with self.subTest(operation=operation):
                session = Mock()
                client, provider = self._asserted_client(session, payload=payload)

                invoke(client)

                sent_method, url, kwargs = self._sent(session)
                self.assertEqual(sent_method, method)
                self.assertEqual(url, f"https://mautic.test/api/{path}")
                # The assertion is minted for this operation and nothing else.
                provider.assert_called_once_with(operation)
                self.assertEqual(
                    kwargs["headers"][ECP_IDENTITY_ASSERTION_HEADER], "assertion-token"
                )

    @override_settings(MAUTIC_BASE_URL="https://mautic.test", MAUTIC_USERNAME="u", MAUTIC_PASSWORD="p")
    def test_bridge_rejection_is_raised_as_a_bridge_error_without_retrying(self):
        session = Mock()
        client, _ = self._asserted_client(session, status_code=403)

        with self.assertRaises(MauticBridgeRejectedError):
            client.create_note({"lead": "51", "text": "hi"})

        # Exactly one attempt: a refused assertion is never retried as the
        # service account.
        self.assertEqual(session.request.call_count, 1)


@override_settings(**PER_USER_ON)
class ContactStageAuditTests(_ContactStageFixtures, TestCase):
    """Successful and denied mutations are both attributed and audited."""

    def _run(self, method, url, data=None, stage=None, client=None):
        client = client or self._provider(stage=stage)
        view_patch, service_patch = self._patch_client(client)
        factory = patch(
            "newsletter.mautic_identity_execution.get_mautic_client",
            return_value=client,
        )
        identity = MauticExecutionIdentity(
            context=MauticExecutionContext.INTERACTIVE,
            auth_mode=MauticAuthMode.ASSERTED_USER,
            actor_id=self.staff.pk,
            mautic_user_id=MAUTIC_USER_ID,
        )
        client.execution_identity = identity
        client.last_assertion_jti = "jti-abc"
        with factory, view_patch, service_patch:
            return getattr(self.client, method)(url, data=data or {}, format="json")

    def _audit(self, action):
        return MauticIdentityAuditLog.objects.filter(action=action).latest("id")

    def test_note_create_is_audited_as_the_mapped_human(self):
        response = self._run("post", self.notes_url, {"text": "QA note"})

        self.assertEqual(response.status_code, 201)
        entry = self._audit(CONTACT_NOTE_CREATE)
        self.assertEqual(entry.ecp_user, self.staff)
        self.assertEqual(entry.mautic_user_id, MAUTIC_USER_ID)
        self.assertEqual(entry.auth_mode, "asserted_user")
        self.assertEqual(entry.assertion_jti, "jti-abc")
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)

    def test_dnc_add_and_remove_are_audited_separately(self):
        self._run("post", self.dnc_url, {"channel": "email", "reason": 3})
        self._run("delete", self.dnc_detail_url)

        for action in (CONTACT_DNC_ADD, CONTACT_DNC_REMOVE):
            entry = self._audit(action)
            self.assertEqual(entry.mautic_user_id, MAUTIC_USER_ID)
            self.assertEqual(entry.auth_mode, "asserted_user")
            self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)

    def test_stage_crud_is_audited(self):
        self._run("post", self.stage_list_url, {"name": "Qualified"})
        self._run("patch", self.stage_detail_url, {"name": "Renamed"})
        self._run("delete", self.stage_detail_url)

        for action in (STAGE_CREATE, STAGE_UPDATE, STAGE_DELETE):
            entry = self._audit(action)
            self.assertEqual(entry.resource, "stage")
            self.assertEqual(entry.mautic_user_id, MAUTIC_USER_ID)
            self.assertEqual(entry.auth_mode, "asserted_user")

    def test_contact_stage_add_and_remove_are_audited(self):
        client = self._provider()
        client.get_contact.side_effect = [_contact(), _contact({"id": 7, "name": "Qualified"})]
        self._run("post", self.contact_stage_url, {"stage_id": "7"}, client=client)
        entry = self._audit(STAGE_CONTACT_ADD)
        self.assertEqual(entry.mautic_user_id, MAUTIC_USER_ID)
        self.assertEqual(entry.auth_mode, "asserted_user")

        client = self._provider()
        client.get_contact.side_effect = [_contact({"id": 7, "name": "Qualified"}), _contact()]
        self._run("delete", self.contact_stage_url, client=client)
        entry = self._audit(STAGE_CONTACT_REMOVE)
        self.assertEqual(entry.mautic_user_id, MAUTIC_USER_ID)
        self.assertEqual(entry.auth_mode, "asserted_user")

    def test_permission_denial_is_surfaced_safely_and_audited(self):
        for action, method, url, data, target in (
            (CONTACT_NOTE_CREATE, "post", self.notes_url, {"text": "x"}, "create_note"),
            (CONTACT_DNC_ADD, "post", self.dnc_url, {"channel": "email"}, "add_contact_dnc"),
            (STAGE_CREATE, "post", self.stage_list_url, {"name": "x"}, "create_stage"),
        ):
            with self.subTest(action=action):
                client = self._provider()
                getattr(client, target).side_effect = MauticBridgeRejectedError(
                    "Mautic API request failed (HTTP 403)"
                )

                response = self._run(method, url, data, client=client)

                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.data["code"], "mautic_permission_denied")
                entry = self._audit(action)
                self.assertEqual(entry.status, MauticIdentityAuditLog.Status.DENIED)
                self.assertEqual(entry.error_code, "mautic_permission_denied")
                self.assertEqual(entry.mautic_user_id, MAUTIC_USER_ID)

    def test_inactive_mapping_fails_closed_before_any_provider_call(self):
        self.connection.is_active = False
        self.connection.status = MauticUserConnection.Status.DISABLED
        self.connection.save(update_fields=["is_active", "status"])

        client = self._provider()
        with patch("newsletter.admin_views.MauticClient", return_value=client):
            response = self.client.post(self.notes_url, {"text": "x"}, format="json")

        # The Marketing Hub permission requires an ACTIVE mapping, so this never
        # reaches the provider at all.
        self.assertEqual(response.status_code, 403)
        client.create_note.assert_not_called()


@override_settings(**PER_USER_OFF)
class ContactStageServiceAccountTests(_ContactStageFixtures, TestCase):
    """With the flag off these stay legitimate service-account operations."""

    def _run(self, method, url, data=None, client=None):
        client = client or self._provider()
        # With the flag off the factory hands back a service-account client, so
        # the stub carries exactly that identity.
        client.execution_identity = MauticExecutionIdentity(
            context=MauticExecutionContext.INTERACTIVE,
            auth_mode=MauticAuthMode.SERVICE_ACCOUNT,
            actor_id=self.staff.pk,
        )
        client.last_assertion_jti = ""
        view_patch, service_patch = self._patch_client(client)
        with patch(
            "newsletter.mautic.identity_assertion.issue_identity_assertion"
        ) as signer:
            with view_patch, service_patch:
                response = getattr(self.client, method)(url, data=data or {}, format="json")
        return response, client, signer

    def test_note_create_uses_service_account_without_signing(self):
        response, client, signer = self._run("post", self.notes_url, {"text": "QA note"})

        self.assertEqual(response.status_code, 201)
        signer.assert_not_called()
        client.create_note.assert_called_once()

        entry = MauticIdentityAuditLog.objects.filter(action=CONTACT_NOTE_CREATE).latest("id")
        self.assertEqual(entry.auth_mode, "service_account")
        self.assertEqual(entry.assertion_jti, "")
        self.assertIsNone(entry.mautic_user_id)

    def test_stage_create_uses_service_account_without_signing(self):
        response, client, signer = self._run("post", self.stage_list_url, {"name": "Qualified"})

        self.assertEqual(response.status_code, 201)
        signer.assert_not_called()
        client.create_stage.assert_called_once()

        entry = MauticIdentityAuditLog.objects.filter(action=STAGE_CREATE).latest("id")
        self.assertEqual(entry.auth_mode, "service_account")
        self.assertEqual(entry.assertion_jti, "")

    @override_settings(MAUTIC_BASE_URL="https://mautic.test", MAUTIC_USERNAME="u", MAUTIC_PASSWORD="p")
    def test_service_account_client_sends_no_assertion_and_uses_native_routes(self):
        session = Mock()
        response = Mock(status_code=200)
        response.json.return_value = {"note": {"id": 9, "text": "hi"}}
        session.request.return_value = response
        client = MauticClient(session=session)

        client.create_note({"lead": "51", "text": "hi"})

        args, kwargs = session.request.call_args
        self.assertEqual(args[1], "https://mautic.test/api/notes/new")
        self.assertNotIn(
            ECP_IDENTITY_ASSERTION_HEADER, (kwargs.get("headers") or {})
        )


@override_settings(**PER_USER_ON)
class BulkStageIdentityTests(_ContactStageFixtures, TestCase):
    """The bulk endpoint must never reuse one assertion across contacts."""

    def _bulk_client(self, stage=None):
        client = self._provider(stage=stage)
        return client

    def test_bulk_move_runs_one_identity_mutation_per_contact(self):
        client = self._bulk_client()
        client.get_contact.side_effect = [
            _contact(), _contact({"id": 7, "name": "Qualified"}),
            _contact(), _contact({"id": 7, "name": "Qualified"}),
            _contact(), _contact({"id": 7, "name": "Qualified"}),
        ]
        view_patch, service_patch = self._patch_client(client)
        with patch(
            "newsletter.admin_views.run_interactive_mutation",
            side_effect=lambda request, **kw: (kw["mutate"](client), None),
        ) as helper:
            with view_patch, service_patch:
                response = self.client.post(
                    self.bulk_url,
                    {"action": "move", "contact_ids": ["51", "52", "53"], "stage_id": "7"},
                    format="json",
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["succeeded"], 3)
        # One identity-bound mutation per contact => one fresh assertion each.
        self.assertEqual(helper.call_count, 3)
        for helper_call in helper.call_args_list:
            self.assertEqual(helper_call.kwargs["action"], STAGE_CONTACT_ADD)
        self.assertEqual(client.add_contact_to_stage.call_count, 3)

    def test_bulk_clear_runs_one_identity_mutation_per_contact(self):
        stage = {"id": 7, "name": "Qualified"}
        client = self._bulk_client()
        client.get_contact.side_effect = [
            _contact(stage), _contact(),
            _contact(stage), _contact(),
        ]
        view_patch, service_patch = self._patch_client(client)
        with patch(
            "newsletter.admin_views.run_interactive_mutation",
            side_effect=lambda request, **kw: (kw["mutate"](client), None),
        ) as helper:
            with view_patch, service_patch:
                response = self.client.post(
                    self.bulk_url,
                    {"action": "clear", "contact_ids": ["51", "52"]},
                    format="json",
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(helper.call_count, 2)
        for helper_call in helper.call_args_list:
            self.assertEqual(helper_call.kwargs["action"], STAGE_CONTACT_REMOVE)

    def test_bulk_mints_a_distinct_assertion_for_every_contact(self):
        """The real proof: one single-use assertion per provider mutation."""
        minted = []

        def fake_run(request, **kw):
            minted.append(kw["action"])
            return kw["mutate"](client), None

        client = self._bulk_client()
        client.get_contact.side_effect = [
            _contact(), _contact({"id": 7, "name": "Qualified"}),
            _contact(), _contact({"id": 7, "name": "Qualified"}),
        ]
        view_patch, service_patch = self._patch_client(client)
        with patch("newsletter.admin_views.run_interactive_mutation", side_effect=fake_run):
            with view_patch, service_patch:
                self.client.post(
                    self.bulk_url,
                    {"action": "move", "contact_ids": ["51", "52"], "stage_id": "7"},
                    format="json",
                )

        self.assertEqual(minted, [STAGE_CONTACT_ADD, STAGE_CONTACT_ADD])
        self.assertEqual(
            client.add_contact_to_stage.call_args_list,
            [call("7", "51"), call("7", "52")],
        )

    def test_bulk_preserves_partial_failure_reporting(self):
        client = self._bulk_client()
        client.get_contact.side_effect = [
            _contact(), _contact({"id": 7, "name": "Qualified"}),
            _contact(), _contact(),  # second contact never lands in the stage
        ]
        view_patch, service_patch = self._patch_client(client)
        with patch(
            "newsletter.admin_views.run_interactive_mutation",
            side_effect=lambda request, **kw: (kw["mutate"](client), None),
        ):
            with view_patch, service_patch:
                response = self.client.post(
                    self.bulk_url,
                    {"action": "move", "contact_ids": ["51", "52"], "stage_id": "7"},
                    format="json",
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["succeeded"], 1)
        self.assertEqual(response.data["failed"], 1)
        self.assertTrue(response.data["results"][0]["success"])
        self.assertFalse(response.data["results"][1]["success"])
        self.assertIn("error", response.data["results"][1])

    def test_identity_refusal_fails_the_whole_bulk_request_once(self):
        from rest_framework.response import Response as DrfResponse

        denied = DrfResponse(
            {"detail": "denied", "code": "mautic_permission_denied"}, status=403
        )
        client = self._bulk_client()
        view_patch, service_patch = self._patch_client(client)
        with patch(
            "newsletter.admin_views.run_interactive_mutation",
            return_value=(None, denied),
        ) as helper:
            with view_patch, service_patch:
                response = self.client.post(
                    self.bulk_url,
                    {"action": "move", "contact_ids": ["51", "52", "53"], "stage_id": "7"},
                    format="json",
                )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["code"], "mautic_permission_denied")
        # Refused on the first contact; the rest are not attempted.
        self.assertEqual(helper.call_count, 1)
        self.assertEqual(client.add_contact_to_stage.call_count, 0)
