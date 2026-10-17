"""Visual design storage (NewsletterEmailDesign) for Templates and Broadcasts.

Mautic is mocked at the template_views boundary like the other Template API
tests; MJML is compiled by the real CMS compiler.
"""

import copy
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.email_design_services import (
    DESIGN_STATUS_IN_SYNC,
    DESIGN_STATUS_INVALID,
    DESIGN_STATUS_NONE,
    DESIGN_STATUS_STALE,
    MAX_DESIGN_BLOCKS,
    EmailDesignValidationError,
    _TEMPLATE_LOCK_NAMESPACE,
    design_state,
    html_fingerprint,
    validate_design,
)
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    MauticIdentityAuditLog,
    NewsletterCampaign,
    NewsletterCategory,
    NewsletterEmailDesign,
)
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_email_design_compile import DESIGN_MJML


User = get_user_model()

STYLES = {"padding": {"top": 0, "right": 0, "bottom": 0, "left": 0}, "margin": {"top": 0, "right": 0, "bottom": 0, "left": 0}}


def make_design(text="Hello {contactfield=firstname}"):
    """A design envelope shaped like the editor's output."""
    return {
        "editor": "templatical",
        "version": 1,
        "content": {
            "blocks": [
                {"id": "t1", "type": "title", "content": "Monthly deals", "level": 1, "styles": STYLES},
                {
                    "id": "s1",
                    "type": "section",
                    "columns": "2",
                    "children": [
                        [{"id": "i1", "type": "image", "src": "https://cdn.example.com/a.png", "alt": "A", "styles": STYLES}],
                        [{"id": "p1", "type": "paragraph", "content": f"<p>{text}</p>", "styles": STYLES}],
                    ],
                    "styles": STYLES,
                },
                {"id": "b1", "type": "button", "text": "Read", "url": "{webview_url}", "styles": STYLES},
            ],
            "settings": {"width": 600, "backgroundColor": "#ffffff", "fontFamily": "Arial", "locale": "en"},
        },
    }


# Mautic normalizes stored HTML (e.g. xmlns:v -> xmlnsv), so the stored
# version differs from what ECP compiled and sent.
def mautic_normalized(html):
    return html.replace("xmlns:v=", "xmlnsv=") + "\n<!-- stored by Mautic -->"


class DesignValidationTests(TestCase):
    def test_editor_output_is_accepted(self):
        design = make_design()
        self.assertIs(validate_design(design), design)

    def test_unreopenable_designs_are_refused_never_repaired(self):
        cases = {
            "not an object": [],
            "other editor": {**make_design(), "editor": "grapesjs"},
            "future version": {**make_design(), "version": 2},
            "boolean version": {**make_design(), "version": True},
            "no content": {"editor": "templatical", "version": 1},
            "no settings": {"editor": "templatical", "version": 1, "content": {"blocks": []}},
            "bad width": {"editor": "templatical", "version": 1, "content": {"blocks": [], "settings": {"width": 5000}}},
        }
        broken_blocks = {
            "custom block": [{"id": "c", "type": "custom"}],
            "missing id": [{"type": "paragraph"}],
            "four columns": [{"id": "s", "type": "section", "children": [[], [], [], []]}],
            "not a list": "blocks",
        }
        for name, blocks in broken_blocks.items():
            design = make_design()
            design["content"]["blocks"] = blocks
            cases[name] = design
        too_many = make_design()
        too_many["content"]["blocks"] = [
            {"id": f"p{i}", "type": "spacer"} for i in range(MAX_DESIGN_BLOCKS + 1)
        ]
        cases["too many blocks"] = too_many
        nested = make_design()
        node = nested["content"]["blocks"]
        for depth in range(6):
            section = {"id": f"s{depth}", "type": "section", "children": [[]]}
            node.append(section)
            node = section["children"][0]
        cases["too deep"] = nested
        oversized = make_design("x" * (1024 * 1024))
        cases["oversized"] = oversized

        for name, design in cases.items():
            with self.subTest(name), self.assertRaises(EmailDesignValidationError):
                validate_design(design)

    def test_state_reports_none_in_sync_stale_and_invalid(self):
        campaign = NewsletterCampaign.objects.create(name="State", html_content="<p>A</p>")
        self.assertEqual(design_state(None, "<p>A</p>")["status"], DESIGN_STATUS_NONE)

        row = NewsletterEmailDesign.objects.create(
            campaign=campaign, design_json=make_design(), mjml=DESIGN_MJML, html_sha256=html_fingerprint("<p>A</p>")
        )
        self.assertEqual(design_state(row, "<p>A</p>")["status"], DESIGN_STATUS_IN_SYNC)
        stale = design_state(row, "<p>A, edited in HTML mode</p>")
        self.assertEqual(stale["status"], DESIGN_STATUS_STALE)
        self.assertEqual(stale["design"], make_design())

        row.design_json = {**make_design(), "version": 99}
        invalid = design_state(row, "<p>A</p>")
        self.assertEqual(invalid["status"], DESIGN_STATUS_INVALID)
        self.assertIsNone(invalid["design"])


class EmailDesignModelConstraintTests(TestCase):
    def setUp(self):
        self.campaign = NewsletterCampaign.objects.create(name="Owner")

    def _create(self, **owner):
        with transaction.atomic():
            return NewsletterEmailDesign.objects.create(
                design_json=make_design(), mjml="<mjml/>", html_sha256="0" * 64, **owner
            )

    def test_exactly_one_owner(self):
        with self.assertRaises(IntegrityError):
            self._create()
        with self.assertRaises(IntegrityError):
            self._create(mautic_email_id="18", campaign=self.campaign)
        with self.assertRaises(IntegrityError):
            self._create(mautic_email_id="")
        self.assertIsNotNone(self._create(mautic_email_id="18"))
        self.assertIsNotNone(self._create(campaign=self.campaign))

    def test_one_design_per_template_and_per_broadcast(self):
        self._create(mautic_email_id="18")
        with self.assertRaises(IntegrityError):
            self._create(mautic_email_id="18")
        self._create(campaign=self.campaign)
        with self.assertRaises(IntegrityError):
            self._create(campaign=self.campaign)

    def test_deleting_the_broadcast_deletes_its_design(self):
        self._create(campaign=self.campaign)
        self.campaign.delete()
        self.assertFalse(NewsletterEmailDesign.objects.exists())


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class TemplateDesignAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.marketer = User.objects.create_user(
            username="design-templates",
            email="design-templates@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        grant_marketing_access(self.marketer)
        self.client.force_authenticate(user=self.marketer)
        self.list_url = reverse("newsletter-admin-template-list")
        self.detail_url = reverse("newsletter-admin-template-detail", args=["18"])
        self.duplicate_url = reverse("newsletter-admin-template-duplicate", args=["18"])

        patcher = patch("newsletter.template_views.MauticClient")
        self.mautic = patcher.start().return_value
        self.addCleanup(patcher.stop)
        # In-memory Mautic: what was sent, and what Mautic stores (normalized).
        self.stored = {"18": self._email("18", "<h1>Legacy HTML</h1>")}

        def get(email_id):
            return copy.deepcopy(self.stored[str(email_id)])

        def create(payload):
            email = self._email("31", mautic_normalized(payload["customHtml"]), name=payload["name"])
            self.stored["31"] = email
            return copy.deepcopy(email)

        def update(email_id, payload):
            email = self.stored[str(email_id)]
            if "customHtml" in payload:
                email["customHtml"] = mautic_normalized(payload["customHtml"])
            for key in ("name", "subject", "plainText"):
                if key in payload:
                    email[key] = payload[key]
            return copy.deepcopy(email)

        def duplicate(email_id, name=None):
            source = self.stored[str(email_id)]
            email = {**copy.deepcopy(source), "id": 44, "name": name or f"{source['name']} Copy"}
            self.stored["44"] = email
            return copy.deepcopy(email)

        self.mautic.get_email_template.side_effect = get
        self.mautic.create_email_template.side_effect = create
        self.mautic.update_email_template.side_effect = update
        self.mautic.duplicate_email_template.side_effect = duplicate
        self.mautic.delete_email_template.return_value = {}

    @staticmethod
    def _email(email_id, html, name="Reusable Newsletter"):
        return {
            "id": int(email_id),
            "name": name,
            "subject": "Monthly update",
            "customHtml": html,
            "plainText": "",
            "emailType": "template",
            "isPublished": False,
        }

    def _create_visual(self, **extra):
        return self.client.post(
            self.list_url,
            {"name": "Visual", "subject": "Hi", "design": make_design(), "mjml": DESIGN_MJML, **extra},
            format="json",
        )

    def test_create_compiles_on_the_server_and_stores_the_design_against_mautic_html(self):
        response = self._create_visual()

        self.assertEqual(response.status_code, 201, response.data)
        sent_html = self.mautic.create_email_template.call_args.args[0]["customHtml"]
        self.assertIn("Hello {contactfield=firstname}", sent_html)
        self.assertIn('href="{unsubscribe_url}"', sent_html)
        row = NewsletterEmailDesign.objects.get(mautic_email_id="31")
        self.assertEqual(row.design_json, make_design())
        self.assertEqual(row.mjml, DESIGN_MJML)
        self.assertEqual(row.created_by, self.marketer)
        # Fingerprint of what Mautic stored, not of what ECP sent.
        self.assertEqual(row.html_sha256, html_fingerprint(self.stored["31"]["customHtml"]))
        self.assertNotEqual(row.html_sha256, html_fingerprint(sent_html))
        self.assertEqual(response.data["visualDesign"]["status"], DESIGN_STATUS_IN_SYNC)
        self.assertEqual(response.data["visualDesign"]["design"], make_design())

        reopened = self.client.get(reverse("newsletter-admin-template-detail", args=["31"]))
        self.assertEqual(reopened.data["visualDesign"]["status"], DESIGN_STATUS_IN_SYNC)
        self.assertEqual(reopened.data["visualDesign"]["design"], make_design())

    def test_invalid_visual_requests_are_refused_before_mautic(self):
        cases = [
            {"design": make_design(), "mjml": DESIGN_MJML, "customHtml": "<p>also html</p>"},
            {"design": make_design()},
            {"mjml": DESIGN_MJML},
            {"design": {**make_design(), "version": 2}, "mjml": DESIGN_MJML},
            {"design": make_design(), "mjml": "<p>not mjml</p>"},
            {"design": make_design(), "mjml": '<mjml><mj-body><mj-include path="/etc/passwd"/></mj-body></mjml>'},
        ]
        for extra in cases:
            with self.subTest(extra=sorted(extra)):
                response = self.client.post(self.list_url, {"name": "Visual", "subject": "Hi", **extra}, format="json")
                self.assertEqual(response.status_code, 400)
        self.mautic.create_email_template.assert_not_called()
        self.assertFalse(NewsletterEmailDesign.objects.exists())

    def test_html_only_create_is_unchanged_and_reports_no_design(self):
        response = self.client.post(
            self.list_url, {"name": "HTML", "subject": "Hi", "customHtml": "<p>Plain HTML</p>"}, format="json"
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.mautic.create_email_template.call_args.args[0]["customHtml"], "<p>Plain HTML</p>")
        self.assertEqual(response.data["visualDesign"]["status"], DESIGN_STATUS_NONE)
        self.assertFalse(NewsletterEmailDesign.objects.exists())

    def test_partial_failures_are_reported_not_called_success(self):
        self.mautic.get_email_template.side_effect = TemporaryMauticError("read back failed")
        response = self._create_visual()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data["code"], "design_not_saved")
        self.assertIs(response.data["designSaved"], False)
        self.assertEqual(response.data["template"]["id"], "31")
        self.assertFalse(NewsletterEmailDesign.objects.exists())

        self.mautic.get_email_template.side_effect = lambda email_id: copy.deepcopy(self.stored[str(email_id)])
        with patch("newsletter.template_views.save_template_design", side_effect=DatabaseError("db down")):
            response = self._create_visual()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data["code"], "design_not_saved")
        # The Template exists in Mautic as HTML only, so it reopens in HTML mode.
        self.assertEqual(response.data["template"]["visualDesign"]["status"], DESIGN_STATUS_NONE)

    def _save_visual_over_18(self, fingerprint, text="Edited {contactfield=firstname}"):
        mjml = DESIGN_MJML.replace("Hello {contactfield=firstname}", text)
        return self.client.patch(
            self.detail_url,
            {"design": make_design(text), "mjml": mjml, "baseFingerprint": fingerprint},
            format="json",
        )

    def test_legacy_template_opens_without_a_design_and_is_not_touched_by_reading(self):
        response = self.client.get(self.detail_url)
        self.assertEqual(response.data["visualDesign"]["status"], DESIGN_STATUS_NONE)
        self.assertEqual(response.data["customHtml"], "<h1>Legacy HTML</h1>")
        preview = self.client.get(reverse("newsletter-admin-template-preview", args=["18"]))
        self.assertEqual(preview.data["template"]["visualDesign"]["status"], DESIGN_STATUS_NONE)
        self.mautic.update_email_template.assert_not_called()
        self.assertFalse(NewsletterEmailDesign.objects.exists())

    def test_visual_save_requires_the_loaded_fingerprint(self):
        for fingerprint in (None, "", "not-a-hash"):
            with self.subTest(fingerprint=fingerprint):
                response = self._save_visual_over_18(fingerprint)
                self.assertEqual(response.status_code, 400)
        self.mautic.update_email_template.assert_not_called()

    def test_visual_save_and_reopen_then_edit_again(self):
        loaded = self.client.get(self.detail_url).data["visualDesign"]["htmlFingerprint"]
        first = self._save_visual_over_18(loaded, "First {contactfield=firstname}")
        self.assertEqual(first.status_code, 200, first.data)
        self.assertEqual(first.data["visualDesign"]["status"], DESIGN_STATUS_IN_SYNC)

        second = self._save_visual_over_18(first.data["visualDesign"]["htmlFingerprint"], "Second {contactfield=firstname}")
        self.assertEqual(second.status_code, 200, second.data)
        reopened = self.client.get(self.detail_url).data
        self.assertEqual(reopened["visualDesign"]["status"], DESIGN_STATUS_IN_SYNC)
        self.assertEqual(reopened["visualDesign"]["design"], make_design("Second {contactfield=firstname}"))
        self.assertIn("Second {contactfield=firstname}", reopened["customHtml"])
        self.assertEqual(NewsletterEmailDesign.objects.count(), 1)

    def test_external_change_is_a_conflict_and_nothing_is_overwritten(self):
        loaded = self.client.get(self.detail_url).data["visualDesign"]["htmlFingerprint"]
        self.stored["18"]["customHtml"] = "<h1>Edited in the Mautic UI</h1>"

        response = self._save_visual_over_18(loaded)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "template_changed")
        self.mautic.update_email_template.assert_not_called()
        self.assertEqual(self.stored["18"]["customHtml"], "<h1>Edited in the Mautic UI</h1>")
        self.assertFalse(NewsletterEmailDesign.objects.exists())
        self.assertFalse(
            MauticIdentityAuditLog.objects.filter(status=MauticIdentityAuditLog.Status.SUCCEEDED).exists()
        )

    def test_html_mode_edit_marks_the_design_stale_and_keeps_html_authoritative(self):
        loaded = self.client.get(self.detail_url).data["visualDesign"]["htmlFingerprint"]
        saved = self._save_visual_over_18(loaded).data["visualDesign"]["htmlFingerprint"]

        html_edit = self.client.patch(
            self.detail_url, {"customHtml": "<p>Hand edited</p>", "baseFingerprint": saved}, format="json"
        )
        self.assertEqual(html_edit.status_code, 200, html_edit.data)

        reopened = self.client.get(self.detail_url).data
        self.assertEqual(reopened["visualDesign"]["status"], DESIGN_STATUS_STALE)
        self.assertIn("Hand edited", reopened["customHtml"])
        # The old design is kept for an explicit restore, not deleted.
        self.assertTrue(NewsletterEmailDesign.objects.filter(mautic_email_id="18").exists())

        # An HTML save made against an out-of-date fingerprint is refused too.
        conflict = self.client.patch(
            self.detail_url, {"customHtml": "<p>Late</p>", "baseFingerprint": saved}, format="json"
        )
        self.assertEqual(conflict.status_code, 409)

    def test_concurrent_save_of_the_same_template_is_refused(self):
        loaded = self.client.get(self.detail_url).data["visualDesign"]["htmlFingerprint"]
        other = connection.copy()
        try:
            with other.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(%s, %s)", [_TEMPLATE_LOCK_NAMESPACE, 18])
            response = self._save_visual_over_18(loaded)
        finally:
            with other.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s, %s)", [_TEMPLATE_LOCK_NAMESPACE, 18])
            other.close()

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "template_save_in_progress")
        self.mautic.update_email_template.assert_not_called()
        # Lock released afterwards: the next save goes through.
        self.assertEqual(self._save_visual_over_18(loaded).status_code, 200)

    def test_duplicate_copies_an_in_sync_design_independently(self):
        loaded = self.client.get(self.detail_url).data["visualDesign"]["htmlFingerprint"]
        self._save_visual_over_18(loaded)

        response = self.client.post(self.duplicate_url, {}, format="json")

        self.assertEqual(response.status_code, 201, response.data)
        self.assertIs(response.data["designCopied"], True)
        self.assertEqual(response.data["visualDesign"]["status"], DESIGN_STATUS_IN_SYNC)
        source = NewsletterEmailDesign.objects.get(mautic_email_id="18")
        copy_row = NewsletterEmailDesign.objects.get(mautic_email_id="44")
        self.assertNotEqual(source.pk, copy_row.pk)
        self.assertEqual(copy_row.design_json, source.design_json)

        # Editing the duplicate leaves the original's design untouched.
        dup_url = reverse("newsletter-admin-template-detail", args=["44"])
        dup_fp = self.client.get(dup_url).data["visualDesign"]["htmlFingerprint"]
        mjml = DESIGN_MJML.replace("Hello {contactfield=firstname}", "Duplicate only")
        edit = self.client.patch(dup_url, {"design": make_design("Duplicate only"), "mjml": mjml, "baseFingerprint": dup_fp}, format="json")
        self.assertEqual(edit.status_code, 200, edit.data)
        source.refresh_from_db()
        self.assertEqual(source.design_json, make_design("Edited {contactfield=firstname}"))
        self.assertNotIn("Duplicate only", self.stored["18"]["customHtml"])

    def test_duplicate_of_stale_or_legacy_template_stays_html_only(self):
        response = self.client.post(self.duplicate_url, {}, format="json")
        self.assertIs(response.data["designCopied"], False)
        self.assertEqual(self.mautic.get_email_template.call_count, 0)

        NewsletterEmailDesign.objects.create(
            mautic_email_id="18", design_json=make_design(), mjml=DESIGN_MJML, html_sha256="f" * 64
        )
        response = self.client.post(self.duplicate_url, {}, format="json")
        self.assertIs(response.data["designCopied"], False)
        self.assertFalse(NewsletterEmailDesign.objects.filter(mautic_email_id="44").exists())

    def test_delete_removes_the_design_only_after_mautic_confirms(self):
        NewsletterEmailDesign.objects.create(
            mautic_email_id="18", design_json=make_design(), mjml=DESIGN_MJML, html_sha256="f" * 64
        )
        self.mautic.delete_email_template.side_effect = PermanentMauticError("HTTP 400 in use")
        self.assertEqual(self.client.delete(self.detail_url).status_code, 400)
        self.assertTrue(NewsletterEmailDesign.objects.filter(mautic_email_id="18").exists())

        self.mautic.delete_email_template.side_effect = None
        self.assertEqual(self.client.delete(self.detail_url).status_code, 204)
        self.assertFalse(NewsletterEmailDesign.objects.filter(mautic_email_id="18").exists())

    def test_users_without_marketing_access_cannot_save_designs(self):
        outsider = User.objects.create_user(username="design-outsider", email="o@example.test", password="x", is_staff=True)
        self.client.force_authenticate(user=outsider)
        self.assertEqual(self._create_visual().status_code, 403)
        self.assertEqual(self._save_visual_over_18("a" * 64).status_code, 403)
        self.mautic.create_email_template.assert_not_called()
        self.assertFalse(NewsletterEmailDesign.objects.exists())


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class BroadcastDesignAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.marketer = User.objects.create_user(
            username="design-broadcasts",
            email="design-broadcasts@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        grant_marketing_access(self.marketer)
        self.client.force_authenticate(user=self.marketer)
        self.category = NewsletterCategory.objects.get(slug="imaa-events")
        self.list_url = reverse("newsletter-admin-campaign-list")

    def _payload(self, **overrides):
        payload = {
            "name": "Visual Broadcast",
            "subject": "Deals",
            "preview_text": "Top deals",
            "from_name": "IMAA Connect",
            "from_email": "newsletter@example.test",
            "html_content": "<p>client html is ignored</p>",
            "plain_text": "Deals",
            "audience_slugs": ["imaa-events"],
            "design": make_design(),
            "mjml": DESIGN_MJML,
        }
        payload.update(overrides)
        return payload

    def _detail(self, uuid):
        return reverse("newsletter-admin-campaign-detail", args=[uuid])

    def test_create_and_reopen_a_visual_broadcast(self):
        response = self.client.post(self.list_url, self._payload(), format="json")

        self.assertEqual(response.status_code, 201, response.data)
        campaign = NewsletterCampaign.objects.get(uuid=response.data["uuid"])
        self.assertNotIn("client html is ignored", campaign.html_content)
        self.assertIn("Hello {contactfield=firstname}", campaign.html_content)
        self.assertNotIn("design", response.data)
        self.assertNotIn("mjml", response.data)
        self.assertEqual(response.data["visual_design"]["status"], DESIGN_STATUS_IN_SYNC)

        reopened = self.client.get(self._detail(campaign.uuid)).data
        self.assertEqual(reopened["visual_design"]["design"], make_design())
        self.assertEqual(reopened["html_content"], campaign.html_content)
        self.assertEqual(campaign.email_design.html_sha256, html_fingerprint(campaign.html_content))

    def test_list_reports_only_a_status_summary(self):
        self.client.post(self.list_url, self._payload(), format="json")
        rows = self.client.get(self.list_url).data
        self.assertEqual(rows[0]["visual_design"], {"status": DESIGN_STATUS_IN_SYNC})

    def test_draft_update_saves_design_and_html_together(self):
        uuid = self.client.post(self.list_url, self._payload(), format="json").data["uuid"]
        mjml = DESIGN_MJML.replace("Hello {contactfield=firstname}", "Updated {contactfield=firstname}")

        response = self.client.patch(self._detail(uuid), {"design": make_design("Updated"), "mjml": mjml}, format="json")

        self.assertEqual(response.status_code, 200, response.data)
        campaign = NewsletterCampaign.objects.get(uuid=uuid)
        self.assertIn("Updated {contactfield=firstname}", campaign.html_content)
        self.assertEqual(campaign.email_design.design_json, make_design("Updated"))
        self.assertEqual(response.data["visual_design"]["status"], DESIGN_STATUS_IN_SYNC)
        self.assertEqual(NewsletterEmailDesign.objects.count(), 1)

    def test_html_mode_update_keeps_the_design_but_marks_it_stale(self):
        uuid = self.client.post(self.list_url, self._payload(), format="json").data["uuid"]
        response = self.client.patch(self._detail(uuid), {"html_content": "<p>Hand edited</p>"}, format="json")
        self.assertEqual(response.data["visual_design"]["status"], DESIGN_STATUS_STALE)
        self.assertEqual(NewsletterCampaign.objects.get(uuid=uuid).html_content, "<p>Hand edited</p>")

    def test_locked_broadcasts_cannot_take_a_design(self):
        uuid = self.client.post(self.list_url, self._payload(), format="json").data["uuid"]
        campaign = NewsletterCampaign.objects.get(uuid=uuid)
        original_html = campaign.html_content
        for locked in (
            NewsletterCampaign.Status.SCHEDULED,
            NewsletterCampaign.Status.SENDING,
            NewsletterCampaign.Status.SENT,
            NewsletterCampaign.Status.FAILED,
            NewsletterCampaign.Status.CANCELLED,
        ):
            NewsletterCampaign.objects.filter(pk=campaign.pk).update(status=locked)
            with self.subTest(status=locked):
                response = self.client.patch(
                    self._detail(uuid), {"design": make_design("Sneaky"), "mjml": DESIGN_MJML.replace("Hello", "Sneaky")}, format="json"
                )
                self.assertEqual(response.status_code, 400)
        campaign.refresh_from_db()
        self.assertEqual(campaign.html_content, original_html)
        self.assertEqual(campaign.email_design.design_json, make_design())

    def test_invalid_designs_are_refused(self):
        for overrides in ({"design": {**make_design(), "editor": "x"}}, {"mjml": "<p>x</p>"}, {"mjml": None}):
            with self.subTest(overrides=sorted(overrides)):
                payload = self._payload(**overrides)
                if overrides.get("mjml") is None and "mjml" in overrides:
                    payload.pop("mjml")
                response = self.client.post(self.list_url, payload, format="json")
                self.assertEqual(response.status_code, 400)
                self.assertIn("design", response.data)
        self.assertFalse(NewsletterCampaign.objects.filter(name="Visual Broadcast").exists())

    def test_duplicate_gets_an_independent_design_copy(self):
        uuid = self.client.post(self.list_url, self._payload(), format="json").data["uuid"]
        dup = self.client.post(reverse("newsletter-admin-campaign-duplicate", args=[uuid]), {}, format="json").data

        source = NewsletterCampaign.objects.get(uuid=uuid)
        duplicate = NewsletterCampaign.objects.get(uuid=dup["uuid"])
        self.assertNotEqual(source.email_design.pk, duplicate.email_design.pk)
        self.assertEqual(duplicate.email_design.design_json, source.email_design.design_json)
        self.assertEqual(dup["visual_design"]["status"], DESIGN_STATUS_IN_SYNC)

        mjml = DESIGN_MJML.replace("Hello {contactfield=firstname}", "Only the copy")
        self.client.patch(self._detail(dup["uuid"]), {"design": make_design("Only the copy"), "mjml": mjml}, format="json")
        source.email_design.refresh_from_db()
        self.assertEqual(source.email_design.design_json, make_design())

    def test_duplicate_of_a_stale_design_is_html_only(self):
        uuid = self.client.post(self.list_url, self._payload(), format="json").data["uuid"]
        self.client.patch(self._detail(uuid), {"html_content": "<p>Hand edited</p>"}, format="json")
        dup = self.client.post(reverse("newsletter-admin-campaign-duplicate", args=[uuid]), {}, format="json").data
        self.assertEqual(dup["visual_design"]["status"], DESIGN_STATUS_NONE)
        self.assertEqual(dup["html_content"], "<p>Hand edited</p>")

    def test_deleting_an_unsynced_draft_removes_its_design(self):
        uuid = self.client.post(self.list_url, self._payload(), format="json").data["uuid"]
        self.assertEqual(self.client.delete(self._detail(uuid)).status_code, 204)
        self.assertFalse(NewsletterEmailDesign.objects.exists())
