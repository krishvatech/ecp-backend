from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.test import APIClient

from newsletter import template_views as views
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticIdentityConfigurationError
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    TEMPLATE_TRANSLATION_CREATE,
    TEMPLATE_VARIANT_CREATE,
    TEMPLATE_VARIANT_UPDATE,
    TEMPLATE_VARIANT_WINNER,
)
from newsletter.models import NewsletterEmailDesign
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import response

User = get_user_model()
LOCMEM = {"CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "template-family-tests"}}}


def email(eid, **extra):
    return {"id": eid, "name": f"T{eid}", "subject": "Hi", "emailType": "template", "customHtml": f"<p>{eid}</p>",
            "language": "en", "isPublished": True, "variantParent": None, "translationParent": None,
            "variantChildren": [], "translationChildren": [], **extra}


class FamilyFieldTests(SimpleTestCase):
    def test_roles_and_members(self):
        main = views._normalize_template(email(18, variantChildren=[email(19, isPublished=False)],
                                                translationChildren=[email(21, language="fr")]))
        self.assertEqual((main["role"], main["language"]), ("main", "en"))
        self.assertEqual(main["variants"], [{"id": "19", "name": "T19", "language": "en", "isPublished": False}])
        self.assertEqual([t["language"] for t in main["translations"]], ["fr"])
        self.assertEqual(views._normalize_template(email(19, variantParent={"id": 18}))["role"], "variant")
        translation = views._normalize_template(email(21, translationParent={"id": 18}))
        self.assertEqual((translation["role"], translation["translationParentId"]), ("translation", "18"))

    def test_language_is_an_editable_two_letter_locale(self):
        self.assertEqual(views._parse_template_payload({"language": "fr_CA"}, partial=True), {"language": "fr_CA"})
        for bad in ("fil_PH", "FR", "fr-CA", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                views._parse_template_payload({"language": bad}, partial=True)

    def test_weights_and_criteria(self):
        self.assertEqual(views._parse_weight("30"), 30)
        for bad in (0, 101, "x", True, "1.5", "-5"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                views._parse_weight(bad)
        self.assertEqual(views._parse_criteria("email.clickthrough"), "email.clickthrough")
        with self.assertRaises(ValueError):
            views._parse_criteria("email.bounce")

    def test_abtest_normalization(self):
        test = views.normalize_template_abtest({"parentId": 18, "criteria": "email.openrate", "winners": [19], "versions": [
            {"id": 18, "isMain": True, "isPublished": True, "weight": 70, "sent": 10, "opened": 2, "openRate": 20},
            {"id": 19, "isMain": False, "isPublished": True, "weight": 30, "sent": 5, "opened": 3, "openRate": 60},
        ]})
        self.assertEqual((test["criteriaLabel"], test["running"]), ("Open rate", True))
        self.assertEqual([(v["id"], v["isLeading"], v["openRate"]) for v in test["versions"]], [("18", False, 20.0), ("19", True, 60.0)])


class FamilyClientTests(SimpleTestCase):
    def test_writes_require_the_admins_identity(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.create_template_variant(18, weight=30, winner_criteria="email.openrate"),
                     lambda: client.make_template_variant_winner(19), lambda: client.create_template_translation(18, language="fr")):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_writes_use_the_bridge_with_their_operation(self):
        session = Mock()
        session.request.side_effect = [response(200, {"email": email(19)}), response(200, {"template": {"id": 18}}),
                                       response(200, {"template": {"id": 19}}), response(200, {"email": email(21)})]
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.create_template_variant(18, weight=30, winner_criteria="email.openrate", name="B")
        client.make_template_variant_winner(19)
        client.update_template_variant(19, weight=40)
        client.create_template_translation(18, language="fr")
        self.assertEqual([c.args[1].split("/api/")[1] for c in session.request.call_args_list], [
            "ecp/bridge/templates/18/variants/new", "ecp/bridge/templates/19/winner",
            "ecp/bridge/templates/19/variant/edit", "ecp/bridge/templates/18/translations/new"])
        operations = [TEMPLATE_VARIANT_CREATE, TEMPLATE_VARIANT_WINNER, TEMPLATE_VARIANT_UPDATE, TEMPLATE_TRANSLATION_CREATE]
        self.assertEqual([c.args[0] for c in provider.call_args_list], operations)
        for operation in operations:
            self.assertIn(operation, ASSERTABLE_OPERATIONS)
        self.assertIn(("weight", "30"), [(k, str(v)) for k, v in session.request.call_args_list[0].kwargs["data"]])

    def test_template_list_hides_variants_and_translations(self):
        session = Mock()
        session.request.return_value = response(200, {"total": 4, "emails": [
            email(18), email(19, variantParent={"id": 18}), email(21, translationParent={"id": 18}), email(30, emailType="list")]})
        self.assertEqual([row["id"] for row in MauticClient(session=session).list_email_templates()["emails"]], [18])


@override_settings(**LOCMEM)
class FamilyApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="family-admin", email="fa@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)

    def url(self, name, tid="18"):
        return reverse(f"newsletter-admin-template-{name}", args=[tid])

    @patch("newsletter.template_views.run_interactive_mutation")
    @patch("newsletter.template_views.MauticClient")
    def test_variant_create_validates_then_runs_as_the_admin(self, client_cls, run):
        client_cls.return_value.get_email_template.side_effect = lambda tid: email(int(tid))
        run.return_value = (email(19, variantParent={"id": 18}, isPublished=False), None)
        r = self.api.post(self.url("variants"), {"weight": 0, "winnerCriteria": "email.openrate"}, format="json")
        self.assertEqual((r.status_code, r.json()["code"]), (400, "invalid_setting"))
        run.assert_not_called()
        r = self.api.post(self.url("variants"), {"weight": 30, "winnerCriteria": "email.openrate"}, format="json")
        self.assertEqual((r.status_code, r.json()["role"], r.json()["variantParentId"]), (201, "variant", "18"))
        self.assertEqual(run.call_args.kwargs["action"], TEMPLATE_VARIANT_CREATE)

    @patch("newsletter.template_views.run_interactive_mutation")
    @patch("newsletter.template_views.MauticClient")
    def test_family_members_only_hang_off_a_main_template(self, client_cls, run):
        client_cls.return_value.get_email_template.return_value = email(19, variantParent={"id": 18})
        r = self.api.post(self.url("translations", "19"), {"language": "fr"}, format="json")
        self.assertEqual((r.status_code, r.json()["code"]), (409, "template_not_main"))
        run.assert_not_called()

    @patch("newsletter.template_views.run_interactive_mutation")
    @patch("newsletter.template_views.MauticClient")
    def test_plugin_refusals_come_back_as_conflicts(self, client_cls, run):
        client_cls.return_value.get_email_template.return_value = email(18)
        run.side_effect = PermanentMauticError("Mautic request failed (HTTP 409): The main template is already in en.")
        r = self.api.post(self.url("translations"), {"language": "en_GB"}, format="json")
        self.assertEqual((r.status_code, r.json()["detail"]), (409, "The main template is already in en."))
        r = self.api.post(self.url("translations"), {"language": "fil_PH"}, format="json")
        self.assertEqual(r.status_code, 400)

    @patch("newsletter.template_views.run_interactive_mutation")
    @patch("newsletter.template_views.MauticClient")
    def test_winner_takes_over_the_main_template_and_its_design(self, client_cls, run):
        winner = email(19, variantParent={"id": 18}, customHtml="<p>win</p>")
        main_after = email(18, customHtml="<p>win</p>")
        client_cls.return_value.get_email_template.side_effect = lambda tid: winner if str(tid) == "19" else main_after
        run.return_value = ({"template": {"id": 18}}, None)
        NewsletterEmailDesign.objects.create(mautic_email_id="18", design_json={"old": True}, mjml="<mjml/>", html_sha256="x" * 64)
        with patch("newsletter.template_views.copy_template_design", return_value=object()) as copy:
            r = self.api.post(self.url("winner", "19"))
        self.assertEqual((r.status_code, r.json()["template"]["id"], r.json()["winnerId"]), (200, "18", "19"))
        self.assertEqual(run.call_args.kwargs["action"], TEMPLATE_VARIANT_WINNER)
        copy.assert_called_once()
        self.assertEqual(copy.call_args.args[:4], ("19", "<p>win</p>", "18", "<p>win</p>"))
        self.assertFalse(NewsletterEmailDesign.objects.filter(mautic_email_id="18", design_json={"old": True}).exists())

    @patch("newsletter.template_views.MauticClient")
    def test_only_a_variant_can_win(self, client_cls):
        client_cls.return_value.get_email_template.return_value = email(18)
        r = self.api.post(self.url("winner"))
        self.assertEqual((r.status_code, r.json()["code"]), (409, "template_not_variant"))

    @patch("newsletter.template_views.run_interactive_mutation")
    @patch("newsletter.template_views.MauticClient")
    def test_abtest_read_and_weight_change(self, client_cls, run):
        client_cls.return_value.get_template_abtest.return_value = {"parentId": 18, "criteria": "email.openrate", "versions": [
            {"id": 18, "isMain": True, "isPublished": True, "weight": 60}, {"id": 19, "isPublished": True, "weight": 40}]}
        self.assertEqual(self.api.get(self.url("abtest", "19")).json()["running"], True)
        run.return_value = ({}, None)
        r = self.api.patch(self.url("abtest", "19"), {"weight": 40}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(run.call_args.kwargs["action"], TEMPLATE_VARIANT_UPDATE)
        self.assertEqual(self.api.patch(self.url("abtest", "19"), {"name": "x"}, format="json").status_code, 400)

    @patch("newsletter.template_views.MauticClient")
    def test_language_change_keeps_each_version_on_its_own_language(self, client_cls):
        family = email(18, translationChildren=[email(21, language="fr")])
        client_cls.return_value.get_email_template.side_effect = lambda tid: (
            family if str(tid) == "18" else email(21, language="fr", translationParent={"id": 18}))
        r = self.api.patch(reverse("newsletter-admin-template-detail", args=["18"]), {"language": "fr_CA"}, format="json")
        self.assertEqual((r.status_code, r.json()["code"]), (409, "template_language_taken"))
        r = self.api.patch(reverse("newsletter-admin-template-detail", args=["21"]), {"language": "en_GB"}, format="json")
        self.assertEqual((r.status_code, r.json()["code"]), (409, "template_language_taken"))

    @patch("newsletter.template_views.run_interactive_mutation")
    def test_delete_refusal_for_a_family_is_a_conflict(self, run):
        run.side_effect = PermanentMauticError("Mautic request failed (HTTP 409): This template has A/B variants or translations. Delete those first.")
        r = self.api.delete(reverse("newsletter-admin-template-detail", args=["18"]))
        self.assertEqual((r.status_code, r.json()["detail"]), (409, "This template has A/B variants or translations. Delete those first."))


class ContactLocaleTests(SimpleTestCase):
    """Translations reach contacts by their Preferred locale; it must be settable and clearable."""

    def test_a_blank_value_is_sent_as_a_deliberate_clear(self):
        from newsletter import contact_services

        client = Mock()
        with patch.object(contact_services, "get_admin_contact", return_value={}):
            contact_services.update_admin_contact("3", {"preferred_locale": ""}, client=client)
            contact_services.update_admin_contact("3", {"preferred_locale": "de_DE"}, client=client)
            contact_services.update_admin_contact("3", {"owner": ""}, client=client)
        sent = [call.args[1] for call in client.update_contact.call_args_list]
        self.assertEqual(sent[0], {"preferred_locale": "", "overwriteWithBlank": 1})
        self.assertEqual(sent[1], {"preferred_locale": "de_DE"})
        # The owner is not a field value: clearing it never needed the flag.
        self.assertEqual(sent[2], {"owner": ""})
