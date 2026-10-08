"""Tests for the public CMS by-path endpoint (cms.public_pages).

The Wagtail test database already contains the tree root (id 1), the default "Welcome"
page (id 2, slug ``home``) and one default Site pointing at it. Each test builds its own
ECP page tree under a fresh HomePage and re-points the Site at it.
"""

from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from wagtail.models import Page, PageViewRestriction, Site
from wagtail.rich_text import RichText

from cms.models import HomePage, StandardPage

BY_PATH = "/api/cms/public/pages/by-path/"


def make_home(slug="connect", title="IMAA Connect"):
    root = Page.get_first_root_node()
    home = HomePage(title=title, slug=slug, live=True)
    root.add_child(instance=home)
    return home


def make_standard(parent, slug, title=None, body="<p>Body</p>", live=True, **fields):
    page = StandardPage(title=title or slug.replace("-", " ").title(), slug=slug, body=body, live=live, **fields)
    parent.add_child(instance=page)
    return page


def point_default_site_at(home, hostname="connect.test"):
    site = Site.objects.get(is_default_site=True)
    site.root_page = home
    site.hostname = hostname
    site.save()
    return site


class PublicPageByPathResolutionTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.home = make_home()
        self.site = point_default_site_at(self.home)

    def get(self, path):
        return self.client.get(BY_PATH, {"path": path})

    def test_resolves_nested_path_and_exposes_public_fields(self):
        legal = make_standard(self.home, "legal")
        make_standard(
            legal,
            "privacy-policy",
            title="Privacy Policy",
            body="<p>We respect your privacy.</p>",
            seo_title="Privacy Policy | IMAA Connect",
            search_description="How IMAA Connect handles personal data.",
        )

        response = self.get("/legal/privacy-policy/")

        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertEqual(data["title"], "Privacy Policy")
        self.assertEqual(data["slug"], "privacy-policy")
        self.assertEqual(data["type"], "StandardPage")
        self.assertEqual(data["path"], "/legal/privacy-policy/")
        self.assertIn("<p>We respect your privacy.</p>", data["body_html"])
        self.assertEqual(data["seo_title"], "Privacy Policy | IMAA Connect")
        self.assertEqual(data["search_description"], "How IMAA Connect handles personal data.")
        self.assertIn("first_published_at", data)
        self.assertIn("last_published_at", data)

    def test_path_without_trailing_slash_resolves_too(self):
        make_standard(self.home, "imprint", body="<p>Imprint</p>")
        self.assertEqual(self.get("/imprint").status_code, 200)
        self.assertEqual(self.get("/imprint/").json()["path"], "/imprint/")

    def test_duplicate_final_slugs_resolve_to_their_own_page(self):
        members = make_standard(self.home, "members")
        partners = make_standard(self.home, "partners")
        make_standard(members, "terms-and-conditions", body="<p>Member terms</p>")
        make_standard(partners, "terms-and-conditions", body="<p>Partner terms</p>")

        member_terms = self.get("/members/terms-and-conditions/").json()
        partner_terms = self.get("/partners/terms-and-conditions/").json()

        self.assertIn("Member terms", member_terms["body_html"])
        self.assertIn("Partner terms", partner_terms["body_html"])
        self.assertNotEqual(member_terms["id"], partner_terms["id"])
        # The slug endpoint cannot tell them apart: it returns one of the two.
        by_slug = self.client.get("/api/cms/pages/terms-and-conditions/")
        self.assertEqual(by_slug.status_code, 200)
        self.assertIn(by_slug.json()["id"], {member_terms["id"], partner_terms["id"]})

    def test_missing_page_is_404(self):
        self.assertEqual(self.get("/does-not-exist/").status_code, 404)
        make_standard(self.home, "references")
        self.assertEqual(self.get("/references/missing-child/").status_code, 404)

    def test_unpublished_page_is_404(self):
        make_standard(self.home, "privacy-policy", live=False)
        self.assertEqual(self.get("/privacy-policy/").status_code, 404)

    def test_expired_page_is_404(self):
        make_standard(self.home, "privacy-policy", expire_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.get("/privacy-policy/").status_code, 404)

    def test_archived_page_is_404(self):
        page = make_standard(self.home, "privacy-policy")
        page.soft_delete(reason="test")
        self.assertEqual(self.get("/privacy-policy/").status_code, 404)

    def test_archived_ancestor_hides_live_children(self):
        legal = make_standard(self.home, "legal")
        make_standard(legal, "privacy-policy")
        self.assertEqual(self.get("/legal/privacy-policy/").status_code, 200)

        # Archive only the parent record (without unpublishing the child): the subtree is gone.
        StandardPage.objects.filter(pk=legal.pk).update(cms_is_deleted=True)
        self.assertEqual(self.get("/legal/privacy-policy/").status_code, 404)

    def test_unpublished_ancestor_still_routes_to_live_child(self):
        # Wagtail semantics: a draft parent does not block its published children.
        legal = make_standard(self.home, "legal", live=False)
        make_standard(legal, "imprint")
        self.assertEqual(self.get("/legal/").status_code, 404)
        self.assertEqual(self.get("/legal/imprint/").status_code, 200)

    def test_view_restriction_on_ancestor_is_404(self):
        legal = make_standard(self.home, "legal")
        make_standard(legal, "privacy-policy")
        PageViewRestriction.objects.create(page=legal, restriction_type="password", password="secret")
        self.assertEqual(self.get("/legal/privacy-policy/").status_code, 404)

    def test_view_restriction_on_page_is_404(self):
        page = make_standard(self.home, "privacy-policy")
        PageViewRestriction.objects.create(page=page, restriction_type="login")
        self.assertEqual(self.get("/privacy-policy/").status_code, 404)

    def test_unsupported_page_type_is_404(self):
        self.home.add_child(instance=Page(title="Plain", slug="plain", live=True))
        self.assertEqual(self.get("/plain/").status_code, 404)

    def test_root_path_and_invalid_paths_are_400(self):
        for bad in ["/", "privacy-policy", "/a//b/", "/../privacy-policy/", "/x?y=1", "/a b/", "/x#frag", "/a\\b/", "x" * 600]:
            with self.subTest(path=bad):
                self.assertEqual(self.get(bad).status_code, 400, bad)
        self.assertEqual(self.client.get(BY_PATH).status_code, 400)


class PublicPageByPathSiteSelectionTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.home_a = make_home(slug="connect-a", title="Site A")
        self.site_a = point_default_site_at(self.home_a, hostname="a.test")
        self.home_b = make_home(slug="connect-b", title="Site B")
        self.site_b = Site.objects.create(hostname="b.test", port=80, root_page=self.home_b, is_default_site=False)
        make_standard(self.home_a, "privacy-policy", body="<p>Site A policy</p>")
        make_standard(self.home_b, "imprint", body="<p>Site B imprint</p>")

    def get(self, path):
        return self.client.get(BY_PATH, {"path": path})

    def test_default_site_is_used_when_hostname_not_configured(self):
        with override_settings(CMS_PUBLIC_SITE_HOSTNAME=""):
            self.assertIn("Site A policy", self.get("/privacy-policy/").json()["body_html"])
            # Site B's page is not reachable through site A.
            self.assertEqual(self.get("/imprint/").status_code, 404)

    def test_configured_hostname_selects_that_site(self):
        with override_settings(CMS_PUBLIC_SITE_HOSTNAME="b.test"):
            self.assertIn("Site B imprint", self.get("/imprint/").json()["body_html"])
            self.assertEqual(self.get("/privacy-policy/").status_code, 404)
        with override_settings(CMS_PUBLIC_SITE_HOSTNAME="B.TEST"):
            self.assertEqual(self.get("/imprint/").status_code, 200)

    def test_unknown_configured_hostname_is_503(self):
        with override_settings(CMS_PUBLIC_SITE_HOSTNAME="nowhere.test"):
            response = self.get("/privacy-policy/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("nowhere.test", response.json()["detail"])

    def test_multiple_sites_without_default_is_503(self):
        Site.objects.update(is_default_site=False)
        with override_settings(CMS_PUBLIC_SITE_HOSTNAME=""):
            response = self.get("/privacy-policy/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("CMS_PUBLIC_SITE_HOSTNAME", response.json()["detail"])

    def test_hostname_matching_two_sites_is_503(self):
        Site.objects.create(hostname="a.test", port=8080, root_page=self.home_b, is_default_site=False)
        with override_settings(CMS_PUBLIC_SITE_HOSTNAME="a.test"):
            response = self.get("/privacy-policy/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("matches 2", response.json()["detail"])


RAW_BODY = (
    "<p>Hello <strong>there</strong>.</p>"
    "<script>alert(1)</script>"
    '<img src="/media/images/photo.png" alt="Photo">'
    '<a href="/cms/documents/7/terms.pdf">Download</a>'
    '<a href="https://example.com/x">External</a>'
    '<a href="/about/">About</a>'
    '<p onclick="steal()" style="color:red">Styled</p>'
    '<a href="javascript:alert(2)">bad</a>'
)


class PublicPageRichTextTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.home = make_home()
        point_default_site_at(self.home)
        make_standard(self.home, "privacy-policy", body=RAW_BODY)

    def test_body_html_is_sanitised_and_media_urls_absolute(self):
        html = self.client.get(BY_PATH, {"path": "/privacy-policy/"}).json()["body_html"]

        self.assertIn("<p>Hello <strong>there</strong>.</p>", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("alert(1)", html)
        self.assertNotIn("onclick", html)
        self.assertNotIn("style=", html)
        self.assertNotIn("javascript:", html)
        # Backend media and documents become absolute; page links stay relative.
        self.assertIn('src="http://testserver/media/images/photo.png"', html)
        self.assertIn('href="http://testserver/cms/documents/7/terms.pdf"', html)
        self.assertIn('href="/about/"', html)
        # External links get the safe rel.
        self.assertIn('href="https://example.com/x" rel="noopener noreferrer"', html)

    def test_slug_endpoint_contract_is_unchanged(self):
        response = self.client.get("/api/cms/pages/privacy-policy/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(set(data.keys()), {"id", "title", "slug", "type", "body_html"})
        # Unsanitised, exactly as before this change.
        self.assertEqual(data["body_html"], str(RichText(RAW_BODY)))


class PublicPageAbsenceSignalTests(TestCase):
    """404 ``code`` for the default-eligible paths: absent vs unavailable, never more detail."""

    def setUp(self):
        self.client = APIClient()
        self.home = make_home()
        self.site = point_default_site_at(self.home)

    def get(self, path):
        return self.client.get(BY_PATH, {"path": path})

    def assert_code(self, path, code):
        response = self.get(path)
        self.assertEqual(response.status_code, 404, response.content)
        self.assertEqual(response.json(), {"detail": "Not found", "code": code})
        return response

    def test_missing_eligible_page_is_absent(self):
        for slug in ("frequently-asked-questions", "references", "terms-and-conditions", "privacy-policy", "imprint"):
            with self.subTest(slug=slug):
                self.assert_code(f"/{slug}/", "page_absent")
        self.assert_code("/imprint", "page_absent")

    def test_found_page_has_no_code(self):
        make_standard(self.home, "imprint", body="<p>Imprint</p>")
        response = self.get("/imprint/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("code", response.json())

    def test_draft_is_unavailable_and_reveals_nothing(self):
        make_standard(self.home, "imprint", title="Secret Draft Title", body="<p>Draft body</p>", live=False)
        response = self.assert_code("/imprint/", "page_unavailable")
        self.assertNotIn(b"Secret Draft Title", response.content)
        self.assertNotIn(b"Draft body", response.content)

    def test_unpublished_page_is_unavailable(self):
        page = make_standard(self.home, "imprint")
        page.unpublish()
        self.assert_code("/imprint/", "page_unavailable")

    def test_expired_page_is_unavailable(self):
        make_standard(self.home, "imprint", expire_at=timezone.now() - timedelta(minutes=1))
        self.assert_code("/imprint/", "page_unavailable")

    def test_archived_page_is_unavailable(self):
        page = make_standard(self.home, "imprint")
        page.soft_delete(reason="test")
        self.assert_code("/imprint/", "page_unavailable")

    def test_restricted_page_is_unavailable(self):
        page = make_standard(self.home, "imprint")
        PageViewRestriction.objects.create(page=page, restriction_type="password", password="secret")
        response = self.assert_code("/imprint/", "page_unavailable")
        self.assertNotIn(b"password", response.content)

    def test_restricted_site_root_blocks_absence(self):
        PageViewRestriction.objects.create(page=self.home, restriction_type="login")
        self.assert_code("/imprint/", "page_unavailable")

    def test_archived_site_root_blocks_absence(self):
        HomePage.objects.filter(pk=self.home.pk).update(cms_is_deleted=True)
        self.assert_code("/imprint/", "page_unavailable")

    def test_site_root_that_is_not_the_homepage_blocks_absence(self):
        # Wagtail's default "Welcome" page as Site root: the published pages under the HomePage
        # are out of reach, so a missing path proves nothing and defaults must not appear.
        welcome = Page.objects.get(depth=2, slug="home")
        self.site.root_page = welcome
        self.site.save()
        make_standard(self.home, "imprint")
        for slug in ("imprint", "privacy-policy"):
            with self.subTest(slug=slug):
                self.assert_code(f"/{slug}/", "page_unavailable")

    def test_out_of_sync_child_counter_does_not_make_a_draft_look_absent(self):
        make_standard(self.home, "imprint", live=False)
        Page.objects.filter(pk=self.home.pk).update(numchild=0)  # treebeard counter out of sync
        self.assert_code("/imprint/", "page_unavailable")

    def test_other_page_type_at_slug_is_unavailable(self):
        self.home.add_child(instance=Page(title="Plain", slug="imprint", live=True))
        self.assert_code("/imprint/", "page_unavailable")

    def test_wagtail_redirect_for_path_is_unavailable(self):
        from wagtail.contrib.redirects.models import Redirect

        Redirect.add_redirect("/imprint/", redirect_to="/legal/imprint/", site=self.site)
        self.assert_code("/imprint/", "page_unavailable")

    def test_global_redirect_for_path_is_unavailable(self):
        from wagtail.contrib.redirects.models import Redirect

        Redirect.add_redirect("/imprint", redirect_to="https://example.com/imprint")
        self.assert_code("/imprint/", "page_unavailable")

    def test_page_elsewhere_in_tree_does_not_make_path_unavailable(self):
        legal = make_standard(self.home, "legal")
        make_standard(legal, "imprint")
        self.assert_code("/imprint/", "page_absent")

    def test_page_in_another_site_does_not_make_path_unavailable(self):
        other_home = make_home(slug="other-home", title="Other")
        Site.objects.create(hostname="other.test", port=80, root_page=other_home, is_default_site=False)
        make_standard(other_home, "imprint", live=False)
        self.assert_code("/imprint/", "page_absent")

    def test_non_eligible_paths_keep_plain_404(self):
        self.assertEqual(self.get("/unknown-page/").json(), {"detail": "Not found"})
        make_standard(self.home, "legal", live=False)
        self.assertEqual(self.get("/legal/").json(), {"detail": "Not found"})
        self.assertEqual(self.get("/legal/imprint/").json(), {"detail": "Not found"})

    def test_slug_endpoint_contract_unchanged_for_missing_page(self):
        response = self.client.get("/api/cms/pages/imprint/")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Not found"})
