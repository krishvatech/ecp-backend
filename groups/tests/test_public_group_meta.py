"""Server-rendered social-preview metadata for public group landing pages.

Covers the HTML endpoint GET /groups/public/<slug>/ that the
ecp-event-social-preview Cloudflare Worker serves to social crawlers.
"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.files.storage import FileSystemStorage
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from community.models import Community
from events.models import Event
from groups.models import Group


User = get_user_model()

FRONTEND = "https://connect.example.org"
LOCAL_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
CDN_STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"base_url": "https://media-bucket.example.com/"},
    },
    "staticfiles": LOCAL_STORAGES["staticfiles"],
}


class SignedUrlStorage(FileSystemStorage):
    """Mimics an S3 storage that would hand out presigned (expiring) URLs."""

    def url(self, name):
        return (
            f"https://media-bucket.example.com/{name}"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE"
            "&X-Amz-Signature=deadbeef"
        )


SIGNED_STORAGES = {
    "default": {"BACKEND": f"{__name__}.SignedUrlStorage"},
    "staticfiles": LOCAL_STORAGES["staticfiles"],
}


@override_settings(FRONTEND_URL=f"{FRONTEND}/", STORAGES=LOCAL_STORAGES, MEDIA_URL="/media/")
class PublicGroupMetaTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(
            username="group-meta-owner",
            email="group-meta-owner@example.com",
            password="pass1234",
        )
        cls.community = Community.objects.create(
            name="Group Meta Test Community",
            owner=cls.owner,
        )

    def _group(self, cover_image="", logo="", **overrides):
        values = {
            "name": "Cloud & Data Forum",
            "slug": "cloud-data-forum",
            "short_description": "",
            "description": "A forum about cloud and data topics.",
            "community": self.community,
            "owner": self.owner,
            "created_by": self.owner,
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
            "public_landing_enabled": True,
        }
        values.update(overrides)
        group = Group.objects.create(**values)
        if cover_image or logo:
            # Group.save() reads image sizes; set stored names directly so no
            # real files are needed or written.
            Group.all_objects.filter(pk=group.pk).update(cover_image=cover_image, logo=logo)
            group.refresh_from_db()
        return group

    def _get(self, slug, **extra):
        return self.client.get(
            reverse("public-group-meta", kwargs={"slug": slug}), secure=True, **extra
        )

    # --- happy path -----------------------------------------------------

    def test_anonymous_request_returns_html_with_group_title(self):
        group = self._group()

        response = self._get(group.slug)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Type"].startswith("text/html"))
        self.assertContains(response, "<title>Cloud &amp; Data Forum</title>", html=False)
        self.assertContains(response, '<meta property="og:title" content="Cloud &amp; Data Forum" />')
        self.assertContains(response, '<meta name="twitter:title" content="Cloud &amp; Data Forum" />')
        self.assertContains(response, '<meta property="og:type" content="website" />')
        self.assertContains(response, '<meta name="twitter:card" content="summary_large_image" />')

    def test_short_description_is_preferred(self):
        group = self._group(short_description="Short tagline here.")

        response = self._get(group.slug)

        self.assertContains(response, '<meta property="og:description" content="Short tagline here." />')
        self.assertContains(response, '<meta name="twitter:description" content="Short tagline here." />')
        self.assertNotContains(response, "A forum about cloud and data topics.")

    def test_full_description_used_when_short_description_empty(self):
        group = self._group(short_description="   ")

        response = self._get(group.slug)

        self.assertContains(
            response,
            '<meta property="og:description" content="A forum about cloud and data topics." />',
        )

    def test_generic_fallback_when_no_description(self):
        group = self._group(description="")

        response = self._get(group.slug)

        self.assertContains(response, '<meta property="og:description" content="Join this group." />')

    def test_html_is_stripped_whitespace_normalised_and_output_escaped(self):
        group = self._group(
            name='Deals "Insider" <b>Club</b>',
            description=(
                '<p>Mergers &amp; <strong>Acquisitions</strong></p>\n\n'
                '<script>alert(1)</script>   "quoted" <img src=x onerror=alert(2)>'
            ),
        )

        body = self._get(group.slug).content.decode()

        self.assertIn('content="Deals &quot;Insider&quot; Club"', body)
        self.assertIn(
            '<meta property="og:description" content="Mergers &amp; Acquisitions alert(1) &quot;quoted&quot;" />',
            body,
        )
        self.assertNotIn("<script", body)
        self.assertNotIn("<img", body)
        self.assertNotIn("<strong>", body)

    def test_long_description_is_truncated(self):
        group = self._group(description="word " * 100)

        response = self._get(group.slug)

        description = response.context["description"]
        self.assertLessEqual(len(description), 200)
        self.assertTrue(description.endswith("..."))

    def test_canonical_url_points_to_frontend_group_page(self):
        group = self._group()

        response = self._get(group.slug)

        url = f"{FRONTEND}/groups/public/cloud-data-forum"
        self.assertContains(response, f'<meta property="og:url" content="{url}" />')
        self.assertContains(response, f'<link rel="canonical" href="{url}" />')
        self.assertContains(response, f'<meta http-equiv="refresh" content="0; url={url}" />')

    # --- images ---------------------------------------------------------

    def test_cover_image_preferred_over_logo(self):
        group = self._group(cover_image="group_covers/cover.jpg", logo="group_logos/logo.png")

        response = self._get(group.slug)

        self.assertContains(
            response,
            '<meta property="og:image" content="https://testserver/media/group_covers/cover.jpg" />',
        )
        self.assertContains(
            response,
            '<meta name="twitter:image" content="https://testserver/media/group_covers/cover.jpg" />',
        )
        self.assertNotContains(response, "group_logos/logo.png")

    def test_logo_used_when_cover_missing(self):
        group = self._group(logo="group_logos/logo.png")

        response = self._get(group.slug)

        self.assertContains(
            response,
            '<meta property="og:image" content="https://testserver/media/group_logos/logo.png" />',
        )

    def test_missing_images_render_without_image_tags(self):
        group = self._group()

        response = self._get(group.slug)

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "og:image")
        self.assertNotContains(response, "twitter:image")

    @override_settings(STORAGES=CDN_STORAGES)
    def test_absolute_storage_urls_are_kept_as_https(self):
        group = self._group(cover_image="group_covers/cover.jpg")

        response = self._get(group.slug)

        self.assertContains(
            response,
            '<meta property="og:image" content="https://media-bucket.example.com/group_covers/cover.jpg" />',
        )

    def test_real_s3_storage_custom_domain_public_and_presigned_rejected(self):
        group = self._group(cover_image="group_covers/cover.jpg")
        s3_options = {
            "bucket_name": "example-bucket",
            "region_name": "eu-central-1",
            "access_key": "AKIAEXAMPLEONLY",
            "secret_key": "example-secret-only",
        }

        # Production shape: AWS_S3_CUSTOM_DOMAIN set -> plain public URL.
        with override_settings(STORAGES={
            **LOCAL_STORAGES,
            "default": {
                "BACKEND": "storages.backends.s3.S3Storage",
                "OPTIONS": {**s3_options, "custom_domain": "example-bucket.s3.eu-central-1.amazonaws.com"},
            },
        }):
            response = self._get(group.slug)
        self.assertContains(
            response,
            '<meta property="og:image" '
            'content="https://example-bucket.s3.eu-central-1.amazonaws.com/group_covers/cover.jpg" />',
        )

        # No custom domain -> boto3 presigns locally; it must never be published.
        with override_settings(STORAGES={
            **LOCAL_STORAGES,
            "default": {
                "BACKEND": "storages.backends.s3.S3Storage",
                "OPTIONS": {**s3_options, "custom_domain": None, "querystring_auth": True},
            },
        }):
            response = self._get(group.slug)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "og:image")
        self.assertNotContains(response, "X-Amz")

    @override_settings(FRONTEND_URL="https://connect.imaa-institute.org")
    def test_production_frontend_url_canonical(self):
        group = self._group()

        response = self._get(group.slug)

        self.assertEqual(
            response.context["group_url"],
            "https://connect.imaa-institute.org/groups/public/cloud-data-forum",
        )

    @override_settings(STORAGES=SIGNED_STORAGES)
    def test_signed_storage_urls_are_never_published(self):
        group = self._group(cover_image="group_covers/cover.jpg", logo="group_logos/logo.png")

        response = self._get(group.slug)

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "og:image")
        self.assertNotContains(response, "X-Amz")

    # --- exposure rules -------------------------------------------------

    def test_private_group_returns_404(self):
        group = self._group(visibility=Group.VISIBILITY_PRIVATE, join_policy=Group.JOIN_INVITE)

        response = self._get(group.slug)

        self.assertEqual(response.status_code, 404)
        self.assertNotContains(response, "Cloud", status_code=404)

    def test_disabled_public_landing_returns_404(self):
        group = self._group(public_landing_enabled=False)

        self.assertEqual(self._get(group.slug).status_code, 404)

    def test_soft_deleted_group_returns_404(self):
        group = self._group()
        Group.all_objects.filter(pk=group.pk).update(is_deleted=True, deleted_at=timezone.now())

        self.assertEqual(self._get(group.slug).status_code, 404)

    def test_unknown_slug_returns_404(self):
        self.assertEqual(self._get("does-not-exist").status_code, 404)

    # --- methods --------------------------------------------------------

    def test_head_request_returns_200_without_body(self):
        group = self._group()

        response = self.client.head(
            reverse("public-group-meta", kwargs={"slug": group.slug}), secure=True
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")

    def test_unsafe_methods_are_rejected(self):
        group = self._group()

        response = self.client.post(
            reverse("public-group-meta", kwargs={"slug": group.slug}), secure=True
        )

        self.assertEqual(response.status_code, 405)

    # --- regressions ----------------------------------------------------

    def test_html_route_does_not_shadow_public_json_api(self):
        group = self._group(short_description="Short tagline here.")

        response = self.client.get(
            reverse("public-group-landing", kwargs={"slug": group.slug}), secure=True
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json()["short_description"], "Short tagline here.")

    def test_event_meta_endpoints_are_unchanged(self):
        Event.objects.create(
            title="Sample Summit",
            slug="sample-summit",
            description="<p>An example event.</p>",
            format="virtual",
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            community=self.community,
            created_by=self.owner,
            status="published",
        )

        for name, page_type in (
            ("public-event-meta", "public"),
            ("event-meta", "events"),
            ("landing-event-meta", "landing"),
        ):
            with self.subTest(page_type=page_type):
                response = self.client.get(
                    reverse(name, kwargs={"slug": "sample-summit"}), secure=True
                )
                self.assertEqual(response.status_code, 200)
                self.assertTemplateUsed(response, "public_event_meta.html")
                self.assertContains(response, '<meta property="og:title" content="Sample Summit" />')
                self.assertContains(
                    response,
                    f'<meta property="og:url" content="{FRONTEND}/{page_type}/sample-summit/" />',
                )
