# Our Team schema change (implemented, migration not applied)

Status: **approved and implemented in `cms/models.py` and `cms/public_pages.py` (2026-10-10);
migration `cms/migrations/0017_programme_teammember_teampage.py` generated locally, not applied.**
Applying it, importing the content and deploying each need separate approval.

## Why

The WordPress Our Team page (imaa-institute.org/our-team/, page 1982) lists 63 faculty and 24 staff
(87 WordPress `team` posts; the page shows 184 cards because faculty repeat under each programme
tab) with seven programme filters. Nothing in ECP models public Institute people: community
profiles are IMAA Connect user accounts, `events.VirtualSpeaker` is per event. The content package
(`cms/team_page_content/`), the API serialisation (`cms/team_page_api.py`), the import command
(`populate_team_page`) and the frontend are implemented and wait only for these models.

## Change

* `Programme` snippet: the filter list (code shown on the filter, slug, order). Editable labels
  and order; filters with no public faculty are not shown.
* `TeamMember` snippet: one record per person: name, unique slug, type (faculty / staff /
  advisory board), position, one-line summary, biography (rich text, for a future profile page),
  photo, location, LinkedIn, profile URL (imaa-institute.org until profiles are migrated),
  **many-to-many `programmes`** (a person in several programmes is one record), order,
  `is_public`, WordPress ID. Not linked to user accounts.
* `TeamPage` page (under the HomePage, no children, at most one per site tree: `max_count = 1`): hero title/intro/button, faculty heading,
  subheading, intro and up to three buttons, staff heading, subheading, intro and button, and the
  same reusable `sections` blocks as the About page (programme carousel, offices).
* `cms/public_pages.py`: `TeamPage` joins `SUPPORTED_PAGE_TYPES`, so the public by-path API serves it
  with the same publication, restriction and archive rules as the other public pages.

No existing model or field changes.

## Expected migration (from `makemigrations --dry-run` on a scratch copy)

`cms/migrations/0017_programme_teammember_teampage.py`, depending on
`cms.0016_about_page_sections_testimonial`: `CreateModel Programme`, `CreateModel TeamMember`
(including its many-to-many table to Programme), `CreateModel TeamPage`. Additive and reversible
(migrating back to 0016 drops the new tables). Like 0016 it is git-ignored (`**/migrations/**`)
and must be preserved deliberately for deployment.

## After approval

1. Apply the diff below, then `python manage.py makemigrations cms` (expect exactly 0017).
2. Locally (separate approval): `AWS_BUCKET_NAME= SENTRY_DSN= python manage.py migrate cms 0017`.
3. `AWS_BUCKET_NAME= SENTRY_DSN= python manage.py populate_team_page` (preview), then, once the
   preview is approved, `... populate_team_page --apply --publish`.
4. `pytest cms/test_team_page.py` (the apply test runs once the models exist).

## Model diff

```diff
--- a/cms/models.py
+++ b/cms/models.py
@@ -1,3 +1,4 @@
+from django import forms
 from django.db import models
 from django.conf import settings
 from django.utils import timezone
@@ -12,7 +13,7 @@
 from wagtail.snippets.models import register_snippet
 from wagtail_ai.panels import AITitleFieldPanel, AIDescriptionFieldPanel
 
-from cms.about_blocks import RICH_TEXT_FEATURES, SECTION_BLOCKS, STAT_BLOCKS, validate_safe_url
+from cms.about_blocks import RICH_TEXT_FEATURES, SECTION_BLOCKS, STAT_BLOCKS, LinkBlock, validate_safe_url
 
 
 class CmsSoftDeletePageMixin(models.Model):
@@ -351,6 +352,108 @@
         return self.name
 
 
+@register_snippet
+class Programme(models.Model):
+    """A training programme used to group people on the Our Team page (IM&A, CPMI, ...)."""
+
+    code = models.CharField(max_length=20, unique=True, help_text="Shown on the filter, e.g. IM&A")
+    slug = models.SlugField(max_length=40, unique=True)
+    sort_order = models.PositiveIntegerField(default=0)
+
+    panels = [FieldPanel("code"), FieldPanel("slug"), FieldPanel("sort_order")]
+
+    class Meta:
+        ordering = ["sort_order", "code"]
+
+    def __str__(self):
+        return self.code
+
+
+@register_snippet
+class TeamMember(models.Model):
+    """A public faculty or staff member of the Institute (not an IMAA Connect user account)."""
+
+    FACULTY, STAFF, ADVISORY = "faculty", "staff", "advisory"
+    MEMBER_TYPES = [(FACULTY, "Faculty"), (STAFF, "Staff"), (ADVISORY, "Advisory board")]
+
+    name = models.CharField(max_length=160)
+    slug = models.SlugField(max_length=160, unique=True)
+    member_type = models.CharField(max_length=20, choices=MEMBER_TYPES, db_index=True)
+    position = models.CharField(max_length=200, blank=True, help_text="Shown on the card, e.g. Faculty or Managing Director")
+    summary = models.TextField(blank=True, max_length=400, help_text="One-line tagline on the card")
+    biography = RichTextField(blank=True, features=RICH_TEXT_FEATURES)
+    photo = models.ForeignKey(
+        "wagtailimages.Image", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
+    )
+    location = models.CharField(max_length=120, blank=True, help_text="City (staff) or country (faculty)")
+    linkedin_url = models.URLField(max_length=300, blank=True)
+    profile_url = models.CharField(
+        max_length=300, blank=True, validators=[validate_safe_url],
+        help_text="Full profile page (imaa-institute.org until profiles are migrated).",
+    )
+    programmes = models.ManyToManyField(Programme, blank=True, related_name="team_members")
+    sort_order = models.PositiveIntegerField(default=0, db_index=True)
+    is_public = models.BooleanField(default=True, help_text="Untick to hide this person from the public page.")
+    wordpress_id = models.PositiveIntegerField(null=True, blank=True, unique=True, editable=False)
+
+    panels = [
+        FieldPanel("name"),
+        FieldPanel("slug"),
+        FieldPanel("member_type"),
+        FieldPanel("position"),
+        FieldPanel("summary"),
+        FieldPanel("photo"),
+        FieldPanel("location"),
+        FieldPanel("programmes", widget=forms.CheckboxSelectMultiple),
+        FieldPanel("biography"),
+        FieldPanel("linkedin_url"),
+        FieldPanel("profile_url"),
+        FieldPanel("sort_order"),
+        FieldPanel("is_public"),
+    ]
+
+    class Meta:
+        ordering = ["member_type", "sort_order", "name"]
+
+    def __str__(self):
+        return f"{self.name} ({self.get_member_type_display()})"
+
+
+class TeamPage(CmsSoftDeletePageMixin, Page):
+    """The public Our Team page: page texts here; the people are TeamMember snippets."""
+
+    hero_title = models.CharField(max_length=160, blank=True)
+    hero_intro = models.TextField(blank=True)
+    hero_button = StreamField([("button", LinkBlock())], blank=True, use_json_field=True, max_num=1)
+    faculty_heading = models.CharField(max_length=160, blank=True)
+    faculty_subheading = models.CharField(max_length=160, blank=True)
+    faculty_intro = RichTextField(blank=True, features=RICH_TEXT_FEATURES)
+    faculty_buttons = StreamField([("button", LinkBlock())], blank=True, use_json_field=True, max_num=3)
+    staff_heading = models.CharField(max_length=160, blank=True)
+    staff_subheading = models.CharField(max_length=160, blank=True)
+    staff_intro = RichTextField(blank=True, features=RICH_TEXT_FEATURES)
+    staff_button = StreamField([("button", LinkBlock())], blank=True, use_json_field=True, max_num=1)
+    # Ordered sections after the people (programme carousel, offices, ...), as on the About page.
+    sections = StreamField(SECTION_BLOCKS, blank=True, use_json_field=True)
+
+    content_panels = Page.content_panels + [
+        MultiFieldPanel([FieldPanel("hero_title"), FieldPanel("hero_intro"), FieldPanel("hero_button")], heading="Hero"),
+        MultiFieldPanel(
+            [FieldPanel("faculty_heading"), FieldPanel("faculty_subheading"), FieldPanel("faculty_intro"), FieldPanel("faculty_buttons")],
+            heading="Experts & faculty",
+        ),
+        MultiFieldPanel(
+            [FieldPanel("staff_heading"), FieldPanel("staff_subheading"), FieldPanel("staff_intro"), FieldPanel("staff_button")],
+            heading="Staff",
+        ),
+        FieldPanel("sections", heading="Page sections"),
+    ]
+
+    parent_page_types = ["cms.HomePage"]
+    subpage_types = []
+    max_count = 1
+
+
 class EventsLandingPage(CmsSoftDeletePageMixin, Page):
     # Hero
     hero_title = models.CharField(
--- a/cms/public_pages.py
+++ b/cms/public_pages.py
@@ -37,12 +37,12 @@
 from wagtail.contrib.redirects.models import Redirect
 from wagtail.models import Page, Site
 
-from cms.models import AboutPage, EventsLandingPage, HomePage, StandardPage
+from cms.models import AboutPage, EventsLandingPage, HomePage, StandardPage, TeamPage
 from cms.public_page_content import PUBLIC_PAGE_SLUGS
 
 # Page types the public website knows how to render. Plain ``wagtailcore.Page`` rows
 # (for example Wagtail's default "Welcome" page) are deliberately not exposed.
-SUPPORTED_PAGE_TYPES = (StandardPage, HomePage, AboutPage, EventsLandingPage)
+SUPPORTED_PAGE_TYPES = (StandardPage, HomePage, AboutPage, EventsLandingPage, TeamPage)
 
 MAX_PATH_LENGTH = 512
 # Wagtail's default slug alphabet (``allow_unicode`` is off for these page types).
```
