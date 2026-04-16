from django.db import models
from django.core.exceptions import ValidationError
from django.template import Template as DjangoTemplate, TemplateSyntaxError

from wagtail import blocks
from wagtail.images.blocks import ImageChooserBlock
from wagtail.fields import StreamField, RichTextField
from wagtail.admin.panels import FieldPanel, MultiFieldPanel
from wagtail.models import Page
from wagtail.snippets.models import register_snippet
from wagtail_ai.panels import AITitleFieldPanel, AIDescriptionFieldPanel

class HomeFeaturedCardBlock(blocks.StructBlock):
    image = ImageChooserBlock(required=False)
    title = blocks.CharBlock(required=True, max_length=120)
    desc = blocks.TextBlock(required=True, max_length=400)
    link_url = blocks.CharBlock(required=False, max_length=200)

    class Meta:
        icon = "doc-full"
        label = "Featured Event Card"


class HomeMiniCardBlock(blocks.StructBlock):
    image = ImageChooserBlock(required=False)
    title = blocks.CharBlock(required=True, max_length=120)
    desc = blocks.TextBlock(required=True, max_length=400)
    link_url = blocks.CharBlock(required=False, max_length=200)

    class Meta:
        icon = "doc-full"
        label = "Community Card"


class HomePage(Page):
    intro = RichTextField(blank=True)
    hero_title = models.CharField(
        max_length=160,
        blank=True,
        default="Connect, Collaborate, and Grow Your M&A Network",
    )
    hero_subtitle = models.TextField(
        blank=True,
        default=(
            "IMAA Connect is the premier platform for M&A professionals to "
            "discover events, engage with peers, and access valuable resources."
        ),
    )
    hero_background_image = models.ForeignKey(
        "wagtailimages.Image",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    hero_cta_label = models.CharField(
        max_length=80,
        blank=True,
        default="Explore Events",
    )
    hero_cta_url = models.CharField(
        max_length=200,
        blank=True,
        default="/events",
    )
    search_placeholder = models.CharField(
        max_length=160,
        blank=True,
        default="Search for events by keyword or location",
    )
    featured_events_title = models.CharField(
        max_length=120,
        blank=True,
        default="Featured Events",
    )
    featured_events = StreamField(
        [("featured_event", HomeFeaturedCardBlock())],
        blank=True,
        use_json_field=True,
    )
    community_title = models.CharField(
        max_length=120,
        blank=True,
        default="Community Highlights",
    )
    community_cards = StreamField(
        [("community_card", HomeMiniCardBlock())],
        blank=True,
        use_json_field=True,
    )
    newsletter_title = models.CharField(
        max_length=160,
        blank=True,
        default="Stay Updated with Our Newsletter",
    )
    newsletter_subtitle = models.TextField(
        blank=True,
        default=(
            "Get the latest news, event announcements, and exclusive content "
            "delivered straight to your inbox."
        ),
    )
    newsletter_email_placeholder = models.CharField(
        max_length=120,
        blank=True,
        default="Enter your email",
    )
    newsletter_button_label = models.CharField(
        max_length=60,
        blank=True,
        default="Subscribe",
    )

    content_panels = Page.content_panels + [
        MultiFieldPanel(
            [
                AITitleFieldPanel("hero_title"),
                AITitleFieldPanel("hero_subtitle"),
                FieldPanel("hero_background_image"),
                FieldPanel("hero_cta_label"),
                FieldPanel("hero_cta_url"),
            ],
            heading="Hero Section",
        ),
        MultiFieldPanel(
            [
                FieldPanel("search_placeholder"),
            ],
            heading="Search Bar",
        ),
        MultiFieldPanel(
            [
                FieldPanel("featured_events_title"),
                FieldPanel("featured_events"),
            ],
            heading="Featured Events",
        ),
        MultiFieldPanel(
            [
                FieldPanel("community_title"),
                FieldPanel("community_cards"),
            ],
            heading="Community Highlights",
        ),
        MultiFieldPanel(
            [
                FieldPanel("newsletter_title"),
                FieldPanel("newsletter_subtitle"),
                FieldPanel("newsletter_email_placeholder"),
                FieldPanel("newsletter_button_label"),
            ],
            heading="Newsletter",
        ),
        FieldPanel("intro"),
    ]


class StandardPage(Page):
    body = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel("body"),
    ]

    parent_page_types = ["cms.HomePage", "cms.StandardPage"]
    subpage_types = ["cms.StandardPage"]


class AboutFeatureBlock(blocks.StructBlock):
    image = ImageChooserBlock(required=False)
    title = blocks.CharBlock(required=True, max_length=120)
    desc = blocks.TextBlock(required=True, max_length=400)

    class Meta:
        icon = "doc-full"
        label = "Feature Card"


class AboutPage(Page):
    # Hero
    hero_title = models.CharField(max_length=160, blank=True, default="About IMAA Connect")
    hero_subtitle = models.TextField(blank=True, default="")
    hero_background_image = models.ForeignKey(
        "wagtailimages.Image",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    # Sections
    intro_html = RichTextField(blank=True)

    features_title = models.CharField(max_length=120, blank=True, default="What You Can Do With IMAA Connect")
    features = StreamField(
        [("feature", AboutFeatureBlock())],
        blank=True,
        use_json_field=True,
    )

    mission_title = models.CharField(max_length=120, blank=True, default="Our Mission")
    mission_html = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        MultiFieldPanel(
            [
                AITitleFieldPanel("hero_title"),
                AITitleFieldPanel("hero_subtitle"),
                FieldPanel("hero_background_image"),
            ],
            heading="Hero Section",
        ),
        MultiFieldPanel(
            [
                FieldPanel("intro_html"),
            ],
            heading="Intro Section",
        ),
        MultiFieldPanel(
            [
                AITitleFieldPanel("features_title"),
                FieldPanel("features"),
            ],
            heading="Feature Cards",
        ),
        MultiFieldPanel(
            [
                AITitleFieldPanel("mission_title"),
                FieldPanel("mission_html"),
            ],
            heading="Mission Section",
        ),
    ]

    parent_page_types = ["cms.HomePage"]
    subpage_types = []


class EventsLandingPage(Page):
    # Hero
    hero_title = models.CharField(
        max_length=160,
        blank=True,
        default="Explore M&A Events",
    )
    hero_subtitle = models.TextField(
        blank=True,
        default="The leading platform for M&A professionals to connect, learn, and grow",
    )
    hero_background_image = models.ForeignKey(
        "wagtailimages.Image",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    cta_primary_label = models.CharField(
        max_length=80,
        blank=True,
        default="Explore events",
    )
    cta_primary_url = models.CharField(
        max_length=200,
        blank=True,
        default="/events",
    )
    cta_secondary_label = models.CharField(
        max_length=80,
        blank=True,
        default="Join Community",
    )
    cta_secondary_url = models.CharField(
        max_length=200,
        blank=True,
        default="/signup",
    )

    content_panels = Page.content_panels + [
        MultiFieldPanel(
            [
                AITitleFieldPanel("hero_title"),
                AITitleFieldPanel("hero_subtitle"),
                FieldPanel("hero_background_image"),
            ],
            heading="Hero Section",
        ),
        MultiFieldPanel(
            [
                FieldPanel("cta_primary_label"),
                FieldPanel("cta_primary_url"),
                FieldPanel("cta_secondary_label"),
                FieldPanel("cta_secondary_url"),
            ],
            heading="CTA Buttons",
        ),
    ]

    parent_page_types = ["cms.HomePage"]
    subpage_types = []


PROFILE_SECTION_CHOICES = [
    ("verification", "Verification"),
    ("about", "About"),
    ("skills", "Skills"),
    ("experience", "Experience"),
    ("education", "Education"),
    ("certifications", "Certifications & Licenses"),
    ("memberships", "Memberships"),
    ("email", "E-Mail"),
    ("phone", "Phone Numbers"),
    ("social_profiles", "Social Profiles"),
    ("websites", "Websites"),
    ("scheduling_link", "Scheduling Link"),
    ("location", "Location"),
    ("trainings", "Trainings & Executive Education"),
    ("languages", "Languages"),
    # Deprecated but kept for backward compatibility
    ("contact", "Contact (Deprecated - use granular sections)"),
]


class ProfileLayoutPage(Page):
    left_column = StreamField(
        [("section", blocks.ChoiceBlock(choices=PROFILE_SECTION_CHOICES))],
        blank=True,
        use_json_field=True,
    )
    right_column = StreamField(
        [("section", blocks.ChoiceBlock(choices=PROFILE_SECTION_CHOICES))],
        blank=True,
        use_json_field=True,
    )

    content_panels = Page.content_panels + [
        MultiFieldPanel(
            [FieldPanel("left_column")],
            heading="Left Column Sections (drag to reorder)",
        ),
        MultiFieldPanel(
            [FieldPanel("right_column")],
            heading="Right Column Sections (drag to reorder)",
        ),
    ]

    parent_page_types = ["cms.HomePage"]
    subpage_types = []
    max_count = 1


# Email template choices for all transactional email types
TEMPLATE_KEY_CHOICES = [
    ("welcome", "Welcome"),
    ("password_changed", "Password Changed"),
    ("speaker_credentials", "Speaker Credentials"),
    ("admin_credentials", "Admin Credentials"),
    ("event_confirmation", "Event Confirmation"),
    ("event_cancelled", "Event Cancelled"),
    ("event_invite", "Event Invite"),
    ("group_invite", "Group Invite"),
    ("replay_no_show", "Replay: No Show"),
    ("replay_partial", "Replay: Partial Attendance"),
    ("application_acknowledgement", "Application Acknowledgement"),
    ("application_approved", "Application Approved"),
    ("application_declined", "Application Declined"),
    ("user_registration_acknowledgement", "User Registration Acknowledgement"),
    ("guest_registration_acknowledgement", "Guest Registration Acknowledgement"),
    ("guest_otp", "Guest OTP"),
    ("guest_followup", "Guest Followup"),
    ("kyc_approved", "KYC Approved"),
    ("kyc_failed", "KYC Failed"),
    ("name_change_approved", "Name Change Approved"),
    ("name_change_manual_review", "Name Change Manual Review"),
    ("name_change_verification_failed", "Name Change Verification Failed"),
    ("name_change_rejected", "Name Change Rejected"),
    ("admin_name_change_review", "Admin Name Change Review"),
]

# Per-template-key required placeholders — used in clean() validation
REQUIRED_PLACEHOLDERS = {
    "welcome": ["{{ first_name }}", "{{ app_name }}"],
    "password_changed": ["{{ first_name }}", "{{ changed_at }}"],
    "speaker_credentials": ["{{ first_name }}", "{{ temporary_password }}", "{{ login_url }}"],
    "admin_credentials": ["{{ first_name }}", "{{ temporary_password }}", "{{ login_url }}"],
    "event_confirmation": ["{{ first_name }}", "{{ event_title }}"],
    "event_cancelled": ["{{ first_name }}", "{{ event_title }}"],
    "event_invite": ["{{ inviter_name }}", "{{ event_title }}", "{{ invite_url }}"],
    "group_invite": ["{{ inviter_name }}", "{{ group_name }}", "{{ invite_url }}"],
    "replay_no_show": ["{{ first_name }}", "{{ event_title }}", "{{ replay_url }}"],
    "replay_partial": ["{{ first_name }}", "{{ event_title }}", "{{ replay_url }}"],
    "application_acknowledgement": ["{{ applicant_name }}", "{{ event_title }}"],
    "application_approved": ["{{ applicant_name }}", "{{ event_title }}"],
    "application_declined": ["{{ applicant_name }}", "{{ event_title }}"],
    "user_registration_acknowledgement": ["{{ first_name }}", "{{ event_title }}"],
    "guest_registration_acknowledgement": ["{{ guest_name }}", "{{ event_title }}"],
    "guest_otp": ["{{ guest_name }}", "{{ otp_code }}", "{{ event_title }}"],
    "guest_followup": ["{{ guest_name }}", "{{ event_title }}", "{{ signup_url }}"],
    "kyc_approved": ["{{ first_name }}"],
    "kyc_failed": ["{{ first_name }}"],
    "name_change_approved": ["{{ first_name }}", "{{ new_name }}"],
    "name_change_manual_review": ["{{ first_name }}"],
    "name_change_verification_failed": ["{{ first_name }}"],
    "name_change_rejected": ["{{ first_name }}"],
    "admin_name_change_review": ["{{ user_email }}", "{{ request_id }}"],
}


@register_snippet
class EmailTemplate(models.Model):
    """
    Editable email template snippet for Wagtail CMS.
    Stores subject line, HTML body, and plain-text body for transactional emails.
    All fields support Django template syntax ({{ variable }}, {% if %}, filters, etc).
    """

    template_key = models.CharField(
        max_length=80,
        choices=TEMPLATE_KEY_CHOICES,
        unique=True,
        help_text="Identifier used in code. Cannot be changed after creation.",
    )
    subject = models.CharField(
        max_length=250,
        help_text="Email subject line. Supports {{ variable }} substitution.",
    )
    html_body = models.TextField(
        help_text=(
            "Full HTML email body. Supports Django template syntax: "
            "{{ variable }}, {% if %}, {% for %}, filters like |date:\"F j, Y\"."
        ),
    )
    text_body = models.TextField(
        help_text="Plain-text fallback body. Supports Django template syntax.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text=(
            "If unchecked, the system falls back to the file-based template. "
            "Use this to temporarily disable DB overrides without deleting."
        ),
    )
    notes = models.TextField(
        blank=True,
        help_text="Internal notes for editors. Not sent to users.",
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    panels = [
        FieldPanel("template_key"),
        FieldPanel("subject"),
        FieldPanel("html_body", classname="full"),
        FieldPanel("text_body", classname="full"),
        FieldPanel("is_active"),
        FieldPanel("notes"),
    ]

    def __str__(self):
        return f"{self.get_template_key_display()} ({'active' if self.is_active else 'inactive'})"

    def clean(self):
        """Validate Django template syntax and required placeholders."""
        errors = {}

        # 1. Validate Django template syntax for html_body
        if self.html_body:
            try:
                DjangoTemplate(self.html_body)
            except TemplateSyntaxError as e:
                errors["html_body"] = f"Invalid Django template syntax: {e}"

        # 2. Validate Django template syntax for text_body
        if self.text_body:
            try:
                DjangoTemplate(self.text_body)
            except TemplateSyntaxError as e:
                errors["text_body"] = f"Invalid Django template syntax: {e}"

        # 3. Validate Django template syntax for subject
        if self.subject:
            try:
                DjangoTemplate(self.subject)
            except TemplateSyntaxError as e:
                errors["subject"] = f"Invalid Django template syntax in subject: {e}"

        # 4. Check required placeholders present in html_body
        required = REQUIRED_PLACEHOLDERS.get(self.template_key, [])
        missing = [p for p in required if p not in self.html_body]
        if missing:
            errors["html_body"] = (
                errors.get("html_body", "")
                + f"\nMissing required placeholders: {', '.join(missing)}"
            ).strip()

        if errors:
            raise ValidationError(errors)

    class Meta:
        verbose_name = "Email Template"
        verbose_name_plural = "Email Templates"
        ordering = ["template_key"]
