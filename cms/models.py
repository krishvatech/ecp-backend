from django.db import models

from wagtail import blocks
from wagtail.images.blocks import ImageChooserBlock
from wagtail.fields import StreamField, RichTextField
from wagtail.admin.panels import FieldPanel, MultiFieldPanel
from wagtail.models import Page

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
                FieldPanel("hero_title"),
                FieldPanel("hero_subtitle"),
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
                FieldPanel("hero_title"),
                FieldPanel("hero_subtitle"),
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
                FieldPanel("features_title"),
                FieldPanel("features"),
            ],
            heading="Feature Cards",
        ),
        MultiFieldPanel(
            [
                FieldPanel("mission_title"),
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
    cta_tertiary_label = models.CharField(
        max_length=80,
        blank=True,
        default="Post an event",
    )
    cta_tertiary_url = models.CharField(
        max_length=200,
        blank=True,
        default="/signup",
    )

    content_panels = Page.content_panels + [
        MultiFieldPanel(
            [
                FieldPanel("hero_title"),
                FieldPanel("hero_subtitle"),
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
                FieldPanel("cta_tertiary_label"),
                FieldPanel("cta_tertiary_url"),
            ],
            heading="CTA Buttons",
        ),
    ]

    parent_page_types = ["cms.HomePage"]
    subpage_types = []
