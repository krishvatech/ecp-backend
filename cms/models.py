from django.db import models

from wagtail import blocks
from wagtail.images.blocks import ImageChooserBlock
from wagtail.fields import StreamField, RichTextField
from wagtail.admin.panels import FieldPanel, MultiFieldPanel
from wagtail.models import Page

class HomePage(Page):
    intro = RichTextField(blank=True)

    content_panels = Page.content_panels + [
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
