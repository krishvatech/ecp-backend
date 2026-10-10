"""Wagtail blocks for the About page's statistics and ordered sections.

Defined here, apart from cms.models, so they can be reviewed and tested before the schema change
that attaches them to AboutPage (``stats`` and ``sections`` StreamFields; see
docs/about-page-schema.md). Until then nothing in the database uses them.

Rich text uses the same Draftail features as the public pages. Links are validated: only
http(s), mailto:, tel: and site-relative ("/…") destinations are accepted, so an editor cannot
store a javascript: or protocol-relative URL that the public API would then serve.
"""

import re

from django.core.exceptions import ValidationError
from wagtail import blocks
from wagtail.images.blocks import ImageChooserBlock
from wagtail.snippets.blocks import SnippetChooserBlock

RICH_TEXT_FEATURES = ["bold", "italic", "link", "ol", "ul"]
SAFE_URL_RE = re.compile(r"^(https?://[^\s]+|mailto:[^\s]+|tel:\+?[0-9][0-9 ()./-]*|/(?!/)[^\s]*)$", re.IGNORECASE)

# Study-format icons: frontend design assets (inline SVG from the WordPress page).
FORMAT_ICON_CHOICES = [
    ("onsite", "Onsite"),
    ("interactive-online-live", "Interactive online live"),
    ("online", "Online"),
    ("inhouse", "In-house"),
]


def validate_safe_url(value):
    if value and not SAFE_URL_RE.match(value.strip()):
        raise ValidationError("Use an https:// address, mailto:, tel: or a site path starting with '/'.")


class SafeURLBlock(blocks.CharBlock):
    """A link destination: absolute http(s), mailto:, tel: or a site-relative path."""

    def __init__(self, **kwargs):
        kwargs.setdefault("max_length", 300)
        kwargs.setdefault("validators", [validate_safe_url])
        super().__init__(**kwargs)


class LinkBlock(blocks.StructBlock):
    label = blocks.CharBlock(required=False, max_length=80)
    url = SafeURLBlock(required=False)

    class Meta:
        icon = "link"
        label = "Button"

    def clean(self, value):
        value = super().clean(value)
        if bool(value.get("label")) != bool(value.get("url")):
            raise blocks.StructBlockValidationError(
                block_errors={"url": ValidationError("A button needs both a label and a link (or neither).")}
            )
        return value


class StatBlock(blocks.StructBlock):
    value = blocks.CharBlock(max_length=20, help_text="As displayed, e.g. 100+")
    label = blocks.CharBlock(max_length=80)

    class Meta:
        icon = "order"
        label = "Statistic"


class AccordionItemBlock(blocks.StructBlock):
    title = blocks.CharBlock(max_length=160)
    body = blocks.RichTextBlock(features=RICH_TEXT_FEATURES)
    logo = ImageChooserBlock(required=False)

    class Meta:
        icon = "list-ul"
        label = "Accordion item"


class AccordionSectionBlock(blocks.StructBlock):
    heading = blocks.CharBlock(required=False, max_length=160)
    image = ImageChooserBlock(required=False, help_text="Optional banner under the heading")
    items = blocks.ListBlock(AccordionItemBlock())

    class Meta:
        icon = "list-ul"
        label = "Accordion (e.g. accreditations)"


class CtaBandBlock(blocks.StructBlock):
    text = blocks.RichTextBlock(features=RICH_TEXT_FEATURES)
    logos = blocks.ListBlock(
        blocks.StructBlock([("image", ImageChooserBlock()), ("name", blocks.CharBlock(max_length=120))]),
        required=False,
        help_text="Optional logos shown beside the text; the name is the image's alt text.",
    )
    button = LinkBlock(required=False)

    class Meta:
        icon = "pick"
        label = "Text band with button"


class CardBlock(blocks.StructBlock):
    image = ImageChooserBlock(required=False)
    icon = blocks.ChoiceBlock(choices=FORMAT_ICON_CHOICES, required=False)
    title = blocks.CharBlock(max_length=160)
    text = blocks.TextBlock(required=False, max_length=800)
    link = LinkBlock(required=False)

    class Meta:
        icon = "doc-full"
        label = "Card"


class CardGroupBlock(blocks.StructBlock):
    heading = blocks.CharBlock(required=False, max_length=160)
    layout = blocks.ChoiceBlock(choices=[("grid", "Grid"), ("carousel", "Carousel")], default="grid")
    cards = blocks.ListBlock(CardBlock())
    prompt = blocks.CharBlock(required=False, max_length=200, help_text="Optional line above the button")
    button = LinkBlock(required=False)

    class Meta:
        icon = "table"
        label = "Cards (grid or carousel)"


class TestimonialsSectionBlock(blocks.StructBlock):
    heading = blocks.CharBlock(required=False, max_length=160)
    testimonials = blocks.ListBlock(SnippetChooserBlock("cms.Testimonial"))
    button = LinkBlock(required=False)

    class Meta:
        icon = "openquote"
        label = "Featured testimonials"


class LogoStripBlock(blocks.StructBlock):
    heading = blocks.CharBlock(required=False, max_length=160)
    logos = blocks.ListBlock(
        blocks.StructBlock([("image", ImageChooserBlock()), ("name", blocks.CharBlock(max_length=120))])
    )
    button = LinkBlock(required=False)

    class Meta:
        icon = "image"
        label = "Logo strip"


class ContactCalloutBlock(blocks.StructBlock):
    heading = blocks.CharBlock(max_length=160)
    text = blocks.RichTextBlock(features=RICH_TEXT_FEATURES)
    email = blocks.EmailBlock(required=False)
    button_label = blocks.CharBlock(required=False, max_length=60)

    class Meta:
        icon = "mail"
        label = "Contact callout"


class OfficeBlock(blocks.StructBlock):
    city = blocks.CharBlock(max_length=80)
    country = blocks.CharBlock(max_length=80)
    phone = blocks.CharBlock(required=False, max_length=40, help_text="As displayed, e.g. +41 43 505 17 99")
    image = ImageChooserBlock(required=False)

    class Meta:
        icon = "site"
        label = "Office"


class OfficesBlock(blocks.StructBlock):
    heading = blocks.CharBlock(required=False, max_length=160)
    email = blocks.EmailBlock(required=False)
    offices = blocks.ListBlock(OfficeBlock())

    class Meta:
        icon = "site"
        label = "Offices"


STAT_BLOCKS = [("stat", StatBlock())]

SECTION_BLOCKS = [
    ("accordion", AccordionSectionBlock()),
    ("cta_band", CtaBandBlock()),
    ("card_group", CardGroupBlock()),
    ("testimonials", TestimonialsSectionBlock()),
    ("logo_strip", LogoStripBlock()),
    ("contact_callout", ContactCalloutBlock()),
    ("offices", OfficesBlock()),
]


def tel_href(phone):
    """'+41 43 505 17 99' -> 'tel:+41435051799' (digits and a leading +)."""
    digits = re.sub(r"[^0-9+]", "", phone or "")
    digits = digits[:1] + digits[1:].replace("+", "")
    return f"tel:{digits}" if re.search(r"[0-9]{4,}", digits) else ""
