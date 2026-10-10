"""Public API fields for the About page's intro image, statistics and ordered sections.

``about_page_extras(request, page)`` returns ``{}`` for pages without these fields, so it is a
no-op until the AboutPage schema change adds ``intro_image``, ``stats`` and ``sections``
(docs/about-page-schema.md). Output rules, the same for both CMS endpoints:

* rich text is expanded and passed through the public sanitiser (cms.public_pages);
* every link is re-checked against cms.about_blocks.SAFE_URL_RE and dropped when unsafe;
* images are absolute Wagtail rendition URLs with their width and height (no layout shift);
* blocks without content (no items, no text) are left out, so the page shows no empty section.
"""

import re

from wagtail.rich_text import RichText

from cms.about_blocks import SAFE_URL_RE, tel_href
from cms.public_pages import prepare_public_rich_text

# Rendition specs per use (Wagtail never upscales with max-/fill- below the original size).
SPEC_HERO = "max-2000x900"
SPEC_INTRO = "max-1200x1200"
SPEC_BANNER = "fill-1600x464"
SPEC_LOGO = "max-320x120"
SPEC_CARD = "max-800x800"
SPEC_PHOTO = "fill-240x240"
SPEC_OFFICE = "max-160x160"  # round flag badges shown at 64px


def _absolute(request, url):
    if not url:
        return ""
    if url.startswith(("http://", "https://")):
        return url
    return request.build_absolute_uri(url) if request is not None else url


def image_data(request, image, spec, alt=""):
    """{url, width, height, alt} for a rendition of ``image``, or None."""
    if image is None:
        return None
    try:
        rendition = image.get_rendition(spec)
    except Exception:
        return None
    url = _absolute(request, rendition.url)
    if not url:
        return None
    return {"url": url, "width": rendition.width, "height": rendition.height, "alt": alt or ""}


def rich_text(request, value):
    html = str(RichText(str(value.source if hasattr(value, "source") else value or "")))
    return prepare_public_rich_text(html, request)


def has_text(html):
    return bool(re.sub(r"<[^>]*>|&nbsp;|\s", "", html or ""))


def safe_url(value):
    value = (value or "").strip()
    return value if value and SAFE_URL_RE.match(value) else ""


def link(value):
    if not value:
        return None
    label, url = (value.get("label") or "").strip(), safe_url(value.get("url"))
    return {"label": label, "url": url} if label and url else None


def _accordion(request, v):
    items = [
        {
            "title": item["title"],
            "body_html": rich_text(request, item["body"]),
            "logo": image_data(request, item.get("logo"), SPEC_LOGO, item["title"]),
        }
        for item in v["items"]
        if item.get("title")
    ]
    if not items:
        return None
    return {"heading": v.get("heading") or "", "image": image_data(request, v.get("image"), SPEC_BANNER), "items": items}


def _logos(request, values):
    return [
        logo
        for logo in (image_data(request, item["image"], SPEC_LOGO, item["name"]) for item in values or [])
        if logo is not None
    ]


def _cta_band(request, v):
    text = rich_text(request, v["text"])
    if not has_text(text):
        return None
    return {"text_html": text, "logos": _logos(request, v.get("logos")), "button": link(v.get("button"))}


def _card_group(request, v):
    cards = [
        {
            "title": card["title"],
            "text": card.get("text") or "",
            "icon": card.get("icon") or "",
            "image": image_data(request, card.get("image"), SPEC_CARD),
            "link": link(card.get("link")),
        }
        for card in v["cards"]
        if card.get("title")
    ]
    if not cards:
        return None
    return {
        "heading": v.get("heading") or "",
        "layout": v.get("layout") or "grid",
        "cards": cards,
        "prompt": v.get("prompt") or "",
        "button": link(v.get("button")),
    }


def _testimonials(request, v):
    items = []
    for testimonial in v["testimonials"]:
        if testimonial is None or not getattr(testimonial, "name", ""):
            continue  # a deleted snippet leaves an empty chooser
        items.append(
            {
                "name": testimonial.name,
                "role": getattr(testimonial, "role", "") or "",
                "company": getattr(testimonial, "company", "") or "",
                "programme": getattr(testimonial, "programme", "") or "",
                "quote_html": rich_text(request, getattr(testimonial, "quote", "")),
                "photo": image_data(request, getattr(testimonial, "photo", None), SPEC_PHOTO, testimonial.name),
                "url": safe_url(getattr(testimonial, "url", "")),
            }
        )
    if not items:
        return None
    return {"heading": v.get("heading") or "", "items": items, "button": link(v.get("button"))}


def _logo_strip(request, v):
    logos = _logos(request, v["logos"])
    if not logos:
        return None
    return {"heading": v.get("heading") or "", "logos": logos, "button": link(v.get("button"))}


def _contact_callout(request, v):
    text = rich_text(request, v["text"])
    email = (v.get("email") or "").strip()
    if not has_text(text) and not email:
        return None
    return {
        "heading": v.get("heading") or "",
        "text_html": text,
        "email": email,
        "button_label": (v.get("button_label") or "").strip() if email else "",
    }


def _offices(request, v):
    offices = [
        {
            "city": office["city"],
            "country": office.get("country") or "",
            "phone": office.get("phone") or "",
            "phone_href": tel_href(office.get("phone")),
            "image": image_data(request, office.get("image"), SPEC_OFFICE),
        }
        for office in v["offices"]
        if office.get("city")
    ]
    if not offices and not v.get("email"):
        return None
    return {"heading": v.get("heading") or "", "email": (v.get("email") or "").strip(), "offices": offices}


SECTION_SERIALISERS = {
    "accordion": _accordion,
    "cta_band": _cta_band,
    "card_group": _card_group,
    "testimonials": _testimonials,
    "logo_strip": _logo_strip,
    "contact_callout": _contact_callout,
    "offices": _offices,
}


def serialise_stats(stream):
    return [
        {"value": block.value["value"], "label": block.value["label"]}
        for block in stream or []
        if block.block_type == "stat" and block.value.get("value") and block.value.get("label")
    ]


def serialise_sections(request, stream):
    out = []
    for block in stream or []:
        serialiser = SECTION_SERIALISERS.get(block.block_type)
        data = serialiser(request, block.value) if serialiser else None
        if data is not None:
            out.append({"type": block.block_type, "id": str(block.id or ""), **data})
    return out


def about_page_extras(request, page):
    """Extra public fields of an AboutPage once its schema has them; {} otherwise."""
    extras = {}
    if hasattr(page, "intro_image"):
        extras["intro_image"] = image_data(request, page.intro_image, SPEC_INTRO)
    if hasattr(page, "stats"):
        extras["stats"] = serialise_stats(page.stats)
    if hasattr(page, "sections"):
        extras["sections"] = serialise_sections(request, page.sections)
    if extras and hasattr(page, "hero_background_image"):
        extras["hero_image"] = image_data(request, page.hero_background_image, SPEC_HERO)
    return extras
