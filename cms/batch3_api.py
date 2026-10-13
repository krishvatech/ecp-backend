"""Public API fields for the Testimonials page (TestimonialsPage) and the Contact Us page (ContactPage).

``testimonials_page_extras`` and ``contact_page_extras`` return ``{}`` for every other page type.
Same rules as the About and Our Team pages (cms/about_page_api.py, cms/team_page_api.py): rich text
expanded and sanitised, links re-checked, images as absolute rendition URLs, only public records.
"""

from django.apps import apps

from cms.about_page_api import SPEC_INTRO, SPEC_PHOTO, image_data, rich_text, serialise_sections, serialise_stats
from cms.contact import contact_form_config


def _testimonial(request, t):
    return {
        "slug": t.slug,
        "name": t.name,
        "role": t.role or "",
        "company": t.company or "",
        "programme": t.programme or "",
        "programmes": [p.slug for p in t.programmes.all()],
        "quote_html": rich_text(request, t.quote),
        "photo": image_data(request, t.photo, SPEC_PHOTO, t.name),
    }


def public_testimonials(request):
    """Public testimonials, newest first (undated ones last, by name)."""
    from django.db.models import F

    Testimonial = apps.get_model("cms", "Testimonial")
    queryset = (Testimonial.objects.filter(is_public=True).exclude(quote="")
                .select_related("photo").prefetch_related("programmes")
                .order_by(F("published_at").desc(nulls_last=True), "name"))
    return [_testimonial(request, t) for t in queryset]


def testimonials_page_extras(request, page):
    if type(page).__name__ != "TestimonialsPage":
        return {}
    Programme = apps.get_model("cms", "Programme")
    testimonials = public_testimonials(request)
    used = {slug for t in testimonials for slug in t["programmes"]}
    return {
        "hero_title": page.hero_title or "",
        "hero_intro": page.hero_intro or "",
        "programmes": [{"code": p.code, "slug": p.slug} for p in Programme.objects.order_by("sort_order", "code") if p.slug in used],
        "testimonials": testimonials,
        "sections": serialise_sections(request, page.sections),
    }


def contact_page_extras(request, page):
    if type(page).__name__ != "ContactPage":
        return {}
    return {
        "hero_title": page.hero_title or "",
        "hero_intro": page.hero_intro or "",
        "form_heading": page.form_heading or "",
        "form_intro_html": rich_text(request, page.form_intro),
        "consent_html": rich_text(request, page.consent_text),
        "success_message": page.success_message or "",
        "form_image": image_data(request, page.form_image, SPEC_INTRO),
        "stats": serialise_stats(page.stats),
        "sections": serialise_sections(request, page.sections),
        "form": contact_form_config(),
    }
