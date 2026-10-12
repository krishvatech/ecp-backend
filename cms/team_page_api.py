"""Public API fields for the Our Team page (TeamPage) and its people (TeamMember snippets).

``team_page_extras(request, page)`` returns ``{}`` for any other page, so it is a no-op until the
schema change that adds TeamPage, TeamMember and Programme (docs/team-page-schema.md). Rules, as
for the About page (cms/about_page_api.py):

* rich text is expanded and passed through the public sanitiser;
* links are re-checked against SAFE_URL_RE (LinkedIn must be https) and dropped when unsafe;
* images are absolute rendition URLs with width and height;
* only people marked public are listed; the list carries no biography (cards show the tagline;
  biographies are kept for a future profile page).
"""

from django.apps import apps

from cms.about_page_api import image_data, link, rich_text, safe_url, serialise_sections

SPEC_TEAM_PHOTO = "fill-400x400"


def _buttons(stream):
    return [button for button in (link(block.value) for block in stream or [] if block.block_type == "button") if button]


def _member(request, member):
    linkedin = (member.linkedin_url or "").strip()
    return {
        "slug": member.slug,
        "name": member.name,
        "position": member.position or "",
        "summary": member.summary or "",
        "location": member.location or "",
        "linkedin_url": linkedin if linkedin.startswith("https://") else "",
        "profile_url": safe_url(member.profile_url),
        "programmes": [programme.slug for programme in member.programmes.all()],
        "photo": image_data(request, member.photo, SPEC_TEAM_PHOTO, member.name),
    }


def team_members(request):
    """{member_type: [public members in display order]} — empty until the TeamMember model exists."""
    try:
        model = apps.get_model("cms", "TeamMember")
    except LookupError:
        return {}
    grouped = {}
    queryset = model.objects.filter(is_public=True).select_related("photo").prefetch_related("programmes")
    for member in queryset.order_by("member_type", "sort_order", "name"):
        grouped.setdefault(member.member_type, []).append(_member(request, member))
    return grouped


def team_programmes():
    try:
        model = apps.get_model("cms", "Programme")
    except LookupError:
        return []
    return [{"code": p.code, "slug": p.slug} for p in model.objects.order_by("sort_order", "code")]


def team_page_extras(request, page):
    """Public fields of a TeamPage; {} for every other page type."""
    if not hasattr(page, "faculty_heading"):
        return {}
    members = team_members(request)
    programmes = team_programmes()
    # Only filters that someone public belongs to; the page shows "All" itself.
    used = {slug for member in members.get("faculty", []) for slug in member["programmes"]}
    hero = _buttons(page.hero_button)
    staff_button = _buttons(page.staff_button)
    return {
        "hero_title": page.hero_title or "",
        "hero_intro": page.hero_intro or "",
        "hero_button": hero[0] if hero else None,
        "faculty_heading": page.faculty_heading or "",
        "faculty_subheading": page.faculty_subheading or "",
        "faculty_intro_html": rich_text(request, page.faculty_intro),
        "faculty_buttons": _buttons(page.faculty_buttons),
        "staff_heading": page.staff_heading or "",
        "staff_subheading": page.staff_subheading or "",
        "staff_intro_html": rich_text(request, page.staff_intro),
        "staff_button": staff_button[0] if staff_button else None,
        "programmes": [programme for programme in programmes if programme["slug"] in used],
        "faculty": members.get("faculty", []),
        "staff": members.get("staff", []),
        "advisory": members.get("advisory", []),
        "sections": serialise_sections(request, page.sections),
    }
