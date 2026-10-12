"""Shared logic for importing the approved About page content (cms/about_page_content/).

Used by two explicit management commands; nothing calls this at runtime, on startup or in a
migration:

* ``populate_about_page``: local development databases only (local PostgreSQL, local storage);
  imports the bundled image files into local storage.
* ``import_about_page``: any configured environment, production included; never uploads or
  overwrites a file, it reuses the originals already in storage (verified by SHA-256).

Rules both commands share live here: the schema check, editor-format rich text, the page
blockers (unpublished changes, locks, workflows, schedules, restrictions) and the stored form of
the ordered sections.
"""

import uuid

from django.apps import apps
from django.db import connection

from cms.about_blocks import RICH_TEXT_FEATURES
from cms.editor_checks import draftail_problem
from cms.models import AboutPage
from cms.public_page_setup import editor_line_breaks
from cms.public_pages import is_archived

ABOUT_SLUG = "about"
SCHEMA_FIELDS = ("intro_image", "stats", "sections")
SCHEMA_HINT = "the AboutPage migration that adds intro_image, stats, sections and the Testimonial snippet is not applied"


def schema_missing():
    """What the import needs that the code or the database schema does not have, read-only.

    Checks the model and the database itself (table and column names, not migration names: the
    same schema change is recorded under different migration names in different environments).
    """
    model_fields = {f.name for f in AboutPage._meta.get_fields()}
    missing = [name for name in SCHEMA_FIELDS if name not in model_fields]
    try:
        testimonial_model = apps.get_model("cms", "Testimonial")
    except LookupError:
        testimonial_model = None
        missing.append("Testimonial snippet")
    if missing:
        return missing
    with connection.cursor() as cursor:
        tables = set(connection.introspection.table_names(cursor))
        columns = {c.name for c in connection.introspection.get_table_description(cursor, AboutPage._meta.db_table)}
    for name in SCHEMA_FIELDS:
        column = AboutPage._meta.get_field(name).column
        if column not in columns:
            missing.append(f"database column {AboutPage._meta.db_table}.{column} ({SCHEMA_HINT})")
    if testimonial_model._meta.db_table not in tables:
        missing.append(f"database table {testimonial_model._meta.db_table} ({SCHEMA_HINT})")
    return missing


def editor_rich_text(content):
    """Every approved rich-text value in Wagtail's storage format (``<br/>``), checked against Draftail.

    Returns ``(stored, problems)``: ``stored`` maps a location (``intro_html``,
    ``sections[2].items[0].body``, ...) to its value; ``problems`` lists values the editor would
    fail to load or would change.
    """
    stored, problems = {}, []

    def check(location, html, features):
        value = editor_line_breaks(html)
        problem = draftail_problem(value, features)
        if problem:
            problems.append(f"{location}: {problem}")
        stored[location] = value

    check("intro_html", content["intro_html"], None)
    check("mission_html", content["mission_html"], None)
    for i, section in enumerate(content["sections"]):
        if "text_html" in section:
            check(f"sections[{i}].text", section["text_html"], RICH_TEXT_FEATURES)
        for j, item in enumerate(section.get("items", [])):
            if "body_html" in item:
                check(f"sections[{i}].items[{j}].body", item["body_html"], RICH_TEXT_FEATURES)
            if "quote_html" in item:
                check(f"sections[{i}].items[{j}].quote", item["quote_html"], RICH_TEXT_FEATURES)
    return stored, problems


def page_blockers(page, current, slug=ABOUT_SLUG):
    """Reasons the page must not be changed by a command; [] when it can be.

    ``current`` is the page as of its live revision.
    """
    blockers = []
    if not page.live:
        blockers.append("the page is not live")
    if page.has_unpublished_changes or page.latest_revision_id != page.live_revision_id:
        blockers.append("the page has unpublished changes in Wagtail; they are never overwritten")
    if is_archived(page):
        blockers.append("the page is archived (deleted in Wagtail)")
    if page.alias_of_id:
        blockers.append("the page is an alias of another page")
    if page.locked:
        blockers.append("the page is locked in Wagtail")
    if page.workflow_in_progress:
        blockers.append("a Wagtail workflow is in progress on the page")
    latest = page.get_latest_revision()
    if latest is not None and getattr(latest, "submitted_for_moderation", False):
        blockers.append("the latest revision is submitted for moderation")
    if page.go_live_at or page.expire_at or current.go_live_at or current.expire_at:
        blockers.append("a go-live or expiry date is set")
    if page.revisions.filter(approved_go_live_at__isnull=False).exists():
        blockers.append("a revision is scheduled for publishing")
    if page.get_view_restrictions().exists():
        blockers.append("a view restriction applies (on the page or an ancestor)")
    if current.slug != slug:
        blockers.append(f"the live revision has the slug '{current.slug}'")
    return blockers


def _item(value):
    return {"type": "item", "value": value, "id": str(uuid.uuid4())}


def _link(value):
    return {"label": value["label"], "url": value["url"]} if value else {"label": "", "url": ""}


def sections_raw(content, stored, image_id, testimonial_id):
    """The approved sections in the stored StreamField form (ListBlock items with ids).

    ``image_id(media key or None)`` and ``testimonial_id(slug)`` give the database ids to store.
    """
    names = {m["key"]: m["alt"] for m in content["media"]}
    raw = []
    for i, s in enumerate(content["sections"]):
        kind = s["type"]
        if kind == "accordion":
            value = {"heading": s["heading"], "image": image_id(s.get("image")), "items": [
                _item({"title": item["title"], "body": stored[f"sections[{i}].items[{j}].body"], "logo": None})
                for j, item in enumerate(s["items"])
            ]}
        elif kind == "cta_band":
            value = {"text": stored[f"sections[{i}].text"], "button": _link(s.get("button")), "logos": [
                _item({"image": image_id(key), "name": names[key]}) for key in s["logos"]
            ]}
        elif kind == "card_group":
            value = {"heading": s["heading"], "layout": s["layout"], "prompt": s.get("prompt") or "",
                     "button": _link(s.get("button")), "cards": [
                         _item({"image": image_id(card.get("image")), "icon": card.get("icon") or "",
                                "title": card["title"], "text": card.get("text") or "", "link": _link(card.get("link"))})
                         for card in s["cards"]
                     ]}
        elif kind == "testimonials":
            value = {"heading": s["heading"], "button": _link(s.get("button")),
                     "testimonials": [_item(testimonial_id(item["slug"])) for item in s["items"]]}
        elif kind == "logo_strip":
            value = {"heading": s["heading"], "button": _link(s.get("button")),
                     "logos": [_item({"image": image_id(logo["image"]), "name": logo["name"]}) for logo in s["logos"]]}
        elif kind == "contact_callout":
            value = {"heading": s["heading"], "text": stored[f"sections[{i}].text"], "email": s["email"],
                     "button_label": s.get("button_label") or ""}
        elif kind == "offices":
            value = {"heading": s["heading"], "email": s["email"], "offices": [
                _item({"city": o["city"], "country": o["country"], "phone": o["phone"], "image": image_id(o.get("image"))})
                for o in s["offices"]
            ]}
        else:  # load_about_content rejects unknown types; this guards against future edits
            raise ValueError(f"Unknown section type {kind!r}.")
        raw.append({"type": kind, "value": value, "id": str(uuid.uuid4())})
    return raw


def stats_raw(content):
    return [{"type": "stat", "value": dict(stat), "id": str(uuid.uuid4())} for stat in content["stats"]]


def features_raw(content):
    return [{"type": "feature", "value": {"image": None, "title": f["title"], "desc": f["desc"]}, "id": str(uuid.uuid4())}
            for f in content["features"]]


def without_ids(raw):
    """StreamField raw data without block ids, for comparing stored content with the approved content."""
    if isinstance(raw, dict):
        return {key: without_ids(value) for key, value in raw.items() if key != "id"}
    if isinstance(raw, list):
        return [without_ids(value) for value in raw]
    return raw
