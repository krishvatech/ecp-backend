"""Populate the published About page (cms.AboutPage, /about/) with its approved content. Local only.

    python manage.py populate_about_page            # preview (the default; no database writes)
    python manage.py populate_about_page --apply    # import media, save and publish a revision

Source: cms/about_page_content/ (about.json + images/), migrated from imaa-institute.org/about-us/.

* Local development databases only: the database must be PostgreSQL on this machine and the
  default file storage local; production settings are refused (cms.local_safety). With the dev
  settings run it with ``AWS_BUCKET_NAME=`` so media is stored locally, never in S3.
* Requires the AboutPage schema change (``intro_image``, ``stats``, ``sections``) and the
  ``Testimonial`` snippet (docs/about-page-schema.md). Until then the preview shows the plan and
  ``--apply`` is refused.
* The page must be the AboutPage at /about/ under the IMAA Connect HomePage: live, its latest
  revision published (no unpublished editor changes), not archived, an alias, locked, in a
  workflow or moderation, scheduled or view-restricted.
* Only empty fields are filled. A field that holds the model's default value counts as empty
  (``hero_title`` "About IMAA Connect" and similar); one that already holds the approved value
  is left alone; any other value is an editor's content and the whole run is refused. Page ID,
  title, slug, existing revisions and non-empty SEO fields are kept.
* Media is imported into the "Public website pages" collection; a file whose content is already
  in the image library is reused (repeat runs import nothing). Testimonials are created once,
  keyed by their WordPress ID; existing testimonials are never changed.
* Rich text is stored in Wagtail's editor format (``<br/>``) and must load in Draftail with its
  text intact before anything is written.
* The result is saved as a new revision (logged as an edit) and published, so the page stays
  live without unpublished changes. A repeat run reports "already populated" and writes nothing.
* Without ``--apply`` no SQL other than SELECT runs (enforced). With ``--apply`` the page row is
  locked and every check is repeated under the lock.

Nothing calls this command automatically.
"""

import json
import re
import uuid
from dataclasses import dataclass, field

from django.apps import apps
from django.core.files.images import ImageFile
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from wagtail.admin.rich_text.converters.contentstate import ContentstateConverter
from wagtail.blocks import StreamValue
from wagtail.images import get_image_model
from wagtail.log_actions import log
from wagtail.models import Page
from wagtail.rich_text import features as feature_registry
from wagtail.utils.file import hash_filelike

from cms.about_blocks import RICH_TEXT_FEATURES
from cms.about_page_content import IMAGES_DIR, AboutContentError, load_about_content
from cms.local_safety import describe_environment, local_environment_problems
from cms.models import AboutPage
from cms.public_page_setup import DryRunWriteGuard, editor_line_breaks, media_collection, resolve_site_and_root, rich_text_is_empty
from cms.public_pages import is_archived

ABOUT_SLUG = "about"
SCHEMA_FIELDS = ("intro_image", "stats", "sections")
_TAGS_RE = re.compile(r"<[^>]+>")

EMPTY, SAME, OTHER = "empty", "same", "other"


def schema_missing():
    """What the populated page needs that the code or the database schema does not have yet.

    Checks the model and, read-only, the database itself: with the model change in place but
    migration cms.0016 not applied, every AboutPage query would fail on the missing columns.
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
            missing.append(f"database column {AboutPage._meta.db_table}.{column} (migration cms.0016 not applied)")
    if testimonial_model._meta.db_table not in tables:
        missing.append(f"database table {testimonial_model._meta.db_table} (migration cms.0016 not applied)")
    return missing


def _words(html):
    from html import unescape

    return unescape(_TAGS_RE.sub(" ", html or "")).replace("\xa0", " ").split()


_converters = {}


def draftail_problem(html, features=None):
    """None when ``html`` (editor format) loads in Draftail with its text intact."""
    key = tuple(features) if features else None
    if key not in _converters:
        _converters[key] = ContentstateConverter(features or feature_registry.get_default_features())
    converter = _converters[key]
    try:
        saved = converter.to_database_format(converter.from_database_format(html))
    except Exception as exc:  # the converter raises AssertionError on markup it cannot read
        return f"the Wagtail editor cannot load it ({type(exc).__name__}: {exc})"
    if _words(saved) != _words(html):
        return "the Wagtail editor would change its text"
    return None


def field_default(name):
    return AboutPage._meta.get_field(name).get_default()


@dataclass
class Inspection:
    page: object
    current: object  # the page as of its live (= latest) revision
    blockers: list = field(default_factory=list)
    fields: dict = field(default_factory=dict)  # name -> (state, current display, approved display)


class Command(BaseCommand):
    help = "Local only: populate the published About page with its approved content. Preview unless --apply."

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Preview only; no database writes (the default).")
        mode.add_argument("--apply", action="store_true", help="Import media, save the content as a revision and publish it.")

    def handle(self, *args, **options):
        apply = options["apply"]
        self.stdout.write(self.style.MIGRATE_HEADING(
            f"Populate About page /{ABOUT_SLUG}/: {'APPLY' if apply else 'PREVIEW (no database changes)'}"
        ))
        environment = local_environment_problems()
        self.stdout.write(describe_environment())
        if environment:
            raise CommandError(f"Refused, nothing was read or changed: {'; '.join(environment)}.")
        self.stdout.write("  ok: local PostgreSQL database and local file storage")

        try:
            content = load_about_content()
        except AboutContentError as exc:
            raise CommandError(f"Approved content is invalid, nothing was changed: {exc}") from exc
        self.stdout.write(f"  ok: approved content (sha256 {content['content_sha256'][:12]}, {len(content['media'])} media files verified)")
        stored = self._stored_rich_text(content)

        missing = schema_missing()
        unmigrated = [item for item in missing if item.startswith("database ")]
        if unmigrated:
            # The model has the new fields but the database does not: the page cannot even be read.
            for item in unmigrated:
                self.stdout.write(self.style.WARNING(f"  schema: missing {item}"))
            message = (
                "Migration cms.0016_about_page_sections_testimonial is not applied to this database, so the "
                "About page cannot be read or populated. Apply it locally first (python manage.py migrate cms)."
            )
            if apply:
                raise CommandError(f"Refused, nothing was changed: {message}")
            self.stdout.write(self.style.WARNING(f"Preview stopped: {message}"))
            return
        if not apply:
            with connection.execute_wrapper(DryRunWriteGuard()):
                site, root = resolve_site_and_root()
                inspection = self._inspect(root, content, stored, missing)
                self._report(site, root, inspection, content, missing)
            if missing:
                self.stdout.write(self.style.WARNING(
                    f"--apply is refused until the schema change is applied (missing: {', '.join(missing)})."
                ))
            elif inspection.blockers:
                raise CommandError(f"Refused, nothing was changed: {'; '.join(inspection.blockers)}.")
            elif self._all_same(inspection):
                self.stdout.write("Already populated with the approved content; nothing to do.")
            else:
                self.stdout.write("Preview: run again with --apply to import the media and publish this content.")
            return

        if missing:
            raise CommandError(
                f"Refused, nothing was changed: the AboutPage schema change is not applied (missing: {', '.join(missing)})."
            )
        site, root = resolve_site_and_root()
        inspection = self._inspect(root, content, stored, missing)
        self._report(site, root, inspection, content, missing)
        if inspection.blockers:
            raise CommandError(f"Refused, nothing was changed: {'; '.join(inspection.blockers)}.")
        if self._all_same(inspection):
            self.stdout.write(self.style.SUCCESS("Already populated with the approved content; nothing changed."))
            return
        revision, created_images, created_testimonials = self._apply(root, content, stored, inspection)
        self.stdout.write(self.style.SUCCESS(
            f"Imported {created_images} images and {created_testimonials} testimonials; saved and published "
            f"revision #{revision.pk}. /{ABOUT_SLUG}/ is live with the approved content."
        ))

    # -- content preparation ---------------------------------------------------------------

    def _stored_rich_text(self, content):
        """Every rich-text value in editor format, validated against Draftail before any write."""
        default_features = None
        stored, problems = {}, []

        def check(location, html, features):
            value = editor_line_breaks(html)
            problem = draftail_problem(value, features)
            if problem:
                problems.append(f"{location}: {problem}")
            stored[location] = value

        check("intro_html", content["intro_html"], default_features)
        check("mission_html", content["mission_html"], default_features)
        for i, section in enumerate(content["sections"]):
            if "text_html" in section:
                check(f"sections[{i}].text", section["text_html"], RICH_TEXT_FEATURES)
            for j, item in enumerate(section.get("items", [])):
                if "body_html" in item:
                    check(f"sections[{i}].items[{j}].body", item["body_html"], RICH_TEXT_FEATURES)
                if "quote_html" in item:
                    check(f"sections[{i}].items[{j}].quote", item["quote_html"], RICH_TEXT_FEATURES)
        if problems:
            raise CommandError(f"Approved rich text is not editor-safe, nothing was changed: {'; '.join(problems[:3])}.")
        self.stdout.write(f"  ok: {len(stored)} rich-text values load in the Wagtail editor with their text intact")
        return stored

    def _media_plan(self, content):
        """{key: (existing image or None, sha1 file hash)} — matched by file content, read-only."""
        hashes = {}
        for item in content["media"]:
            with open(IMAGES_DIR / item["file"], "rb") as fh:
                hashes[item["key"]] = hash_filelike(fh)
        by_hash = {}
        for image in get_image_model().objects.filter(file_hash__in=set(hashes.values())).order_by("pk"):
            by_hash.setdefault(image.file_hash, image)
        return {key: (by_hash.get(file_hash), file_hash) for key, file_hash in hashes.items()}

    # -- inspection (read-only) ------------------------------------------------------------

    def _inspect(self, root, content, stored, missing):
        existing = Page.objects.child_of(root).filter(slug=ABOUT_SLUG).first()
        if existing is None:
            raise CommandError(f"No page exists at /{ABOUT_SLUG}/ under the HomePage; nothing was changed.")
        page = existing.specific
        if not isinstance(page, AboutPage):
            raise CommandError(f"/{ABOUT_SLUG}/ is {type(page).__name__} #{page.pk}, not an AboutPage; nothing was changed.")
        live_revision = page.live_revision
        current = live_revision.as_object() if live_revision is not None else page
        inspection = Inspection(page=page, current=current)
        blockers = inspection.blockers

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
        if current.slug != ABOUT_SLUG:
            blockers.append(f"the live revision has the slug '{current.slug}'")

        def text_state(name, approved, empty_values=("",)):
            value = getattr(current, name) or ""
            if value == approved:
                return SAME
            return EMPTY if value in empty_values or value == field_default(name) else OTHER

        def rich_state(name):
            value = getattr(current, name) or ""
            if value == stored[name]:
                return SAME
            return EMPTY if rich_text_is_empty(value) else OTHER

        fields = inspection.fields
        fields["hero_title"] = (text_state("hero_title", content["hero_title"]), current.hero_title, content["hero_title"])
        fields["hero_subtitle"] = (text_state("hero_subtitle", content["hero_subtitle"]), current.hero_subtitle, content["hero_subtitle"])
        fields["intro_html"] = (rich_state("intro_html"), f"{len(current.intro_html or '')} characters", "3 paragraphs + 6 highlights")
        fields["mission_title"] = (text_state("mission_title", content["mission_title"]), current.mission_title, content["mission_title"])
        fields["mission_html"] = (rich_state("mission_html"), f"{len(current.mission_html or '')} characters", "mission statement")
        fields["features_title"] = (text_state("features_title", content["features_title"]), current.features_title, content["features_title"] or "(none)")
        features_state = EMPTY if len(current.features) == 0 else (SAME if self._features_match(current, content) else OTHER)
        fields["features"] = (features_state, f"{len(current.features)} cards", f"{len(content['features'])} mission pillars")
        fields["hero_background_image"] = (
            EMPTY if current.hero_background_image_id is None else OTHER,
            f"image #{current.hero_background_image_id}" if current.hero_background_image_id else "none",
            "hero banner",
        )
        for name in ("seo_title", "search_description"):
            value = getattr(current, name) or ""
            fields[name] = (SAME if value == content[name] else EMPTY if not value.strip() else SAME, value or "(empty)",
                            content[name] if not value.strip() else f"kept: {value}")
        if not missing:
            fields["intro_image"] = (EMPTY if current.intro_image_id is None else OTHER, current.intro_image_id or "none", "intro photograph")
            fields["stats"] = (EMPTY if len(current.stats) == 0 else OTHER, f"{len(current.stats)} statistics", f"{len(content['stats'])} statistics")
            fields["sections"] = (EMPTY if len(current.sections) == 0 else OTHER, f"{len(current.sections)} sections", f"{len(content['sections'])} sections")
        # A field whose image or stream is set counts as populated by this command only when everything matches.
        others = [name for name, (state, _cur, _app) in fields.items() if state == OTHER]
        all_set = not others or (set(others) <= {"hero_background_image", "intro_image", "stats", "sections", "features"}
                                 and all(fields[n][0] != EMPTY for n in fields))
        if others and not all_set:
            blockers.append(
                f"these fields already hold other content and are never overwritten: {', '.join(others)}; edit the page in Wagtail"
            )
        elif others:
            # Everything is populated: the page was filled before (by this command or by an editor).
            for name in others:
                fields[name] = (SAME, fields[name][1], fields[name][2])
        return inspection

    @staticmethod
    def _features_match(current, content):
        values = [(b.value.get("title"), b.value.get("desc")) for b in current.features if b.block_type == "feature"]
        return values == [(f["title"], f["desc"]) for f in content["features"]]

    @staticmethod
    def _all_same(inspection):
        return all(state == SAME for state, _cur, _app in inspection.fields.values())

    # -- writing ---------------------------------------------------------------------------

    def _apply(self, root, content, stored, planned):
        plan = self._media_plan(content)
        images, created_images = {}, 0
        collection = media_collection()
        image_model = get_image_model()
        media_by_key = {m["key"]: m for m in content["media"]}
        imported_by_hash = {}
        for key, (image, file_hash) in plan.items():
            if image is None:
                image = imported_by_hash.get(file_hash)
            if image is None:
                item = media_by_key[key]
                image = image_model(title=(item["alt"] or item["file"].rsplit(".", 1)[0])[:255], collection=collection)
                with open(IMAGES_DIR / item["file"], "rb") as fh:
                    image.file.save(item["file"], ImageFile(fh, name=item["file"]), save=False)
                image._set_image_file_metadata()
                image.save()
                created_images += 1
                imported_by_hash[file_hash] = image
            images[key] = image

        testimonial_model = apps.get_model("cms", "Testimonial")
        testimonials, created_testimonials = {}, 0
        for section in content["sections"]:
            if section["type"] != "testimonials":
                continue
            for i, item in enumerate(section["items"]):
                existing = testimonial_model.objects.filter(wordpress_id=item["wordpress_id"]).first() or \
                    testimonial_model.objects.filter(slug=item["slug"]).first()
                if existing is None:
                    existing = testimonial_model.objects.create(
                        name=item["name"], slug=item["slug"], role=item["role"], company=item["company"],
                        programme=item["programme"], quote=stored[f"sections[{content['sections'].index(section)}].items[{i}].quote"],
                        photo=images.get(item["photo"]) if item.get("photo") else None,
                        url=item["url"], wordpress_id=item["wordpress_id"],
                    )
                    created_testimonials += 1
                testimonials[item["slug"]] = existing

        with transaction.atomic():
            Page.objects.select_for_update().get(pk=planned.page.pk)
            site, root = resolve_site_and_root()
            current = self._inspect(root, content, stored, [])
            if current.page.latest_revision_id != planned.page.latest_revision_id:
                raise CommandError("The page changed while this command was running; nothing was changed. Run the preview again.")
            if current.blockers:
                raise CommandError(f"Refused, nothing was changed: {'; '.join(current.blockers)}.")

            page = current.current
            fields = current.fields
            if fields["hero_title"][0] == EMPTY:
                page.hero_title = content["hero_title"]
            if fields["hero_subtitle"][0] == EMPTY:
                page.hero_subtitle = content["hero_subtitle"]
            if fields["intro_html"][0] == EMPTY:
                page.intro_html = stored["intro_html"]
            if fields["mission_title"][0] == EMPTY:
                page.mission_title = content["mission_title"]
            if fields["mission_html"][0] == EMPTY:
                page.mission_html = stored["mission_html"]
            if fields["features_title"][0] == EMPTY:
                page.features_title = content["features_title"]
            if fields["features"][0] == EMPTY:
                page.features = StreamValue(page.features.stream_block, [
                    {"type": "feature", "value": {"image": None, "title": f["title"], "desc": f["desc"]}, "id": str(uuid.uuid4())}
                    for f in content["features"]
                ], is_lazy=True)
            if fields["hero_background_image"][0] == EMPTY:
                page.hero_background_image = images[content["hero_background_image"]]
            if fields["intro_image"][0] == EMPTY:
                page.intro_image = images[content["intro_image"]]
            for name in ("seo_title", "search_description"):
                if not (getattr(page, name) or "").strip():
                    setattr(page, name, content[name])
            if fields["stats"][0] == EMPTY:
                page.stats = StreamValue(page.stats.stream_block, [
                    {"type": "stat", "value": stat, "id": str(uuid.uuid4())} for stat in content["stats"]
                ], is_lazy=True)
            if fields["sections"][0] == EMPTY:
                page.sections = StreamValue(page.sections.stream_block, self._sections_raw(content, stored, images, testimonials), is_lazy=True)

            revision = page.save_revision(log_action=False)
            log(instance=page, action="wagtail.edit", revision=revision, content_changed=True,
                data={"source": "populate_about_page", "content_sha256": content["content_sha256"]})
            revision.publish(log_action=True)
            stored_page = AboutPage.objects.get(pk=page.pk)
            if not stored_page.live or stored_page.live_revision_id != revision.pk or len(stored_page.sections) == 0:
                raise CommandError("The page did not end up live with the approved content; rolled back.")
        return revision, created_images, created_testimonials

    @staticmethod
    def _item(value):
        return {"type": "item", "value": value, "id": str(uuid.uuid4())}

    def _sections_raw(self, content, stored, images, testimonials):
        def image_id(key):
            return images[key].pk if key else None

        def link(value):
            return {"label": value["label"], "url": value["url"]} if value else {"label": "", "url": ""}

        raw = []
        for i, s in enumerate(content["sections"]):
            kind = s["type"]
            if kind == "accordion":
                value = {"heading": s["heading"], "image": image_id(s.get("image")), "items": [
                    self._item({"title": item["title"], "body": stored[f"sections[{i}].items[{j}].body"], "logo": None})
                    for j, item in enumerate(s["items"])
                ]}
            elif kind == "cta_band":
                names = {m["key"]: m["alt"] for m in content["media"]}
                value = {"text": stored[f"sections[{i}].text"], "button": link(s.get("button")), "logos": [
                    self._item({"image": image_id(key), "name": names[key]}) for key in s["logos"]
                ]}
            elif kind == "card_group":
                value = {"heading": s["heading"], "layout": s["layout"], "prompt": s.get("prompt") or "",
                         "button": link(s.get("button")), "cards": [
                             self._item({"image": image_id(card.get("image")), "icon": card.get("icon") or "",
                                         "title": card["title"], "text": card.get("text") or "", "link": link(card.get("link"))})
                             for card in s["cards"]
                         ]}
            elif kind == "testimonials":
                value = {"heading": s["heading"], "button": link(s.get("button")),
                         "testimonials": [self._item(testimonials[item["slug"]].pk) for item in s["items"]]}
            elif kind == "logo_strip":
                value = {"heading": s["heading"], "button": link(s.get("button")),
                         "logos": [self._item({"image": image_id(logo["image"]), "name": logo["name"]}) for logo in s["logos"]]}
            elif kind == "contact_callout":
                value = {"heading": s["heading"], "text": stored[f"sections[{i}].text"], "email": s["email"],
                         "button_label": s.get("button_label") or ""}
            elif kind == "offices":
                value = {"heading": s["heading"], "email": s["email"], "offices": [
                    self._item({"city": o["city"], "country": o["country"], "phone": o["phone"], "image": image_id(o.get("image"))})
                    for o in s["offices"]
                ]}
            else:  # load_about_content rejects unknown types; this is a guard for future edits
                raise CommandError(f"Unknown section type {kind!r}.")
            raw.append({"type": kind, "value": value, "id": str(uuid.uuid4())})
        return raw

    # -- output ----------------------------------------------------------------------------

    def _report(self, site, root, inspection, content, missing):
        page = inspection.page
        self.stdout.write(f"Site: #{site.pk} {site.hostname}:{site.port}{' (default site)' if site.is_default_site else ''}")
        self.stdout.write(f"Root page: #{root.pk} HomePage '{root.title}'")
        self.stdout.write(
            f"Page: AboutPage #{page.pk} '{inspection.current.title}' ({'live' if page.live else 'not live'}; "
            f"live revision #{page.live_revision_id}; {page.revisions.count()} revisions)"
        )
        for reason in inspection.blockers:
            self.stdout.write(self.style.ERROR(f"  blocked: {reason}"))
        if not inspection.blockers:
            self.stdout.write("  ok: live without unpublished changes, not archived, locked, scheduled or restricted")
        if missing:
            self.stdout.write(self.style.WARNING(f"  schema: missing {', '.join(missing)} (docs/about-page-schema.md)"))

        self.stdout.write("Fields (title, slug and page ID are kept):")
        for name, (state, current, approved) in inspection.fields.items():
            verb = {EMPTY: "->", SAME: "already", OTHER: "KEEP (editor content)"}[state]
            self.stdout.write(f"    {name:<22} {state:<6} {current!s:.48} {verb} {approved!s:.70}")
        if missing:
            self.stdout.write(
                f"    {'intro_image, stats, sections':<22} after the schema change: intro photograph, "
                f"{len(content['stats'])} statistics, {len(content['sections'])} sections"
            )

        plan = self._media_plan(content)
        reused = sum(1 for image, _h in plan.values() if image is not None)
        unique = len({h for _i, h in plan.values()})
        self.stdout.write(
            f"Media: {len(plan)} references, {unique} distinct files: {reused} already in the image library, "
            f"{unique - len({h for i, h in plan.values() if i is not None})} to import into 'Public website pages'"
        )
        sections = content["sections"]
        counts = {s["type"]: 0 for s in sections}
        for s in sections:
            counts[s["type"]] += 1
        detail = {
            "accordion": lambda s: f"{len(s['items'])} items",
            "cta_band": lambda s: f"{len(s['logos'])} logos + button",
            "card_group": lambda s: f"{len(s['cards'])} cards ({s['layout']})",
            "testimonials": lambda s: f"{len(s['items'])} testimonials",
            "logo_strip": lambda s: f"{len(s['logos'])} logos",
            "contact_callout": lambda s: s["email"],
            "offices": lambda s: f"{len(s['offices'])} offices",
        }
        self.stdout.write("Sections, in order:")
        for s in sections:
            self.stdout.write(f"    {s['type']:<16} {s.get('heading') or '':<34} {detail[s['type']](s)}")
