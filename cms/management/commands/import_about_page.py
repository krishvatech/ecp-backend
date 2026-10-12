"""Import the approved About page content into the existing AboutPage. Preview unless --apply.

    python manage.py import_about_page                       # preview (same as --dry-run)
    python manage.py import_about_page --dry-run             # preview: read-only, prints a confirmation token
    python manage.py import_about_page --apply --page-id 7 --confirm <token> --backup-snapshot <rds-snapshot-id>

Source: cms/about_page_content/ (about.json + images/), migrated from imaa-institute.org/about-us/.
Runbook: docs/about-page-import-runbook.md. Nothing calls this command automatically (not on
startup, image build or migration).

What it does
* Finds the public Wagtail Site, its IMAA Connect HomePage root and the AboutPage at /about/
  (verified by site, type, parent and slug; the page ID is whatever that page has and must be
  passed back with --page-id).
* Replaces the About-specific fields (hero, introduction, statistics, feature cards, mission and
  the ordered sections: accreditations, programmes, testimonials, logos, offices) with the
  approved content and publishes it as a new revision. Page ID, title, slug, position, earlier
  revisions and non-empty SEO fields are kept.
* A field that is empty, holds the model's default ("About IMAA Connect", ...) or already holds
  the approved value is handled automatically. Any other content (for example the earlier
  IMAA Connect texts) is only replaced with --replace-existing-content, after review.
* Images: never uploaded, overwritten or deleted. Each approved file must already be in the
  configured storage, either behind an existing Wagtail image with the same content or at
  ``original_images/<file name>``; the stored bytes are downloaded and must match the approved
  SHA-256 and dimensions. Missing Wagtail image records are created for those stored files.
* Testimonials: the 10 approved Testimonial snippets are created when no snippet with the same
  WordPress ID or slug exists; existing snippets are reused and never changed.

Safety
* The preview runs only SELECT statements (enforced) and only reads from storage. It prints every
  field's current state and a confirmation token that binds the database, the site, the page, its
  revisions, the reviewed current content, the approved content and the chosen options.
* --apply requires --page-id and that token: any change in between (an editor saving the page, a
  different database or page) changes the token and the run is refused.
* --apply on a non-local database requires --backup-snapshot: an RDS snapshot of this database,
  verified through the RDS API (available, recent). --backup-verified-externally records an
  operator-verified backup instead when this host may not call the RDS API.
* Refused, before anything is written: unpublished changes, locks, workflows, moderation,
  schedules, view restrictions, aliases, archived pages, a missing schema, invalid content,
  missing or different stored images, rich text the Wagtail editor cannot load.
* All database changes (image records, testimonials, the revision and publishing) are one
  transaction; the page row is locked and every check repeated under the lock.
* A repeat run reports "already imported" and changes nothing.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone
from io import BytesIO

from django.apps import apps
from django.conf import settings
from django.core.files.storage import storages
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from wagtail.blocks import StreamValue
from wagtail.images import get_image_model
from wagtail.log_actions import log
from wagtail.models import Page
from wagtail.utils.file import hash_filelike
from willow.image import Image as WillowImage

from cms.about_page_content import IMAGES_DIR, AboutContentError, load_about_content
from cms.about_page_import import (
    ABOUT_SLUG,
    editor_rich_text,
    features_raw,
    page_blockers,
    schema_missing,
    sections_raw,
    stats_raw,
    without_ids,
)
from cms.local_safety import LOCAL_DATABASE_HOSTS, LOCAL_STORAGE_CLASSES, describe_environment
from cms.models import AboutPage
from cms.public_page_setup import DryRunWriteGuard, media_collection, resolve_site_and_root, rich_text_is_empty

STORAGE_FOLDER = "original_images"
EMPTY, SAME, REPLACE = "empty", "same", "replace"
TEXT_FIELDS = ("hero_title", "hero_subtitle", "mission_title", "features_title")
RICH_FIELDS = ("intro_html", "mission_html")
IMAGE_FIELDS = ("hero_background_image", "intro_image")
STREAM_FIELDS = ("stats", "features", "sections")
REPLACED_FIELDS = TEXT_FIELDS + RICH_FIELDS + IMAGE_FIELDS + STREAM_FIELDS
SEO_FIELDS = ("seo_title", "search_description")
DEFAULT_BACKUP_MAX_AGE_HOURS = 24


@dataclass
class MediaFile:
    sha256: str
    file: str
    keys: list
    sha1: str = ""
    image: object = None  # an existing Wagtail image for this content
    storage_name: str = ""  # where the original is stored (existing image or original_images/<file>)
    width: int = 0
    height: int = 0
    size: int = 0
    problem: str = ""

    @property
    def action(self):
        return "reuse" if self.image is not None else "create record"


@dataclass
class Plan:
    site: object
    root: object
    page: object
    current: object
    blockers: list = field(default_factory=list)
    page_ok: bool = True  # no page-level blockers (unpublished changes, locks, ...)
    fields: dict = field(default_factory=dict)  # name -> (state, current display, approved display)
    seo: dict = field(default_factory=dict)  # name -> new value (only when empty now)
    media: dict = field(default_factory=dict)  # sha256 -> MediaFile
    testimonials: list = field(default_factory=list)  # (item, existing snippet or None)
    fingerprint: str = ""

    def image_for_key(self, key):
        for media_file in self.media.values():
            if key in media_file.keys:
                return media_file
        raise KeyError(key)

    @property
    def replacements(self):
        return [name for name, (state, _c, _a) in self.fields.items() if state == REPLACE]

    @property
    def changes(self):
        return [name for name, (state, _c, _a) in self.fields.items() if state != SAME] + list(self.seo)

    @property
    def nothing_to_do(self):
        return not self.changes and all(m.image is not None for m in self.media.values()) and \
            all(existing is not None for _item, existing in self.testimonials)


def _is_local_database():
    db = connection.settings_dict
    return "postgresql" in db.get("ENGINE", "") and (db.get("HOST") or "").strip() in LOCAL_DATABASE_HOSTS


def _short(value, limit=60):
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Command(BaseCommand):
    help = "Import the approved About page content into the existing AboutPage. Read-only preview unless --apply."

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Read-only preview (the default).")
        mode.add_argument("--apply", action="store_true", help="Import and publish; needs --page-id, --confirm and a verified backup.")
        parser.add_argument("--page-id", type=int, help="With --apply: the AboutPage ID shown by the preview.")
        parser.add_argument("--confirm", help="With --apply: the confirmation token printed by the preview.")
        parser.add_argument("--replace-existing-content", action="store_true",
                            help="Replace About fields that hold other (reviewed) content, e.g. the earlier IMAA Connect texts.")
        parser.add_argument("--backup-snapshot", help="With --apply: the RDS snapshot taken of this database before the import.")
        parser.add_argument("--db-instance", help="RDS DB instance or cluster identifier, when the database host is not its endpoint (RDS Proxy).")
        parser.add_argument("--backup-max-age-hours", type=float, default=DEFAULT_BACKUP_MAX_AGE_HOURS,
                            help=f"Newest acceptable snapshot age (default {DEFAULT_BACKUP_MAX_AGE_HOURS} hours).")
        parser.add_argument("--backup-verified-externally", action="store_true",
                            help="Record --backup-snapshot as verified by the operator instead of checking it through the RDS API.")

    # -- entry point ------------------------------------------------------------------------

    def handle(self, *args, **options):
        apply = options["apply"]
        replace = options["replace_existing_content"]
        self.stdout.write(self.style.MIGRATE_HEADING(
            f"Import About page /{ABOUT_SLUG}/: {'APPLY' if apply else 'PREVIEW (read-only, no changes)'}"
        ))
        self.stdout.write(describe_environment())
        if apply and (options["page_id"] is None or not options["confirm"]):
            raise CommandError("--apply needs --page-id and --confirm (both printed by the preview); nothing was changed.")
        if apply and not _is_local_database() and not options["backup_snapshot"]:
            raise CommandError("--apply on this database needs --backup-snapshot <RDS snapshot ID>; nothing was changed.")

        content, stored = self._load_content()
        missing = schema_missing()
        if missing:
            raise CommandError(f"Refused, nothing was changed: the database schema is not ready: {'; '.join(missing)}.")

        if not apply:
            with connection.execute_wrapper(DryRunWriteGuard()):
                plan = self._plan(content, stored, replace)
            token = self._token(plan, content, replace)
            self._report(plan, content, token, replace)
            if plan.blockers:
                raise CommandError(f"Refused, nothing was changed: {'; '.join(plan.blockers)}.")
            if plan.nothing_to_do:
                self.stdout.write(self.style.SUCCESS("Already imported: the page holds the approved content; nothing to do."))
                return
            self.stdout.write("Review the plan above. To import it, run:")
            self.stdout.write(f"  python manage.py import_about_page --apply --page-id {plan.page.pk} --confirm {token}"
                              f"{' --replace-existing-content' if replace else ''}"
                              f"{'' if _is_local_database() else ' --backup-snapshot <rds-snapshot-id>'}")
            return

        with connection.execute_wrapper(DryRunWriteGuard()):
            plan = self._plan(content, stored, replace)
        token = self._token(plan, content, replace)
        self._report(plan, content, token, replace)
        if plan.blockers:
            raise CommandError(f"Refused, nothing was changed: {'; '.join(plan.blockers)}.")
        if plan.page.pk != options["page_id"]:
            raise CommandError(
                f"Refused, nothing was changed: --page-id {options['page_id']} does not match the AboutPage at "
                f"/{ABOUT_SLUG}/ in this database (#{plan.page.pk})."
            )
        if plan.nothing_to_do:
            self.stdout.write(self.style.SUCCESS("Already imported: the page holds the approved content; nothing changed."))
            return
        if options["confirm"] != token:
            raise CommandError(
                "Refused, nothing was changed: the confirmation token does not match this database, page and content "
                "(the page or its content changed since the preview, or the options differ). Run the preview again."
            )
        backup = self._verify_backup(options)
        revision, counts = self._apply(content, stored, plan, token, replace, backup)
        self.stdout.write(self.style.SUCCESS(
            f"Created {counts['images']} image records (no files uploaded) and {counts['testimonials']} testimonials; "
            f"published revision #{revision.pk} of AboutPage #{plan.page.pk}. /{ABOUT_SLUG}/ is live with the approved content."
        ))

    # -- content ----------------------------------------------------------------------------

    def _load_content(self):
        try:
            content = load_about_content()
        except AboutContentError as exc:
            raise CommandError(f"Approved content is invalid, nothing was changed: {exc}") from exc
        self.stdout.write(f"  ok: approved content (sha256 {content['content_sha256'][:12]}, "
                          f"{len(content['media'])} media references verified against their SHA-256)")
        stored, problems = editor_rich_text(content)
        if problems:
            raise CommandError(f"Approved rich text is not editor-safe, nothing was changed: {'; '.join(problems[:3])}.")
        self.stdout.write(f"  ok: {len(stored)} rich-text values load in the Wagtail editor with their text intact")
        return content, stored

    # -- inspection (read-only) ---------------------------------------------------------------

    def _plan(self, content, stored, replace, verified=frozenset()):
        """``verified``: (storage name, sha256) pairs already checked in storage during this run."""
        site, root = resolve_site_and_root()
        existing = Page.objects.child_of(root).filter(slug=ABOUT_SLUG).first()
        if existing is None:
            raise CommandError(f"No page exists at /{ABOUT_SLUG}/ under the HomePage #{root.pk}; nothing was changed.")
        page = existing.specific
        if not isinstance(page, AboutPage):
            raise CommandError(f"/{ABOUT_SLUG}/ is {type(page).__name__} #{page.pk}, not an AboutPage; nothing was changed.")
        live_revision = page.live_revision
        current = live_revision.as_object() if live_revision is not None else page
        plan = Plan(site=site, root=root, page=page, current=current, blockers=page_blockers(page, current))
        plan.page_ok = not plan.blockers

        self._plan_media(plan, content, verified)
        self._plan_testimonials(plan, content)
        self._plan_fields(plan, content, stored, replace)
        plan.fingerprint = self._fingerprint(current)
        return plan

    def _plan_media(self, plan, content, verified):
        storage = storages["default"]
        image_model = get_image_model()
        for item in content["media"]:
            entry = plan.media.get(item["sha256"])
            if entry is None:
                entry = plan.media[item["sha256"]] = MediaFile(sha256=item["sha256"], file=item["file"], keys=[],
                                                               width=item["width"], height=item["height"])
            entry.keys.append(item["key"])
        for entry in plan.media.values():
            path = IMAGES_DIR / entry.file
            with open(path, "rb") as fh:
                entry.sha1 = hash_filelike(fh)
            entry.size = path.stat().st_size
            name = f"{STORAGE_FOLDER}/{entry.file}"
            entry.image = (image_model.objects.filter(file_hash=entry.sha1).order_by("pk").first()
                           or image_model.objects.filter(file=name).order_by("pk").first())
            entry.storage_name = entry.image.file.name if entry.image is not None else name
            if (entry.storage_name, entry.sha256) not in verified or entry.image is not None and \
                    entry.image.file_hash not in ("", entry.sha1):
                entry.problem = self._check_stored_file(storage, entry)
            if entry.problem:
                plan.blockers.append(entry.problem)

    @staticmethod
    def _check_stored_file(storage, entry):
        """'' when the stored original is the approved file (content, size and dimensions)."""
        name = entry.storage_name
        try:
            if not storage.exists(name):
                return f"image file {entry.file}: no object at '{name}' in storage (it is never uploaded by this command)"
            with storage.open(name, "rb") as fh:
                data = fh.read()
        except Exception as exc:  # network, permissions, ...
            return f"image file {entry.file}: cannot read '{name}' from storage ({type(exc).__name__}: {exc})"
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            return f"image file {entry.file}: the object at '{name}' differs from the approved file (SHA-256 mismatch)"
        if len(data) != entry.size:
            return f"image file {entry.file}: the object at '{name}' has {len(data)} bytes, expected {entry.size}"
        width, height = WillowImage.open(BytesIO(data)).get_size()
        if (width, height) != (entry.width, entry.height):
            return f"image file {entry.file}: '{name}' is {width}x{height}, expected {entry.width}x{entry.height}"
        if entry.image is not None and entry.image.file_hash not in ("", entry.sha1):
            return f"image file {entry.file}: Wagtail image #{entry.image.pk} records a different file hash"
        return ""

    def _plan_testimonials(self, plan, content):
        testimonial_model = apps.get_model("cms", "Testimonial")
        for section in content["sections"]:
            if section["type"] != "testimonials":
                continue
            for item in section["items"]:
                existing = (testimonial_model.objects.filter(wordpress_id=item["wordpress_id"]).first()
                            or testimonial_model.objects.filter(slug=item["slug"]).first())
                plan.testimonials.append((item, existing))

    def _plan_fields(self, plan, content, stored, replace):
        current = plan.current

        def default(name):
            return AboutPage._meta.get_field(name).get_default()

        def state(is_same, is_empty):
            return SAME if is_same else EMPTY if is_empty else REPLACE

        fields = plan.fields
        for name in TEXT_FIELDS:
            value = getattr(current, name) or ""
            fields[name] = (state(value == content[name], value.strip() == "" or value == default(name)),
                            repr(_short(value, 48)), repr(_short(content[name] or "", 60)))
        for name in RICH_FIELDS:
            value = getattr(current, name) or ""
            fields[name] = (state(value == stored[name], rich_text_is_empty(value)),
                            f"{len(value)} characters: {_short(value, 40)!r}", f"{len(stored[name])} characters")
        for name in IMAGE_FIELDS:
            approved = plan.image_for_key(content[name])
            current_id = getattr(current, f"{name}_id")
            same = approved.image is not None and current_id == approved.image.pk
            fields[name] = (state(same, current_id is None), f"image #{current_id}" if current_id else "none", approved.file)

        image_ids = {key: m.image.pk for m in plan.media.values() if m.image is not None for key in m.keys}
        testimonial_ids = {item["slug"]: existing.pk for item, existing in plan.testimonials if existing is not None}
        approved_streams = {
            "stats": without_ids(stats_raw(content)),
            "features": without_ids(features_raw(content)),
        }
        complete = len(image_ids) == len(content["media"]) and len(testimonial_ids) == len(plan.testimonials)
        approved_streams["sections"] = without_ids(sections_raw(
            content, stored,
            image_id=lambda key: image_ids.get(key) if key else None,
            testimonial_id=lambda slug: testimonial_ids.get(slug),
        )) if complete else None
        described = {"stats": f"{len(content['stats'])} statistics", "features": f"{len(content['features'])} feature cards",
                     "sections": f"{len(content['sections'])} sections"}
        for name in STREAM_FIELDS:
            raw = without_ids(list(getattr(current, name).raw_data))
            fields[name] = (state(approved_streams[name] is not None and raw == approved_streams[name], len(raw) == 0),
                            f"{len(raw)} blocks", described[name])

        for name in SEO_FIELDS:
            if not (getattr(current, name) or "").strip():
                plan.seo[name] = content[name]

        if plan.replacements and not replace:
            plan.blockers.append(
                f"these fields hold other content: {', '.join(plan.replacements)}; review it above and add "
                "--replace-existing-content to replace it"
            )

    @staticmethod
    def _fingerprint(current):
        """SHA-256 of the page's current reviewable state (all About fields, SEO, title, slug)."""
        values = {"title": current.title, "slug": current.slug}
        for name in TEXT_FIELDS + RICH_FIELDS + SEO_FIELDS:
            values[name] = getattr(current, name) or ""
        for name in IMAGE_FIELDS:
            values[name] = getattr(current, f"{name}_id")
        for name in STREAM_FIELDS:
            values[name] = list(getattr(current, name).raw_data)
        return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()

    @staticmethod
    def _token(plan, content, replace):
        db = connection.settings_dict
        parts = [
            db.get("NAME") or "", (db.get("HOST") or "").strip(), str(db.get("PORT") or ""),
            f"site{plan.site.pk}", f"root{plan.root.pk}", f"page{plan.page.pk}",
            f"live{plan.page.live_revision_id}", f"latest{plan.page.latest_revision_id}",
            content["content_sha256"], plan.fingerprint, "replace" if replace else "fill",
        ]
        digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
        return f"about-{plan.page.pk}-{digest}"

    # -- backup -----------------------------------------------------------------------------

    def _verify_backup(self, options):
        """A description of the verified backup for the page log; refuses when none is verified."""
        if _is_local_database():
            self.stdout.write("  backup: local development database; no RDS snapshot required")
            return {"backup": "local database"}
        snapshot = options["backup_snapshot"]
        if options["backup_verified_externally"]:
            self.stdout.write(self.style.WARNING(
                f"  backup: snapshot '{snapshot}' recorded as verified by the operator (RDS API check skipped)"
            ))
            return {"backup_snapshot": snapshot, "backup_verification": "operator"}
        try:
            details = verify_rds_snapshot(
                snapshot, host=(connection.settings_dict.get("HOST") or "").strip(),
                max_age=timedelta(hours=options["backup_max_age_hours"]), db_identifier=options["db_instance"],
            )
        except BackupNotVerified as exc:
            raise CommandError(f"Refused, nothing was changed: the backup is not verified: {exc}") from exc
        self.stdout.write(f"  ok: backup {details['snapshot']} of {details['source']} ({details['status']}, created {details['created']})")
        return {"backup_snapshot": details["snapshot"], "backup_source": details["source"],
                "backup_created": details["created"], "backup_verification": "rds-api"}

    # -- writing ----------------------------------------------------------------------------

    def _apply(self, content, stored, planned, token, replace, backup):
        image_model = get_image_model()
        testimonial_model = apps.get_model("cms", "Testimonial")
        with transaction.atomic():
            Page.objects.select_for_update().get(pk=planned.page.pk)
            verified = {(m.storage_name, m.sha256) for m in planned.media.values() if not m.problem}
            with connection.execute_wrapper(DryRunWriteGuard()):
                plan = self._plan(content, stored, replace, verified)
            if plan.blockers:
                raise CommandError(f"Refused, nothing was changed: {'; '.join(plan.blockers)}.")
            if self._token(plan, content, replace) != token:
                raise CommandError("The page changed while this command was running; nothing was changed. Run the preview again.")

            created_images, collection = 0, None
            images = {}
            for entry in plan.media.values():
                image = entry.image
                if image is None:
                    collection = collection or media_collection()
                    media_item = next(m for m in content["media"] if m["sha256"] == entry.sha256)
                    image = image_model(
                        title=(media_item["alt"] or entry.file.rsplit(".", 1)[0])[:255], collection=collection,
                        width=entry.width, height=entry.height, file_size=entry.size, file_hash=entry.sha1,
                    )
                    image.file.name = entry.storage_name  # the stored original; nothing is uploaded
                    image.save()
                    created_images += 1
                for key in entry.keys:
                    images[key] = image

            created_testimonials, testimonials = 0, {}
            section_index = {id(s): i for i, s in enumerate(content["sections"])}
            for section in content["sections"]:
                if section["type"] != "testimonials":
                    continue
                for j, item in enumerate(section["items"]):
                    existing = dict((it["slug"], ex) for it, ex in plan.testimonials).get(item["slug"])
                    if existing is None:
                        existing = testimonial_model.objects.create(
                            name=item["name"], slug=item["slug"], role=item["role"], company=item["company"],
                            programme=item["programme"],
                            quote=stored[f"sections[{section_index[id(section)]}].items[{j}].quote"],
                            photo=images.get(item["photo"]) if item.get("photo") else None,
                            url=item["url"], wordpress_id=item["wordpress_id"],
                        )
                        created_testimonials += 1
                    testimonials[item["slug"]] = existing

            page = plan.current
            states = {name: state for name, (state, _c, _a) in plan.fields.items()}
            for name in TEXT_FIELDS:
                if states[name] != SAME:
                    setattr(page, name, content[name])
            for name in RICH_FIELDS:
                if states[name] != SAME:
                    setattr(page, name, stored[name])
            for name in IMAGE_FIELDS:
                if states[name] != SAME:
                    setattr(page, name, images[content[name]])
            if states["stats"] != SAME:
                page.stats = StreamValue(page.stats.stream_block, stats_raw(content), is_lazy=True)
            if states["features"] != SAME:
                page.features = StreamValue(page.features.stream_block, features_raw(content), is_lazy=True)
            if states["sections"] != SAME:
                page.sections = StreamValue(page.sections.stream_block, sections_raw(
                    content, stored,
                    image_id=lambda key: images[key].pk if key else None,
                    testimonial_id=lambda slug: testimonials[slug].pk,
                ), is_lazy=True)
            for name, value in plan.seo.items():
                setattr(page, name, value)

            revision = page.save_revision(log_action=False)
            log(instance=page, action="wagtail.edit", revision=revision, content_changed=True, data={
                "source": "import_about_page", "content_sha256": content["content_sha256"], "confirmation": token,
                "replaced_existing_content": plan.replacements, **backup,
            })
            revision.publish(log_action=True)

            stored_page = AboutPage.objects.get(pk=page.pk)
            if (not stored_page.live or stored_page.live_revision_id != revision.pk or stored_page.has_unpublished_changes
                    or len(stored_page.sections) != len(content["sections"]) or len(stored_page.stats) != len(content["stats"])):
                raise CommandError("The page did not end up live with the approved content; every change was rolled back.")
        return revision, {"images": created_images, "testimonials": created_testimonials}

    # -- output -----------------------------------------------------------------------------

    def _report(self, plan, content, token, replace):
        site, root, page = plan.site, plan.root, plan.page
        storage = storages["default"]
        self.stdout.write(f"Storage: {type(storage).__name__}"
                          f"{' bucket ' + storage.bucket_name if getattr(storage, 'bucket_name', None) else ''}"
                          f"{'' if isinstance(storage, LOCAL_STORAGE_CLASSES) else ' (read only: objects are checked, never written)'}")
        self.stdout.write(f"Site: #{site.pk} {site.hostname}:{site.port}{' (default site)' if site.is_default_site else ''}")
        self.stdout.write(f"Root page: #{root.pk} HomePage '{root.title}'")
        self.stdout.write(
            f"Page: AboutPage #{page.pk} '{plan.current.title}' at {page.url_path} ({'live' if page.live else 'not live'}; "
            f"live revision #{page.live_revision_id}; {page.revisions.count()} revisions)"
        )
        for reason in plan.blockers:
            self.stdout.write(self.style.ERROR(f"  blocked: {reason}"))
        if plan.page_ok:
            self.stdout.write("  ok: live without unpublished changes, not archived, locked, in a workflow, scheduled or restricted")

        verbs = {EMPTY: "->", SAME: "already", REPLACE: "REPLACE ->"}
        self.stdout.write("Fields (page ID, title, slug and earlier revisions are kept):")
        for name, (state, current, approved) in plan.fields.items():
            self.stdout.write(f"    {name:<22} {state:<8} {current!s:.60} {verbs[state]} {approved!s:.60}")
        for name in SEO_FIELDS:
            if name in plan.seo:
                self.stdout.write(f"    {name:<22} {'empty':<8} '' -> {_short(plan.seo[name])!r}")
            else:
                self.stdout.write(f"    {name:<22} {'kept':<8} {_short(getattr(plan.current, name))!r}")

        reuse = [m for m in plan.media.values() if m.image is not None]
        create = [m for m in plan.media.values() if m.image is None and not m.problem]
        problems = [m for m in plan.media.values() if m.problem]
        self.stdout.write(
            f"Images: {len(content['media'])} references, {len(plan.media)} distinct files, all verified in storage "
            f"by SHA-256: {len(reuse)} existing Wagtail images reused, {len(create)} image records to create for stored "
            f"originals, {len(problems)} problems; 0 uploads"
            if not problems else
            f"Images: {len(content['media'])} references, {len(plan.media)} distinct files: {len(problems)} cannot be used (see blocked)"
        )
        new_testimonials = [item["name"] for item, existing in plan.testimonials if existing is None]
        self.stdout.write(f"Testimonials: {len(plan.testimonials)} approved: {len(plan.testimonials) - len(new_testimonials)} "
                          f"existing reused unchanged, {len(new_testimonials)} to create")
        self.stdout.write("Sections, in order:")
        detail = {
            "accordion": lambda s: f"{len(s['items'])} items",
            "cta_band": lambda s: f"{len(s['logos'])} logos + button",
            "card_group": lambda s: f"{len(s['cards'])} cards ({s['layout']})",
            "testimonials": lambda s: f"{len(s['items'])} testimonials",
            "logo_strip": lambda s: f"{len(s['logos'])} logos",
            "contact_callout": lambda s: s["email"],
            "offices": lambda s: f"{len(s['offices'])} offices",
        }
        for s in content["sections"]:
            self.stdout.write(f"    {s['type']:<16} {s.get('heading') or '':<34} {detail[s['type']](s)}")
        if plan.replacements:
            self.stdout.write(self.style.WARNING(
                f"Existing content that {'WILL' if replace else 'would'} be replaced: {', '.join(plan.replacements)}"
                f"{'' if replace else ' (needs --replace-existing-content)'}"
            ))
        self.stdout.write(f"Confirmation token: {token}")


class BackupNotVerified(Exception):
    pass


def _rds_client():
    import boto3

    region = (os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
              or getattr(settings, "AWS_S3_REGION_NAME", None))
    return boto3.client("rds", region_name=region) if region else boto3.client("rds")


def verify_rds_snapshot(snapshot_id, host, max_age, db_identifier=None, client=None, now=None):
    """Check that ``snapshot_id`` is an available, recent RDS snapshot of the database at ``host``.

    Accepts DB instance snapshots and Aurora cluster snapshots. The source of the snapshot must be
    the instance or cluster whose endpoint is ``host``, or ``db_identifier`` when the host is not
    an RDS endpoint (RDS Proxy). Raises BackupNotVerified with the reason otherwise.
    """
    client = client or _rds_client()
    now = now or datetime.now(dt_timezone.utc)
    try:
        snapshot, kind = _find_snapshot(client, snapshot_id)
        if snapshot is None:
            raise BackupNotVerified(f"no RDS snapshot named '{snapshot_id}'")
        source = snapshot.get("DBClusterIdentifier") if kind == "cluster" else snapshot.get("DBInstanceIdentifier")
        expected = db_identifier or _identifier_for_host(client, host, kind)
    except BackupNotVerified:
        raise
    except Exception as exc:  # credentials, permissions, network
        raise BackupNotVerified(
            f"the RDS API could not be queried ({type(exc).__name__}: {exc}); grant rds:DescribeDBSnapshots, "
            "rds:DescribeDBInstances (and the cluster equivalents) or use --backup-verified-externally"
        ) from exc
    if expected is None:
        raise BackupNotVerified(f"the database host '{host}' is not an RDS {kind} endpoint; pass --db-instance <identifier>")
    if source != expected:
        raise BackupNotVerified(f"snapshot '{snapshot_id}' is of '{source}', not of this database ('{expected}')")
    status = snapshot.get("Status")
    if status != "available":
        raise BackupNotVerified(f"snapshot '{snapshot_id}' is '{status}', not 'available'")
    created = snapshot.get("SnapshotCreateTime")
    if created is None or now - created > max_age:
        raise BackupNotVerified(f"snapshot '{snapshot_id}' was created {created}, more than {max_age} ago")
    return {"snapshot": snapshot_id, "source": source, "status": status, "created": created.isoformat()}


def _find_snapshot(client, snapshot_id):
    for kind, call, key in (("instance", "describe_db_snapshots", "DBSnapshots"),
                            ("cluster", "describe_db_cluster_snapshots", "DBClusterSnapshots")):
        argument = "DBSnapshotIdentifier" if kind == "instance" else "DBClusterSnapshotIdentifier"
        try:
            found = getattr(client, call)(**{argument: snapshot_id}).get(key) or []
        except Exception as exc:
            if "NotFound" in type(exc).__name__ or "NotFound" in str(exc):
                continue
            raise
        if found:
            return found[0], kind
    return None, None


def _identifier_for_host(client, host, kind):
    if kind == "cluster":
        for cluster in client.describe_db_clusters().get("DBClusters", []):
            if host in (cluster.get("Endpoint"), cluster.get("ReaderEndpoint")):
                return cluster["DBClusterIdentifier"]
        return None
    for page in client.get_paginator("describe_db_instances").paginate():
        for instance in page.get("DBInstances", []):
            if (instance.get("Endpoint") or {}).get("Address") == host:
                return instance["DBInstanceIdentifier"]
    return None
