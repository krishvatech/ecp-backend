"""Import the approved Our Team content (programmes, people, the TeamPage). Preview unless --apply.

    python manage.py import_team_page                        # preview (same as --dry-run)
    python manage.py import_team_page --dry-run [--publish]  # read-only; prints a confirmation token
    python manage.py import_team_page --apply --confirm <token> [--publish] --backup-snapshot <rds-snapshot-id>
    python manage.py import_team_page --prepare-renditions   # after the import: generate the page's image renditions

Source: cms/team_page_content/team.json (migrated from imaa-institute.org/our-team/). The image
binaries are NOT needed: the originals must already be in the configured storage at
``original_images/<file name>`` (see ``team_media_transfer``). Runbook:
docs/team-page-import-runbook.md. Nothing calls this command automatically.

What it does
* Finds the public Wagtail Site and its IMAA Connect HomePage root; creates the TeamPage at
  /our-team/ when there is none, otherwise fills only the page's empty fields (an editor's text
  is never overwritten).
* Creates the programmes and people that do not exist yet. Existing records (matched by slug for
  programmes, WordPress ID then slug for people) are kept exactly as they are.
* Images: never uploaded, overwritten or deleted. Every original this run needs (photos of new
  people; section images when the sections are filled) is downloaded once, must match the
  approved SHA-256 and dimensions, and gives the Wagtail file hash and size. An existing Wagtail
  image with that content is reused (the object it points at is verified too); otherwise an image
  record is created for the stored original.
* With --publish the page revision is published; without it the page stays a draft.
* --prepare-renditions (with --apply, or on its own afterwards) generates the image renditions the
  public page uses (portraits fill-400x400, programme cards max-800x800, office badges
  max-160x160), through the same get_rendition() call as the API. Otherwise the first API request
  generates ~100 of them at once (~0.13 s CPU each plus storage I/O) and can time out, and a
  rendition that fails is silently left out of the page. It only adds rendition rows and new
  objects (storage never overwrites); it does not import anything. The preview reports how many
  are still missing.

Safety (as import_about_page)
* The preview runs only SELECT statements (enforced) and only reads from storage.
* --apply needs the token printed by the preview: it binds the database, site, page, revisions,
  the existing Team records, the approved content and the options.
* --apply on a non-local database needs a verified RDS snapshot (--backup-snapshot).
* Refused before anything is written: identity conflicts (a slug and a WordPress ID that point to
  different people, a programme code used by another slug, a second TeamPage), unpublished
  changes on the live page, locks, workflows, schedules, view restrictions, missing schema,
  invalid content, missing or different images.
* All database changes are one transaction with the page (or the HomePage for a new page) locked
  and every check repeated under the lock. A repeat run reports "already imported".

``populate_team_page`` remains the local-only importer that imports the image files themselves.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from django.apps import apps
from django.core.files.storage import storages
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from wagtail.blocks import StreamValue
from wagtail.images import get_image_model
from wagtail.log_actions import log
from wagtail.models import Page

from cms.about_blocks import RICH_TEXT_FEATURES
from cms.editor_checks import draftail_problem
from cms.local_safety import LOCAL_STORAGE_CLASSES, describe_environment
from cms.management.commands.import_about_page import (
    BackupNotVerified,
    Command as AboutImport,
    MediaFile,
    _is_local_database,
    verify_rds_snapshot,
)
from cms.management.commands.populate_team_page import (
    PAGE_TEXT_FIELDS,
    TEAM_SLUG,
    Command as LocalTeamImport,
    schema_missing,
)
from cms.public_page_setup import DryRunWriteGuard, editor_line_breaks, media_collection, resolve_site_and_root, rich_text_is_empty
from cms.public_pages import is_archived
from cms.team_page_content import TeamContentError, load_team_content

STORAGE_FOLDER = "original_images"
RICH_FIELDS = ("faculty_intro", "staff_intro")
STREAM_FIELDS = ("hero_button", "faculty_buttons", "staff_button", "sections")
EMPTY, SAME, KEPT = "empty", "same", "kept"


@dataclass
class Plan:
    site: object
    root: object
    page: object = None  # the TeamPage at /our-team/, or None when it will be created
    current: object = None  # the page as of its latest revision
    blockers: list = field(default_factory=list)
    page_fields: dict = field(default_factory=dict)  # name -> EMPTY | SAME | KEPT
    seo: dict = field(default_factory=dict)  # fields filled because they are empty
    programmes_new: list = field(default_factory=list)
    programmes_kept: list = field(default_factory=list)
    members_new: list = field(default_factory=list)
    members_kept: list = field(default_factory=list)
    media: dict = field(default_factory=dict)  # media key -> MediaFile (only the media this run uses)
    fingerprint: str = ""

    @property
    def fills(self):
        return [name for name, state in self.page_fields.items() if state == EMPTY]

    def nothing_to_do(self, publish):
        return (self.page is not None and not self.fills and not self.seo and not self.programmes_new
                and not self.members_new and (self.page.live or not publish))


class Command(BaseCommand):
    help = "Import the approved Our Team content from storage-verified originals. Read-only preview unless --apply."

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Read-only preview (the default).")
        mode.add_argument("--apply", action="store_true", help="Import; needs --confirm and, on a remote database, a verified backup.")
        parser.add_argument("--publish", action="store_true", help="Publish the page revision (otherwise it is saved as a draft).")
        parser.add_argument("--confirm", help="With --apply: the confirmation token printed by the preview.")
        parser.add_argument("--prepare-renditions", action="store_true",
                            help="Generate the image renditions the public page uses (after the import; adds only).")
        parser.add_argument("--backup-snapshot", help="With --apply on a remote database: the RDS snapshot taken before the import.")
        parser.add_argument("--db-instance", help="RDS DB instance or cluster identifier, when the host is not its endpoint (RDS Proxy).")
        parser.add_argument("--backup-max-age-hours", type=float, default=24, help="Newest acceptable snapshot age (default 24 hours).")
        parser.add_argument("--backup-verified-externally", action="store_true",
                            help="Record --backup-snapshot as verified by the operator instead of checking it through the RDS API.")

    # -- entry point ------------------------------------------------------------------------

    def handle(self, *args, **options):
        apply, publish = options["apply"], options["publish"]
        self.stdout.write(self.style.MIGRATE_HEADING(
            f"Import Our Team /{TEAM_SLUG}/: {'APPLY' if apply else 'PREVIEW (read-only, no changes)'}"
        ))
        self.stdout.write(describe_environment())
        if apply and not options["confirm"]:
            raise CommandError("--apply needs --confirm (the token printed by the preview); nothing was changed.")
        if apply and not _is_local_database() and not options["backup_snapshot"]:
            raise CommandError("--apply on this database needs --backup-snapshot <RDS snapshot ID>; nothing was changed.")

        content, stored = self._load_content()
        missing = schema_missing()
        if missing:
            raise CommandError(f"Refused, nothing was changed: the database schema is not ready: {'; '.join(missing)}.")
        if options["prepare_renditions"] and not apply:
            self._prepare_renditions()
            return

        with connection.execute_wrapper(DryRunWriteGuard()):
            plan = self._plan(content, stored)
        token = self._token(plan, content, publish)
        self._report(plan, content, token, publish)
        if plan.blockers:
            raise CommandError(f"Refused, nothing was changed: {'; '.join(plan.blockers)}.")
        if plan.nothing_to_do(publish):
            self.stdout.write(self.style.SUCCESS("Already imported: the approved Team content is present; nothing to do."))
            if apply and options["prepare_renditions"]:
                self._prepare_renditions()
            elif plan.page is not None:
                with connection.execute_wrapper(DryRunWriteGuard()):
                    needed = self._renditions_needed(plan.page)
                    todo = sum(1 for image, spec in needed if not image.renditions.filter(filter_spec=spec).exists())
                self.stdout.write(f"Renditions: {len(needed) - todo} of {len(needed)} used by the page exist"
                                  f"{f'; run with --prepare-renditions to generate the other {todo}' if todo else ''}")
            return
        if not apply:
            self.stdout.write("Review the plan above. To import it, run:")
            self.stdout.write(f"  python manage.py import_team_page --apply --confirm {token}{' --publish' if publish else ''}"
                              f"{'' if _is_local_database() else ' --backup-snapshot <rds-snapshot-id>'}")
            return
        if options["confirm"] != token:
            raise CommandError(
                "Refused, nothing was changed: the confirmation token does not match this database, page, Team records and "
                "content (something changed since the preview, or the options differ). Run the preview again."
            )
        backup = self._verify_backup(options)
        summary = self._apply(content, stored, plan, token, publish, backup)
        self.stdout.write(self.style.SUCCESS(summary))
        if options["prepare_renditions"]:
            self._prepare_renditions()

    # -- content ----------------------------------------------------------------------------

    def _load_content(self):
        try:
            # The image binaries are not deployed: the originals are verified in storage instead.
            content = load_team_content(verify_files=False)
        except TeamContentError as exc:
            raise CommandError(f"Approved content is invalid, nothing was changed: {exc}") from exc
        members = content["members"]
        faculty = sum(1 for m in members if m["member_type"] == "faculty")
        self.stdout.write(
            f"  ok: approved content (sha256 {content['content_sha256'][:12]}): {faculty} faculty, {len(members) - faculty} "
            f"staff, {len(content['programmes'])} programmes, {len(content['media'])} media files (verified in storage below)"
        )
        stored, problems = {}, []
        for location, html in [("faculty_intro", content["page"]["faculty_intro_html"]),
                               ("staff_intro", content["page"]["staff_intro_html"])] + \
                [(f"biography:{m['slug']}", m["biography_html"]) for m in members]:
            value = editor_line_breaks(html or "")
            problem = draftail_problem(value, RICH_TEXT_FEATURES) if value else None
            if problem:
                problems.append(f"{location}: {problem}")
            stored[location] = value
        if problems:
            raise CommandError(f"Approved rich text is not editor-safe, nothing was changed: {'; '.join(problems[:3])}.")
        self.stdout.write(f"  ok: {len(stored)} rich-text values load in the Wagtail editor with their text intact")
        return content, stored

    # -- inspection (read-only) ---------------------------------------------------------------

    def _plan(self, content, stored):
        TeamPage, Programme, TeamMember = (apps.get_model("cms", n) for n in ("TeamPage", "Programme", "TeamMember"))
        site, root = resolve_site_and_root()
        plan = Plan(site=site, root=root)

        existing = Page.objects.child_of(root).filter(slug=TEAM_SLUG).first()
        if existing is not None:
            page = existing.specific
            if not isinstance(page, TeamPage):
                raise CommandError(f"/{TEAM_SLUG}/ is {type(page).__name__} #{page.pk}, not a TeamPage; nothing was changed.")
            plan.page, plan.current = page, page.get_latest_revision_as_object()
            self._page_blockers(plan)
            self._plan_page_fields(plan, content, stored)
        others = TeamPage.objects.exclude(pk=plan.page.pk if plan.page else None)
        for other in others:
            plan.blockers.append(f"another TeamPage exists (#{other.pk} at {other.url_path}); only one is allowed")

        codes = {p.code: p for p in Programme.objects.all()}
        slugs = {p.slug: p for p in Programme.objects.all()}
        for programme in content["programmes"]:
            if programme["slug"] in slugs:
                plan.programmes_kept.append(programme["slug"])
            elif programme["code"] in codes:
                plan.blockers.append(f"programme code '{programme['code']}' is used by programme slug "
                                     f"'{codes[programme['code']].slug}', not '{programme['slug']}'")
            else:
                plan.programmes_new.append(programme)

        by_wordpress = {m.wordpress_id: m for m in TeamMember.objects.exclude(wordpress_id=None)}
        by_slug = {m.slug: m for m in TeamMember.objects.all()}
        for member in content["members"]:
            wp, sl = by_wordpress.get(member["wordpress_id"]), by_slug.get(member["slug"])
            if wp is not None and sl is not None and wp.pk != sl.pk:
                plan.blockers.append(f"{member['name']}: WordPress ID {member['wordpress_id']} is record #{wp.pk} "
                                     f"but slug '{member['slug']}' is record #{sl.pk}")
            elif wp is None and sl is not None and sl.wordpress_id not in (None, member["wordpress_id"]):
                plan.blockers.append(f"{member['name']}: slug '{member['slug']}' belongs to WordPress ID {sl.wordpress_id}, "
                                     f"not {member['wordpress_id']}")
            elif wp or sl:
                plan.members_kept.append(member)
            else:
                plan.members_new.append(member)
                problem = self._member_problem(TeamMember, member, stored)
                if problem:
                    plan.blockers.append(problem)

        needed = {m["photo"] for m in plan.members_new if m.get("photo")}
        if plan.page is None or plan.page_fields.get("sections") == EMPTY:
            for section in content["page"]["sections"]:
                needed |= {c["image"] for c in section.get("cards", []) if c.get("image")}
                needed |= {o["image"] for o in section.get("offices", []) if o.get("image")}
        self._plan_media(plan, content, needed)
        plan.fingerprint = self._fingerprint(plan)
        return plan

    @staticmethod
    def _member_problem(TeamMember, member, stored):
        """Model validation (field rules, safe links, uniqueness) of a person before anything is written."""
        from django.core.exceptions import ValidationError

        record = TeamMember(
            name=member["name"], slug=member["slug"], member_type=member["member_type"], position=member["position"],
            summary=member["summary"], biography=stored[f"biography:{member['slug']}"], location=member["location"],
            linkedin_url=member["linkedin_url"], profile_url=member["profile_url"], sort_order=member["sort_order"],
            wordpress_id=member["wordpress_id"],
        )
        try:
            record.full_clean(exclude=["photo"])
        except ValidationError as exc:
            return f"{member['name']}: {'; '.join(f'{k}: {v[0]}' for k, v in exc.message_dict.items())}"
        return ""

    def _page_blockers(self, plan):
        page, current, blockers = plan.page, plan.current, plan.blockers
        if page.live and (page.has_unpublished_changes or page.latest_revision_id != page.live_revision_id):
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
        if page.go_live_at or page.expire_at or current.go_live_at or current.expire_at or \
                page.revisions.filter(approved_go_live_at__isnull=False).exists():
            blockers.append("a go-live, expiry or scheduled revision is set")
        if page.get_view_restrictions().exists():
            blockers.append("a view restriction applies (on the page or an ancestor)")

    def _plan_page_fields(self, plan, content, stored):
        current, approved = plan.current, content["page"]
        for name in PAGE_TEXT_FIELDS:
            value = getattr(current, name) or ""
            plan.page_fields[name] = SAME if value == approved[name] else EMPTY if not value.strip() else KEPT
        for name in RICH_FIELDS:
            value = getattr(current, name) or ""
            plan.page_fields[name] = SAME if value == stored[name] else EMPTY if rich_text_is_empty(value) else KEPT
        for name in STREAM_FIELDS:
            plan.page_fields[name] = EMPTY if len(getattr(current, name)) == 0 else KEPT
        for name in ("seo_title", "search_description"):
            if not (getattr(current, name) or "").strip():
                plan.seo[name] = approved[name]

    def _plan_media(self, plan, content, needed):
        storage = storages["default"]
        image_model = get_image_model()
        for item in content["media"]:
            if item["key"] not in needed:
                continue
            entry = MediaFile(sha256=item["sha256"], file=item["file"], keys=[item["key"]], width=item["width"], height=item["height"])
            name = f"{STORAGE_FOLDER}/{entry.file}"
            entry.storage_name = name
            original, entry.problem = self._stored_original(storage, name, entry)
            if original is not None:
                entry.sha1, entry.size = original["sha1"], original["size"]
                entry.image = (image_model.objects.filter(file_hash=entry.sha1).order_by("pk").first()
                               or image_model.objects.filter(file=name).order_by("pk").first())
                if entry.image is not None:
                    entry.storage_name = entry.image.file.name
                    entry.problem = self._existing_image_problem(storage, entry)
            if entry.problem:
                plan.blockers.append(entry.problem)
            plan.media[item["key"]] = entry

    def _stored_original(self, storage, name, entry):
        """Downloaded and verified at most once per run (the locked re-check reuses it)."""
        cache = self.__dict__.setdefault("_originals", {})
        key = (name, entry.sha256, entry.width, entry.height)
        if key not in cache:
            cache[key] = AboutImport._read_original(storage, name, entry)
        return cache[key]

    def _existing_image_problem(self, storage, entry):
        image = entry.image
        label = f"image file {entry.file}: Wagtail image #{image.pk}"
        if image.file_hash not in ("", entry.sha1):
            return f"{label} records a different file hash"
        if (image.width, image.height) != (entry.width, entry.height):
            return f"{label} records {image.width}x{image.height}, expected {entry.width}x{entry.height}"
        if image.file.name != f"{STORAGE_FOLDER}/{entry.file}":
            _original, problem = self._stored_original(storage, image.file.name, entry)
            if problem:
                return f"{label} points at '{image.file.name}': {problem.split(': ', 1)[-1]}"
        return ""

    @staticmethod
    def _fingerprint(plan):
        TeamMember, Programme = apps.get_model("cms", "TeamMember"), apps.get_model("cms", "Programme")
        state = {
            "page": None if plan.page is None else [plan.page.pk, plan.page.live, plan.page.live_revision_id,
                                                    plan.page.latest_revision_id, plan.page_fields, plan.seo],
            "programmes": list(Programme.objects.order_by("pk").values_list("pk", "slug", "code")),
            "members": list(TeamMember.objects.order_by("pk").values_list("pk", "slug", "wordpress_id")),
            "images": {key: [m.sha256, m.image.pk if m.image else None, m.storage_name] for key, m in plan.media.items()},
        }
        return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()

    @staticmethod
    def _token(plan, content, publish):
        db = connection.settings_dict
        parts = [db.get("NAME") or "", (db.get("HOST") or "").strip(), str(db.get("PORT") or ""),
                 f"site{plan.site.pk}", f"root{plan.root.pk}", content["content_sha256"], plan.fingerprint,
                 "publish" if publish else "draft"]
        return f"team-{plan.page.pk if plan.page else 'new'}-{hashlib.sha256('|'.join(parts).encode()).hexdigest()[:16]}"

    # -- backup -----------------------------------------------------------------------------

    def _verify_backup(self, options):
        if _is_local_database():
            self.stdout.write("  backup: local development database; no RDS snapshot required")
            return {"backup": "local database"}
        snapshot = options["backup_snapshot"]
        if options["backup_verified_externally"]:
            self.stdout.write(self.style.WARNING(f"  backup: snapshot '{snapshot}' recorded as verified by the operator (RDS API check skipped)"))
            return {"backup_snapshot": snapshot, "backup_verification": "operator"}
        try:
            details = verify_rds_snapshot(snapshot, host=(connection.settings_dict.get("HOST") or "").strip(),
                                          max_age=timedelta(hours=options["backup_max_age_hours"]), db_identifier=options["db_instance"])
        except BackupNotVerified as exc:
            raise CommandError(f"Refused, nothing was changed: the backup is not verified: {exc}") from exc
        self.stdout.write(f"  ok: backup {details['snapshot']} of {details['source']} ({details['status']}, created {details['created']})")
        return {"backup_snapshot": details["snapshot"], "backup_source": details["source"],
                "backup_created": details["created"], "backup_verification": "rds-api"}

    # -- writing ----------------------------------------------------------------------------

    def _apply(self, content, stored, planned, token, publish, backup):
        TeamPage, Programme, TeamMember = (apps.get_model("cms", n) for n in ("TeamPage", "Programme", "TeamMember"))
        image_model = get_image_model()
        with transaction.atomic():
            Page.objects.select_for_update().get(pk=(planned.page or planned.root).pk)
            with connection.execute_wrapper(DryRunWriteGuard()):
                plan = self._plan(content, stored)  # storage reads are reused from the first plan
            if plan.blockers:
                raise CommandError(f"Refused, nothing was changed: {'; '.join(plan.blockers)}.")
            if self._token(plan, content, publish) != token:
                raise CommandError("The Team content changed while this command was running; nothing was changed. Run the preview again.")

            created_images, collection, images = 0, None, {}
            for key, entry in plan.media.items():
                image = entry.image
                if image is None:
                    image = next((i for i in images.values() if i.file.name == entry.storage_name), None)
                if image is None:
                    collection = collection or media_collection()
                    media_item = next(m for m in content["media"] if m["key"] == key)
                    image = image_model(title=(media_item["alt"] or entry.file.rsplit(".", 1)[0])[:255], collection=collection,
                                        width=entry.width, height=entry.height, file_size=entry.size, file_hash=entry.sha1)
                    image.file.name = entry.storage_name  # the stored original; nothing is uploaded
                    image.save()
                    created_images += 1
                images[key] = image

            programmes = {p.slug: p for p in Programme.objects.all()}
            for programme in plan.programmes_new:
                programmes[programme["slug"]] = Programme.objects.create(
                    code=programme["code"], slug=programme["slug"], sort_order=programme["sort_order"])
            by_code = {p["code"]: programmes[p["slug"]] for p in content["programmes"]}
            for member in plan.members_new:
                record = TeamMember.objects.create(
                    name=member["name"], slug=member["slug"], member_type=member["member_type"], position=member["position"],
                    summary=member["summary"], biography=stored[f"biography:{member['slug']}"], photo=images.get(member["photo"]),
                    location=member["location"], linkedin_url=member["linkedin_url"], profile_url=member["profile_url"],
                    sort_order=member["sort_order"], is_public=True, wordpress_id=member["wordpress_id"],
                )
                record.programmes.set([by_code[code] for code in member["programmes"]])

            approved = content["page"]
            if plan.page is None:
                page = TeamPage(title=approved["title"], slug=TEAM_SLUG, live=False)
                plan.root.add_child(instance=page)
                fields = {name: EMPTY for name in PAGE_TEXT_FIELDS + RICH_FIELDS + STREAM_FIELDS}
                seo = {"seo_title": approved["seo_title"], "search_description": approved["search_description"]}
                draft = page
            else:
                fields, seo = plan.page_fields, plan.seo
                draft = plan.page.get_latest_revision_as_object()
            for name in PAGE_TEXT_FIELDS:
                if fields[name] == EMPTY:
                    setattr(draft, name, approved[name])
            for name in RICH_FIELDS:
                if fields[name] == EMPTY:
                    setattr(draft, name, stored[name])
            button = lambda b: {"type": "button", "value": {"label": b["label"], "url": b["url"]}, "id": str(uuid.uuid4())}  # noqa: E731
            streams = {  # built only for the fields that are filled (the section images are loaded only then)
                "hero_button": lambda: [button(approved["hero_button"])] if approved.get("hero_button") else [],
                "faculty_buttons": lambda: [button(b) for b in approved["faculty_buttons"]],
                "staff_button": lambda: [button(approved["staff_button"])] if approved.get("staff_button") else [],
                "sections": lambda: LocalTeamImport._sections_raw(approved["sections"], images),
            }
            for name, build in streams.items():
                if fields[name] == EMPTY:
                    setattr(draft, name, StreamValue(getattr(draft, name).stream_block, build(), is_lazy=True))
            for name, value in seo.items():
                setattr(draft, name, value)
            revision = draft.save_revision(log_action=False)
            log(instance=draft, action="wagtail.edit", revision=revision, content_changed=True, data={
                "source": "import_team_page", "content_sha256": content["content_sha256"], "confirmation": token, **backup})
            if publish:
                revision.publish(log_action=True)

            stored_page = TeamPage.objects.get(pk=draft.pk)
            created = TeamMember.objects.filter(wordpress_id__in=[m["wordpress_id"] for m in plan.members_new]).count()
            if (publish and (not stored_page.live or stored_page.live_revision_id != revision.pk)) or created != len(plan.members_new):
                raise CommandError("The import did not end in the expected state; every change was rolled back.")
        state = "published" if publish else "saved as a draft (publish in Wagtail, or run again with --publish)"
        return (f"Created {created_images} image records (no files uploaded), {len(plan.programmes_new)} programmes and "
                f"{len(plan.members_new)} people; /{TEAM_SLUG}/ revision #{revision.pk} {state}.")

    # -- renditions -------------------------------------------------------------------------

    @staticmethod
    def _renditions_needed(page):
        """[(image, spec)] for every image the public page shows, with the API's rendition specs."""
        from cms.about_page_api import SPEC_CARD, SPEC_OFFICE
        from cms.team_page_api import SPEC_TEAM_PHOTO

        TeamMember = apps.get_model("cms", "TeamMember")
        needed = [(m.photo, SPEC_TEAM_PHOTO) for m in TeamMember.objects.filter(is_public=True).exclude(photo=None).select_related("photo")]
        for block in page.sections:
            if block.block_type == "card_group":
                needed += [(card["image"], SPEC_CARD) for card in block.value["cards"] if card.get("image")]
            elif block.block_type == "offices":
                needed += [(office["image"], SPEC_OFFICE) for office in block.value["offices"] if office.get("image")]
        unique = {}
        for image, spec in needed:
            unique.setdefault((image.pk, spec), (image, spec))
        return list(unique.values())

    def _prepare_renditions(self):
        """Generate the renditions the page uses; adds rendition rows and new storage objects only."""
        import time

        TeamPage = apps.get_model("cms", "TeamPage")
        page = TeamPage.objects.filter(slug=TEAM_SLUG).first()
        if page is None:
            raise CommandError(f"No TeamPage at /{TEAM_SLUG}/ yet: import the content first.")
        page = page.get_latest_revision_as_object()
        needed = self._renditions_needed(page)
        started, created, failed = time.monotonic(), 0, []
        for image, spec in needed:
            existed = image.renditions.filter(filter_spec=spec).exists()
            try:
                image.get_rendition(spec)
            except Exception as exc:  # reported, never silently skipped
                failed.append(f"image #{image.pk} {image.file.name} {spec}: {type(exc).__name__}: {exc}")
                continue
            created += 0 if existed else 1
        self.stdout.write(f"Renditions: {len(needed)} used by the page; {created} generated, {len(needed) - created - len(failed)} "
                          f"already existed, {len(failed)} failed ({time.monotonic() - started:.1f}s)")
        if failed:
            raise CommandError("Some renditions could not be generated (those images would be missing on the page): " + "; ".join(failed[:5]))
        self.stdout.write(self.style.SUCCESS("All renditions the Our Team page uses exist."))

    # -- output -----------------------------------------------------------------------------

    def _report(self, plan, content, token, publish):
        storage = storages["default"]
        self.stdout.write(f"Storage: {type(storage).__name__}"
                          f"{' bucket ' + storage.bucket_name if getattr(storage, 'bucket_name', None) else ''}"
                          f"{'' if isinstance(storage, LOCAL_STORAGE_CLASSES) else ' (read only: objects are checked, never written)'}")
        self.stdout.write(f"Site: #{plan.site.pk} {plan.site.hostname}:{plan.site.port}; root page #{plan.root.pk} '{plan.root.title}'")
        if plan.page is None:
            self.stdout.write(f"Page: none at /{TEAM_SLUG}/ -> a TeamPage '{content['page']['title']}' will be created"
                              f"{' and published' if publish else ' as a draft'}")
        else:
            page = plan.page
            self.stdout.write(f"Page: TeamPage #{page.pk} '{page.title}' at {page.url_path} ({'live' if page.live else 'draft'}; "
                              f"live revision #{page.live_revision_id}; {page.revisions.count()} revisions)")
            for name, state in plan.page_fields.items():
                self.stdout.write(f"    {name:<20} {state}{' (already set; never overwritten)' if state == KEPT else ''}")
        for reason in plan.blockers:
            self.stdout.write(self.style.ERROR(f"  blocked: {reason}"))
        self.stdout.write(f"Programmes: {len(plan.programmes_new)} to create, {len(plan.programmes_kept)} existing kept unchanged")
        new_faculty = sum(1 for m in plan.members_new if m["member_type"] == "faculty")
        self.stdout.write(f"People: {len(plan.members_new)} to create ({new_faculty} faculty, {len(plan.members_new) - new_faculty} staff), "
                          f"{len(plan.members_kept)} existing kept unchanged")
        reuse = sum(1 for m in plan.media.values() if m.image is not None)
        problems = sum(1 for m in plan.media.values() if m.problem)
        self.stdout.write(f"Images: {len(plan.media)} needed by this run, verified in storage by SHA-256: {reuse} existing Wagtail "
                          f"images reused, {len(plan.media) - reuse - problems} image records to create, {problems} problems; 0 uploads")
        self.stdout.write(f"Confirmation token: {token}")
