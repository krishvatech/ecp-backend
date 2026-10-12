"""Populate the Our Team page (cms.TeamPage at /our-team/) and its people. Local only.

    python manage.py populate_team_page                       # preview (the default; no database writes)
    python manage.py populate_team_page --apply               # import media and records; page saved as a draft
    python manage.py populate_team_page --apply --publish     # ... and publish the page

Source: cms/team_page_content/ (team.json + images/), migrated from imaa-institute.org/our-team/.

* Local development databases only (cms.local_safety): PostgreSQL on this machine, local file
  storage, never production settings. With the dev settings run it with ``AWS_BUCKET_NAME=``.
* Requires the Our Team schema change (Programme, TeamMember, TeamPage; docs/team-page-schema.md).
  Until it is applied, the preview stops after the content checks and ``--apply`` is refused.
* The page: created under the IMAA Connect HomePage when no page exists at /our-team/. An existing
  page must be a TeamPage that is not archived, locked, in a workflow or moderation, scheduled or
  restricted, without unpublished changes; only its empty fields are filled, never overwritten.
* Programmes are matched by slug; people by WordPress ID (then slug). Existing records are never
  changed: they are reported as kept (an editor's version wins). Only missing records are created.
* Photos are imported into the "Public website pages" collection; files already in the image
  library (matched by content, e.g. the About page's programme and office images) are reused.
* Rich text is stored in Wagtail's editor format and must load in Draftail before any write.
* Without ``--apply`` no SQL other than SELECT runs (enforced). A repeat run creates nothing.

Nothing calls this command automatically.
"""

import uuid
from dataclasses import dataclass, field

from django.apps import apps
from django.core.files.images import ImageFile
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from wagtail.blocks import StreamValue
from wagtail.images import get_image_model
from wagtail.log_actions import log
from wagtail.models import Page
from wagtail.utils.file import hash_filelike

from cms.about_blocks import RICH_TEXT_FEATURES
from cms.local_safety import describe_environment, local_environment_problems
from cms.editor_checks import draftail_problem
from cms.public_page_setup import DryRunWriteGuard, editor_line_breaks, media_collection, resolve_site_and_root, rich_text_is_empty
from cms.public_pages import is_archived
from cms.team_page_content import IMAGES_DIR, TeamContentError, load_team_content

TEAM_SLUG = "our-team"
MODELS = ("Programme", "TeamMember", "TeamPage")
PAGE_TEXT_FIELDS = ("hero_title", "hero_intro", "faculty_heading", "faculty_subheading", "staff_heading", "staff_subheading")


def schema_missing():
    """Models (in the code) and tables (in the database) the import needs but that do not exist yet."""
    missing = []
    found = {}
    for name in MODELS:
        try:
            found[name] = apps.get_model("cms", name)
        except LookupError:
            missing.append(f"model cms.{name}")
    if missing:
        return missing
    with connection.cursor() as cursor:
        tables = set(connection.introspection.table_names(cursor))
    for name, model in found.items():
        if model._meta.db_table not in tables:
            missing.append(f"database table {model._meta.db_table} (migration cms.0017 not applied)")
    return missing


@dataclass
class Plan:
    page: object = None  # existing TeamPage or None (to be created)
    page_blockers: list = field(default_factory=list)
    page_fields: dict = field(default_factory=dict)  # name -> "empty" | "same" | "kept"
    programmes_new: list = field(default_factory=list)
    programmes_existing: list = field(default_factory=list)
    members_new: list = field(default_factory=list)
    members_kept: list = field(default_factory=list)
    images: dict = field(default_factory=dict)  # media key -> (existing image or None, sha1)


class Command(BaseCommand):
    help = "Local only: populate the Our Team page and its people from the approved content. Preview unless --apply."

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Preview only; no database writes (the default).")
        mode.add_argument("--apply", action="store_true", help="Import media and create missing records.")
        parser.add_argument("--publish", action="store_true", help="With --apply: publish the Our Team page.")

    def handle(self, *args, **options):
        apply, publish = options["apply"], options["publish"]
        self.stdout.write(self.style.MIGRATE_HEADING(
            f"Populate Our Team /{TEAM_SLUG}/: {'APPLY' if apply else 'PREVIEW (no database changes)'}"
        ))
        environment = local_environment_problems()
        self.stdout.write(describe_environment())
        if environment:
            raise CommandError(f"Refused, nothing was read or changed: {'; '.join(environment)}.")
        self.stdout.write("  ok: local PostgreSQL database and local file storage")

        try:
            content = load_team_content()
        except TeamContentError as exc:
            raise CommandError(f"Approved content is invalid, nothing was changed: {exc}") from exc
        members = content["members"]
        faculty = sum(1 for m in members if m["member_type"] == "faculty")
        self.stdout.write(
            f"  ok: approved content (sha256 {content['content_sha256'][:12]}): {faculty} faculty, "
            f"{len(members) - faculty} staff, {len(content['programmes'])} programmes, {len(content['media'])} media files verified"
        )
        stored = self._stored_rich_text(content)

        missing = schema_missing()
        if missing:
            for item in missing:
                self.stdout.write(self.style.WARNING(f"  schema: missing {item}"))
            message = "The Our Team schema change is not applied (docs/team-page-schema.md); nothing can be imported yet."
            if apply:
                raise CommandError(f"Refused, nothing was changed: {message}")
            self.stdout.write(self.style.WARNING(f"Preview stopped: {message}"))
            return

        if not apply:
            with connection.execute_wrapper(DryRunWriteGuard()):
                site, root = resolve_site_and_root()
                plan = self._plan(root, content, stored)
                self._report(plan, content)
            if plan.page_blockers:
                raise CommandError(f"Refused, nothing was changed: {'; '.join(plan.page_blockers)}.")
            if not self._has_work(plan) and not publish:
                self.stdout.write("Already populated with the approved content; nothing to do.")
            else:
                self.stdout.write("Preview: run again with --apply (and --publish to publish the page) to make these changes.")
            return

        site, root = resolve_site_and_root()
        plan = self._plan(root, content, stored)
        self._report(plan, content)
        if plan.page_blockers:
            raise CommandError(f"Refused, nothing was changed: {'; '.join(plan.page_blockers)}.")
        if not self._has_work(plan) and not (publish and plan.page is not None and not plan.page.live):
            self.stdout.write(self.style.SUCCESS("Already populated with the approved content; nothing changed."))
            return
        summary = self._apply(root, content, stored, plan, publish)
        self.stdout.write(self.style.SUCCESS(summary))

    # -- preparation ---------------------------------------------------------------------------

    def _stored_rich_text(self, content):
        stored, problems = {}, []

        def check(location, html):
            value = editor_line_breaks(html or "")
            problem = draftail_problem(value, RICH_TEXT_FEATURES) if value else None
            if problem:
                problems.append(f"{location}: {problem}")
            stored[location] = value

        check("faculty_intro", content["page"]["faculty_intro_html"])
        check("staff_intro", content["page"]["staff_intro_html"])
        for member in content["members"]:
            check(f"biography:{member['slug']}", member["biography_html"])
        if problems:
            raise CommandError(f"Approved rich text is not editor-safe, nothing was changed: {'; '.join(problems[:3])}.")
        self.stdout.write(f"  ok: {len(stored)} rich-text values load in the Wagtail editor with their text intact")
        return stored

    @staticmethod
    def _media_plan(content):
        hashes = {}
        for item in content["media"]:
            with open(IMAGES_DIR / item["file"], "rb") as fh:
                hashes[item["key"]] = hash_filelike(fh)
        by_hash = {}
        for image in get_image_model().objects.filter(file_hash__in=set(hashes.values())).order_by("pk"):
            by_hash.setdefault(image.file_hash, image)
        return {key: (by_hash.get(sha1), sha1) for key, sha1 in hashes.items()}

    # -- inspection (read-only) -------------------------------------------------------------------

    def _plan(self, root, content, stored):
        TeamPage = apps.get_model("cms", "TeamPage")
        Programme = apps.get_model("cms", "Programme")
        TeamMember = apps.get_model("cms", "TeamMember")
        plan = Plan(images=self._media_plan(content))

        existing = Page.objects.child_of(root).filter(slug=TEAM_SLUG).first()
        if existing is not None:
            page = existing.specific
            if not isinstance(page, TeamPage):
                raise CommandError(f"/{TEAM_SLUG}/ is {type(page).__name__} #{page.pk}, not a TeamPage; nothing was changed.")
            plan.page = page
            blockers = plan.page_blockers
            if page.has_unpublished_changes and page.live:
                blockers.append("the page has unpublished changes in Wagtail; they are never overwritten")
            if is_archived(page):
                blockers.append("the page is archived (deleted in Wagtail)")
            if page.locked:
                blockers.append("the page is locked in Wagtail")
            if page.workflow_in_progress:
                blockers.append("a Wagtail workflow is in progress on the page")
            if page.go_live_at or page.expire_at or page.revisions.filter(approved_go_live_at__isnull=False).exists():
                blockers.append("a go-live, expiry or scheduled revision is set")
            if page.get_view_restrictions().exists():
                blockers.append("a view restriction applies (on the page or an ancestor)")
            current = page.get_latest_revision_as_object()
            approved = content["page"]
            for name in PAGE_TEXT_FIELDS:
                value = getattr(current, name) or ""
                plan.page_fields[name] = "same" if value == approved[name] else "empty" if not value.strip() else "kept"
            for name, key in (("faculty_intro", "faculty_intro"), ("staff_intro", "staff_intro")):
                value = getattr(current, name) or ""
                plan.page_fields[name] = "same" if value == stored[key] else "empty" if rich_text_is_empty(value) else "kept"
            for name in ("hero_button", "faculty_buttons", "staff_button", "sections"):
                plan.page_fields[name] = "empty" if len(getattr(current, name)) == 0 else "kept"

        existing_programmes = {p.slug: p for p in Programme.objects.all()}
        for programme in content["programmes"]:
            if programme["slug"] in existing_programmes:
                plan.programmes_existing.append(programme["slug"])
            else:
                plan.programmes_new.append(programme)

        by_wordpress = {m.wordpress_id: m for m in TeamMember.objects.exclude(wordpress_id=None)}
        by_slug = {m.slug: m for m in TeamMember.objects.all()}
        for member in content["members"]:
            found = by_wordpress.get(member["wordpress_id"]) or by_slug.get(member["slug"])
            (plan.members_kept if found else plan.members_new).append(member)
        return plan

    @staticmethod
    def _has_work(plan):
        return bool(
            plan.page is None or plan.programmes_new or plan.members_new
            or any(state == "empty" for state in plan.page_fields.values())
        )

    # -- writing ----------------------------------------------------------------------------------

    def _apply(self, root, content, stored, plan, publish):
        TeamPage = apps.get_model("cms", "TeamPage")
        Programme = apps.get_model("cms", "Programme")
        TeamMember = apps.get_model("cms", "TeamMember")
        image_model = get_image_model()
        media = {m["key"]: m for m in content["media"]}

        images, created_images, imported = {}, 0, {}
        collection = media_collection()
        for key, (image, sha1) in plan.images.items():
            image = image or imported.get(sha1)
            if image is None:
                item = media[key]
                image = image_model(title=(item["alt"] or item["file"].rsplit(".", 1)[0])[:255], collection=collection)
                with open(IMAGES_DIR / item["file"], "rb") as fh:
                    image.file.save(item["file"], ImageFile(fh, name=item["file"]), save=False)
                image._set_image_file_metadata()
                image.save()
                imported[sha1] = image
                created_images += 1
            images[key] = image

        with transaction.atomic():
            programmes = {p.slug: p for p in Programme.objects.all()}
            for programme in plan.programmes_new:
                programmes[programme["slug"]] = Programme.objects.create(
                    code=programme["code"], slug=programme["slug"], sort_order=programme["sort_order"]
                )
            by_code = {p["code"]: programmes[p["slug"]] for p in content["programmes"]}

            created_members = 0
            for member in plan.members_new:
                # Re-check under the transaction: never create a second record for the same person.
                if TeamMember.objects.filter(wordpress_id=member["wordpress_id"]).exists() or \
                        TeamMember.objects.filter(slug=member["slug"]).exists():
                    continue
                record = TeamMember.objects.create(
                    name=member["name"], slug=member["slug"], member_type=member["member_type"],
                    position=member["position"], summary=member["summary"],
                    biography=stored[f"biography:{member['slug']}"], photo=images.get(member["photo"]),
                    location=member["location"], linkedin_url=member["linkedin_url"], profile_url=member["profile_url"],
                    sort_order=member["sort_order"], is_public=True, wordpress_id=member["wordpress_id"],
                )
                record.programmes.set([by_code[code] for code in member["programmes"]])
                created_members += 1

            page = plan.page
            approved = content["page"]
            if page is None:
                page = TeamPage(title=approved["title"], slug=TEAM_SLUG, live=False,
                                seo_title=approved["seo_title"], search_description=approved["search_description"])
                root.add_child(instance=page)
                fields = {name: "empty" for name in PAGE_TEXT_FIELDS + ("faculty_intro", "staff_intro", "hero_button", "faculty_buttons", "staff_button", "sections")}
                draft = page
            else:
                Page.objects.select_for_update().get(pk=page.pk)
                fields = plan.page_fields
                draft = page.get_latest_revision_as_object()
            for name in PAGE_TEXT_FIELDS:
                if fields[name] == "empty":
                    setattr(draft, name, approved[name])
            for name in ("faculty_intro", "staff_intro"):
                if fields[name] == "empty":
                    setattr(draft, name, stored[name])
            button = lambda b: {"type": "button", "value": {"label": b["label"], "url": b["url"]}, "id": str(uuid.uuid4())}  # noqa: E731
            if fields["hero_button"] == "empty":
                draft.hero_button = StreamValue(draft.hero_button.stream_block, [button(approved["hero_button"])], is_lazy=True)
            if fields["faculty_buttons"] == "empty":
                draft.faculty_buttons = StreamValue(draft.faculty_buttons.stream_block, [button(b) for b in approved["faculty_buttons"]], is_lazy=True)
            if fields["staff_button"] == "empty":
                draft.staff_button = StreamValue(draft.staff_button.stream_block, [button(approved["staff_button"])], is_lazy=True)
            if fields["sections"] == "empty":
                draft.sections = StreamValue(draft.sections.stream_block, self._sections_raw(approved["sections"], images), is_lazy=True)
            for name in ("seo_title", "search_description"):
                if not (getattr(draft, name) or "").strip():
                    setattr(draft, name, approved[name])
            revision = draft.save_revision(log_action=False)
            log(instance=draft, action="wagtail.edit", revision=revision, content_changed=True,
                data={"source": "populate_team_page", "content_sha256": content["content_sha256"]})
            if publish:
                revision.publish(log_action=True)
        state = "published" if publish else "saved as a draft (publish in Wagtail or with --apply --publish)"
        return (f"Imported {created_images} images, created {len(plan.programmes_new)} programmes and {created_members} people; "
                f"/{TEAM_SLUG}/ revision #{revision.pk} {state}.")

    @staticmethod
    def _sections_raw(sections, images):
        def item(value):
            return {"type": "item", "value": value, "id": str(uuid.uuid4())}

        def link(value):
            return {"label": value["label"], "url": value["url"]} if value else {"label": "", "url": ""}

        raw = []
        for s in sections:
            if s["type"] == "card_group":
                value = {"heading": s["heading"], "layout": s["layout"], "prompt": s.get("prompt") or "", "button": link(s.get("button")),
                         "cards": [item({"image": images[c["image"]].pk if c.get("image") else None, "icon": c.get("icon") or "",
                                         "title": c["title"], "text": c.get("text") or "", "link": link(c.get("link"))}) for c in s["cards"]]}
            elif s["type"] == "offices":
                value = {"heading": s["heading"], "email": s["email"], "offices": [
                    item({"city": o["city"], "country": o["country"], "phone": o["phone"], "image": images[o["image"]].pk if o.get("image") else None})
                    for o in s["offices"]]}
            else:
                raise CommandError(f"Unsupported section type {s['type']!r} in team.json.")
            raw.append({"type": s["type"], "value": value, "id": str(uuid.uuid4())})
        return raw

    # -- output -----------------------------------------------------------------------------------

    def _report(self, plan, content):
        page = plan.page
        if page is None:
            self.stdout.write(f"Page: no page at /{TEAM_SLUG}/ -> a TeamPage '{content['page']['title']}' will be created")
        else:
            self.stdout.write(f"Page: TeamPage #{page.pk} '{page.title}' ({'live' if page.live else 'draft'}; {page.revisions.count()} revisions)")
            for reason in plan.page_blockers:
                self.stdout.write(self.style.ERROR(f"  blocked: {reason}"))
            for name, state in plan.page_fields.items():
                self.stdout.write(f"    {name:<20} {state}")
        self.stdout.write(f"Programmes: {len(plan.programmes_new)} to create, {len(plan.programmes_existing)} existing kept")
        new_faculty = sum(1 for m in plan.members_new if m["member_type"] == "faculty")
        self.stdout.write(
            f"People: {len(plan.members_new)} to create ({new_faculty} faculty, {len(plan.members_new) - new_faculty} staff), "
            f"{len(plan.members_kept)} already present and kept unchanged"
        )
        unique = {sha1 for _image, sha1 in plan.images.values()}
        reused = {sha1 for image, sha1 in plan.images.values() if image is not None}
        self.stdout.write(f"Media: {len(plan.images)} files, {len(unique)} distinct: {len(reused)} already in the image library, {len(unique) - len(reused)} to import")
