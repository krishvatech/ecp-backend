"""Fill an EXISTING, never-published, empty public StandardPage draft with its approved content.

    python manage.py populate_public_page_draft terms-and-conditions                    # preview (the default)
    python manage.py populate_public_page_draft terms-and-conditions --apply            # save a draft revision
    python manage.py populate_public_page_draft terms-and-conditions --apply --publish  # ...and publish it

Companion of ``setup_public_pages``, which only creates missing pages. Scope: the
``terms-and-conditions`` and ``references`` pages, one explicit slug per run.

* Same Site rules as the public API; the Site root must be the IMAA Connect HomePage.
* The page must be a StandardPage that is a direct child of that HomePage and has never been
  published. It is refused when it is live or was ever published, archived, an alias, locked,
  in a workflow or submitted for moderation, scheduled (go-live, expiry or a scheduled
  revision), view-restricted (on itself or an ancestor), or when its latest draft changes the
  slug.
* Its body must be empty both in the page record and in its latest revision, so a draft saved
  by an editor is never overwritten. A body that already equals the approved content counts
  as populated: repeated runs change nothing, and ``--publish`` may then publish it.
* Only the body and EMPTY SEO fields are set, on top of the latest draft revision; title, slug,
  page identity, privacy and every non-empty SEO field are kept. The result is saved as a new
  Wagtail revision (and logged), exactly like an editor's "Save draft".
* ``--publish`` (with ``--apply``) publishes that revision, and only when the approved content
  is complete and no Wagtail redirect claims the path. Without it, the page stays a draft:
  its public URL keeps returning 404 and the frontend never shows default content for it.
* Without ``--apply`` the command makes no database writes (enforced). With ``--apply`` the
  page row is locked and every check is repeated under the lock; if the page changed since the
  preview in the same run, nothing is written.
* For References, the bundled logos are imported into the Wagtail image library (collection
  "Public website pages") before the page is locked; identical files are reused.

Nothing calls this command automatically.
"""

from dataclasses import dataclass, field

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from wagtail.log_actions import log
from wagtail.models import Page

from cms.models import StandardPage
from cms.public_page_content import MIGRATED, PublicPageContentError, load_public_page_content
from cms.public_page_setup import (
    DryRunWriteGuard,
    find_media_images,
    import_media_images,
    prepare_media_renditions,
    progress_printer,
    render_cms_body,
    resolve_site_and_root,
    rich_text_is_empty,
)
from cms.public_pages import is_archived, path_has_redirect

SUPPORTED_SLUGS = ("terms-and-conditions", "references")
SEO_FIELDS = ("seo_title", "search_description")

EMPTY = "empty"  # body empty in the page record and the latest revision: may be populated
APPROVED = "approved"  # the latest draft already holds exactly the approved content
OTHER = "other"  # an editor's content: never overwritten, never published by this command


@dataclass
class DraftInspection:
    page: object
    latest_revision: object
    draft: object  # the page as of its latest revision (the editor's current draft)
    blockers: list = field(default_factory=list)
    publish_blockers: list = field(default_factory=list)
    content_state: str = EMPTY
    seo_changes: dict = field(default_factory=dict)
    expected_body: str = None  # the approved body as stored, when it can be built without writes


def _state_label(page):
    if page.live:
        return "live"
    if page.first_published_at or page.last_published_at or page.live_revision_id:
        return "unpublished (was published before)"
    return "draft, never published"


class Command(BaseCommand):
    help = (
        "Populate an existing, never-published, empty StandardPage draft (terms-and-conditions or "
        "references) with its approved content. Preview unless --apply; publish only with --publish."
    )

    def add_arguments(self, parser):
        parser.add_argument("slug", choices=SUPPORTED_SLUGS, help="The page to populate.")
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Preview only; no database writes (the default).")
        mode.add_argument("--apply", action="store_true", help="Save the approved content as a new draft revision.")
        parser.add_argument(
            "--publish",
            action="store_true",
            help="With --apply: also publish the populated revision (complete content and checks required).",
        )

    def handle(self, *args, **options):
        slug = options["slug"]
        apply = options["apply"]
        publish = options["publish"]

        mode = "APPLY" if apply else "PREVIEW (no database changes)"
        self.stdout.write(self.style.MIGRATE_HEADING(f"Populate existing public page draft /{slug}/: {mode}"))
        if publish and not apply:
            self.stdout.write("--publish without --apply: showing whether it would be published.")

        content = self._load_content(slug)

        if not apply:
            with connection.execute_wrapper(DryRunWriteGuard()):
                site, root = resolve_site_and_root()
                inspection = self._inspect(site, root, slug, content)
                self._report(site, root, inspection, content, publish=publish)
            self._raise_if_refused(inspection, publish)
            if inspection.content_state == EMPTY:
                flags = "--apply --publish" if publish else "--apply (add --publish to publish it as well)"
                self.stdout.write(f"Preview: run again with {flags} to make these changes.")
            elif publish:
                self.stdout.write("Preview: run again with --apply --publish to publish the populated draft.")
            else:
                self.stdout.write(
                    "Already populated with the approved content; nothing to do. "
                    "Review it in Wagtail, then publish it there or with --apply --publish."
                )
            return

        site, root = resolve_site_and_root()
        inspection = self._inspect(site, root, slug, content)
        self._report(site, root, inspection, content, publish=publish)
        self._raise_if_refused(inspection, publish)
        if inspection.content_state == APPROVED and not publish:
            self.stdout.write(self.style.SUCCESS("Already populated with the approved content; nothing changed."))
            return

        images = {}
        if content.has_media and inspection.content_state == EMPTY:
            images, created = import_media_images(content, progress=progress_printer(self.stdout, "Importing images"))
            self.stdout.write(
                f"Images: {created} imported, {len(images) - created} already in the Wagtail image library."
            )
        if content.has_media and (inspection.content_state == EMPTY or publish):
            if not images:
                images, _missing = find_media_images(content)
            prepare_media_renditions(content, images, progress=progress_printer(self.stdout, "Preparing image renditions"))

        revision, published = self._apply(site, root, slug, content, inspection, images, publish)
        if revision is not None:
            self.stdout.write(self.style.SUCCESS(
                f"Saved draft revision #{revision.pk} with the approved content (sha256 {content.content_sha256[:12]})."
            ))
        if published:
            self.stdout.write(self.style.SUCCESS(f"Published /{slug}/ (revision #{published.pk})."))
        else:
            self.stdout.write(self.style.WARNING(
                f"/{slug}/ is still a draft: its public URL returns 404 until it is published "
                "(in Wagtail, or with --apply --publish)."
            ))

    # -- content -------------------------------------------------------------------------

    def _load_content(self, slug):
        try:
            content = load_public_page_content(slug)
        except PublicPageContentError as exc:
            raise CommandError(f"Approved content is invalid, nothing was changed: {exc}") from exc
        if content.migration_status != MIGRATED or not content.has_required_content:
            raise CommandError(f"/{slug}/ has no approved content to populate with; nothing was changed.")
        return content

    # -- inspection (read-only) ------------------------------------------------------------

    def _inspect(self, site, root, slug, content):
        existing = Page.objects.child_of(root).filter(slug=slug).first()
        if existing is None:
            raise CommandError(
                f"No page exists at /{slug}/ under the HomePage; nothing was changed. "
                "Create it with `manage.py setup_public_pages --apply` instead."
            )
        page = existing.specific
        if not isinstance(page, StandardPage):
            raise CommandError(
                f"/{slug}/ is {type(page).__name__} #{page.pk} '{page.title}', not a StandardPage; nothing was changed."
            )

        latest = page.get_latest_revision()
        draft = latest.as_object() if latest is not None else page
        inspection = DraftInspection(page=page, latest_revision=latest, draft=draft)
        blockers = inspection.blockers

        if page.live:
            blockers.append("the page is live; edit published pages in Wagtail")
        elif page.first_published_at or page.last_published_at or page.live_revision_id:
            blockers.append("the page was published before; edit it in Wagtail")
        if is_archived(page):
            blockers.append("the page is archived (deleted in Wagtail)")
        if page.alias_of_id:
            blockers.append("the page is an alias of another page")
        if page.locked:
            blockers.append(f"the page is locked in Wagtail (by user #{page.locked_by_id})" if page.locked_by_id else "the page is locked in Wagtail")
        if page.workflow_in_progress:
            blockers.append("a Wagtail workflow is in progress on the page")
        if latest is not None and getattr(latest, "submitted_for_moderation", False):
            blockers.append("the latest revision is submitted for moderation")
        if page.go_live_at or draft.go_live_at:
            blockers.append("a go-live date is scheduled")
        if page.expire_at or draft.expire_at:
            blockers.append("an expiry date is set")
        if page.revisions.filter(approved_go_live_at__isnull=False).exists():
            blockers.append("a revision is scheduled for publishing")
        if page.get_view_restrictions().exists():
            blockers.append("a view restriction applies (on the page or an ancestor)")
        if draft.slug != slug:
            blockers.append(f"the latest draft changes the slug to '{draft.slug}'")

        # Content: the page record AND the latest revision (an editor's unsaved-to-live draft).
        row_empty = rich_text_is_empty(page.body)
        draft_empty = rich_text_is_empty(draft.body)
        if content.has_media:
            found, missing = find_media_images(content)
            inspection.expected_body = None if missing else render_cms_body(content, found)
        else:
            inspection.expected_body = content.body_html
        if row_empty and draft_empty:
            inspection.content_state = EMPTY
        elif (
            inspection.expected_body is not None
            and draft.body == inspection.expected_body
            and (row_empty or page.body == inspection.expected_body)
        ):
            inspection.content_state = APPROVED
        else:
            inspection.content_state = OTHER
            blockers.append(
                "the page already has content (in the page record or its latest revision) that differs "
                "from the approved content; it is never overwritten, edit it in Wagtail"
            )

        if inspection.content_state == EMPTY:
            for name in SEO_FIELDS:
                current = getattr(draft, name) or ""
                approved = getattr(content, name)
                if not current.strip() and approved:
                    inspection.seo_changes[name] = approved

        if path_has_redirect([slug], site):
            inspection.publish_blockers.append(
                "a Wagtail redirect is configured for this path; publishing would not make it public"
            )
        return inspection

    def _raise_if_refused(self, inspection, publish):
        reasons = list(inspection.blockers)
        if publish:
            reasons += inspection.publish_blockers
        if reasons:
            raise CommandError(
                f"Refused, nothing was changed: {'; '.join(reasons)}."
            )

    # -- writing -------------------------------------------------------------------------

    def _apply(self, site, root, slug, content, planned, images, publish):
        with transaction.atomic():
            # Lock the page row: Wagtail's own "Save draft" and "Publish" update it, so they wait
            # for this transaction. Then repeat every check against the current state.
            Page.objects.select_for_update().get(pk=planned.page.pk)
            current = self._inspect(site, root, slug, content)
            if (
                current.page.latest_revision_id != planned.page.latest_revision_id
                or current.content_state != planned.content_state
            ):
                raise CommandError(
                    f"/{slug}/ changed while this command was running (latest revision "
                    f"#{planned.page.latest_revision_id} -> #{current.page.latest_revision_id}); "
                    "nothing was changed. Run the preview again."
                )
            self._raise_if_refused(current, publish)

            revision = None
            if current.content_state == EMPTY:
                draft = current.draft
                draft.body = render_cms_body(content, images) if content.has_media else content.body_html
                for name, value in current.seo_changes.items():
                    setattr(draft, name, value)
                revision = draft.save_revision(log_action=False)
                log(
                    instance=draft,
                    action="wagtail.edit",
                    revision=revision,
                    content_changed=True,
                    data={"source": "populate_public_page_draft", "content_sha256": content.content_sha256},
                )
            published = None
            if publish:
                to_publish = revision or current.latest_revision
                to_publish.publish(log_action=True)
                published = to_publish
        return revision, published

    # -- output --------------------------------------------------------------------------

    def _report(self, site, root, inspection, content, *, publish):
        page, draft, latest = inspection.page, inspection.draft, inspection.latest_revision
        self.stdout.write(
            f"Site: #{site.pk} {site.hostname}:{site.port}{' (default site)' if site.is_default_site else ''}"
        )
        self.stdout.write(f"Root page: #{root.pk} HomePage '{root.title}' (slug '{root.slug}')")
        revision_text = f"latest revision #{latest.pk} ({latest.created_at:%Y-%m-%d %H:%M})" if latest else "no revisions"
        self.stdout.write(f"Page: StandardPage #{page.pk} '{draft.title}' ({_state_label(page)}; {revision_text})")

        if inspection.blockers:
            for reason in inspection.blockers:
                self.stdout.write(self.style.ERROR(f"  blocked: {reason}"))
        else:
            self.stdout.write("  ok: never published, not archived, not locked, no workflow, nothing scheduled, not restricted")

        state_text = {
            EMPTY: "empty in the page record and in the latest revision",
            APPROVED: "already holds the approved content",
            OTHER: "has other content",
        }[inspection.content_state]
        self.stdout.write(f"  body: {state_text}")

        if inspection.content_state == EMPTY and not inspection.blockers:
            self.stdout.write(
                f"Plan, from the approved content (sha256 {content.content_sha256[:12]}, "
                f"{len(content.body_lines)} body lines):"
            )
            self.stdout.write("    body                 empty -> approved content")
            for name in SEO_FIELDS:
                current = getattr(draft, name) or ""
                if name in inspection.seo_changes:
                    self.stdout.write(f"    {name:<20} empty -> {inspection.seo_changes[name]!r}")
                elif current.strip():
                    self.stdout.write(f"    {name:<20} kept: {current!r}")
                else:
                    self.stdout.write(f"    {name:<20} empty; no approved value, left empty")
            self.stdout.write(f"    title                kept: {draft.title!r}")
            if content.has_media:
                found, missing = find_media_images(content)
                self.stdout.write(
                    f"    images               {len(content.media)} bundled: {len(found)} already in the Wagtail "
                    f"image library, {len(missing)} to import"
                )

        if publish:
            if inspection.blockers or inspection.publish_blockers:
                for reason in inspection.publish_blockers:
                    self.stdout.write(self.style.ERROR(f"  publish blocked: {reason}"))
            else:
                self.stdout.write("  publish: allowed (complete approved content, no redirect, checks passed)")
