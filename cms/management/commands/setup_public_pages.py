"""Create the public website's StandardPages that are missing from the public Wagtail Site.

    python manage.py setup_public_pages                         # dry run (the default): report only
    python manage.py setup_public_pages --dry-run               # the same, explicitly
    python manage.py setup_public_pages --apply                 # create missing pages as drafts
    python manage.py setup_public_pages --apply --publish-new   # create; publish NEW pages that have content

Scope: the five pages in ``cms.public_page_content.PUBLIC_PAGES`` and nothing else.

* The Site is chosen exactly like the public API does (``cms.public_pages.resolve_public_site``)
  and its root page must be an existing, non-archived IMAA Connect ``HomePage``. Nothing is
  created or changed when the configuration is wrong: no HomePage, no Site edits.
* A page is created only where the public API would report the path as genuinely absent
  (``inspect_public_path`` == ``PATH_ABSENT``), as a direct child of that HomePage.
* Existing pages are never modified: not their title, body, slug, SEO fields, privacy,
  revisions or publication state. Archived pages are not restored, restrictions are not
  removed, nothing existing is (re)published. A page of another type using one of the slugs
  is reported as a collision and skipped.
* New pages get the approved initial content from ``cms/public_page_content``. They are
  drafts unless ``--publish-new`` is given together with ``--apply``, and even then only
  pages whose content has a title and a body are published. Bundled media (the References
  logos) is imported into the Wagtail image library first, reusing identical files.
* Existing drafts are never filled in by this command; ``populate_public_page_draft`` does
  that for empty, never-published drafts.
* Without ``--apply`` the command makes no database writes (enforced: any non-SELECT
  statement aborts the run). With ``--apply`` all creations happen in one transaction, under
  a row lock on the HomePage, after re-checking each path, so concurrent runs cannot create
  duplicates.

Nothing calls this command automatically (not on startup, deployment or page requests).
"""

from dataclasses import dataclass, field

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone
from wagtail.log_actions import log
from wagtail.models import Page

from cms.models import StandardPage
from cms.public_page_content import (
    PUBLIC_PAGES,
    PublicPageContentError,
    load_public_page_content,
)
from cms.public_page_setup import (
    MEDIA_COLLECTION_NAME,
    DryRunWriteGuard as _DryRunWriteGuard,
    describe_media_plan,
    import_media_images,
    prepare_media_renditions,
    progress_printer,
    render_cms_body,
    resolve_site_and_root,
)
from cms.public_pages import (
    PATH_ABSENT,
    PATH_FOUND,
    inspect_public_path,
    is_archived,
)

CREATE_DRAFT = "create_draft"
CREATE_AND_PUBLISH = "create_and_publish"
KEEP = "keep"
SKIP = "skip"

REASON_TEXT = {
    "site_root_archived": "the Site's root page is archived",
    "site_root_not_homepage": "the Site's root page is not the IMAA Connect HomePage",
    "ancestor_view_restricted": "the Site's root page (or an ancestor) has a view restriction, so a page here would not be public",
    "redirect": "a Wagtail redirect is configured for this path (a page was probably renamed or moved); review Wagtail > Settings > Redirects",
}


@dataclass
class PagePlan:
    slug: str
    title: str
    content: object
    action: str
    status: str
    details: list = field(default_factory=list)
    created: object = None


def _describe_existing(page):
    """Operator-facing state of an existing StandardPage (never sent to the public)."""
    parts = []
    if page.live:
        parts.append("live")
    elif page.first_published_at:
        parts.append("unpublished")
    else:
        parts.append("draft, never published")
    if page.has_unpublished_changes and page.live:
        parts.append("has unpublished changes")
    if is_archived(page):
        parts.append("archived")
    if page.expire_at and page.expire_at <= timezone.now():
        parts.append("expired")
    if page.go_live_at and page.go_live_at > timezone.now():
        parts.append(f"scheduled for {page.go_live_at:%Y-%m-%d %H:%M}")
    if page.get_view_restrictions().exists():
        parts.append("view-restricted")
    return ", ".join(parts)


class Command(BaseCommand):
    help = (
        "Create missing public website StandardPages (FAQ, References, Terms and Conditions, "
        "Privacy Policy, Imprint) under the public Site's HomePage. Dry run unless --apply."
    )

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Report only; no database writes (the default).")
        mode.add_argument("--apply", action="store_true", help="Create the missing pages.")
        parser.add_argument(
            "--publish-new",
            action="store_true",
            help="With --apply: publish newly created pages that have approved content (title and body). "
            "Existing pages are never published. Without it, new pages are drafts.",
        )

    def handle(self, *args, **options):
        apply = options["apply"]
        publish_new = options["publish_new"]

        mode = "APPLY" if apply else "DRY RUN (no database changes)"
        self.stdout.write(self.style.MIGRATE_HEADING(f"Public website pages: {mode}"))
        if publish_new and not apply:
            self.stdout.write("--publish-new without --apply: showing what would be published.")

        contents = self._load_contents()

        if not apply:
            with connection.execute_wrapper(_DryRunWriteGuard()):
                site, root = self._resolve_site_and_root()
                plans = self._plan(site, root, contents, publish_new)
            self._report(site, root, plans, applied=False)
            return

        site, root = self._resolve_site_and_root()
        plans = self._plan(site, root, contents, publish_new)
        if any(plan.action in (CREATE_DRAFT, CREATE_AND_PUBLISH) for plan in plans):
            plans = self._apply(site, root, contents, publish_new, plans)
        self._report(site, root, plans, applied=True)

    # -- configuration ---------------------------------------------------------------

    def _load_contents(self):
        contents = {}
        for slug, _title in PUBLIC_PAGES:
            try:
                contents[slug] = load_public_page_content(slug)
            except PublicPageContentError as exc:
                raise CommandError(f"Initial content is invalid, nothing was changed: {exc}") from exc
        return contents

    def _resolve_site_and_root(self):
        return resolve_site_and_root()

    # -- planning --------------------------------------------------------------------

    def _plan(self, site, root, contents, publish_new):
        plans = []
        for slug, title in PUBLIC_PAGES:
            content = contents[slug]
            existing = Page.objects.child_of(root).filter(slug=slug).first()
            inspection = inspect_public_path([slug], site)

            if existing is not None:
                existing = existing.specific
                if not isinstance(existing, StandardPage):
                    plans.append(PagePlan(
                        slug, title, content, SKIP, "collision",
                        [f"slug '{slug}' already belongs to {type(existing).__name__} #{existing.pk} "
                         f"'{existing.title}'; rename or move that page in Wagtail to free the slug"],
                    ))
                    continue
                public = "served publicly" if inspection.state == PATH_FOUND else "not public (404)"
                plans.append(PagePlan(
                    slug, title, content, KEEP, "exists",
                    [f"StandardPage #{existing.pk} '{existing.title}': {_describe_existing(existing)}; {public}; left unchanged"],
                ))
                continue

            if inspection.state != PATH_ABSENT:
                plans.append(PagePlan(
                    slug, title, content, SKIP, "blocked",
                    [REASON_TEXT.get(inspection.reason, inspection.reason or "path is not available")],
                ))
                continue

            details = [describe_media_plan(content)] if content.has_media else []
            if publish_new and content.has_required_content:
                plans.append(PagePlan(slug, title, content, CREATE_AND_PUBLISH, "missing", details))
            else:
                if publish_new:
                    details.append("stays a draft: no approved initial content (title and body) to publish")
                plans.append(PagePlan(slug, title, content, CREATE_DRAFT, "missing", details))
        return plans

    # -- writing ---------------------------------------------------------------------

    def _apply(self, site, root, contents, publish_new, planned):
        # Bundled media first, outside the page transaction: importing reuses identical files,
        # so an aborted run leaves only reusable images behind, and the HomePage lock below is
        # not held while files are written to the media storage.
        images, imported = {}, {}
        for plan in planned:
            if plan.action in (CREATE_DRAFT, CREATE_AND_PUBLISH) and plan.content.has_media:
                images[plan.slug], imported[plan.slug] = import_media_images(
                    plan.content, progress=progress_printer(self.stdout, f"/{plan.slug}/: importing images")
                )
                prepare_media_renditions(
                    plan.content, images[plan.slug],
                    progress=progress_printer(self.stdout, f"/{plan.slug}/: preparing image renditions"),
                )

        with transaction.atomic():
            # Serialise concurrent runs (and Wagtail editors adding children) on the HomePage row,
            # then re-plan under the lock so nothing created meanwhile is duplicated.
            locked_root = Page.objects.select_for_update().get(pk=root.pk)
            plans = self._plan(site, root, contents, publish_new)
            for plan in plans:
                if plan.action not in (CREATE_DRAFT, CREATE_AND_PUBLISH):
                    continue
                content = plan.content
                if content.has_media and plan.slug not in images:
                    images[plan.slug], imported[plan.slug] = import_media_images(content)
                    prepare_media_renditions(content, images[plan.slug])
                if content.has_media:
                    body = render_cms_body(content, images[plan.slug])
                    total, created = len(content.media), imported[plan.slug]
                    plan.details[0] = (
                        f"{total} bundled images: {created} imported into the '{MEDIA_COLLECTION_NAME}' "
                        f"collection, {total - created} reused from the Wagtail image library"
                    )
                else:
                    body = content.body_html if content.has_body else ""
                page = StandardPage(
                    title=content.title,
                    slug=plan.slug,
                    body=body,
                    seo_title=content.seo_title,
                    search_description=content.search_description,
                    live=False,
                    has_unpublished_changes=True,
                )
                locked_root.add_child(instance=page)
                revision = page.save_revision(log_action=False)
                # Same audit entry as a page created in the Wagtail admin, tagged with its origin.
                log(instance=page, action="wagtail.create", content_changed=True, data={"source": "setup_public_pages"})
                if plan.action == CREATE_AND_PUBLISH:
                    revision.publish(log_action=True)
                plan.created = page
        return plans

    # -- output ----------------------------------------------------------------------

    def _report(self, site, root, plans, *, applied):
        self.stdout.write(
            f"Site: #{site.pk} {site.hostname}:{site.port}{' (default site)' if site.is_default_site else ''}"
        )
        self.stdout.write(
            f"Root page: #{root.pk} HomePage '{root.title}' (slug '{root.slug}', {'live' if root.live else 'not live'})"
        )
        if not root.live:
            self.stdout.write(self.style.WARNING(
                "  The root HomePage is not live. Wagtail still serves its published children, but check this is intended."
            ))

        verbs = {
            CREATE_DRAFT: ("created draft", "would create draft"),
            CREATE_AND_PUBLISH: ("created and published", "would create and publish"),
            KEEP: ("kept", "would keep"),
            SKIP: ("skipped", "would skip"),
        }
        for plan in plans:
            verb = verbs[plan.action][0 if applied else 1]
            content = plan.content
            if plan.action in (CREATE_DRAFT, CREATE_AND_PUBLISH):
                body = "approved content" if content.has_body else "title only, no approved body"
                line = f"  /{plan.slug:<28} {plan.status:<10} {verb} '{plan.title}' ({body}, sha256 {content.content_sha256[:12]})"
                if plan.created is not None:
                    line += f" -> #{plan.created.pk}"
            else:
                line = f"  /{plan.slug:<28} {plan.status:<10} {verb}"
            style = self.style.WARNING if plan.action == SKIP else (self.style.SUCCESS if applied and plan.created else None)
            self.stdout.write(style(line) if style else line)
            for detail in plan.details:
                self.stdout.write(f"      {detail}")

        created = [p for p in plans if p.action in (CREATE_DRAFT, CREATE_AND_PUBLISH)]
        drafts = [p for p in created if p.action == CREATE_DRAFT]
        published = [p for p in created if p.action == CREATE_AND_PUBLISH]
        skipped = [p for p in plans if p.action == SKIP]
        kept = [p for p in plans if p.action == KEEP]
        prefix = "" if applied else "would be "
        self.stdout.write(
            f"Summary: {len(drafts)} {prefix}created as draft, {len(published)} {prefix}created and published, "
            f"{len(kept)} kept unchanged, {len(skipped)} skipped."
        )
        if not created:
            self.stdout.write("Nothing to create.")
        if drafts:
            note = (
                "Note: a draft occupies its path. Its public URL returns 404 until an editor publishes it in "
                "Wagtail; the frontend's default content is shown only while no page exists at the path."
            )
            # Only drafts WITH approved content could have been published (without --publish-new).
            if any(p.content.has_required_content for p in drafts):
                note += " Use --apply --publish-new to publish new pages that have approved content instead."
            self.stdout.write(self.style.WARNING(note))
        if skipped:
            self.stdout.write(self.style.WARNING(f"{len(skipped)} page(s) skipped; see the messages above."))
        if not applied and created:
            flags = "--apply --publish-new" if published else "--apply"
            self.stdout.write(f"Dry run: run again with {flags} to create these pages.")
