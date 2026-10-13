"""Import a public website article section (In The News, M&A Publications) from WordPress.

    python manage.py import_wordpress_section --section in-the-news                 # dry run (read-only report)
    python manage.py import_wordpress_section --section publications --report-json /tmp/pubs.json
    python manage.py import_wordpress_section --section in-the-news --commit        # import (writes; see below)

The articles are BlogPost rows of the WordPress categories ``news`` (97 posts) and ``publications``
(388), served anonymously by blogs/public_sections.py and left out of the member Blogs.

* Dry run (default): the existing WordPress Blog importer's planning report for that category; no
  database or storage writes.
* --commit: the existing full sync (blogs.wordpress.sync.execute_import_run) for that category,
  recorded as a BlogImportRun: posts are created/updated idempotently by WordPress ID, and featured
  and inline images are downloaded from WordPress and stored under new content-hash names (never
  overwriting). Run it only after a database backup and with approval for the media it adds.
  Links between articles keep their imaa-institute.org URLs; links are never rewritten to the
  member /blogs/ reader for these sections.
* Held for review (REVIEW_HOLD): posts whose WordPress content is only a page-builder placeholder are
  returned to draft right after the import (``BlogPost.unpublish``), which also hands their status to
  ECP, so later syncs keep them unpublished. An editor publishes them in the Blog admin once the client
  has supplied or approved their content.
"""

import json

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from blogs.models import BlogImportRun, BlogPost
from blogs.public_sections import PUBLIC_SECTIONS
from blogs.wordpress.client import WordPressBlogAPIError, WordPressBlogClient
from blogs.wordpress.importer import ImportAborted, WordPressBlogImporter
from blogs.wordpress.report import render_text
from blogs.wordpress.sync import execute_import_run, mark_failed

# WordPress category ids on imaa-institute.org (checked 2026-10-12 via /wp-json/wp/v2/categories).
SECTION_CATEGORIES = {"in-the-news": (66, "news"), "publications": (59, "publications")}

# WordPress post ids whose content is only the Divi placeholder text (the article was never filled
# in on imaa-institute.org; checked 2026-10-12). Not published without the client's decision.
REVIEW_HOLD = {"publications": (45714, 45785, 45398, 45944, 46084, 46104)}


class _DryRunRollback(Exception):
    pass


class Command(BaseCommand):
    help = "Import a public website article section (in-the-news, publications) from WordPress. Dry run unless --commit."

    def add_arguments(self, parser):
        parser.add_argument("--section", required=True, choices=sorted(SECTION_CATEGORIES))
        parser.add_argument("--commit", action="store_true", help="Import (writes posts and stores their images).")
        parser.add_argument("--limit", type=int, help="Dry run only: analyse at most N posts.")
        parser.add_argument("--report-json", metavar="PATH", help="Dry run: also write the full report as JSON.")

    def handle(self, *args, **options):
        section = options["section"]
        category_id, category_slug = SECTION_CATEGORIES[section]
        assert PUBLIC_SECTIONS[section] == category_slug
        if options["commit"] and options["limit"]:
            raise CommandError("--limit is for dry runs only; --commit imports the whole section.")
        if not options["commit"]:
            try:
                client = WordPressBlogClient.from_settings()
                importer = WordPressBlogImporter(client, commit=False, category_id=category_id, expected_category_slug=category_slug)
                # As import_wordpress_blogs: the dry run never writes, and runs in a transaction that is always rolled back.
                result = {}
                try:
                    with transaction.atomic():
                        result["report"] = importer.run(limit=options["limit"])
                        raise _DryRunRollback()
                except _DryRunRollback:
                    pass
                report = result["report"]
            except (WordPressBlogAPIError, ImportAborted) as exc:
                raise CommandError(f"Dry run failed, nothing was changed: {exc}") from exc
            self.stdout.write(render_text(report))
            if options["report_json"]:
                with open(options["report_json"], "w") as fh:
                    json.dump(report, fh, indent=1, default=str)
            self.stdout.write(f"Dry run of '{section}' (category {category_slug}, id {category_id}): nothing was changed. "
                              f"Import with: python manage.py import_wordpress_section --section {section} --commit")
            return
        run = BlogImportRun.objects.create(source_url="", current_step=f"section:{section}")
        try:
            status = execute_import_run(run, category_id=category_id, category_slug=category_slug)
        except (WordPressBlogAPIError, ImportAborted) as exc:
            # As the Celery task: a stopped run is failed, so it never blocks the next import.
            mark_failed(run, str(exc))
            held = self.hold_for_review(section)  # posts written before the stop are held as well
            raise CommandError(f"Import of '{section}' stopped: {exc} (run {run.pk}); held for review: {held}") from exc
        run.refresh_from_db()
        held = self.hold_for_review(section)
        self.stdout.write(f"Import of '{section}' finished: {status}; created {run.created_count}, updated {run.updated_count}, "
                          f"skipped {run.skipped_count}, failed {run.failed_count}; media migrated {run.media_migrated_count}, "
                          f"reused {run.media_reused_count}, failed {run.media_failed_count} (run {run.pk}).")
        if held:
            self.stdout.write(f"Held for client review (draft, not public): {len(held)} posts, WordPress ids {held}.")

    @staticmethod
    def hold_for_review(section):
        """Unpublish the review-hold posts the import published (posts an editor already decided on are left alone)."""
        held = []
        for post in BlogPost.objects.filter(wp_post_id__in=REVIEW_HOLD.get(section, ()), status=BlogPost.STATUS_PUBLISHED,
                                            wp_status_managed=True).order_by("wp_post_id"):
            post.unpublish()
            held.append(post.wp_post_id)
        return held
