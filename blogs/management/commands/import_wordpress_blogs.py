"""
Import published IMAA WordPress Blog posts into the ECP Blog.

Safe by default: without --commit nothing is written.

    python manage.py import_wordpress_blogs                          # dry run, whole category
    python manage.py import_wordpress_blogs --dry-run --report-json /tmp/blog-import.json
    python manage.py import_wordpress_blogs --post-id 157765          # dry run, one post
    python manage.py import_wordpress_blogs --post-id 157765 --commit # import that post

Bulk commit is disabled in Batch 3: --commit requires explicit --post-id values.
"""
import json

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from blogs.wordpress.client import WordPressBlogAPIError, WordPressBlogClient
from blogs.wordpress.importer import MAX_COMMIT_POSTS, ImportAborted, WordPressBlogImporter
from blogs.wordpress.report import render_text


class _DryRunRollback(Exception):
    pass


class Command(BaseCommand):
    help = (
        "Import published WordPress Blog posts (category WP_IMAA_BLOG_CATEGORY_ID). "
        "Dry run unless --commit is given. Bulk commit is disabled in Batch 3: "
        f"--commit requires explicit --post-id values (max {MAX_COMMIT_POSTS})."
    )

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Plan only; make no database changes (default).")
        mode.add_argument("--commit", action="store_true", help="Write the selected --post-id posts to the ECP Blog.")
        parser.add_argument("--post-id", type=int, action="append", dest="post_ids", default=[],
                            help="WordPress post ID to process. Repeat for several posts.")
        parser.add_argument("--limit", type=int, help="Dry run only: analyse at most N posts.")
        parser.add_argument("--report-json", metavar="PATH", help="Also write the full report as JSON to PATH.")
        parser.add_argument("--show-posts", action="store_true", help="Print one line per post in the report.")
        parser.add_argument("--allow-category-mismatch", action="store_true",
                            help="Proceed even if the configured category slug is not the expected Blog slug.")

    def handle(self, *args, **options):
        commit = options["commit"]
        post_ids = options["post_ids"]
        if commit and not post_ids:
            raise CommandError("Bulk commit is disabled in Batch 3. Pass one or more --post-id values with --commit.")
        if commit and options.get("limit"):
            raise CommandError("--limit only applies to dry runs.")

        try:
            client = WordPressBlogClient.from_settings()
            importer = WordPressBlogImporter(client, commit=commit)
            if commit:
                report = importer.run(post_ids=post_ids, allow_category_mismatch=options["allow_category_mismatch"])
            else:
                report = self._dry_run(importer, post_ids, options)
        except (ImportAborted, WordPressBlogAPIError) as exc:
            raise CommandError(str(exc))

        self.stdout.write(render_text(report))
        if options["show_posts"]:
            self.stdout.write("")
            for post in report["posts"]:
                codes = ",".join(sorted({w["code"] for w in post["warnings"]}))
                self.stdout.write(
                    f"{post['wp_post_id']:>7} {post['action']:<6} {post['format']:<9} {post['slug'][:60]:<60} {codes}"
                )
        if options.get("report_json"):
            with open(options["report_json"], "w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, ensure_ascii=False, default=str)
            self.stdout.write(f"JSON report written to {options['report_json']}")
        if report["plan"]["error"]:
            self.stderr.write(self.style.WARNING(f"{report['plan']['error']} post(s) could not be imported; see ERRORS."))

    @staticmethod
    def _dry_run(importer, post_ids, options):
        """Defence in depth: even though the dry run never writes, run it inside
        a transaction that is always rolled back."""
        result = {}
        try:
            with transaction.atomic():
                result["report"] = importer.run(
                    post_ids=post_ids,
                    limit=options.get("limit"),
                    allow_category_mismatch=options["allow_category_mismatch"],
                )
                raise _DryRunRollback
        except _DryRunRollback:
            pass
        return result["report"]
