"""
Manually update the bundled disposable email blocklist from the upstream repo.

Never run automatically. Default is a dry run that downloads, validates and
prints a diff summary; --write replaces the local files for code review.

Usage:
    python manage.py update_disposable_email_domains --ref <commit-sha>          # dry-run
    python manage.py update_disposable_email_domains --ref <commit-sha> --write  # write files

After --write: review the git diff, run the disposable email tests, rebuild the
Cognito Lambda (deploy/cognito_pre_signup/build.sh) and deploy both together.
"""
import hashlib
import json
from datetime import date

import requests
from django.core.management.base import BaseCommand, CommandError

from users import disposable_email as de

UPSTREAM_REPO = "disposable-email-domains/disposable-email-domains"
UPSTREAM_FILE = "disposable_email_blocklist.conf"
SOURCE_PATH = de.DATA_DIR / "SOURCE.json"

# Mainstream providers that must never be blocked. If an upstream update lists
# one, stop and let a human decide (allowlist it or skip the update).
MUST_NOT_BLOCK = (
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
)


class Command(BaseCommand):
    help = "Download, validate and (with --write) update the disposable email blocklist."

    def add_arguments(self, parser):
        parser.add_argument("--ref", required=True, help="Upstream commit SHA (or branch/tag) to use.")
        parser.add_argument("--write", action="store_true", help="Write the new files. Default is dry-run.")
        parser.add_argument("--timeout", type=int, default=30)

    def handle(self, *args, ref, write, timeout, **options):
        commit = self._fetch_json(f"https://api.github.com/repos/{UPSTREAM_REPO}/commits/{ref}", timeout)
        sha = commit["sha"]
        commit_date = commit["commit"]["committer"]["date"]
        raw = self._fetch_bytes(f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{sha}/{UPSTREAM_FILE}", timeout)

        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise CommandError(f"Upstream file is not UTF-8: {exc}")
        new = de.parse_domain_lines(lines, source=UPSTREAM_FILE)
        entries = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        irregular = [entry for entry in entries if de.normalize_domain(entry) != entry]
        if irregular:
            raise CommandError(f"Upstream has {len(irregular)} non-normalized entries, e.g. {irregular[:5]}")
        if len(new) < de.MIN_EXPECTED_BLOCKLIST_SIZE:
            raise CommandError(f"Upstream list has only {len(new)} domains; refusing to use it.")

        allowlist = de.load_domain_lists().allowed
        lists = de.DomainLists(blocked=new, allowed=allowlist)
        listed = [d for d in MUST_NOT_BLOCK if de.match_disposable_domain(d, lists)]
        if listed:
            raise CommandError(f"Upstream now lists mainstream providers {listed}; allowlist them or skip.")

        current = de.load_domain_lists().blocked
        added, removed = sorted(new - current), sorted(current - new)
        self.stdout.write(f"Upstream {sha} ({commit_date}): {len(new)} domains")
        self.stdout.write(f"Current: {len(current)} domains; +{len(added)} added, -{len(removed)} removed")
        for label, items in (("added", added), ("removed", removed)):
            if items:
                self.stdout.write(f"  {label} (first 20): {', '.join(items[:20])}")

        if not write:
            self.stdout.write(self.style.WARNING("Dry run: nothing written. Re-run with --write to update."))
            return

        de.BLOCKLIST_PATH.write_bytes(raw)
        source = {
            "source_repository": f"https://github.com/{UPSTREAM_REPO}",
            "source_file": UPSTREAM_FILE,
            "source_commit": sha,
            "source_commit_date": commit_date,
            "fetched_at": date.today().isoformat(),
            "license": "CC0-1.0",
            "domain_count": len(new),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        SOURCE_PATH.write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")
        de.get_bundled_domain_lists.cache_clear()
        self.stdout.write(self.style.SUCCESS(f"Wrote {de.BLOCKLIST_PATH.name} and {SOURCE_PATH.name}. Review the diff."))

    def _fetch_json(self, url, timeout):
        return json.loads(self._fetch_bytes(url, timeout))

    def _fetch_bytes(self, url, timeout):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise CommandError(f"Download failed for {url}: {exc}")
        return response.content
