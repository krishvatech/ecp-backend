"""The manual blocklist update command. All downloads are mocked."""
import hashlib
import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase

from users import disposable_email as de

COMMAND = "users.management.commands.update_disposable_email_domains"
SHA = "a" * 40


def fake_get(blocklist_bytes):
    def _get(url, timeout):
        response = mock.MagicMock()
        response.raise_for_status.return_value = None
        if "api.github.com" in url:
            response.content = json.dumps({"sha": SHA, "commit": {"committer": {"date": "2026-10-01T00:00:00Z"}}}).encode()
        else:
            assert SHA in url, url  # the file is always fetched at the resolved commit
            response.content = blocklist_bytes
        return response

    return _get


def domains(count, extra=()):
    lines = [f"disposable{i}.example" for i in range(count)] + list(extra)
    return ("\n".join(lines) + "\n").encode()


class UpdateCommandTests(SimpleTestCase):
    def run_command(self, blocklist_bytes, *args):
        out = StringIO()
        with mock.patch(f"{COMMAND}.requests.get", side_effect=fake_get(blocklist_bytes)):
            call_command("update_disposable_email_domains", "--ref", "main", *args, stdout=out)
        return out.getvalue()

    def test_dry_run_reports_and_writes_nothing(self):
        before = de.BLOCKLIST_PATH.read_bytes()
        output = self.run_command(domains(1200))
        self.assertIn("Dry run", output)
        self.assertIn(SHA, output)
        self.assertEqual(de.BLOCKLIST_PATH.read_bytes(), before)

    def test_rejects_truncated_irregular_or_dangerous_lists(self):
        for payload, expected in (
            (domains(10), "only 10 domains"),
            (domains(1200, ["Upper.Example"]), "non-normalized"),
            (domains(1200, ["gmail.com"]), "mainstream providers"),
        ):
            with self.subTest(expected=expected), self.assertRaisesMessage(CommandError, expected):
                self.run_command(payload)

    def test_write_updates_blocklist_and_source_metadata(self):
        payload = domains(1200)
        with tempfile.TemporaryDirectory() as tmp:
            blocklist, source = Path(tmp) / "blocklist.conf", Path(tmp) / "SOURCE.json"
            with mock.patch.object(de, "BLOCKLIST_PATH", blocklist), mock.patch(f"{COMMAND}.SOURCE_PATH", source):
                self.run_command(payload, "--write")
            self.assertEqual(blocklist.read_bytes(), payload)
            meta = json.loads(source.read_text())
        self.assertEqual(meta["source_commit"], SHA)
        self.assertEqual(meta["domain_count"], 1200)
        self.assertEqual(meta["sha256"], hashlib.sha256(payload).hexdigest())
        de.get_bundled_domain_lists.cache_clear()
