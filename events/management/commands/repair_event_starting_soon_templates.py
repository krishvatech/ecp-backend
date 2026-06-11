import copy
import json
import re
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from events.models import EventEmailTemplate


RANGE_TAG = "{{ event_date_range_str }}"
DATE_TAG = "{{ event_date_str }}"
START_TAG = "{{ event_start_str }}"
END_TAG = "{{ event_end_str }}"
TIMEZONE_TAG = "{{ event_timezone }}"


def parse_bool(value):
    if value is True or value is False:
        return value
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def is_event_multi_day(event):
    if getattr(event, "is_multi_day", False):
        return True

    start_time = getattr(event, "start_time", None)
    end_time = getattr(event, "end_time", None)

    if start_time and end_time:
        return start_time.date() != end_time.date()

    return False


def looks_like_date_time_row(block):
    lowered = str(block).lower()
    return (
        "date" in lowered
        or "time" in lowered
        or "📅" in lowered
        or "⏰" in lowered
    )


def remove_bad_html_blocks(text, bad_tags, keep_tags):
    if not text:
        return text

    output = str(text)

    bad_pattern = "|".join(re.escape(tag) for tag in bad_tags)

    # Remove common email rows/blocks only when they look like Date/Time rows.
    # This avoids removing custom client text that may mention the same merge tag.
    for tag in ("tr", "p", "li", "div"):
        pattern = re.compile(
            rf"<{tag}\b[^>]*>[\s\S]*?(?:{bad_pattern})[\s\S]*?</{tag}>",
            re.IGNORECASE,
        )

        def repl(match):
            block = match.group(0)

            if any(keep_tag in block for keep_tag in keep_tags):
                return block

            if not looks_like_date_time_row(block):
                return block

            # Avoid deleting a huge wrapper div by mistake.
            if tag == "div" and len(block) > 1500:
                return block

            return ""

        output = pattern.sub(repl, output)

    # Also handle plain text / editor text lines.
    lines = output.splitlines()
    if len(lines) > 1:
        kept_lines = []
        for line in lines:
            has_bad = any(tag in line for tag in bad_tags)
            has_keep = any(tag in line for tag in keep_tags)

            if has_bad and not has_keep and looks_like_date_time_row(line):
                continue

            kept_lines.append(line)

        output = "\n".join(kept_lines)

    return output


def repair_string(value, is_multi_day):
    if not value:
        return value

    if is_multi_day:
        # Multi-day should keep date range and standalone timezone row.
        # Do not protect TIMEZONE_TAG here because the old broken Time row contains
        # timezone inside parentheses, and that whole Time row must be removed.
        return remove_bad_html_blocks(
            value,
            bad_tags=[DATE_TAG, START_TAG, END_TAG],
            keep_tags=[RANGE_TAG],
        )

    # Single-day should keep normal date + time, remove date range.
    return remove_bad_html_blocks(
        value,
        bad_tags=[RANGE_TAG],
        keep_tags=[DATE_TAG, START_TAG, END_TAG, TIMEZONE_TAG],
    )


def json_contains_problem(value):
    try:
        text = json.dumps(value)
    except Exception:
        text = str(value)

    return RANGE_TAG in text and (
        DATE_TAG in text or START_TAG in text or END_TAG
    )


def repair_editor_json(value, is_multi_day):
    """
    Recursively repair saved editor JSON without resetting the template.

    This is intentionally conservative:
    - Drops only blocks/list items that look like Date/Time rows.
    - Does not remove unrelated custom text, colors, buttons, links, footer, etc.
    """
    if value in (None, "", [], {}):
        return value

    bad_tags = [DATE_TAG, START_TAG, END_TAG] if is_multi_day else [RANGE_TAG]
    keep_tags = [RANGE_TAG] if is_multi_day else [DATE_TAG, START_TAG, END_TAG, TIMEZONE_TAG]

    def should_drop_node(node):
        try:
            text = json.dumps(node)
        except Exception:
            text = str(node)

        has_bad = any(tag in text for tag in bad_tags)
        has_keep = any(tag in text for tag in keep_tags)

        return has_bad and not has_keep and looks_like_date_time_row(text)

    def walk(node):
        if isinstance(node, list):
            new_items = []
            for item in node:
                if should_drop_node(item):
                    continue
                new_items.append(walk(item))
            return new_items

        if isinstance(node, dict):
            if should_drop_node(node):
                return {}

            return {key: walk(val) for key, val in node.items()}

        if isinstance(node, str):
            return repair_string(node, is_multi_day)

        return node

    return walk(copy.deepcopy(value))


def template_has_duplicate_date_problem(template):
    values = [
        template.html_body or "",
        template.text_body or "",
        template.mjml_body or "",
    ]

    if any(RANGE_TAG in value and (DATE_TAG in value or START_TAG in value or END_TAG in value) for value in values):
        return True

    if template.editor_json and json_contains_problem(template.editor_json):
        return True

    return False


class Command(BaseCommand):
    help = "Safely repair old broken event_starting_soon templates without resetting client customizations."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Actually save repaired templates.")
        parser.add_argument("--event-id", type=int, help="Repair only one event id.")
        parser.add_argument("--backup-dir", default="template_repair_backups")

    def handle(self, *args, **options):
        apply_changes = options["apply"]
        event_id = options.get("event_id")
        backup_dir = Path(options["backup_dir"])

        qs = EventEmailTemplate.objects.select_related("event").filter(
            template_key="event_starting_soon"
        )

        if event_id:
            qs = qs.filter(event_id=event_id)

        backups = []
        changed_templates = []
        skipped_no_safe_change = 0
        update_lines = []

        for template in qs.order_by("id"):
            if not template_has_duplicate_date_problem(template):
                continue

            event = template.event
            is_multi_day = is_event_multi_day(event)

            old_html = template.html_body
            old_text = template.text_body
            old_mjml = template.mjml_body
            old_json = template.editor_json

            new_html = repair_string(old_html, is_multi_day)
            new_text = repair_string(old_text, is_multi_day)
            new_mjml = repair_string(old_mjml, is_multi_day)
            new_json = repair_editor_json(old_json, is_multi_day)

            changed = (
                new_html != old_html
                or new_text != old_text
                or new_mjml != old_mjml
                or new_json != old_json
            )

            if not changed:
                skipped_no_safe_change += 1
                continue

            update_lines.append(
                f"[WILL UPDATE] template_id={template.id} event_id={template.event_id} "
                f"is_multi_day={is_multi_day} subject={template.subject!r}"
            )

            backups.append({
                "id": template.id,
                "event_id": template.event_id,
                "event_title": getattr(event, "title", ""),
                "is_multi_day": is_multi_day,
                "template_key": template.template_key,
                "subject": template.subject,
                "html_body": old_html,
                "text_body": old_text,
                "mjml_body": old_mjml,
                "editor_json": old_json,
            })

            changed_templates.append((template, new_html, new_text, new_mjml, new_json))

        self.stdout.write(self.style.WARNING(
            f"{'APPLY MODE' if apply_changes else 'DRY RUN'}: found {len(changed_templates)} template(s) needing safe update."
        ))

        for line in update_lines:
            self.stdout.write(line)

        if skipped_no_safe_change:
            self.stdout.write(f"Skipped {skipped_no_safe_change} already-clean/no-safe-change template(s).")

        if not apply_changes:
            self.stdout.write(self.style.WARNING("Dry-run only. No database changes were made."))
            self.stdout.write("Run again with --apply only after reviewing the output.")
            return

        if not changed_templates:
            self.stdout.write(self.style.SUCCESS("Nothing to update."))
            return

        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"event_starting_soon_templates_backup_{timezone.now().strftime('%Y%m%d_%H%M%S')}.json"
        backup_path.write_text(json.dumps(backups, indent=2, default=str), encoding="utf-8")

        with transaction.atomic():
            for template, new_html, new_text, new_mjml, new_json in changed_templates:
                template.html_body = new_html
                template.text_body = new_text
                template.mjml_body = new_mjml
                template.editor_json = new_json
                template.save(update_fields=["html_body", "text_body", "mjml_body", "editor_json", "updated_at"])

        self.stdout.write(self.style.SUCCESS(f"Updated {len(changed_templates)} template(s)."))
        self.stdout.write(self.style.SUCCESS(f"Backup saved to: {backup_path}"))
