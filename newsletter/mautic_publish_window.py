"""Publish windows (publishUp / publishDown) for Mautic items.

Mautic reads these as UTC in "YYYY-MM-DD HH:MM" and refuses ISO's "T" form.
The admin's browser sends an ISO moment with its offset; it is converted to UTC
here. ``None`` means "no date" (clear it).
"""

from __future__ import annotations

from datetime import datetime, timezone

MAUTIC_FORMAT = "%Y-%m-%d %H:%M"


class PublishWindowError(ValueError):
    def __init__(self, message: str, *, field: str):
        super().__init__(message)
        self.field = field


def to_mautic(value, *, field: str) -> str | None:
    """An ISO moment (with offset, or UTC "Z") as Mautic's UTC text; blank -> None."""
    if value in (None, ""):
        return None
    try:
        moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        raise PublishWindowError("Enter a valid date and time.", field=field) from None
    if moment.tzinfo is None:
        raise PublishWindowError("Send the date and time with its time zone.", field=field)
    return moment.astimezone(timezone.utc).strftime(MAUTIC_FORMAT)


def from_mautic(value) -> datetime | None:
    """Mautic's stored value (ISO with offset, or its UTC text) as an aware moment."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            moment = datetime.strptime(text, MAUTIC_FORMAT)
        except ValueError:
            return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def parse_window(data, current: dict | None = None) -> dict[str, str | None]:
    """The publishUp/publishDown changes in ``data``, checked against each other
    and against the stored values of the one not being changed."""
    changes: dict[str, str | None] = {}
    for key in ("publishUp", "publishDown"):
        if key in data:
            changes[key] = to_mautic(data.get(key), field=key)
    up = changes["publishUp"] if "publishUp" in changes else (current or {}).get("publishUp")
    down = changes["publishDown"] if "publishDown" in changes else (current or {}).get("publishDown")
    start, end = from_mautic(up), from_mautic(down)
    if start and end and end <= start:
        raise PublishWindowError("The unpublish date must be after the publish date.", field="publishDown")
    return changes
