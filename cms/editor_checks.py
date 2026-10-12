"""Checks that rich text can be opened and saved in Wagtail's Draftail editor without loss.

Used by the local content-import commands before they write anything.
"""

import re
from html import unescape

from wagtail.admin.rich_text.converters.contentstate import ContentstateConverter
from wagtail.rich_text import features as feature_registry

_TAGS_RE = re.compile(r"<[^>]+>")
_converters = {}


def _words(html):
    return unescape(_TAGS_RE.sub(" ", html or "")).replace("\xa0", " ").split()


def draftail_problem(html, features=None):
    """None when ``html`` (Wagtail storage format) loads in Draftail with its text intact."""
    key = tuple(features) if features else None
    if key not in _converters:
        _converters[key] = ContentstateConverter(features or feature_registry.get_default_features())
    converter = _converters[key]
    try:
        saved = converter.to_database_format(converter.from_database_format(html))
    except Exception as exc:  # the converter raises AssertionError on markup it cannot read
        return f"the Wagtail editor cannot load it ({type(exc).__name__}: {exc})"
    if _words(saved) != _words(html):
        return "the Wagtail editor would change its text"
    return None
