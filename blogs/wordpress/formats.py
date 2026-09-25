"""Content-format detection for WordPress post HTML, based on markup markers only."""
import re

from .types import FORMAT_CLASSIC, FORMAT_ELEMENTOR, FORMAT_GUTENBERG, FORMAT_MIXED, FORMAT_UNKNOWN

# Markers are matched inside markup (comments, class/data attributes), never in
# visible text, so an article that merely mentions "Elementor" is not flagged.
_GUTENBERG_COMMENT = re.compile(r"<!--\s*/?wp:[a-z0-9-]+", re.I)
_GUTENBERG_CLASS = re.compile(r"""class\s*=\s*["'][^"']*\bwp-block-[a-z0-9-]+""", re.I)
_ELEMENTOR_DATA = re.compile(r"""\sdata-elementor-(?:type|id|settings|element_type|widget_type)\s*=""", re.I)
_ELEMENTOR_CLASS = re.compile(
    r"""class\s*=\s*["'][^"']*\belementor-(?:section|container|column|widget|element|widget-container|text-editor|heading-title|button|image)\b""",
    re.I,
)
_TAG = re.compile(r"<\s*[a-zA-Z][a-zA-Z0-9-]*\b")


def format_signals(html):
    html = html or ""
    return {
        "gutenberg_comments": len(_GUTENBERG_COMMENT.findall(html)),
        "gutenberg_classes": len(_GUTENBERG_CLASS.findall(html)),
        "elementor_data": len(_ELEMENTOR_DATA.findall(html)),
        "elementor_classes": len(_ELEMENTOR_CLASS.findall(html)),
        "tags": len(_TAG.findall(html)),
        "text_length": len(re.sub(r"<[^>]+>", "", html).strip()),
    }


def detect_source_format(html):
    """Return gutenberg | elementor | classic | mixed | unknown for post HTML."""
    s = format_signals(html)
    gutenberg = s["gutenberg_comments"] > 0 or s["gutenberg_classes"] >= 1
    elementor = s["elementor_data"] > 0 or s["elementor_classes"] >= 2
    if gutenberg and elementor:
        return FORMAT_MIXED
    if elementor:
        return FORMAT_ELEMENTOR
    if gutenberg:
        return FORMAT_GUTENBERG
    if s["tags"] > 0 or s["text_length"] > 0:
        return FORMAT_CLASSIC
    return FORMAT_UNKNOWN
