"""Active content in landing page HTML.

Landing pages are served from Mautic's own domain, the same origin as the
Mautic admin. Mautic strips event-handler attributes and ``javascript:`` links
from page HTML but keeps ``<script>`` elements, so only superusers may save page
HTML that runs code (the agreed LP1 policy). This module only reports what it
finds; the view decides who may save it. It never rewrites the HTML.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

# Elements that run code or change how every other URL on the page resolves.
_ACTIVE_ELEMENTS = {
    "script": "a <script> element",
    "object": "an <object> element",
    "embed": "an <embed> element",
    "applet": "an <applet> element",
    "base": "a <base> element",
    "frame": "a <frame> element",
    "frameset": "a <frameset> element",
}

_URL_ATTRIBUTES = {"href", "src", "action", "formaction", "data", "xlink:href", "poster", "background"}

# Browsers ignore ASCII whitespace and control characters inside a scheme.
_SCHEME_NOISE = re.compile(r"[\x00-\x20\x7f]+")
_SCRIPT_SCHEMES = ("javascript:", "vbscript:", "data:text/html", "data:application/xhtml", "data:image/svg")

MAX_FINDINGS = 10


class _ActiveContentParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.findings: list[str] = []

    def _add(self, finding: str) -> None:
        if finding not in self.findings:
            self.findings.append(finding)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _ACTIVE_ELEMENTS:
            self._add(_ACTIVE_ELEMENTS[tag])
        for name, value in attrs:
            name = (name or "").lower()
            if name.startswith("on"):
                self._add(f"an event-handler attribute ({name})")
            elif name == "srcdoc" and tag == "iframe":
                self._add("an <iframe srcdoc> document")
            elif name in _URL_ATTRIBUTES and _is_script_url(value):
                self._add(f"a script URL in {name}")
            elif tag == "meta" and name == "http-equiv" and str(value or "").strip().lower() == "refresh":
                self._add("a <meta http-equiv=refresh> redirect")

    handle_startendtag = handle_starttag


def _is_script_url(value) -> bool:
    compact = _SCHEME_NOISE.sub("", str(value or "")).lower()
    return compact.startswith(_SCRIPT_SCHEMES)


def find_active_content(html: str) -> list[str]:
    """Plain-language descriptions of every kind of active content found, in
    order, at most MAX_FINDINGS. Empty means the HTML runs no code."""
    parser = _ActiveContentParser()
    parser.feed(str(html or ""))
    parser.close()
    return parser.findings[:MAX_FINDINGS]
