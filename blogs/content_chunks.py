"""
Split a Blog's stored article HTML into reader chunks for lazy loading.

Chunks are exact slices of `content_html` cut only where a top-level element
starts, so:
  * no element (paragraph, list, table, figure, anchor...) is ever divided;
  * joining the chunks in order reproduces `content_html` byte for byte
    (IDs, sanitisation and everything else are untouched);
  * boundaries depend only on the content, so they are deterministic.

Boundaries are cached per content hash; nothing is stored in the database.
If the cache is unavailable they are simply recomputed.
"""
import hashlib

from bs4 import BeautifulSoup, Tag
from blogs.cache import safe_get, safe_set

# Aim for chunks of roughly this many characters of HTML. A chunk closes at the
# first top-level element boundary after reaching the target, so a single
# large block is never split.
CHUNK_TARGET_CHARS = 20_000
CACHE_SECONDS = 60 * 60


def _line_offsets(html):
    """Start offset of each line as html.parser counts them ("\\n" only)."""
    offsets, position = [0], html.find("\n")
    while position != -1:
        offsets.append(position + 1)
        position = html.find("\n", position + 1)
    return offsets


def _top_level_starts(html):
    """Character offsets where top-level elements start (verified), in order."""
    soup = BeautifulSoup(html, "html.parser")
    lines = _line_offsets(html)
    starts = []
    for node in soup.contents:
        if not isinstance(node, Tag) or node.sourceline is None:
            continue
        offset = lines[node.sourceline - 1] + node.sourcepos
        # Guard against position drift: the slice must start with this tag.
        if not html.startswith(f"<{node.name}", offset):
            return None
        starts.append(offset)
    return starts


def chunk_boundaries(html, target=CHUNK_TARGET_CHARS):
    """Offsets at which chunks 2..n start (empty list = one chunk)."""
    html = html or ""
    if len(html) <= target:
        return []
    starts = _top_level_starts(html)
    if not starts:
        return []  # unparseable layout: serve the article as one chunk
    boundaries, chunk_start = [], 0
    for offset in starts:
        if offset - chunk_start >= target:
            boundaries.append(offset)
            chunk_start = offset
    return boundaries


def content_chunks(html, target=CHUNK_TARGET_CHARS):
    """List of HTML chunks (at least one, possibly empty)."""
    html = html or ""
    digest = hashlib.sha256(html.encode("utf-8")).hexdigest()
    key = f"blogs:chunks:{target}:{digest}"
    boundaries = safe_get(key)
    if boundaries is None:
        boundaries = chunk_boundaries(html, target)
        safe_set(key, boundaries, CACHE_SECONDS)
    edges = [0, *boundaries, len(html)]
    return [html[a:b] for a, b in zip(edges, edges[1:])]
