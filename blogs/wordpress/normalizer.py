"""
WordPress HTML -> safe, semantic ECP article HTML.

Two layers, deliberately separate:
  1. Structure (BeautifulSoup): drop comments/JSON-LD/embeds/unsafe elements,
     turn Elementor buttons into plain links, unwrap layout wrappers, promote
     lazy-loaded image sources, and discover images/links for reporting.
     BeautifulSoup is NOT the security boundary.
  2. Security (nh3, the Rust "ammonia" allowlist sanitiser): only the tags,
     attributes and URL schemes listed below survive. No inline styles, no
     event handlers, no javascript:/vbscript:/data: URLs.
"""
import json
import re
from urllib.parse import urlsplit

import nh3
from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from .types import (
    FORMAT_ELEMENTOR,
    FORMAT_MIXED,
    W_CONTENT_EMPTY,
    W_CONTENT_NO_TEXT,
    W_CONTENT_REDUCED,
    W_ELEMENTS_REMOVED,
    W_EXTERNAL_IMAGES_NOT_MIGRATED,
    W_FAQ_SCHEMA_DETECTED,
    W_INTERNAL_LINK_NEEDS_REWRITE,
    W_INVALID_JSON_LD,
    W_JSON_LD_REMOVED,
    W_MEMBERS_ONLY,
    W_UNSUPPORTED_EMBED,
    EmbedRef,
    ImportWarning,
    InlineImage,
    LinkRef,
    NormalizedContent,
)

ALLOWED_TAGS = {
    "p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "b", "em", "i", "u", "s", "del", "ins",
    "sub", "sup", "small", "mark", "abbr", "cite", "q", "code", "pre", "kbd", "blockquote",
    "ul", "ol", "li", "dl", "dt", "dd", "a", "img", "figure", "figcaption",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col", "hr",
}
ALLOWED_ATTRIBUTES = {
    "*": {"class"},
    "a": {"href", "title"},
    "img": {"src", "alt", "title", "width", "height", "srcset", "sizes"},
    "th": {"colspan", "rowspan", "scope"},
    "td": {"colspan", "rowspan"},
    "col": {"span"},
    "colgroup": {"span"},
    "ol": {"start", "reversed"},
    "abbr": {"title"},
    "blockquote": {"cite"},
    "q": {"cite"},
}
URL_SCHEMES = {"http", "https", "mailto", "tel"}
# Only content-meaning classes survive (alignment/size), never layout/utility classes.
SAFE_CLASS = re.compile(r"^(align(?:left|right|center|wide|full|none)|has-text-align-(?:left|center|right)|size-[a-z0-9-]+|wp-image-\d+)$")

# Removed together with their content before sanitising (never article text).
DROP_WITH_CONTENT = (
    "script", "style", "noscript", "template", "object", "embed", "applet", "svg", "math", "canvas",
    "form", "input", "textarea", "select", "option", "button", "base", "meta", "link", "param",
)
EMBED_TAGS = ("iframe", "video", "audio")
LAYOUT_TAGS = ("div", "section", "article", "header", "footer", "main", "aside", "nav", "span", "font", "center")
BLOCK_TAGS = {
    "p", "div", "section", "article", "header", "footer", "main", "aside", "nav", "h1", "h2", "h3", "h4", "h5",
    "h6", "ul", "ol", "li", "table", "figure", "blockquote", "pre", "hr", "dl", "form", "center",
}
INLINE_CONTEXT = {"li", "td", "th", "figcaption", "dd", "dt", "caption", "p", "a", "strong", "em", "b", "i", "h1", "h2", "h3", "h4", "h5", "h6"}
REMOVE_WHEN_EMPTY = {
    "p", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "b", "em", "i", "u", "s", "small", "mark",
    "li", "ul", "ol", "blockquote", "figure", "figcaption", "a", "sup", "sub", "dl", "dd", "dt",
}
MEDIA_EXTENSIONS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".csv",
                    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".mp4", ".mp3", ".mov")
BLOG_PATH = re.compile(r"^/blog/([^/?#]+)/?$")
_WS = re.compile(r"[\s ​]+")
LAZY_SRC_ATTRS = ("data-src", "data-lazy-src", "data-original", "data-orig-file")
LAZY_SRCSET_ATTRS = ("data-srcset", "data-lazy-srcset")


def collapse(text):
    return _WS.sub(" ", text or "").strip()


def _bare_host(host):
    host = (host or "").lower().split(":")[0]
    return host[4:] if host.startswith("www.") else host


# ------------------------------------------------------------ plain text --
def text_from_html(html):
    """Readable plain text: tags stripped, entities decoded, whitespace collapsed."""
    soup = BeautifulSoup(html or "", "html.parser")
    for node in soup.find_all(DROP_WITH_CONTENT):
        node.decompose()
    for br in soup.find_all("br"):
        br.replace_with(" ")
    for block in soup.find_all(BLOCK_TAGS):
        block.append(" ")
    return collapse(soup.get_text(""))


_EXCERPT_TAIL = re.compile(r"\s*\[\s*(?:…|\.\.\.|&hellip;)\s*\]\s*$")
_READ_MORE_TAIL = re.compile(r"\s*(?:read more|continue reading)\b[^.!?]{0,60}$", re.I)


def normalize_excerpt(html):
    text = text_from_html(html)
    if _EXCERPT_TAIL.search(text):
        text = _EXCERPT_TAIL.sub("…", text)
    text = _READ_MORE_TAIL.sub("", text).strip()
    return text


# -------------------------------------------------------- classification --
def classify_link(href, site_url, known_blog_slugs=()):
    """Return LinkRef classification for an href (no network, no rewriting)."""
    raw = (href or "").strip()
    ref = LinkRef(href=raw)
    if not raw:
        ref.classification = "invalid"
        return ref
    if raw.startswith("#"):
        ref.classification = "anchor"
        return ref
    lowered = raw.lower()
    if lowered.startswith("mailto:"):
        ref.classification = "mailto"
        return ref
    if lowered.startswith("tel:"):
        ref.classification = "tel"
        return ref
    try:
        parts = urlsplit(raw)
        _ = parts.port  # raises ValueError for malformed ports
    except ValueError:
        ref.classification = "invalid"
        return ref
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        ref.classification = "invalid"
        return ref
    site_host = _bare_host(urlsplit(site_url or "").hostname)
    host = _bare_host(parts.hostname) if parts.netloc else site_host
    if parts.netloc and not parts.hostname:
        ref.classification = "invalid"
        return ref
    if host != site_host:
        ref.classification = "external"
        return ref
    path = parts.path or "/"
    if "/wp-content/uploads/" in path or path.lower().endswith(MEDIA_EXTENSIONS):
        ref.classification = "media"
        return ref
    match = BLOG_PATH.match(path)
    single_segment = path.strip("/")
    if match:
        ref.classification = "blog"
        ref.blog_slug = match.group(1)
    elif single_segment and "/" not in single_segment and single_segment in set(known_blog_slugs or ()):
        ref.classification = "blog"
        ref.blog_slug = single_segment
    else:
        ref.classification = "internal"
    return ref


def classify_image(src, site_url):
    raw = (src or "").strip()
    image = InlineImage(src=raw)
    if raw.lower().startswith("data:"):
        image.classification = "data_url"
        image.src = raw[:40] + "…"
        return image
    if not raw:
        image.classification = "invalid"
        return image
    try:
        parts = urlsplit(raw if not raw.startswith("//") else f"https:{raw}")
        _ = parts.port
    except ValueError:
        image.classification = "invalid"
        return image
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        image.classification = "invalid"
        return image
    site_host = _bare_host(urlsplit(site_url or "").hostname)
    host = _bare_host(parts.hostname) if parts.netloc else site_host
    image.host = host
    if host == site_host:
        image.classification = "wordpress_media" if "/wp-content/uploads/" in (parts.path or "") else "internal_site_media"
    else:
        image.classification = "external_media"
    return image


def _embed_kind(src):
    host = _bare_host(urlsplit(src).hostname or "")
    if host.endswith(("youtube.com", "youtu.be", "youtube-nocookie.com")):
        return "youtube"
    if host.endswith("vimeo.com"):
        return "vimeo"
    return "other"


def _has_faq(obj):
    if isinstance(obj, dict):
        kind = obj.get("@type")
        kinds = kind if isinstance(kind, list) else [kind]
        if "FAQPage" in kinds:
            return True
        return any(_has_faq(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_faq(v) for v in obj)
    return False


# ------------------------------------------------------------- structure --
def _classes(tag):
    return tag.get("class") or []


def _has_block_child(tag):
    return any(isinstance(child, Tag) and child.name in BLOCK_TAGS for child in tag.children)


def _has_direct_text(tag):
    return any(isinstance(child, NavigableString) and not isinstance(child, Comment) and collapse(str(child))
               for child in tag.children)


def _is_empty(tag):
    if tag.find(["img", "hr", "table", "br"]) and tag.name not in ("p",):
        return False
    if tag.name == "p" and tag.find(["img", "table"]):
        return False
    if tag.name == "a" and tag.find("img"):
        return False
    return not collapse(tag.get_text(""))


def _clean_attribute(element, attribute, value):
    if attribute == "class":
        kept = [token for token in value.split() if SAFE_CLASS.match(token)]
        return " ".join(kept) or None
    if attribute in ("width", "height", "colspan", "rowspan", "span", "start"):
        return value if value.isdigit() else None
    return value


def _to_bold_paragraph(soup, node):
    """Replace a title element with <p><strong>...</strong></p>, keeping its links."""
    if not collapse(node.get_text(" ")):
        node.decompose()
        return
    paragraph = soup.new_tag("p")
    strong = soup.new_tag("strong")
    for child in list(node.contents):
        strong.append(child.extract())
    paragraph.append(strong)
    node.replace_with(paragraph)


def _flatten_tabs(soup):
    """Tabs/accordions -> static reading order without losing any title.

    - Nested tabs (e-n-tabs): each title (a <button>) becomes an <h3> above
      its panel, then the button bar is removed.
    - Classic Elementor tabs/accordion/toggle: titles are real content (often
      FAQ questions). The desktop tab bar is dropped only when every title is
      duplicated as a mobile title next to its panel; remaining titles become
      bold paragraphs, links included.
    """
    for panel in soup.select('[role="tabpanel"][aria-labelledby]'):
        title_el = soup.find(id=panel.get("aria-labelledby"))
        if title_el is None or title_el.name != "button":
            continue
        title = collapse(title_el.get_text(" "))
        if title and not collapse(panel.get_text(" ")).startswith(title):
            heading = soup.new_tag("h3")
            heading.string = title
            panel.insert(0, heading)
    for bar in soup.select(".e-n-tabs-heading"):
        if not getattr(bar, "decomposed", False):
            bar.decompose()

    for widget in soup.select(".elementor-tabs"):
        desktop = widget.select(".elementor-tabs-wrapper .elementor-tab-title")
        mobile = widget.select(".elementor-tab-mobile-title")
        if desktop and len(mobile) >= len(desktop):
            for bar in widget.select(".elementor-tabs-wrapper"):
                bar.decompose()
    for title in soup.select(".elementor-tab-title, .elementor-tab-mobile-title"):
        if not getattr(title, "decomposed", False):
            _to_bold_paragraph(soup, title)


def _flatten_details(soup):
    """<details><summary>Q</summary>A</details> -> <p><strong>Q</strong></p> A (links kept)."""
    for summary in soup.find_all("summary"):
        _to_bold_paragraph(soup, summary)
    for details in soup.find_all("details"):
        details.unwrap()

def sanitize_html(html):
    """Security boundary: allowlist sanitiser (nh3)."""
    return nh3.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes=URL_SCHEMES,
        attribute_filter=_clean_attribute,
        strip_comments=True,
        link_rel="noopener noreferrer",
        clean_content_tags={"script", "style"},
    )


def normalize_wordpress_html(html, source_format, *, site_url="", known_blog_slugs=()):
    result = NormalizedContent(html="")
    warnings = result.warnings
    removed = result.removed_elements
    soup = BeautifulSoup(html or "", "html.parser")

    # 1. Comments (Gutenberg block delimiters, editor notes).
    for comment in soup.find_all(string=lambda node: isinstance(node, Comment)):
        comment.extract()

    # 2. JSON-LD: parse for diagnostics, never keep.
    faq = False
    for script in soup.find_all("script"):
        if "ld+json" in (script.get("type") or "").lower():
            try:
                data = json.loads(script.string or script.get_text() or "")
                result.json_ld.append(data)
                faq = faq or _has_faq(data)
                warnings.append(ImportWarning(W_JSON_LD_REMOVED))
            except (ValueError, TypeError):
                warnings.append(ImportWarning(W_INVALID_JSON_LD))
            script.decompose()
    if faq:
        warnings.append(ImportWarning(W_FAQ_SCHEMA_DETECTED))

    # 3. Embeds become plain links (no iframe runtime in ECP).
    for node in soup.find_all(EMBED_TAGS):
        src = node.get("src") or ""
        if not src:
            source = node.find("source")
            src = source.get("src", "") if source else ""
        kind = _embed_kind(src) if src else "other"
        if src.startswith(("https://", "http://", "//")):
            href = f"https:{src}" if src.startswith("//") else src
            label = {"youtube": "Watch on YouTube", "vimeo": "Watch on Vimeo"}.get(kind, "View embedded content")
            paragraph = soup.new_tag("p")
            link = soup.new_tag("a", href=href)
            link.string = label
            paragraph.append(link)
            node.replace_with(paragraph)
            result.embeds.append(EmbedRef(kind=kind, src=href, replaced_with_link=True))
        else:
            node.decompose()
            result.embeds.append(EmbedRef(kind=kind, src=src, replaced_with_link=False))
        warnings.append(ImportWarning(W_UNSUPPORTED_EMBED, kind))

    # Paywalled posts (WooCommerce Memberships): the public API only returns a
    # teaser plus a purchase notice, never the article.
    if soup.select_one('[class*="wc-memberships"]'):
        warnings.append(ImportWarning(W_MEMBERS_ONLY, "public REST API returns a members-only teaser"))

    baseline = BeautifulSoup(str(soup), "html.parser")
    for node in baseline.find_all(DROP_WITH_CONTENT + EMBED_TAGS):
        node.decompose()
    source_text_length = len(collapse(baseline.get_text(" ")))
    result.source_text_length = source_text_length

    # 3b. Interactive widgets -> static reading order.
    _flatten_tabs(soup)
    _flatten_details(soup)

    # 4. Unsafe / non-article elements, removed with their content.
    for node in soup.find_all(DROP_WITH_CONTENT):
        if getattr(node, "decomposed", False):
            continue  # already removed together with an ancestor
        removed[node.name] = removed.get(node.name, 0) + 1
        node.decompose()

    # 5. Lazy-loaded images: promote the real source.
    for img in soup.find_all("img"):
        src = img.get("src") or ""
        if not src or src.startswith("data:"):
            for attr in LAZY_SRC_ATTRS:
                if img.get(attr):
                    img["src"] = img[attr]
                    break
        if not img.get("srcset"):
            for attr in LAZY_SRCSET_ATTRS:
                if img.get(attr):
                    img["srcset"] = img[attr]
                    break

    # 6. Elementor: buttons -> plain links, spacers dropped, dividers -> <hr>.
    if source_format in (FORMAT_ELEMENTOR, FORMAT_MIXED) or soup.select_one("[class*=elementor]"):
        for button in soup.select("a.elementor-button, a.elementor-button-link"):
            text = collapse(button.get_text(" "))
            href = button.get("href", "")
            if text and href:
                paragraph = soup.new_tag("p")
                link = soup.new_tag("a", href=href)
                link.string = text
                paragraph.append(link)
                button.replace_with(paragraph)
            else:
                button.decompose()
        for spacer in soup.select(".elementor-widget-spacer"):
            spacer.decompose()
        for divider in soup.select(".elementor-widget-divider"):
            divider.replace_with(soup.new_tag("hr"))

    # 7. Layout wrappers: unwrap containers, keep text blocks as paragraphs.
    for node in reversed(soup.find_all(LAYOUT_TAGS)):
        if node.parent is None:
            continue
        if node.name in ("span", "font"):
            node.unwrap()
        elif _has_direct_text(node) and not _has_block_child(node) and node.parent.name not in INLINE_CONTEXT:
            node.name = "p"
            node.attrs = {}
        else:
            node.unwrap()

    # 8. Discovery (before sanitising so unsafe/data URLs are still visible).
    for img in soup.find_all("img"):
        image = classify_image(img.get("src"), site_url)
        image.alt = collapse(img.get("alt", ""))
        image.srcset = img.get("srcset", "") or ""
        figure = img.find_parent("figure")
        caption = figure.find("figcaption") if figure else None
        image.caption = collapse(caption.get_text(" ")) if caption else ""
        result.inline_images.append(image)
    for anchor in soup.find_all("a"):
        link = classify_link(anchor.get("href"), site_url, known_blog_slugs)
        link.text = collapse(anchor.get_text(" "))[:120]
        result.internal_links.append(link)

    # 9. Security boundary.
    cleaned = sanitize_html(str(soup))

    # 10. Tidy: drop emptied wrappers and image tags that lost their source.
    tidy = BeautifulSoup(cleaned, "html.parser")
    for img in tidy.find_all("img"):
        if not img.get("src"):
            img.decompose()
    for anchor in tidy.find_all("a"):
        if not anchor.get("href"):
            anchor.unwrap()
    changed = True
    while changed:
        changed = False
        for node in tidy.find_all(REMOVE_WHEN_EMPTY):
            if _is_empty(node):
                node.decompose()
                changed = True
    html_out = str(tidy).strip()
    html_out = re.sub(r"\n{3,}", "\n\n", html_out)
    result.html = html_out
    result.text_length = len(collapse(tidy.get_text(" ")))

    if removed:
        detail = ", ".join(f"{tag}×{count}" for tag, count in sorted(removed.items()))
        warnings.append(ImportWarning(W_ELEMENTS_REMOVED, detail))
    has_media = tidy.find(["img", "table"]) is not None
    if not result.text_length and (source_text_length or not has_media):
        # Text was lost in normalization, or nothing publishable remains.
        warnings.append(ImportWarning(W_CONTENT_EMPTY))
    elif not result.text_length:
        warnings.append(ImportWarning(W_CONTENT_NO_TEXT, "image-only article"))
    elif source_text_length > 200 and result.text_length < 0.6 * source_text_length:
        warnings.append(ImportWarning(W_CONTENT_REDUCED, f"{result.text_length}/{source_text_length} chars kept"))
    rewrite = [l for l in result.internal_links if l.classification in ("blog", "internal", "media")]
    if rewrite:
        warnings.append(ImportWarning(W_INTERNAL_LINK_NEEDS_REWRITE, f"{len(rewrite)} link(s)"))
    wp_images = [i for i in result.inline_images if i.classification in ("wordpress_media", "internal_site_media")]
    if wp_images:
        warnings.append(ImportWarning(W_EXTERNAL_IMAGES_NOT_MIGRATED, f"{len(wp_images)} image(s) still on WordPress"))
    return result
