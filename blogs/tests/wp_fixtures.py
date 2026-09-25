"""
Short fictional WordPress payloads reproducing real markup patterns
(Gutenberg, Elementor, Classic, Mixed, unsafe markup, JSON-LD, embeds).
No live WordPress access and no copied article text.
"""
import copy
from urllib.parse import urlsplit

import requests

SITE = "https://imaa.test"
CATEGORY = {"id": 58, "name": "Blog", "slug": "blog", "count": 2, "taxonomy": "category"}

GUTENBERG_HTML = """
<!-- wp:paragraph --><p>Hello world.</p><!-- /wp:paragraph -->
<!-- wp:heading --><h2 class="wp-block-heading">Deal trends</h2><!-- /wp:heading -->
<!-- wp:list --><ul class="wp-block-list"><li>First point</li><li>Second point</li></ul><!-- /wp:list -->
<!-- wp:image --><figure class="wp-block-image size-large"><img src="https://imaa.test/wp-content/uploads/2024/01/chart.png" alt="Chart" class="wp-image-12"/><figcaption>Deal volume chart</figcaption></figure><!-- /wp:image -->
<!-- wp:table --><figure class="wp-block-table"><table><thead><tr><th>Year</th></tr></thead><tbody><tr><td>2024</td></tr></tbody></table></figure><!-- /wp:table -->
<p>Read <a href="https://imaa.test/blog/other-post/">another post</a> or <a href="https://example.org/report">an external report</a>.</p>
"""

ELEMENTOR_HTML = """
<div data-elementor-type="wp-post" data-elementor-id="9" class="elementor elementor-9">
 <div class="elementor-element elementor-section e-con"><div class="elementor-container">
  <div class="elementor-element elementor-widget elementor-widget-heading"><div class="elementor-widget-container">
   <h2 class="elementor-heading-title elementor-size-default">Elementor heading</h2></div></div>
  <div class="elementor-element elementor-widget elementor-widget-text-editor"><div class="elementor-widget-container">
   <p style="position:fixed;z-index:9999">Elementor paragraph text.</p>
   <div class="elementor-text-editor">Loose text in a div.</div></div></div>
  <div class="elementor-element elementor-widget elementor-widget-spacer"><div class="elementor-spacer"></div></div>
  <div class="elementor-element elementor-widget elementor-widget-button"><div class="elementor-widget-container">
   <a class="elementor-button elementor-button-link" href="https://imaa.test/wp-content/uploads/report.pdf">
    <span class="elementor-button-content-wrapper"><span class="elementor-button-icon"><svg viewBox="0 0 1 1"><path d="M0"/></svg></span>
    <span class="elementor-button-text">Download report</span></span></a></div></div>
 </div></div>
</div>
"""

CLASSIC_HTML = """<p>Classic intro with <strong>bold</strong> and <em>emphasis</em>.</p>
<p><img class="alignnone wp-image-5" src="https://imaa.test/wp-content/uploads/2020/01/photo.jpg" alt="Photo" width="300" height="200"></p>
<blockquote><p>A quoted line.</p></blockquote>"""

MIXED_HTML = """<div class="elementor elementor-5" data-elementor-type="wp-post"><div class="elementor-element elementor-widget">
<!-- wp:paragraph --><p class="wp-block-paragraph">Mixed paragraph one.</p><!-- /wp:paragraph -->
</div></div><p>Mixed paragraph two.</p>"""

UNSAFE_HTML = """<p onclick="steal()" onmouseover="x()">Safe text.</p>
<script>alert('x')</script>
<p><a href="javascript:alert(1)">bad link</a> <a href="vbscript:msgbox">vb</a></p>
<img src="https://imaa.test/wp-content/uploads/a.png" onerror="alert(1)" alt="A">
<object data="evil.swf"></object><embed src="evil.swf"><form action="/x"><input name="q"><button>Go</button></form>
<iframe src="https://www.youtube.com/embed/abc123"></iframe>
<iframe src="https://player.vimeo.com/video/42"></iframe>
<p style="background:url(javascript:alert(1))">Styled text.</p>"""

JSON_LD_HTML = """<p>FAQ article body.</p>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[]}</script>"""


def make_post(
    post_id=101,
    *,
    title="M&amp;A Outlook",
    slug="ma-outlook",
    content="<p>Hello world, a fictional article.</p>",
    excerpt="<p>Short excerpt about deals [&hellip;]</p>",
    author=7,
    author_name="Jane Writer",
    categories=(58,),
    tags=((5, "Cross-border M&amp;A", "cross-border-ma"),),
    featured=True,
    yoast=None,
    status="publish",
    date_gmt="2024-03-01T10:00:00",
    modified_gmt="2024-03-05T12:30:00",
    embed=True,
):
    tag_terms = [{"id": t[0], "name": t[1], "slug": t[2], "taxonomy": "post_tag"} for t in tags]
    post = {
        "id": post_id,
        "status": status,
        "slug": slug,
        "link": f"{SITE}/blog/{slug}/",
        "date": date_gmt,
        "date_gmt": date_gmt,
        "modified": modified_gmt,
        "modified_gmt": modified_gmt,
        "title": {"rendered": title},
        "excerpt": {"rendered": excerpt},
        "content": {"rendered": content},
        "author": author,
        "categories": list(categories),
        "tags": [t[0] for t in tags],
        "featured_media": 900 + post_id if featured else 0,
        "yoast_head_json": yoast if yoast is not None else {
            "title": "M&A Outlook - IMAA",
            "description": "Fictional SEO description.",
            "canonical": f"https://www.imaa.test/blog/{slug}/",
            "twitter_misc": {"Written by": author_name} if author_name else {},
        },
    }
    if embed:
        post["_embedded"] = {
            "author": [{"code": "rest_no_route", "message": "No route", "data": {"status": 404}}],
            "wp:term": [
                [{"id": c, "name": "Blog" if c == 58 else f"Cat {c}", "slug": "blog" if c == 58 else f"cat-{c}", "taxonomy": "category"} for c in categories],
                tag_terms,
            ],
        }
        if featured:
            post["_embedded"]["wp:featuredmedia"] = [{
                "id": 900 + post_id,
                "source_url": f"{SITE}/wp-content/uploads/cover-{post_id}.jpg",
                "alt_text": "Cover",
                "caption": {"rendered": "<p>Cover caption</p>"},
                "mime_type": "image/jpeg",
                "media_details": {"width": 1200, "height": 630},
            }]
    return post


INVALID_JSON = object()


class FakeResponse:
    def __init__(self, status=200, payload=None, headers=None):
        self.status_code = status
        self._payload = payload
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})

    def json(self):
        if self._payload is INVALID_JSON:
            raise ValueError("invalid json")
        return copy.deepcopy(self._payload)


class FakeWordPress:
    """A fake requests.Session serving a tiny WordPress REST API."""

    def __init__(self, posts=(), category=None, terms=None, media=None):
        self.posts = list(posts)
        self.category = category or CATEGORY
        self.terms = terms or {"categories": {}, "tags": {}}
        self.media = media or {}
        self.calls = []
        self.overrides = {}  # path -> FakeResponse or Exception

    def get(self, url, params=None, timeout=None, headers=None):
        path = urlsplit(url).path.replace("/wp-json/wp/v2", "")
        params = dict(params or {})
        self.calls.append((path, params))
        if path in self.overrides:
            override = self.overrides[path]
            if isinstance(override, Exception):
                raise override
            return override
        if path == f"/categories/{self.category['id']}":
            return FakeResponse(200, self.category)
        if path.startswith("/categories/"):
            return FakeResponse(404, {"code": "rest_term_invalid", "message": "Term does not exist."})
        if path == "/posts":
            per_page = int(params.get("per_page", 10))
            page = int(params.get("page", 1))
            chosen = [p for p in self.posts if int(params.get("categories", 0)) in p["categories"]]
            total_pages = max(1, -(-len(chosen) // per_page))
            if page > total_pages:
                return FakeResponse(400, {"code": "rest_post_invalid_page_number", "message": "Invalid page."})
            items = chosen[(page - 1) * per_page : page * per_page]
            if "_embed" not in params:
                items = [{k: v for k, v in p.items() if k != "_embedded"} for p in items]
            if params.get("_fields"):
                wanted = params["_fields"].split(",")
                items = [{k: p[k] for k in wanted if k in p} for p in items]
            return FakeResponse(200, items, {"X-WP-Total": str(len(chosen)), "X-WP-TotalPages": str(total_pages)})
        if path.startswith("/posts/"):
            post_id = int(path.rsplit("/", 1)[1])
            for post in self.posts:
                if post["id"] == post_id:
                    return FakeResponse(200, post if "_embed" in params else {k: v for k, v in post.items() if k != "_embedded"})
            return FakeResponse(404, {"code": "rest_post_invalid_id", "message": "Invalid post ID."})
        if path in ("/categories", "/tags"):
            taxonomy = path.strip("/")
            ids = [int(i) for i in params.get("include", "").split(",") if i]
            return FakeResponse(200, [self.terms[taxonomy][i] for i in ids if i in self.terms[taxonomy]])
        if path.startswith("/media/"):
            media_id = int(path.rsplit("/", 1)[1])
            if media_id in self.media:
                return FakeResponse(200, self.media[media_id])
            return FakeResponse(404, {"code": "rest_post_invalid_id", "message": "Invalid post ID."})
        if path.startswith("/users/"):
            return FakeResponse(404, {"code": "rest_no_route", "message": "No route"})
        return FakeResponse(404, {"code": "rest_no_route", "message": "No route"})

    def paths(self, prefix=""):
        return [path for path, _ in self.calls if path.startswith(prefix)]
