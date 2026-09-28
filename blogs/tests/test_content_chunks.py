from bs4 import BeautifulSoup
from django.core.cache import cache
from django.test import SimpleTestCase
from django.urls import reverse
from rest_framework import status

from blogs.content_chunks import chunk_boundaries, content_chunks

from .factories import BlogAPITestCase, make_post, make_published_post, make_superuser, make_user

TARGET = 400  # small target so fixtures stay short


def article(sections=12):
    """Imported-article shaped HTML: flat top-level blocks with IDs, lists, tables, figures."""
    parts = []
    for i in range(sections):
        parts.append(f'<h2 id="section-{i}">Section {i}</h2>')
        parts.append(f"<p>Paragraph {i} with <a href=\"/blogs/other#part-{i}\">a link</a> and <strong>bold</strong> text.</p>")
        if i % 3 == 0:
            parts.append(f"<ul><li>Item {i}a<ul><li>Nested {i}</li></ul></li><li>Item {i}b</li></ul>")
        if i % 4 == 1:
            parts.append(f"<table><thead><tr><th>Year</th></tr></thead><tbody><tr><td>{2020 + i}</td></tr></tbody></table>")
        if i % 4 == 2:
            parts.append(f'<figure><img src="/media/blogs/wordpress/media/{i}.png" alt="Chart {i}" loading="lazy">'
                         f"<figcaption>Caption {i}</figcaption></figure>")
    return "\n".join(parts)


def top_level_blocks(html):
    return [str(n) for n in BeautifulSoup(html, "html.parser").contents if getattr(n, "name", None)]


class ChunkingTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def test_chunks_reconstruct_the_article_exactly_without_splitting_blocks(self):
        html = article()
        chunks = content_chunks(html, target=TARGET)
        self.assertGreater(len(chunks), 3, "large article -> several chunks")
        self.assertEqual("".join(chunks), html, "byte-for-byte reconstruction")
        per_chunk = [block for chunk in chunks for block in top_level_blocks(chunk)]
        self.assertEqual(per_chunk, top_level_blocks(html), "no duplicate, missing or divided blocks")
        for chunk in chunks:
            soup = BeautifulSoup(chunk, "html.parser")
            for tag in ("p", "a", "ul", "li", "table", "tr", "figure", "figcaption", "h2", "strong"):
                self.assertEqual(chunk.count(f"<{tag}>") + chunk.count(f"<{tag} "), chunk.count(f"</{tag}>"),
                                 f"every <{tag}> opened in a chunk closes in that chunk")
            for table in soup.find_all("table"):
                self.assertTrue(table.find("tbody"), "tables intact")
            for figure in soup.find_all("figure"):
                self.assertTrue(figure.find("img") and figure.find("figcaption"), "figure + caption intact")
            for ul in soup.find_all("ul", recursive=False):
                self.assertTrue(ul.find("li"), "lists intact")

    def test_heading_ids_are_preserved(self):
        chunks = content_chunks(article(), target=TARGET)
        ids = [h["id"] for chunk in chunks for h in BeautifulSoup(chunk, "html.parser").find_all("h2")]
        self.assertEqual(ids, [f"section-{i}" for i in range(12)])

    def test_small_article_is_one_chunk_and_empty_content_is_safe(self):
        self.assertEqual(content_chunks("<p>Short.</p>"), ["<p>Short.</p>"])
        self.assertEqual(content_chunks(""), [""])
        self.assertEqual(content_chunks(None), [""])

    def test_deterministic_boundaries_with_and_without_cache(self):
        html = article()
        first = content_chunks(html, target=TARGET)
        cache.clear()
        self.assertEqual(content_chunks(html, target=TARGET), first)
        self.assertEqual(content_chunks(html, target=TARGET), first, "cached")
        self.assertEqual(chunk_boundaries(html, TARGET), chunk_boundaries(html, TARGET))

    def test_a_single_large_block_is_never_split(self):
        big = "<table>" + "".join(f"<tr><td>{i}</td></tr>" for i in range(300)) + "</table>"
        html = f"<p>Intro</p>{big}<p>Outro</p>"
        chunks = content_chunks(html, target=TARGET)
        self.assertEqual("".join(chunks), html)
        self.assertTrue(any(chunk.startswith("<table>") and chunk.rstrip().endswith("</table>") or big in chunk for chunk in chunks))
        self.assertEqual(sum(chunk.count("<table>") for chunk in chunks), 1)

    def test_chunking_never_changes_or_adds_markup(self):
        html = '<p>Safe</p><p><img src="/a.png" alt="A"></p>' * 40 + '<p data-x="1">End &amp; more</p>'
        chunks = content_chunks(html, target=TARGET)
        self.assertEqual("".join(chunks), html)
        self.assertNotIn("<script", "".join(chunks))


def detail(slug, **params):
    return reverse("blogs:post-detail", kwargs={"slug": slug}), params


class ChunkedReaderApiTests(BlogAPITestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.client.force_authenticate(make_user("reader"))
        self.html = article(sections=300)  # ~60 KB: several real 20 KB chunks
        self.post = make_published_post(title="Long read", content_html=self.html)
        self.detail_url = reverse("blogs:post-detail", kwargs={"slug": self.post.slug})
        self.content_url = reverse("blogs:post-content", kwargs={"slug": self.post.slug})

    def fetch_all(self, slug=None):
        first = self.client.get(reverse("blogs:post-detail", kwargs={"slug": slug or self.post.slug}),
                                {"content_mode": "chunked"}).data
        parts, chunk, more = [first["content_html"]], 1, first["content_has_more"]
        while more:
            chunk += 1
            response = self.client.get(reverse("blogs:post-content", kwargs={"slug": slug or self.post.slug}),
                                       {"chunk": chunk})
            self.assertEqual(response.data["chunk"], chunk)
            parts.append(response.data["content_html"])
            more = response.data["has_more"]
        return first, parts

    def test_chunked_detail_returns_metadata_and_only_the_first_chunk(self):
        response = self.client.get(self.detail_url, {"content_mode": "chunked"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual((data["title"], data["content_chunk"], data["content_has_more"]), ("Long read", 1, True))
        self.assertGreater(data["content_chunks"], 1)
        self.assertLess(len(data["content_html"]), len(self.html) / 2, "not the whole article")
        self.assertTrue(self.html.startswith(data["content_html"]))
        self.assertEqual(str(BeautifulSoup(data["content_html"], "html.parser")).count("<h2"), data["content_html"].count("<h2"))

    def test_chunks_follow_in_order_and_rebuild_the_article(self):
        first, parts = self.fetch_all()
        self.assertEqual(len(parts), first["content_chunks"])
        self.assertEqual("".join(parts), self.html)
        last = self.client.get(self.content_url, {"chunk": len(parts)}).data
        self.assertFalse(last["has_more"])
        second = self.client.get(self.content_url, {"chunk": 2}).data
        self.assertEqual(second["content_html"], parts[1])
        self.assertTrue(second["has_more"] or len(parts) == 2)

    def test_small_article_is_a_single_chunk(self):
        small = make_published_post(title="Short read", content_html="<p>Short.</p>")
        first, parts = self.fetch_all(small.slug)
        self.assertEqual((first["content_chunks"], first["content_has_more"], parts), (1, False, ["<p>Short.</p>"]))

    def test_default_detail_still_returns_the_full_article(self):
        data = self.client.get(self.detail_url).data
        self.assertEqual(data["content_html"], self.html)
        self.assertNotIn("content_chunk", data)

    def test_drafts_members_only_and_unknown_slugs_are_404(self):
        drafts = [
            make_post(title="WP draft", content_html=self.html, wp_post_id=1, wp_status="draft"),
            make_post(title="Members only", content_html=self.html, wp_post_id=2, wp_status="publish",
                      wp_membership_restricted=True),
            make_post(title="Pending", content_html=self.html, wp_post_id=3, wp_status="pending"),
        ]
        for slug in [d.slug for d in drafts] + ["no-such-blog"]:
            self.assertEqual(self.client.get(reverse("blogs:post-detail", kwargs={"slug": slug}),
                                             {"content_mode": "chunked"}).status_code, 404, slug)
            response = self.client.get(reverse("blogs:post-content", kwargs={"slug": slug}), {"chunk": 1})
            self.assertEqual(response.status_code, 404, slug)
            self.assertNotIn("Section", str(response.data))

    def test_invalid_chunk_numbers_are_rejected(self):
        for bad in ("", "0", "-1", "abc", "1.5"):
            self.assertEqual(self.client.get(self.content_url, {"chunk": bad}).status_code, 400, bad)
        self.assertEqual(self.client.get(self.content_url, {"chunk": 999}).status_code, 404)

    def test_unauthenticated_requests_are_rejected(self):
        self.client.force_authenticate(None)
        self.assertIn(self.client.get(self.content_url, {"chunk": 1}).status_code, (401, 403))

    def test_admin_api_still_returns_complete_content(self):
        self.client.force_authenticate(make_superuser())
        data = self.client.get(reverse("blogs:admin-post-detail", kwargs={"pk": self.post.pk}),
                               {"content_mode": "chunked"}).data
        self.assertEqual(data["content_html"], self.html)
        self.assertNotIn("content_chunk", data)
