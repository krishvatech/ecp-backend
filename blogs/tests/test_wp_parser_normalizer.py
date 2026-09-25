from datetime import datetime, timezone

from bs4 import BeautifulSoup
from django.test import SimpleTestCase

from blogs.wordpress.client import WordPressBlogClient
from blogs.wordpress.normalizer import (
    classify_image,
    classify_link,
    normalize_excerpt,
    normalize_wordpress_html,
    text_from_html,
)
from blogs.wordpress.parser import WordPressPostParseError, parse_wordpress_post

from .wp_fixtures import (
    CLASSIC_HTML,
    ELEMENTOR_HTML,
    GUTENBERG_HTML,
    JSON_LD_HTML,
    MIXED_HTML,
    SITE,
    UNSAFE_HTML,
    FakeWordPress,
    make_post,
)


def soup(html):
    return BeautifulSoup(html, "html.parser")


def codes(warnings):
    return {w.code for w in warnings}


class ParserTests(SimpleTestCase):
    def parse(self, **kwargs):
        return parse_wordpress_post(make_post(**kwargs), site_url=SITE)

    def test_id_and_basic_fields(self):
        post = self.parse(post_id=157)
        self.assertEqual(post.wp_post_id, 157)
        self.assertEqual(post.status, "publish")
        self.assertEqual(post.slug, "ma-outlook")
        self.assertEqual(post.source_url, f"{SITE}/blog/ma-outlook/")

    def test_title_entities_decoded_and_whitespace_normalised(self):
        post = self.parse(title="  M&amp;A&#8217;s   Outlook  ")
        self.assertEqual(post.title, "M&A’s Outlook")

    def test_title_html_stripped_and_non_ascii_kept(self):
        post = self.parse(title="<h6>January to June</h6> Zürich &amp; <em>São Paulo</em>")
        self.assertEqual(post.title, "January to June Zürich & São Paulo")

    def test_excerpt_normalised(self):
        self.assertEqual(self.parse().excerpt, "Short excerpt about deals…")
        self.assertEqual(normalize_excerpt("<p>Summary here. <a href='/x'>Read more</a></p>"), "Summary here.")
        self.assertEqual(normalize_excerpt(""), "")

    def test_dates_are_utc_aware(self):
        post = self.parse(date_gmt="2021-11-02T08:15:00", modified_gmt="2022-01-05T09:00:00")
        self.assertEqual(post.published_at, datetime(2021, 11, 2, 8, 15, tzinfo=timezone.utc))
        self.assertEqual(post.modified_at, datetime(2022, 1, 5, 9, 0, tzinfo=timezone.utc))

    def test_author_id_and_name_from_yoast_not_broken_embed(self):
        post = self.parse(author=32305, author_name="Danielle Writer")
        self.assertEqual(post.wp_author_id, 32305)
        self.assertEqual(post.wp_author_name, "Danielle Writer")

    def test_missing_author_name_is_warned(self):
        post = self.parse(author_name="")
        self.assertEqual(post.wp_author_name, "")
        self.assertIn("author_name_missing", codes(post.all_warnings()))

    def test_featured_media_from_embed(self):
        media = self.parse(post_id=5).featured_media
        self.assertEqual(media.wp_id, 905)
        self.assertEqual(media.url, f"{SITE}/wp-content/uploads/cover-5.jpg")
        self.assertEqual((media.alt, media.caption, media.mime_type, media.width), ("Cover", "Cover caption", "image/jpeg", 1200))

    def test_missing_featured_media(self):
        post = self.parse(featured=False)
        self.assertIsNone(post.featured_media)
        self.assertIn("missing_featured_image", codes(post.all_warnings()))

    def test_featured_media_falls_back_to_media_endpoint(self):
        raw = make_post(post_id=6)
        del raw["_embedded"]["wp:featuredmedia"]
        fake = FakeWordPress(media={906: {"id": 906, "source_url": f"{SITE}/x.jpg", "alt_text": "X"}})
        post = parse_wordpress_post(raw, site_url=SITE, client=WordPressBlogClient(SITE, session=fake))
        self.assertEqual(post.featured_media.url, f"{SITE}/x.jpg")
        self.assertEqual(fake.paths("/media"), ["/media/906"])

    def test_categories_and_tags_from_embed_decoded(self):
        post = self.parse(tags=((5, "Cross-border M&amp;A", "cross-border-ma"), (6, "Deals", "deals")))
        self.assertEqual([(c.wp_id, c.name, c.slug) for c in post.categories], [(58, "Blog", "blog")])
        self.assertEqual([(t.name, t.slug) for t in post.tags], [("Cross-border M&A", "cross-border-ma"), ("Deals", "deals")])

    def test_terms_fetched_once_when_not_embedded(self):
        fake = FakeWordPress(terms={
            "categories": {58: {"id": 58, "name": "Blog", "slug": "blog"}},
            "tags": {5: {"id": 5, "name": "Deals", "slug": "deals"}},
        })
        client = WordPressBlogClient(SITE, session=fake)
        for post_id in (1, 2, 3):
            parse_wordpress_post(make_post(post_id, tags=((5, "Deals", "deals"),), embed=False), site_url=SITE, client=client)
        self.assertEqual(len(fake.paths("/tags")), 1, "repeated tag IDs must be resolved from the cache")
        self.assertEqual(len(fake.paths("/categories")), 1)

    def test_unresolvable_term_is_warned(self):
        raw = make_post(embed=False)
        post = parse_wordpress_post(raw, site_url=SITE)
        self.assertIn("taxonomy_resolution_failed", codes(post.all_warnings()))

    def test_yoast_seo_and_canonical(self):
        post = self.parse(slug="ma-outlook")
        self.assertEqual(post.seo_title, "M&A Outlook - IMAA")
        self.assertEqual(post.seo_description, "Fictional SEO description.")
        self.assertEqual(post.source_canonical_url, "https://www.imaa.test/blog/ma-outlook/")

    def test_yoast_values_are_entity_decoded(self):
        post = self.parse(yoast={"title": "M&amp;A &#8211; Asia&#039;s Rise", "description": "Deals &amp; trends", "canonical": "c"})
        self.assertEqual(post.seo_title, "M&A \u2013 Asia's Rise")
        self.assertEqual(post.seo_description, "Deals & trends")

    def test_slug_like_seo_description_is_dropped(self):
        post = self.parse(yoast={"title": "T", "description": "/asia-pacific-deals", "canonical": "c"})
        self.assertEqual(post.seo_description, "")
        self.assertIn("seo_description_suspicious", codes(post.all_warnings()))
        self.assertIn("seo_description_missing", codes(post.all_warnings()))
        self.assertEqual(self.parse(yoast={"title": "T", "description": "Deals rise.", "canonical": "c"}).seo_description, "Deals rise.")

    def test_missing_optional_fields(self):
        raw = make_post(yoast={}, featured=False, tags=(), embed=False)
        raw.pop("excerpt")
        raw.pop("modified_gmt")
        raw.pop("modified")
        raw["categories"] = []
        post = parse_wordpress_post(raw, site_url=SITE)
        self.assertEqual((post.excerpt, post.seo_title, post.seo_description, post.modified_at), ("", "", "", None))
        self.assertIn("seo_description_missing", codes(post.all_warnings()))
        self.assertIn("canonical_missing", codes(post.all_warnings()))

    def test_malformed_posts_raise_parse_errors(self):
        for bad in (None, [], {"id": "x"}, {"id": 5}, {"id": 0, "title": {}, "content": {}}):
            with self.assertRaises(WordPressPostParseError):
                parse_wordpress_post(bad, site_url=SITE)

    def test_format_warnings(self):
        self.assertIn("mixed_content", codes(self.parse(content=MIXED_HTML).all_warnings()))
        self.assertIn("unknown_content_format", codes(self.parse(content="").all_warnings()))


class NormalizerTests(SimpleTestCase):
    def norm(self, html, fmt="classic", **kwargs):
        return normalize_wordpress_html(html, fmt, site_url=SITE, **kwargs)

    def test_gutenberg_comments_removed_structure_preserved(self):
        result = self.norm(GUTENBERG_HTML, "gutenberg")
        self.assertNotIn("<!--", result.html)
        doc = soup(result.html)
        self.assertEqual(doc.find("p").get_text(), "Hello world.")
        self.assertEqual(doc.find("h2").get_text(), "Deal trends")
        self.assertEqual([li.get_text() for li in doc.find_all("li")], ["First point", "Second point"])
        figure = doc.find("figure")
        self.assertEqual(figure.find("img")["alt"], "Chart")
        self.assertEqual(figure.find("figcaption").get_text(), "Deal volume chart")
        self.assertEqual(doc.find("th").get_text(), "Year")
        self.assertEqual(doc.find("a", href="https://example.org/report").get_text(), "an external report")
        self.assertNotIn("wp-block", result.html)

    def test_scripts_frames_objects_forms_removed(self):
        result = self.norm(UNSAFE_HTML)
        doc = soup(result.html)
        for tag in ("script", "iframe", "object", "embed", "form", "input", "button"):
            self.assertIsNone(doc.find(tag), tag)
        self.assertIn("Safe text.", result.html)
        self.assertIn("unsafe_elements_removed", codes(result.warnings))

    def test_event_handlers_styles_and_script_urls_removed(self):
        html = self.norm(UNSAFE_HTML).html
        for needle in ("onclick", "onmouseover", "onerror", "javascript:", "vbscript:", "style="):
            self.assertNotIn(needle, html)
        self.assertIn("Styled text.", html)
        self.assertIn('alt="A"', html)

    def test_embeds_become_safe_links(self):
        result = self.norm(UNSAFE_HTML)
        doc = soup(result.html)
        self.assertEqual(doc.find("a", href="https://www.youtube.com/embed/abc123").get_text(), "Watch on YouTube")
        self.assertEqual(doc.find("a", href="https://player.vimeo.com/video/42").get_text(), "Watch on Vimeo")
        self.assertEqual(sorted(e.kind for e in result.embeds), ["vimeo", "youtube"])
        self.assertIn("unsupported_embed", codes(result.warnings))

    def test_elementor_wrappers_reduced_content_kept(self):
        result = self.norm(ELEMENTOR_HTML, "elementor")
        doc = soup(result.html)
        self.assertIsNone(doc.find("div"))
        self.assertNotIn("elementor", result.html)
        self.assertEqual(doc.find("h2").get_text(), "Elementor heading")
        paragraphs = [p.get_text(" ", strip=True) for p in doc.find_all("p")]
        self.assertIn("Elementor paragraph text.", paragraphs)
        self.assertIn("Loose text in a div.", paragraphs)
        self.assertNotIn("position", result.html)

    def test_elementor_button_becomes_plain_link(self):
        doc = soup(self.norm(ELEMENTOR_HTML, "elementor").html)
        link = doc.find("a", href=f"{SITE}/wp-content/uploads/report.pdf")
        self.assertEqual(link.get_text(), "Download report")
        self.assertIsNone(doc.find("svg"))

    def test_elementor_tabs_keep_titles_as_headings(self):
        html = """<div class="e-n-tabs"><div class="e-n-tabs-heading">
        <button id="t1" class="e-n-tab-title">Tab One</button><button id="t2" class="e-n-tab-title">Tab Two</button></div>
        <div class="e-n-tabs-content"><div role="tabpanel" aria-labelledby="t1"><p>First panel.</p></div>
        <div role="tabpanel" aria-labelledby="t2"><p>Second panel.</p></div></div></div>"""
        doc = soup(self.norm(html, "elementor").html)
        self.assertEqual([h.get_text() for h in doc.find_all("h3")], ["Tab One", "Tab Two"])
        self.assertEqual([p.get_text() for p in doc.find_all("p")], ["First panel.", "Second panel."])

    def test_details_summary_become_readable_text(self):
        doc = soup(self.norm("<details><summary>What is PMI?</summary><p>Post-merger integration.</p></details>").html)
        self.assertEqual(doc.find("strong").get_text(), "What is PMI?")
        self.assertIn("Post-merger integration.", doc.get_text())

    def test_links_inside_accordion_titles_are_kept(self):
        html = ('<details class="e-n-accordion-item"><summary class="e-n-accordion-item-title"><span><div class="e-n-accordion-item-title-text">'
                'Acme <a href="https://example.org/deal">acquired</a> Beta</div></span></summary><div><p>Deal details.</p></div></details>')
        doc = soup(self.norm(html, "elementor").html)
        link = doc.find("strong").find("a", href="https://example.org/deal")
        self.assertEqual(link.get_text(), "acquired")
        self.assertIn("Acme acquired Beta", doc.find("strong").get_text(" ", strip=True))

    def test_classic_elementor_accordion_questions_are_kept(self):
        html = """<div class="elementor-accordion"><div class="elementor-accordion-item">
        <div class="elementor-tab-title"><a class="elementor-accordion-title" href="">Question 1: Why is M&amp;A complex?</a></div>
        <div class="elementor-tab-content"><p>Because of integration risk.</p></div></div></div>"""
        result = self.norm(html, "elementor")
        doc = soup(result.html)
        self.assertEqual(doc.find("strong").get_text(" ", strip=True), "Question 1: Why is M&A complex?")
        self.assertIn("Because of integration risk.", doc.get_text())
        self.assertNotIn("content_reduced", codes(result.warnings))

    def test_classic_tabs_drop_desktop_bar_only_when_mobile_titles_exist(self):
        widget = """<div class="elementor-tabs"><div class="elementor-tabs-wrapper"><div class="elementor-tab-title">Tab A</div></div>
        <div class="elementor-tabs-content-wrapper">{mobile}<div class="elementor-tab-content"><p>Panel A.</p></div></div></div>"""
        with_mobile = soup(self.norm(widget.format(mobile='<div class="elementor-tab-mobile-title">Tab A</div>'), "elementor").html)
        self.assertEqual(with_mobile.get_text(" ", strip=True).count("Tab A"), 1)
        without_mobile = soup(self.norm(widget.format(mobile=""), "elementor").html)
        self.assertEqual(without_mobile.find("strong").get_text(), "Tab A")

    def test_classic_preserved_conservatively(self):
        doc = soup(self.norm(CLASSIC_HTML).html)
        self.assertEqual(doc.find("strong").get_text(), "bold")
        self.assertEqual(doc.find("em").get_text(), "emphasis")
        self.assertEqual(doc.find("blockquote").get_text(strip=True), "A quoted line.")
        img = doc.find("img")
        self.assertEqual((img["width"], img["height"], img["class"]), ("300", "200", ["alignnone", "wp-image-5"]))

    def test_mixed_content_survives(self):
        result = self.norm(MIXED_HTML, "mixed")
        text = soup(result.html).get_text(" ", strip=True)
        self.assertIn("Mixed paragraph one.", text)
        self.assertIn("Mixed paragraph two.", text)

    def test_json_ld_removed_and_faq_detected(self):
        result = self.norm(JSON_LD_HTML)
        self.assertNotIn("<script", result.html)
        self.assertNotIn("FAQPage", result.html)
        self.assertEqual(result.json_ld[0]["@type"], "FAQPage")
        self.assertTrue({"json_ld_removed", "faq_schema_detected"} <= codes(result.warnings))

    def test_invalid_json_ld_reported(self):
        result = self.norm('<p>x</p><script type="application/ld+json">{broken</script>')
        self.assertIn("invalid_json_ld", codes(result.warnings))
        self.assertNotIn("script", result.html)

    def test_content_emptied_by_normalization_detected(self):
        result = self.norm("<script>only()</script><button>Click</button>")
        self.assertIn("content_empty_after_normalization", codes(result.warnings))
        self.assertEqual(result.text_length, 0)

    def test_image_only_article_is_not_empty(self):
        result = self.norm(f'<p><img src="{SITE}/wp-content/uploads/x.jpg" alt=""></p>')
        self.assertNotIn("content_empty_after_normalization", codes(result.warnings))
        self.assertIn("content_has_no_text", codes(result.warnings))

    def test_empty_layout_wrappers_and_lazy_images(self):
        html = '<div><p>&nbsp;</p><p> </p></div><p><img src="data:image/svg+xml;base64,AA" data-lazy-src="https://imaa.test/wp-content/uploads/real.jpg" alt="Real"></p>'
        result = self.norm(html)
        self.assertEqual(result.html, '<p><img alt="Real" src="https://imaa.test/wp-content/uploads/real.jpg"/></p>')

    def test_text_from_html_keeps_word_boundaries(self):
        self.assertEqual(text_from_html("<p>One</p><p>Two<br>Three</p>"), "One Two Three")


class MediaDiscoveryTests(SimpleTestCase):
    def test_inline_images_collected_with_alt_and_caption(self):
        result = normalize_wordpress_html(GUTENBERG_HTML, "gutenberg", site_url=SITE)
        image = result.inline_images[0]
        self.assertEqual((image.alt, image.caption, image.classification, image.host), ("Chart", "Deal volume chart", "wordpress_media", "imaa.test"))
        self.assertIn("inline_images_not_migrated", codes(result.warnings))

    def test_image_classification(self):
        self.assertEqual(classify_image("https://www.imaa.test/wp-content/uploads/a.png", SITE).classification, "wordpress_media")
        self.assertEqual(classify_image("/images/logo.png", SITE).classification, "internal_site_media")
        self.assertEqual(classify_image("https://cdn.example.com/a.png", SITE).classification, "external_media")
        self.assertEqual(classify_image("data:image/png;base64,AAAA", SITE).classification, "data_url")
        self.assertEqual(classify_image("", SITE).classification, "invalid")
        self.assertEqual(classify_image("http://[bad", SITE).classification, "invalid")
        self.assertEqual(classify_image("ftp://imaa.test/a.png", SITE).classification, "invalid")


class LinkAnalysisTests(SimpleTestCase):
    def classify(self, href, slugs=()):
        return classify_link(href, SITE, slugs)

    def test_blog_links(self):
        link = self.classify("https://www.imaa.test/blog/some-post/")
        self.assertEqual((link.classification, link.blog_slug), ("blog", "some-post"))
        self.assertEqual(self.classify("/known-post/", {"known-post"}).classification, "blog")

    def test_other_internal(self):
        self.assertEqual(self.classify("https://imaa.test/courses/pmi/").classification, "internal")
        self.assertEqual(self.classify("/about/").classification, "internal")

    def test_external(self):
        self.assertEqual(self.classify("https://example.org/x").classification, "external")

    def test_anchor_mailto_tel(self):
        self.assertEqual(self.classify("#section").classification, "anchor")
        self.assertEqual(self.classify("mailto:a@b.c").classification, "mailto")
        self.assertEqual(self.classify("tel:+41123").classification, "tel")

    def test_media_downloads(self):
        self.assertEqual(self.classify("https://imaa.test/wp-content/uploads/r.pdf").classification, "media")
        self.assertEqual(self.classify("/files/brochure.PDF").classification, "media")

    def test_malformed(self):
        for href in ("", "http://[bad", "javascript:alert(1)", "https://imaa.test:99999/x"):
            self.assertEqual(self.classify(href).classification, "invalid", href)

    def test_links_reported_not_rewritten(self):
        result = normalize_wordpress_html(GUTENBERG_HTML, "gutenberg", site_url=SITE)
        self.assertEqual(sorted(l.classification for l in result.internal_links), ["blog", "external"])
        self.assertIn('href="https://imaa.test/blog/other-post/"', result.html)
        self.assertIn("internal_link_needs_rewrite", codes(result.warnings))
