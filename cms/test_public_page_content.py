"""Tests for the initial public page content files (cms/public_page_content/*.json)."""

import json
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from django.test import SimpleTestCase
from wagtail.rich_text import RichText

from cms import public_page_content as content_module
from cms.public_page_content import (
    MIGRATED,
    PUBLIC_PAGE_SLUGS,
    PUBLIC_PAGES,
    PublicPageContentError,
    compute_content_hash,
    dump_content_file,
    file_sha256,
    load_all_public_page_content,
    load_public_page_content,
    parse_media_line,
)
from cms.public_pages import prepare_public_rich_text, sanitise_public_rich_text


def text_lines(content):
    """Body lines except bundled-image placeholders (those are resolved per consumer)."""
    return [line for line in content.body_lines if parse_media_line(line) is None]

# What Wagtail's default rich-text editor (Draftail) can open and save without losing markup.
EDITOR_TAGS = {"p", "br", "h2", "h3", "h4", "ul", "ol", "li", "a", "b", "strong", "i", "em", "hr"}
URL_PREFIXES = ("https://", "http://", "mailto:", "tel:")


class _MarkupCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = set()
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        self.attributes.extend((tag, name, value) for name, value in attrs)


class PublicPageContentTests(SimpleTestCase):
    def test_catalog_is_the_five_agreed_pages(self):
        self.assertEqual(
            PUBLIC_PAGES,
            (
                ("frequently-asked-questions", "Frequently Asked Questions"),
                ("references", "References"),
                ("terms-and-conditions", "Terms and Conditions"),
                ("privacy-policy", "Privacy Policy"),
                ("imprint", "Imprint"),
            ),
        )

    def test_every_file_loads_with_a_matching_hash(self):
        contents = load_all_public_page_content()
        self.assertEqual([c.slug for c in contents], list(PUBLIC_PAGE_SLUGS))
        for content in contents:
            with self.subTest(slug=content.slug):
                self.assertEqual(
                    content.content_sha256,
                    compute_content_hash(
                        content.slug, content.title, content.seo_title, content.search_description,
                        list(content.body_lines), content.media,
                    ),
                )
                self.assertTrue(content.source.get("url", "").startswith("https://imaa-institute.org/"))
                self.assertTrue(content.migration_notes)

    def test_migration_status(self):
        for content in load_all_public_page_content():
            with self.subTest(slug=content.slug):
                self.assertEqual(content.migration_status, MIGRATED)
                self.assertTrue(content.has_required_content)
        self.assertEqual(
            {c.slug for c in load_all_public_page_content() if c.media}, {"references"}
        )

    def test_files_are_canonically_formatted(self):
        # Byte-identical copies live in the frontend; canonical formatting keeps diffs exact.
        for slug in PUBLIC_PAGE_SLUGS:
            with self.subTest(slug=slug):
                path = content_module.content_path(slug)
                raw = path.read_text(encoding="utf-8")
                self.assertEqual(raw, dump_content_file(json.loads(raw)))

    def test_bodies_are_stable_under_the_public_sanitiser(self):
        for content in load_all_public_page_content():
            with self.subTest(slug=content.slug):
                body = "\n".join(text_lines(content))
                self.assertEqual(sanitise_public_rich_text(body), body)

    def test_bodies_render_identically_when_stored_in_a_rich_text_field(self):
        # A page created from this content and served by the API produces exactly the default HTML
        # (bundled images aside: see test_public_page_media for those).
        for content in load_all_public_page_content():
            with self.subTest(slug=content.slug):
                body = "\n".join(text_lines(content))
                rendered = prepare_public_rich_text(str(RichText(body)), request=None)
                self.assertEqual(rendered, body)

    def test_bodies_use_only_editor_compatible_markup(self):
        for content in load_all_public_page_content():
            with self.subTest(slug=content.slug):
                collector = _MarkupCollector()
                collector.feed("\n".join(text_lines(content)))
                self.assertLessEqual(collector.tags, EDITOR_TAGS)
                for tag, name, value in collector.attributes:
                    self.assertEqual(tag, "a", f"attribute {name} on <{tag}>")
                    self.assertIn(name, {"href", "rel"})
                    if name == "href":
                        self.assertTrue(value.startswith(URL_PREFIXES), value)
                    else:
                        self.assertEqual(value, "noopener noreferrer")

    def test_media_lines_are_canonical_image_placeholders(self):
        from wagtail.images.formats import get_image_format

        for content in load_all_public_page_content():
            with self.subTest(slug=content.slug):
                media_lines = [parse_media_line(line) for line in content.body_lines if "media:" in line]
                self.assertEqual(len(media_lines), len(content.media))
                for media_line, item in zip(media_lines, content.media):
                    self.assertIsNotNone(media_line)
                    self.assertEqual(media_line.key, item.key)
                    self.assertEqual((media_line.width, media_line.height), (item.width, item.height))
                    self.assertTrue(media_line.alt.strip(), item.key)
                    # The rich-text image format exists in Wagtail (cms/image_formats.py).
                    self.assertEqual(get_image_format(media_line.format).classname, f"richtext-image {media_line.format}")

    def test_page_titles_are_not_repeated_as_body_headings(self):
        for content in load_all_public_page_content():
            with self.subTest(slug=content.slug):
                self.assertNotIn("<h1", content.body_html)

    def test_tampered_file_is_rejected(self):
        original = content_module.content_path("imprint").read_text(encoding="utf-8")
        data = json.loads(original)
        data["body_html"][0] = "<h2>Tampered</h2>"
        with TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "imprint.json"
            tampered.write_text(dump_content_file(data), encoding="utf-8")
            with mock.patch.object(content_module, "content_path", return_value=tampered):
                with self.assertRaisesMessage(PublicPageContentError, "content_sha256"):
                    load_public_page_content("imprint")

    def test_title_must_match_catalog(self):
        data = json.loads(content_module.content_path("imprint").read_text(encoding="utf-8"))
        data["title"] = "Impressum"
        data["content_sha256"] = compute_content_hash(
            data["slug"], data["title"], data["seo_title"], data["search_description"], data["body_html"]
        )
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "imprint.json"
            path.write_text(dump_content_file(data), encoding="utf-8")
            with mock.patch.object(content_module, "content_path", return_value=path):
                with self.assertRaisesMessage(PublicPageContentError, "'title' must be 'Imprint'"):
                    load_public_page_content("imprint")

    def test_unknown_slug_is_rejected(self):
        with self.assertRaises(PublicPageContentError):
            load_public_page_content("contact")

    def test_media_files_match_their_entries(self):
        from PIL import Image

        for content in load_all_public_page_content():
            for item in content.media:
                with self.subTest(key=item.key):
                    self.assertTrue(item.path.is_file())
                    self.assertEqual(file_sha256(item.path), item.sha256)
                    with Image.open(item.path) as image:
                        self.assertEqual(image.size, (item.width, item.height))
                        self.assertEqual(image.format, "PNG" if item.key.endswith(".png") else "JPEG")
                    self.assertLessEqual(item.width, 320)
                    self.assertLessEqual(item.height, 160)
        bundled = sorted(p.relative_to(content_module.MEDIA_DIR).as_posix() for p in content_module.MEDIA_DIR.rglob("*") if p.is_file())
        listed = sorted(item.key for content in load_all_public_page_content() for item in content.media)
        self.assertEqual(bundled, listed, "every bundled file is listed exactly once")

    def test_references_is_the_wordpress_logo_wall(self):
        references = load_public_page_content("references")
        self.assertEqual(len(references.media), 258)
        self.assertEqual({item.alt_source for item in references.media}, {"wordpress-alt", "wordpress-company-name"})
        self.assertEqual(sum(1 for item in references.media if item.alt_source == "wordpress-company-name"), 25)
        for item in references.media:
            self.assertTrue(item.company.strip(), item.key)
            self.assertTrue(item.source_url.startswith("https://imaa-institute.org/wp-content/uploads/"), item.key)
        lines = references.body_lines
        self.assertTrue(lines[0].startswith("<p>Our participants have either worked at or joined"))
        self.assertEqual(lines[1], "<h2>Companies by Alphabetical Order:</h2>")
        self.assertEqual(lines[2 + 258], "<h2>Contact Us</h2>")
        self.assertIn('href="mailto:info@imaa-institute.org"', lines[3 + 258])
        self.assertEqual(sum(1 for line in lines if line.startswith("<li>")), 6)

    def test_media_changes_are_detected(self):
        original = json.loads(content_module.content_path("references").read_text(encoding="utf-8"))
        cases = {
            "unlisted media": lambda d: d["media"].pop(0),
            "not used in the body": lambda d: d["body_html"].pop(2),
            "does not match its recorded sha256": lambda d: d["media"][0].update(sha256="0" * 64),
            "body size differs": lambda d: d["media"][0].update(width=d["media"][0]["width"] + 1),
            "not one canonical <img> line": lambda d: d["body_html"].__setitem__(2, d["body_html"][2].replace('" class', '"  class')),
        }
        for message, mutate in cases.items():
            with self.subTest(message=message):
                data = json.loads(json.dumps(original))
                mutate(data)
                data["content_sha256"] = compute_content_hash(
                    data["slug"], data["title"], data["seo_title"], data["search_description"], data["body_html"], data["media"]
                )
                with TemporaryDirectory() as tmp:
                    path = Path(tmp) / "references.json"
                    path.write_text(dump_content_file(data), encoding="utf-8")
                    with mock.patch.object(content_module, "content_path", return_value=path):
                        with self.assertRaisesMessage(PublicPageContentError, message):
                            load_public_page_content("references")

    def test_media_is_part_of_the_content_hash(self):
        references = load_public_page_content("references")
        args = (references.slug, references.title, references.seo_title, references.search_description, list(references.body_lines))
        changed = [dict(key=m.key, sha256="0" * 64 if i == 0 else m.sha256, width=m.width, height=m.height) for i, m in enumerate(references.media)]
        self.assertNotEqual(compute_content_hash(*args, references.media), compute_content_hash(*args, changed))
        # Pages without media keep the hash they had before media existed.
        imprint = load_public_page_content("imprint")
        self.assertEqual(
            compute_content_hash(imprint.slug, imprint.title, imprint.seo_title, imprint.search_description, list(imprint.body_lines)),
            imprint.content_sha256,
        )

    def test_maintenance_check_passes(self):
        from cms.public_page_content.__main__ import main

        with mock.patch("builtins.print"):
            self.assertEqual(main([]), 0)
