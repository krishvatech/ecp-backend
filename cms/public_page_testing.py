"""Helpers shared by the public page command tests (deliberately not named test_*)."""

from dataclasses import replace
from html.parser import HTMLParser

from cms.public_page_content import load_public_page_content, parse_media_line

# Bundled media imported by the commands must never reach the developer's configured storage
# (the dev settings switch to S3 when a bucket is configured): tests keep files in memory.
IN_MEMORY_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def trimmed_references(count=3):
    """The real References content with only its first ``count`` logos (fast tests)."""
    full = load_public_page_content("references")
    keep = {item.key for item in full.media[:count]}
    lines = tuple(
        line for line in full.body_lines if (parsed := parse_media_line(line)) is None or parsed.key in keep
    )
    return replace(full, body_lines=lines, media=full.media[:count])


def content_loader(**overrides):
    """A ``load_public_page_content`` stand-in that returns ``overrides[slug]`` when given."""

    def load(slug, **kwargs):
        if slug in overrides:
            return overrides[slug]
        return load_public_page_content(slug, **kwargs)

    return load


class _ImgCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.images = []

    def handle_starttag(self, tag, attrs):
        if tag == "img":
            self.images.append(dict(attrs))


def image_attributes(html):
    collector = _ImgCollector()
    collector.feed(html)
    return collector.images


def assert_api_body_matches_content(testcase, api_body, content):
    """The public API body equals the approved content line by line; each bundled-image line is
    an <img> of the same format, alt text and size, served from the Wagtail image library."""
    api_lines = api_body.split("\n")
    testcase.assertEqual(len(api_lines), len(content.body_lines))
    for api_line, line in zip(api_lines, content.body_lines):
        media_line = parse_media_line(line)
        if media_line is None:
            testcase.assertEqual(api_line, line)
            continue
        images = image_attributes(api_line)
        testcase.assertEqual(len(images), 1, api_line)
        attrs = images[0]
        testcase.assertEqual(attrs.get("class"), f"richtext-image {media_line.format}")
        testcase.assertEqual(attrs.get("alt"), media_line.alt)
        testcase.assertEqual((int(attrs["width"]), int(attrs["height"])), (media_line.width, media_line.height))
        testcase.assertIn("/images/", attrs.get("src", ""))
