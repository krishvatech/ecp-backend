"""Plain data structures shared by the WordPress Blog import pipeline."""
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

# Content formats
FORMAT_GUTENBERG = "gutenberg"
FORMAT_ELEMENTOR = "elementor"
FORMAT_CLASSIC = "classic"
FORMAT_MIXED = "mixed"
FORMAT_UNKNOWN = "unknown"
FORMATS = (FORMAT_GUTENBERG, FORMAT_ELEMENTOR, FORMAT_CLASSIC, FORMAT_MIXED, FORMAT_UNKNOWN)

# Structured warning codes (stable identifiers for reports and Batch 4)
W_MISSING_FEATURED_IMAGE = "missing_featured_image"
W_FEATURED_IMAGE_UNRESOLVED = "featured_image_unresolved"
W_UNMAPPED_AUTHOR = "unmapped_author"
W_AUTHOR_NAME_MISSING = "author_name_missing"
W_AUTHOR_MAPPING_NAME_MISMATCH = "author_mapping_name_mismatch"
W_AUTHOR_MAPPING_UNVERIFIED = "author_mapping_unverified"
W_AUTHOR_MAPPING_AMBIGUOUS = "author_mapping_ambiguous"
W_MIXED_CONTENT = "mixed_content"
W_UNKNOWN_CONTENT_FORMAT = "unknown_content_format"
W_JSON_LD_REMOVED = "json_ld_removed"
W_INVALID_JSON_LD = "invalid_json_ld"
W_FAQ_SCHEMA_DETECTED = "faq_schema_detected"
W_UNSUPPORTED_EMBED = "unsupported_embed"
W_INTERNAL_LINK_NEEDS_REWRITE = "internal_link_needs_rewrite"
W_SEO_TITLE_MISSING = "seo_title_missing"
W_SEO_DESCRIPTION_MISSING = "seo_description_missing"
W_SEO_DESCRIPTION_SUSPICIOUS = "seo_description_suspicious"
W_CANONICAL_MISSING = "canonical_missing"
W_SLUG_COLLISION = "slug_collision"
W_SLUG_NORMALISED = "slug_normalised"
W_CONTENT_REDUCED = "content_reduced"
W_CONTENT_EMPTY = "content_empty_after_normalization"
W_CONTENT_NO_TEXT = "content_has_no_text"
W_MEMBERS_ONLY = "members_only_teaser"
W_TAXONOMY_RESOLUTION_FAILED = "taxonomy_resolution_failed"
W_ELEMENTS_REMOVED = "unsafe_elements_removed"
W_EXTERNAL_IMAGES_NOT_MIGRATED = "inline_images_not_migrated"

# Plan actions
ACTION_CREATE = "CREATE"
ACTION_UPDATE = "UPDATE"
ACTION_SKIP = "SKIP"
ACTION_ERROR = "ERROR"


@dataclass
class ImportWarning:
    code: str
    detail: str = ""

    def as_dict(self):
        return {"code": self.code, "detail": self.detail}


@dataclass
class InlineImage:
    src: str
    alt: str = ""
    caption: str = ""
    host: str = ""
    classification: str = ""  # wordpress_media | internal_site_media | external_media | data_url | invalid
    srcset: str = ""


@dataclass
class LinkRef:
    href: str
    text: str = ""
    classification: str = ""  # blog | internal | external | anchor | mailto | tel | media | invalid
    blog_slug: str = ""


@dataclass
class EmbedRef:
    kind: str  # youtube | vimeo | other
    src: str
    replaced_with_link: bool = False


@dataclass
class NormalizedContent:
    html: str
    text_length: int = 0
    source_text_length: int = 0
    warnings: list = field(default_factory=list)
    inline_images: list = field(default_factory=list)
    internal_links: list = field(default_factory=list)  # every analysed link (all classes)
    embeds: list = field(default_factory=list)
    removed_elements: dict = field(default_factory=dict)  # tag -> count
    json_ld: list = field(default_factory=list)  # parsed JSON-LD objects (diagnostics only)


@dataclass
class TermRef:
    wp_id: int
    name: str
    slug: str


@dataclass
class FeaturedMedia:
    wp_id: int
    url: str = ""
    alt: str = ""
    caption: str = ""
    mime_type: str = ""
    width: Optional[int] = None
    height: Optional[int] = None


@dataclass
class NormalizedWordPressBlog:
    wp_post_id: int
    status: str
    title: str
    slug: str
    excerpt: str
    content: NormalizedContent
    source_format: str
    wp_author_id: Optional[int]
    wp_author_name: str
    published_at: Optional[datetime]
    modified_at: Optional[datetime]
    featured_media_id: Optional[int]
    featured_media: Optional[FeaturedMedia]
    categories: list  # [TermRef]
    tags: list  # [TermRef]
    seo_title: str
    seo_description: str
    source_canonical_url: str
    source_url: str
    warnings: list = field(default_factory=list)

    @property
    def content_html(self) -> str:
        return self.content.html

    def all_warnings(self):
        return [*self.warnings, *self.content.warnings]


@dataclass
class ImportPlan:
    wp_post_id: int
    action: str
    title: str = ""
    slug: str = ""
    source_format: str = ""
    existing_post_id: Optional[int] = None
    reasons: list = field(default_factory=list)
    field_changes: dict = field(default_factory=dict)  # field -> {"old": ..., "new": ...}
    taxonomy_changes: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)  # [ImportWarning]
    values: dict = field(default_factory=dict)  # target BlogPost field values
    author_user_id: Optional[int] = None
    categories: list = field(default_factory=list)  # [{"name","slug","existing_id"}]
    tags: list = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("values", None)
        data["warnings"] = [w.as_dict() for w in self.warnings]
        return data
