"""
Import planning: NormalizedWordPressBlog -> ImportPlan (CREATE/UPDATE/SKIP/ERROR).

Read-only against the ECP database. Dry-run and commit use the same plans.

Change detection compares WordPress source with WordPress source: the
content is compared through `wp_content_hash` (hash of the normalized
WordPress HTML) because the stored `content_html` is later rewritten with
ECP media URLs and ECP Blog links.

Ownership policy (Batch 3): imported records are source-controlled by
WordPress until the migration is finalised. A re-import updates the
WordPress-owned fields in `WORDPRESS_OWNED_FIELDS` plus categories/tags.
ECP-owned fields are never touched on update: canonical_url, featured_image,
created_by/updated_by.

Status (Batch 4.1): only a public published WordPress post maps to ECP
Published; draft/pending/future/private and members-only posts map to Draft
(`target_ecp_status`). WordPress drives the ECP status while
`wp_status_managed` is True (set on every new import). A manual
Publish/Unpublish in ECP clears it, and from then on the ECP status is never
changed by an import. Rows imported before status tracking (empty
`wp_status`) adopt management only when their status already matches.

Matching is by `wp_post_id` only. Manual ECP posts (wp_post_id NULL) are never
matched, even with the same title or slug; a slug clash gets a deterministic
`-wp<ID>` suffix instead of touching the manual post.
"""
import hashlib
import re
from urllib.parse import unquote

from django.utils.text import slugify

from blogs.models import RESERVED_SLUGS, BlogCategory, BlogPost, BlogTag
from users.models import UserProfile

from .normalizer import collapse
from .types import (
    ACTION_CREATE,
    ACTION_ERROR,
    ACTION_RESTRICTED,
    ACTION_SKIP,
    ACTION_UPDATE,
    SUPPORTED_WP_STATUSES,
    W_AUTHOR_MAPPING_AMBIGUOUS,
    W_AUTHOR_MAPPING_NAME_MISMATCH,
    W_AUTHOR_MAPPING_UNVERIFIED,
    W_CONTENT_EMPTY,
    W_MEMBERS_ONLY,
    W_SLUG_COLLISION,
    W_SLUG_NORMALISED,
    W_UNMAPPED_AUTHOR,
    ImportPlan,
    ImportWarning,
)

WORDPRESS_OWNED_FIELDS = (
    "wp_post_id", "title", "slug", "excerpt", "content_html", "author_id", "legacy_author_name", "published_at",
    "seo_title", "seo_description", "wp_source_url", "wp_author_id", "wp_modified_at", "imported_from_wordpress",
    "wp_content_hash", "wp_status", "wp_membership_restricted",
)
TRASHED_SUFFIX = "__trashed"  # WordPress appends this to the slug of trashed (and restored) posts
_ECP_SLUG = re.compile(r"^[-a-zA-Z0-9_]+$")


def _name_key(value):
    return re.sub(r"[^\w]+", " ", collapse(value).casefold()).strip()


class PlanningContext:
    """Per-run, read-only lookups with caching."""

    def __init__(self):
        self._users = {}

    def ecp_author(self, wp_author_id, wp_author_name):
        """Return (user_or_None, [warnings]) for a WordPress author ID."""
        if not wp_author_id:
            return None, [ImportWarning(W_UNMAPPED_AUTHOR, "no WordPress author id")]
        if wp_author_id not in self._users:
            profiles = list(UserProfile.objects.filter(wordpress_id=wp_author_id).select_related("user")[:2])
            self._users[wp_author_id] = profiles
        profiles = self._users[wp_author_id]
        if not profiles:
            return None, [ImportWarning(W_UNMAPPED_AUTHOR, f"WordPress author {wp_author_id}")]
        if len(profiles) > 1:
            return None, [ImportWarning(W_AUTHOR_MAPPING_AMBIGUOUS, f"WordPress author {wp_author_id}")]
        profile = profiles[0]
        user = profile.user
        # UserProfile.wordpress_id is written by more than one WordPress sync
        # (MANDA staging and imaa-institute.org), so an ID match alone could be
        # a different person. Require the byline to agree when it is known.
        if wp_author_name:
            candidates = {
                _name_key(f"{user.first_name} {user.last_name}"),
                _name_key(profile.full_name),
            } - {""}
            if _name_key(wp_author_name) not in candidates:
                return None, [ImportWarning(
                    W_AUTHOR_MAPPING_NAME_MISMATCH,
                    f"WordPress author {wp_author_id} maps to ECP user {user.pk} but names differ",
                )]
            return user, []
        return user, [ImportWarning(W_AUTHOR_MAPPING_UNVERIFIED, f"WordPress author {wp_author_id} -> ECP user {user.pk}")]

    @staticmethod
    def existing_term(model, term):
        slug_match = model.objects.filter(slug__iexact=term.slug).first() if term.slug else None
        return slug_match or model.objects.filter(name__iexact=term.name).first()


def target_ecp_status(wp_status, membership_restricted):
    """ECP status implied by the WordPress source. Only a published post that
    anyone can read on WordPress is Published; everything else is a Draft
    (members-only content stays hidden until ECP has member visibility)."""
    if wp_status == "publish" and not membership_restricted:
        return BlogPost.STATUS_PUBLISHED
    return BlogPost.STATUS_DRAFT


def source_slug(post):
    """WordPress slug; drafts may have none (or a leftover `__trashed` one), in
    which case WordPress' generated slug is used."""
    raw = post.slug or ""
    if raw.endswith(TRASHED_SUFFIX):
        raw = raw[: -len(TRASHED_SUFFIX)]
    return raw or post.generated_slug or ""


def _ecp_slug(post):
    """WordPress slug if ECP-routable, else a deterministic normalised form."""
    raw = source_slug(post)
    if raw and _ECP_SLUG.match(raw) and len(raw) <= 240:
        return raw, None
    fixed = slugify(unquote(raw)) or slugify(post.title) or f"post-{post.wp_post_id}"
    return fixed[:240].strip("-"), ImportWarning(W_SLUG_NORMALISED, f"{raw!r} -> {fixed!r}")


def _slug_taken(slug, exclude_pk):
    if slug.lower() in RESERVED_SLUGS:
        return "reserved"
    clash = BlogPost.objects.filter(slug__iexact=slug)
    if exclude_pk:
        clash = clash.exclude(pk=exclude_pk)
    clash = clash.values("pk", "wp_post_id").first()
    if not clash:
        return None
    return f"post {clash['pk']} ({'imported' if clash['wp_post_id'] else 'manual'})"


def _plan_terms(model, terms, context):
    planned, seen = [], set()
    for term in terms:
        key = (term.slug or term.name).casefold()
        if key in seen or term.name.casefold() in seen:
            continue
        seen.update({key, term.name.casefold()})
        existing = context.existing_term(model, term)
        if existing:
            planned.append({"name": existing.name, "slug": existing.slug, "existing_id": existing.pk})
        else:
            slug = term.slug if _ECP_SLUG.match(term.slug or "") else slugify(term.name)
            planned.append({"name": term.name, "slug": slug, "existing_id": None})
    return planned


def plan_import(post, context=None):
    context = context or PlanningContext()
    plan = ImportPlan(
        wp_post_id=post.wp_post_id,
        action=ACTION_ERROR,
        title=post.title,
        source_format=post.source_format,
        warnings=list(post.all_warnings()),
    )

    if post.status not in SUPPORTED_WP_STATUSES:
        plan.reasons.append(f"WordPress status '{post.status}' is not imported")
        return plan
    if not post.title:
        plan.reasons.append("title is empty after normalization")
        return plan
    if any(w.code == W_MEMBERS_ONLY for w in plan.warnings):
        # Only the members-only teaser is available (public source): never
        # import the teaser and never overwrite an existing import with it.
        plan.action = ACTION_RESTRICTED
        plan.reasons.append("members-only post: only a teaser is available; not imported")
        return plan
    target_status = target_ecp_status(post.status, post.membership_restricted)
    publishable = target_status == BlogPost.STATUS_PUBLISHED
    if any(w.code == W_CONTENT_EMPTY for w in plan.warnings) or not post.content_html.strip():
        if publishable:
            plan.reasons.append("content is empty after normalization; needs manual review")
            return plan
        plan.reasons.append("content is empty; imported as a Draft for review")
    if post.published_at is None and publishable:
        plan.reasons.append("no usable WordPress publication date")
        return plan

    existing_qs = BlogPost.objects.filter(wp_post_id=post.wp_post_id)
    existing = existing_qs.prefetch_related("categories", "tags").first()
    plan.existing_post_id = existing.pk if existing else None

    slug, slug_warning = _ecp_slug(post)
    if slug_warning:
        plan.warnings.append(slug_warning)
    clash = _slug_taken(slug, plan.existing_post_id)
    if clash:
        suffixed = f"{slug[:240]}-wp{post.wp_post_id}"
        plan.warnings.append(ImportWarning(W_SLUG_COLLISION, f"'{slug}' used by {clash}; using '{suffixed}'"))
        if _slug_taken(suffixed, plan.existing_post_id):
            plan.reasons.append(f"slug '{slug}' and fallback '{suffixed}' are both taken")
            return plan
        slug = suffixed
    plan.slug = slug

    user, author_warnings = context.ecp_author(post.wp_author_id, post.wp_author_name)
    plan.warnings.extend(author_warnings)
    plan.author_user_id = user.pk if user else None

    plan.categories = _plan_terms(BlogCategory, post.categories, context)
    plan.tags = _plan_terms(BlogTag, post.tags, context)
    plan.taxonomy_changes = {
        kind: {
            "reuse": [t["slug"] for t in terms if t["existing_id"]],
            "create": [t["slug"] for t in terms if not t["existing_id"]],
        }
        for kind, terms in (("categories", plan.categories), ("tags", plan.tags))
    }

    plan.values = {
        "wp_post_id": post.wp_post_id,
        "title": post.title[:255],
        "slug": slug,
        "excerpt": post.excerpt,
        "content_html": post.content_html,
        "author_id": plan.author_user_id,
        "legacy_author_name": post.wp_author_name[:255],
        # A draft without a WordPress date keeps any date ECP already has.
        "published_at": post.published_at or (existing.published_at if existing else None),
        "seo_title": post.seo_title[:255],
        "seo_description": post.seo_description,
        "wp_source_url": post.source_url[:500],
        "wp_author_id": post.wp_author_id,
        "wp_modified_at": post.modified_at,
        "imported_from_wordpress": True,
        "wp_content_hash": content_hash(post.content_html),
        "wp_status": post.status,
        "wp_membership_restricted": post.membership_restricted,
    }

    if existing is None:
        plan.action = ACTION_CREATE
        plan.ecp_status, plan.status_managed = target_status, True
        plan.reasons.append("wp_post_id not in ECP")
        plan.field_changes = {f: {"old": None, "new": _short(v)} for f, v in plan.values.items()}
        plan.field_changes["status"] = {"old": None, "new": target_status}
        return plan

    plan.ecp_status, plan.status_managed = _status_decision(existing, target_status)
    if plan.ecp_status != existing.status:
        plan.field_changes["status"] = {"old": existing.status, "new": plan.ecp_status}
        plan.reasons.append(f"WordPress status '{post.status}' -> ECP {plan.ecp_status}")
    if plan.status_managed != existing.wp_status_managed:
        plan.field_changes["wp_status_managed"] = {"old": existing.wp_status_managed, "new": plan.status_managed}

    for field, new in plan.values.items():
        if field == "content_html" and existing.wp_content_hash:
            continue  # compared through wp_content_hash (stored HTML has ECP URLs)
        old = getattr(existing, field)
        if old != new:
            plan.field_changes[field] = {"old": _short(old), "new": _short(new)}
    taxonomy_changed = False
    for kind, terms in (("categories", plan.categories), ("tags", plan.tags)):
        current = {obj.pk for obj in getattr(existing, kind).all()}
        planned = {t["existing_id"] for t in terms}
        if None in planned or planned != current:
            taxonomy_changed = True
    if plan.field_changes or taxonomy_changed:
        plan.action = ACTION_UPDATE
        plan.reasons.append("WordPress source differs from the imported record")
    else:
        plan.action = ACTION_SKIP
        plan.reasons.append("imported record already matches WordPress")
    return plan


def _status_decision(existing, target_status):
    """(ECP status, wp_status_managed) for an existing imported post."""
    if existing.wp_status_managed:
        return target_status, True
    if not existing.wp_status:
        # Imported before WordPress status tracking: adopt management only if
        # nothing diverged (otherwise an ECP admin changed the status).
        return existing.status, existing.status == target_status
    return existing.status, False  # ECP admin owns the status


def content_hash(html):
    """Stable hash of normalized WordPress content (never of ECP-rewritten HTML)."""
    return hashlib.sha256((html or "").encode("utf-8")).hexdigest()


def _short(value):
    if isinstance(value, str) and len(value) > 80:
        return f"{value[:77]}…"
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value

