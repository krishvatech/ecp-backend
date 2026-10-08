"""Public CMS pages resolved by their complete relative path.

The existing ``GET /api/cms/pages/<slug>/`` endpoint picks the first live page with a
matching slug anywhere in the Wagtail tree. That is fine for the single Home and About
pages, but it cannot tell two pages with the same final slug apart and it ignores the
Wagtail Site the page belongs to. This module adds a deliberate resolver:

* the Wagtail Site is chosen explicitly (``CMS_PUBLIC_SITE_HOSTNAME``, otherwise the
  only site, otherwise the single default site). Anything ambiguous is a configuration
  error, never a silent guess, and the request's Host header is never consulted;
* the path is validated and walked slug by slug from the site's root page, so duplicate
  final slugs resolve to the right page;
* only published, public (no view restrictions on the page or its ancestors),
  non-archived pages of the supported ECP CMS types are returned, and an archived
  ancestor hides its whole subtree;
* rich-text HTML is passed through an allowlist sanitiser and relative media/document
  URLs are made absolute, so the public website can render it directly;
* for the five default-eligible public pages (``cms.public_page_content.PUBLIC_PAGE_SLUGS``)
  a 404 says whether nothing exists at the path (``page_absent``) or a record exists but is
  not available (``page_unavailable``), so the frontend can show its approved default
  content only for genuinely absent pages. Absence is decided from every page record
  (drafts, archived, restricted included), never from live pages alone.

No models or migrations are involved.
"""

import re
from dataclasses import dataclass

import nh3
from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from wagtail.contrib.redirects.models import Redirect
from wagtail.models import Page, Site

from cms.models import AboutPage, EventsLandingPage, HomePage, StandardPage
from cms.public_page_content import PUBLIC_PAGE_SLUGS

# Page types the public website knows how to render. Plain ``wagtailcore.Page`` rows
# (for example Wagtail's default "Welcome" page) are deliberately not exposed.
SUPPORTED_PAGE_TYPES = (StandardPage, HomePage, AboutPage, EventsLandingPage)

MAX_PATH_LENGTH = 512
# Wagtail's default slug alphabet (``allow_unicode`` is off for these page types).
SLUG_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# Rich text as the public website renders it. Wagtail's editor only emits a subset of
# this; the allowlist is the security boundary, so anything an editor pastes that is not
# listed (scripts, inline styles, event handlers, iframes, forms) is dropped.
PUBLIC_RICH_TEXT_TAGS = {
    "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
    "strong", "b", "em", "i", "u", "s", "sub", "sup", "small", "mark", "abbr", "code", "pre",
    "blockquote", "ul", "ol", "li", "dl", "dt", "dd",
    "a", "img", "figure", "figcaption",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption",
    "div", "span",
}
PUBLIC_RICH_TEXT_ATTRIBUTES = {
    "*": {"class", "id"},
    # `rel` is deliberately absent: nh3 manages it through `link_rel` below and refuses to
    # allow it as a plain attribute at the same time.
    "a": {"href", "title", "target"},
    "img": {"src", "alt", "title", "width", "height"},
    "th": {"colspan", "rowspan", "scope"},
    "td": {"colspan", "rowspan"},
    "ol": {"start", "reversed"},
    "abbr": {"title"},
    "blockquote": {"cite"},
}
PUBLIC_RICH_TEXT_URL_SCHEMES = {"http", "https", "mailto", "tel"}

# Backend-served media referenced from rich text. Page links (``/about/``) are left
# relative: they are frontend routes, not backend resources.
BACKEND_RELATIVE_URL_RE = re.compile(
    r"""(?P<attr>\b(?:src|href))=(?P<quote>["'])(?P<url>/(?:media|cms/documents|documents)/[^"']*)(?P=quote)"""
)


class PublicSiteConfigurationError(Exception):
    """The Wagtail Site for the public website cannot be chosen unambiguously."""


class PublicPathError(ValueError):
    """The requested path is not a valid relative page path."""


def normalise_public_path(raw):
    """Validate a relative page path and return its slug components.

    Accepts ``/privacy-policy/`` and ``/privacy-policy`` (one or more segments). Rejects
    anything that is not a plain slug path: missing leading slash, empty segments,
    ``.``/``..``, query strings, fragments, backslashes or over-long input.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise PublicPathError("A relative page path is required, e.g. /privacy-policy/.")
    if len(raw) > MAX_PATH_LENGTH:
        raise PublicPathError("The page path is too long.")
    path = raw.strip()
    if not path.startswith("/"):
        raise PublicPathError("The page path must start with '/'.")
    if any(ch in path for ch in ("?", "#", "\\")) or "//" in path:
        raise PublicPathError("The page path may only contain slug segments separated by single slashes.")
    components = [segment for segment in path.split("/") if segment]
    if not components:
        raise PublicPathError("The page path must identify a page below the site root.")
    for segment in components:
        if segment in (".", "..") or not SLUG_RE.match(segment):
            raise PublicPathError("The page path contains an invalid segment.")
    return components


def resolve_public_site():
    """Return the Wagtail Site the public website is served from.

    Order: the site whose hostname equals ``CMS_PUBLIC_SITE_HOSTNAME`` (must match exactly
    one site); otherwise the only configured site; otherwise the single default site.
    Every other configuration raises :class:`PublicSiteConfigurationError`.
    """
    hostname = (getattr(settings, "CMS_PUBLIC_SITE_HOSTNAME", "") or "").strip()
    sites = list(Site.objects.select_related("root_page").order_by("id"))

    if hostname:
        matches = [site for site in sites if site.hostname.lower() == hostname.lower()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise PublicSiteConfigurationError(
                f"CMS_PUBLIC_SITE_HOSTNAME is '{hostname}' but no Wagtail Site has that hostname."
            )
        raise PublicSiteConfigurationError(
            f"CMS_PUBLIC_SITE_HOSTNAME '{hostname}' matches {len(matches)} Wagtail Sites "
            "(same hostname, different ports); keep one site per hostname for the public website."
        )

    if not sites:
        raise PublicSiteConfigurationError("No Wagtail Site is configured.")
    if len(sites) == 1:
        return sites[0]
    defaults = [site for site in sites if site.is_default_site]
    if len(defaults) == 1:
        return defaults[0]
    raise PublicSiteConfigurationError(
        f"{len(sites)} Wagtail Sites exist and none (or more than one) is the default site; "
        "set CMS_PUBLIC_SITE_HOSTNAME to the public website's site hostname."
    )


def is_archived(page):
    """True for ECP CMS pages that were soft-deleted from the Wagtail admin."""
    return bool(getattr(page, "cms_is_deleted", False))


# Outcome of inspecting a path within the public Site.
PATH_FOUND = "found"  # a published, public, supported page: serve it
PATH_ABSENT = "absent"  # no page record at all at this path, and nothing above it blocks it
PATH_UNAVAILABLE = "unavailable"  # a record exists but must not be served (or something blocks the path)

# 404 ``code`` values, returned only for the default-eligible public pages.
NOT_FOUND_CODE_ABSENT = "page_absent"
NOT_FOUND_CODE_UNAVAILABLE = "page_unavailable"


@dataclass(frozen=True)
class PublicPathInspection:
    """Result of :func:`inspect_public_path`.

    ``reason`` and ``blocking_page`` are for operators (the setup command) only; the public
    API never sends them, so no title, ID or restriction detail of a non-public page leaks.
    """

    state: str
    page: object = None
    blocking_page: object = None
    reason: str = ""


def path_has_redirect(components, site):
    """True when a Wagtail redirect is configured for this path (for this Site or all Sites).

    Wagtail creates such redirects automatically when a published page is renamed or moved,
    so the redirect is a retained record that a page used to live here.
    """
    old_path = Redirect.normalise_path("/" + "/".join(components) + "/")
    return Redirect.get_for_site(site).filter(old_path=old_path).exists()


def inspect_public_path(components, site):
    """Walk ``components`` from the site's root page across EVERY page record.

    * ``PATH_FOUND``: the final page is live, not expired, not archived, of a supported type
      and free of view restrictions on itself and its ancestors. Ancestors follow Wagtail's
      own routing (an unpublished parent still routes to a published child) with one
      addition: an archived ancestor hides everything below it.
    * ``PATH_ABSENT``: no page record exists at the path (in any state, archived included),
      no Wagtail redirect claims the path, no existing ancestor (the Site root included) is
      archived or carries a view restriction, and the Site root is an ECP HomePage. These are
      exactly the paths where ``manage.py setup_public_pages`` would create a page.
    * ``PATH_UNAVAILABLE``: everything else (draft, unpublished, expired, archived,
      restricted, unsupported type, blocked ancestor, redirect, misconfigured Site root).
    """
    root = site.root_page.specific
    if is_archived(root):
        return PublicPathInspection(PATH_UNAVAILABLE, blocking_page=root, reason="site_root_archived")

    current = root
    for slug in components:
        # Every child record regardless of publication, privacy or archive state. child_of() is
        # path-based; treebeard's get_children() trusts the in-memory numchild and can miss
        # children when it is stale or out of sync, which would make a page look absent.
        child = Page.objects.child_of(current).filter(slug=slug).first()
        if child is None:
            # A Site whose root is not the ECP HomePage is misconfigured (the public pages live
            # under the HomePage), so a missing child here proves nothing about the real pages.
            if not isinstance(root, HomePage):
                return PublicPathInspection(PATH_UNAVAILABLE, blocking_page=root, reason="site_root_not_homepage")
            if current.get_view_restrictions().exists():
                return PublicPathInspection(PATH_UNAVAILABLE, blocking_page=current, reason="ancestor_view_restricted")
            if path_has_redirect(components, site):
                return PublicPathInspection(PATH_UNAVAILABLE, reason="redirect")
            return PublicPathInspection(PATH_ABSENT)
        child = child.specific
        if is_archived(child):
            return PublicPathInspection(PATH_UNAVAILABLE, blocking_page=child, reason="archived")
        current = child

    page = current
    if not page.live:
        return PublicPathInspection(PATH_UNAVAILABLE, blocking_page=page, reason="not_live")
    if page.expire_at and page.expire_at <= timezone.now():
        return PublicPathInspection(PATH_UNAVAILABLE, blocking_page=page, reason="expired")
    if not isinstance(page, SUPPORTED_PAGE_TYPES):
        return PublicPathInspection(PATH_UNAVAILABLE, blocking_page=page, reason="unsupported_type")
    if page.get_view_restrictions().exists():
        return PublicPathInspection(PATH_UNAVAILABLE, blocking_page=page, reason="view_restricted")
    return PublicPathInspection(PATH_FOUND, page=page)


def resolve_public_page(components, site):
    """The published public page at ``components`` within ``site``, or ``None``."""
    inspection = inspect_public_path(components, site)
    return inspection.page if inspection.state == PATH_FOUND else None


def is_default_eligible_path(components):
    """Paths for which the frontend may render approved default content (and the 404 says why)."""
    return len(components) == 1 and components[0] in PUBLIC_PAGE_SLUGS


def absolutise_backend_urls(html, request):
    """Turn backend-relative media/document URLs into absolute URLs for the public site."""
    if not html or request is None:
        return html or ""

    def _replace(match):
        absolute = request.build_absolute_uri(match.group("url"))
        return f'{match.group("attr")}={match.group("quote")}{absolute}{match.group("quote")}'

    return BACKEND_RELATIVE_URL_RE.sub(_replace, html)


def sanitise_public_rich_text(html):
    """Allowlist-sanitise rich-text HTML for public rendering (nh3 is the security boundary)."""
    if not html:
        return ""
    return nh3.clean(
        html,
        tags=PUBLIC_RICH_TEXT_TAGS,
        attributes=PUBLIC_RICH_TEXT_ATTRIBUTES,
        url_schemes=PUBLIC_RICH_TEXT_URL_SCHEMES,
        link_rel="noopener noreferrer",
    )


def prepare_public_rich_text(html, request):
    return sanitise_public_rich_text(absolutise_backend_urls(html, request))


def build_public_page_data(request, page, components):
    """Public response: the slug endpoint's fields plus path and SEO fields, HTML sanitised."""
    # Imported here to keep cms.api (which also imports Wagtail at module load) free of a cycle.
    from cms.api import build_cms_page_data

    data = build_cms_page_data(request, page, page)
    for key in ("body_html", "intro_html", "mission_html"):
        if key in data:
            data[key] = prepare_public_rich_text(data[key], request)

    data.update(
        {
            "path": "/" + "/".join(components) + "/",
            "seo_title": page.seo_title or "",
            "search_description": page.search_description or "",
            "first_published_at": page.first_published_at,
            "last_published_at": page.last_published_at,
        }
    )
    return data


class CmsPublicPageByPathView(APIView):
    """``GET /api/cms/public/pages/by-path/?path=/privacy-policy/``

    Public, read-only. 400 for an invalid path, 404 for a missing or unavailable page,
    503 when the public Wagtail Site cannot be chosen unambiguously.

    For the default-eligible paths (``/<slug>/`` for ``PUBLIC_PAGE_SLUGS``) the 404 body adds
    ``code``: ``page_absent`` when nothing exists at the path, otherwise ``page_unavailable``.
    Other paths keep the plain ``{"detail": "Not found"}`` body.
    """

    authentication_classes = []
    permission_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "cms_public"

    def get(self, request):
        try:
            components = normalise_public_path(request.query_params.get("path"))
        except PublicPathError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        try:
            site = resolve_public_site()
        except PublicSiteConfigurationError as exc:
            return Response(
                {"detail": f"Public CMS site is not configured unambiguously: {exc}"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        inspection = inspect_public_path(components, site)
        if inspection.state == PATH_FOUND:
            return Response(build_public_page_data(request, inspection.page, components), status=status.HTTP_200_OK)

        body = {"detail": "Not found"}
        if is_default_eligible_path(components):
            body["code"] = NOT_FOUND_CODE_ABSENT if inspection.state == PATH_ABSENT else NOT_FOUND_CODE_UNAVAILABLE
        return Response(body, status=status.HTTP_404_NOT_FOUND)
