"""
Read-only client for the public IMAA WordPress REST API, used by the Blog
importer only. It never authenticates and never writes to WordPress.

Configuration (own namespace, see settings WP_IMAA_BLOG_*):
    WP_IMAA_BLOG_BASE_URL, WP_IMAA_BLOG_CATEGORY_ID, WP_IMAA_BLOG_TIMEOUT
"""
import logging
import time
from dataclasses import dataclass, field

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

API_PREFIX = "/wp-json/wp/v2"
MAX_PER_PAGE = 100
# Full posts with _embed are large (100 per page is ~11 MB and >30 s on IMAA);
# smaller pages keep each request well inside the timeout.
EMBED_PER_PAGE = 25
DEFAULT_MAX_PAGES = 50  # hard stop against pathological pagination
USER_AGENT = "ECP-Blog-Importer/1.0 (+read-only)"
RETRY_STATUSES = {502, 503, 504}
RETRY_CODES = {"timeout", "connection"}


class WordPressBlogAPIError(Exception):
    """A WordPress Blog API request failed. The message is safe to print."""

    def __init__(self, message, *, path="", status=None, code=""):
        super().__init__(message)
        self.path = path
        self.status = status
        self.code = code


class WordPressBlogConfigError(WordPressBlogAPIError):
    pass


@dataclass
class PostsPage:
    posts: list
    total: int | None
    total_pages: int | None


@dataclass
class FetchStats:
    requests: int = 0
    pages_fetched: int = 0
    api_total: int | None = None
    api_total_pages: int | None = None
    posts_fetched: int = 0
    content_pages_fetched: int = 0
    single_post_fallbacks: int = 0
    endpoints: dict = field(default_factory=dict)


def _int_header(headers, name):
    try:
        return int(headers.get(name))
    except (TypeError, ValueError):
        return None


class WordPressBlogClient:
    def __init__(self, base_url, *, timeout=20, session=None, retries=2, backoff=2.0, sleep=time.sleep):
        base_url = (base_url or "").strip().rstrip("/")
        if base_url.endswith("/wp-json"):
            base_url = base_url[: -len("/wp-json")]
        if not base_url.startswith(("https://", "http://")):
            raise WordPressBlogConfigError(
                "WP_IMAA_BLOG_BASE_URL is not configured (expected e.g. https://imaa-institute.org)."
            )
        self.base_url = base_url
        self.timeout = float(timeout)
        self.session = session or requests.Session()
        self.retries = max(0, int(retries))
        self.backoff = float(backoff)
        self._sleep = sleep
        self.stats = FetchStats()
        self._term_cache = {"categories": {}, "tags": {}}
        self._media_cache = {}
        self._user_cache = {}

    @classmethod
    def from_settings(cls, **kwargs):
        return cls(
            getattr(settings, "WP_IMAA_BLOG_BASE_URL", ""),
            timeout=getattr(settings, "WP_IMAA_BLOG_TIMEOUT", 20),
            **kwargs,
        )

    # ----------------------------------------------------------- transport --
    def _get(self, path, params=None):
        """GET with bounded retries for transient failures (timeouts, connection
        errors, HTTP 502/503/504). Returns (json, headers)."""
        for attempt in range(self.retries + 1):
            try:
                return self._get_once(path, params)
            except WordPressBlogAPIError as exc:
                transient = exc.code in RETRY_CODES or exc.status in RETRY_STATUSES
                if not transient or attempt == self.retries:
                    raise
                delay = self.backoff * (attempt + 1)
                logger.warning("%s; retrying in %.0fs (%d/%d)", exc, delay, attempt + 1, self.retries)
                self._sleep(delay)

    def _get_once(self, path, params=None):
        """GET a REST path once. Returns (json, headers). Raises WordPressBlogAPIError."""
        url = f"{self.base_url}{API_PREFIX}{path}"
        label = f"GET {API_PREFIX}{path}"
        self.stats.requests += 1
        self.stats.endpoints[path.split("?")[0]] = self.stats.endpoints.get(path.split("?")[0], 0) + 1
        try:
            response = self.session.get(
                url,
                params=params or {},
                timeout=self.timeout,
                headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            )
        except requests.Timeout as exc:
            raise WordPressBlogAPIError(
                f"WordPress Blog API request timed out after {self.timeout:g}s: {label}", path=path, code="timeout"
            ) from exc
        except requests.ConnectionError as exc:
            raise WordPressBlogAPIError(
                f"WordPress Blog API connection failed: {label} ({exc.__class__.__name__})", path=path, code="connection"
            ) from exc
        except requests.RequestException as exc:
            raise WordPressBlogAPIError(
                f"WordPress Blog API request failed: {label} ({exc.__class__.__name__})", path=path, code="request"
            ) from exc

        try:
            payload = response.json()
        except ValueError:
            payload = None

        if response.status_code >= 400:
            wp_code = payload.get("code", "") if isinstance(payload, dict) else ""
            wp_message = payload.get("message", "") if isinstance(payload, dict) else ""
            detail = f" [{wp_code}] {wp_message}".rstrip() if wp_code else ""
            raise WordPressBlogAPIError(
                f"WordPress Blog API request failed: {label} HTTP {response.status_code}{detail}",
                path=path,
                status=response.status_code,
                code=wp_code or "http_error",
            )
        if payload is None:
            raise WordPressBlogAPIError(
                f"WordPress Blog API returned invalid JSON: {label} HTTP {response.status_code}",
                path=path,
                status=response.status_code,
                code="invalid_json",
            )
        return payload, response.headers

    # ------------------------------------------------------------ category --
    def get_category(self, category_id):
        payload, _ = self._get(f"/categories/{int(category_id)}")
        if not isinstance(payload, dict) or "id" not in payload:
            raise WordPressBlogAPIError(
                f"WordPress Blog API returned a malformed category payload for id {category_id}",
                path=f"/categories/{category_id}",
                code="malformed",
            )
        return payload

    # --------------------------------------------------------------- posts --
    def list_posts(self, category_id, *, status="publish", page=1, per_page=MAX_PER_PAGE, embed=True, fields=None):
        params = {
            "categories": int(category_id),
            "status": status,
            "page": int(page),
            "per_page": min(int(per_page), MAX_PER_PAGE),
            "orderby": "id",
            "order": "asc",
        }
        if embed:
            params["_embed"] = 1
        if fields:
            params["_fields"] = ",".join(fields)
        payload, headers = self._get("/posts", params)
        if not isinstance(payload, list):
            raise WordPressBlogAPIError(
                "WordPress Blog API returned a malformed post list (expected a JSON array): GET /wp-json/wp/v2/posts",
                path="/posts",
                code="malformed",
            )
        return PostsPage(
            posts=payload,
            total=_int_header(headers, "X-WP-Total"),
            total_pages=_int_header(headers, "X-WP-TotalPages"),
        )

    def iter_posts(self, category_id, *, per_page=MAX_PER_PAGE, embed=True, max_pages=DEFAULT_MAX_PAGES, fields=None):
        """Yield every post of the category across pages, without duplicates."""
        seen_ids = set()
        page = 1
        while True:
            if page > max_pages:
                raise WordPressBlogAPIError(
                    f"WordPress Blog API pagination exceeded {max_pages} pages; aborting to avoid a loop.",
                    path="/posts",
                    code="pagination_limit",
                )
            result = self.list_posts(category_id, page=page, per_page=per_page, embed=embed, fields=fields)
            self.stats.pages_fetched += 1
            if page == 1:
                self.stats.api_total = result.total
                self.stats.api_total_pages = result.total_pages
            new = 0
            for post in result.posts:
                post_id = post.get("id") if isinstance(post, dict) else None
                if post_id in seen_ids:
                    continue
                seen_ids.add(post_id)
                new += 1
                self.stats.posts_fetched += 1
                yield post
            total_pages = result.total_pages
            if not result.posts or new == 0:
                break
            if total_pages is not None and page >= total_pages:
                break
            if total_pages is None and len(result.posts) < per_page:
                break
            page += 1

    def get_post(self, post_id, *, embed=True):
        params = {"_embed": 1} if embed else {}
        payload, _ = self._get(f"/posts/{int(post_id)}", params)
        if not isinstance(payload, dict) or "id" not in payload:
            raise WordPressBlogAPIError(
                f"WordPress Blog API returned a malformed post payload for id {post_id}",
                path=f"/posts/{post_id}",
                code="malformed",
            )
        return payload

    # ------------------------------------------------ taxonomy/media/users --
    def get_terms(self, taxonomy, ids):
        """Resolve term IDs for 'categories' or 'tags' with one batched request per 100 uncached IDs."""
        cache = self._term_cache[taxonomy]
        wanted = [int(i) for i in dict.fromkeys(ids) if i is not None]
        missing = [i for i in wanted if i not in cache]
        for start in range(0, len(missing), MAX_PER_PAGE):
            chunk = missing[start : start + MAX_PER_PAGE]
            payload, _ = self._get(
                f"/{taxonomy}",
                {"include": ",".join(str(i) for i in chunk), "per_page": MAX_PER_PAGE, "_fields": "id,name,slug"},
            )
            if not isinstance(payload, list):
                raise WordPressBlogAPIError(
                    f"WordPress Blog API returned a malformed {taxonomy} list", path=f"/{taxonomy}", code="malformed"
                )
            for term in payload:
                if isinstance(term, dict) and "id" in term:
                    cache[int(term["id"])] = term
            for term_id in chunk:
                cache.setdefault(term_id, None)  # remember misses too
        return {i: cache.get(i) for i in wanted}

    def remember_terms(self, taxonomy, terms):
        """Seed the cache from `_embedded['wp:term']` so no request is needed."""
        cache = self._term_cache[taxonomy]
        for term in terms:
            if isinstance(term, dict) and "id" in term:
                cache[int(term["id"])] = term

    def get_media(self, media_id):
        media_id = int(media_id)
        if media_id not in self._media_cache:
            try:
                payload, _ = self._get(f"/media/{media_id}", {"_fields": "id,source_url,alt_text,caption,mime_type,media_details"})
                self._media_cache[media_id] = payload if isinstance(payload, dict) else None
            except WordPressBlogAPIError as exc:
                logger.warning("WordPress Blog media %s could not be resolved: %s", media_id, exc)
                self._media_cache[media_id] = None
        return self._media_cache[media_id]

    def get_user_name(self, user_id):
        """Public author name if the users endpoint is exposed (often disabled). Cached, never raises."""
        user_id = int(user_id)
        if user_id not in self._user_cache:
            try:
                payload, _ = self._get(f"/users/{user_id}", {"_fields": "id,name"})
                self._user_cache[user_id] = (payload or {}).get("name", "") if isinstance(payload, dict) else ""
            except WordPressBlogAPIError:
                self._user_cache[user_id] = ""
        return self._user_cache[user_id]
