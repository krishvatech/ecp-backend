"""
Edwiser Bridge REST API client for IMAA LMS integration.

Replaces direct Moodle REST calls for course catalogue and enrollment syncing.
Edwiser Bridge (WordPress plugin) syncs courses from Moodle into WordPress;
WordPress/EB is the authoritative source for the IMAA platform.

Endpoints used:
  GET /wp-json/eb/api/v1/courses                        — all courses (paginated)
  GET /wp-json/eb/api/v1/courses/{id}                   — single course
  GET /wp-json/eb/api/v1/my-courses?user_id={wp_id}     — user enrollments + progress

Authentication: EB_WP_API_USER / EB_WP_API_PASSWORD (WordPress Application Password)
"""
import logging
import requests
from django.conf import settings
from requests.auth import HTTPBasicAuth
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

EB_API_BASE = "/eb/api/v1"


class EdwiserBridgeAPIClient:
    """Client for the Edwiser Bridge WordPress REST API (imaa-institute.org)."""

    def __init__(self):
        self.base_url = (settings.EB_WP_API_URL or "").rstrip("/")
        self.auth_type = settings.EB_WP_AUTH_TYPE or "basic"
        self.api_user = settings.EB_WP_API_USER or ""
        self.api_password = settings.EB_WP_API_PASSWORD or ""

        if not self.base_url:
            raise ValueError("EB_WP_API_URL is not configured")

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.api_password}"
        return headers

    def _get_auth(self):
        if self.auth_type == "basic":
            return HTTPBasicAuth(self.api_user, self.api_password)
        return None

    def _get(self, path: str, params: Optional[Dict] = None) -> Any:
        """Execute a GET request against the WP REST API."""
        url = f"{self.base_url}{EB_API_BASE}{path}"
        try:
            resp = requests.get(
                url,
                params=params or {},
                headers=self._get_headers(),
                auth=self._get_auth(),
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            logger.error("Edwiser Bridge HTTP error %s: %s", path, e)
            return None
        except requests.exceptions.RequestException as e:
            logger.error("Edwiser Bridge request failed %s: %s", path, e)
            return None

    def get_all_courses(self) -> Dict:
        """
        Fetch all courses from Edwiser Bridge, handling pagination.

        The /courses endpoint returns:
          {
            "total_courses": N, "total_pages": N, "current_page": N, "per_page": N,
            "courses": [...],
            "categories": [...]   <- top-level, only present on page 1
          }

        Returns {"courses": [...all pages...], "categories": [...from page 1...]}
        """
        all_courses = []
        categories = []
        page = 1

        while True:
            result = self._get("/courses", params={"page": page, "per_page": 50})
            if not isinstance(result, dict):
                logger.error("Unexpected response from /courses page %d", page)
                break

            page_courses = result.get("courses") or []
            all_courses.extend(page_courses)

            if page == 1:
                categories = result.get("categories") or []

            total_pages = result.get("total_pages", 1)
            logger.debug("EB courses: page %d/%d, got %d courses", page, total_pages, len(page_courses))

            if page >= total_pages or not page_courses:
                break
            page += 1

        return {"courses": all_courses, "categories": categories}

    def get_course(self, eb_course_id: int) -> Optional[Dict]:
        """Fetch a single course by its WordPress/EB post ID."""
        result = self._get(f"/courses/{eb_course_id}")
        return result if isinstance(result, dict) else None

    def get_course_raw(self, eb_course_id: int) -> Optional[Dict]:
        """
        Fetch a single course with all available fields for discovery/debugging.
        Also probes undocumented EB endpoints for content, sections, modules.
        Returns a dict with 'course' and 'probed_endpoints' keys.
        """
        course = self._get(f"/courses/{eb_course_id}")
        probed = {}

        # Probe potential undocumented EB content endpoints
        for path in [
            f"/courses/{eb_course_id}/content",
            f"/courses/{eb_course_id}/sections",
            f"/courses/{eb_course_id}/modules",
            f"/courses/{eb_course_id}/curriculum",
        ]:
            result = self._get(path)
            probed[path] = result

        return {"course": course, "probed_endpoints": probed}

    def get_sso_login_url(self, wp_user_id: int, redirect_url: str) -> Optional[str]:
        """
        Attempt to generate a one-time auto-login URL for a WordPress user.
        Uses the WP REST API to create a magic login link so the user is
        auto-authenticated inside the iframe without needing to log in again.

        Returns the auto-login URL string, or None if not supported by the site.
        """
        url = f"{self.base_url}/wp/v2/users/{wp_user_id}/auto-login"
        try:
            resp = requests.post(
                url,
                json={"redirect_to": redirect_url},
                headers=self._get_headers(),
                auth=self._get_auth(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("login_url") or data.get("url") or data.get("autologin_url")
            logger.debug("SSO endpoint not available (status %d): %s", resp.status_code, url)
            return None
        except requests.exceptions.RequestException as e:
            logger.debug("SSO login URL generation failed: %s", e)
            return None

    def get_user_id_by_email(self, email: str) -> Optional[int]:
        """
        Look up a WordPress user ID on imaa-institute.org by email address.
        Uses the standard WP REST API (not EB-specific).
        Requires admin credentials to search users.

        Strategy:
          1. Search by email string (works on some WP configs)
          2. Fall back to search by name (first part of email prefix, no digits)
        """
        url = f"{self.base_url}/wp/v2/users"

        # Build search terms: full email prefix and a letters-only version
        prefix = email.split("@")[0].lower()
        import re
        name_only = re.sub(r"[^a-z]", "", prefix)  # e.g. "lakshya19ahlawat" → "lakshyaahlawat"

        search_terms = list(dict.fromkeys([email, prefix, name_only]))  # deduplicated, ordered

        for term in search_terms:
            try:
                resp = requests.get(
                    url,
                    params={"search": term, "per_page": 10},
                    headers=self._get_headers(),
                    auth=self._get_auth(),
                    timeout=10,
                )
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                users = resp.json()
                if not isinstance(users, list) or not users:
                    continue
                # Prefer exact email match
                for u in users:
                    if u.get("email") == email:
                        return u.get("id")
                # Fall back to slug match
                for u in users:
                    if u.get("slug") in (prefix, name_only):
                        return u.get("id")
            except requests.exceptions.RequestException as e:
                logger.error("EB user lookup failed for %s (term=%s): %s", email, term, e)
                continue

        logger.warning("EB user not found on WordPress for email: %s", email)
        return None

    def get_user_courses(self, wp_user_id: int = None, email: str = None) -> List[Dict]:
        """
        Fetch the enrolled courses + progress for a WordPress user.

        Accepts either wp_user_id or email — the EB /my-courses endpoint supports both.
        Email is preferred when wp_user_id is unknown.

        The /my-courses endpoint returns:
          {
            "enrolled_courses": [{..., "progress": {"percentage": N, "completed": bool, "course_url": "...?mdl_course_id=N"}}],
            ...
          }
        """
        if email:
            params = {"email": email}
        elif wp_user_id:
            params = {"user_id": wp_user_id}
        else:
            return []
        result = self._get("/my-courses", params=params)
        if not isinstance(result, dict):
            return []
        return result.get("enrolled_courses") or []

    def get_wp_user_id_by_email(self, email: str) -> Optional[int]:
        """
        Get the WordPress user ID for a given email using the EB dashboard endpoint.
        The /user-account/dashboard endpoint returns the authenticated user's WP ID,
        but when called with admin credentials it reflects the admin user.
        Instead, use get_user_courses(email=email) which works without needing the WP ID.
        This method is kept for cases where the WP ID is explicitly needed.
        """
        return self.get_user_id_by_email(email)


_eb_client: Optional[EdwiserBridgeAPIClient] = None


def get_edwiser_client() -> EdwiserBridgeAPIClient:
    """Get or create the Edwiser Bridge API client singleton."""
    global _eb_client
    if _eb_client is None:
        _eb_client = EdwiserBridgeAPIClient()
    return _eb_client
