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

    def get_user_id_by_email(self, email: str) -> Optional[int]:
        """
        Look up a WordPress user ID on imaa-institute.org by email address.
        Uses the standard WP REST API (not EB-specific).
        Requires admin credentials to search users.

        TODO: Remove static override before production.
        """

        url = f"{self.base_url}/wp/v2/users"
        try:
            resp = requests.get(
                url,
                params={"search": email, "per_page": 5},
                headers=self._get_headers(),
                auth=self._get_auth(),
                timeout=10,
            )
            resp.raise_for_status()
            users = resp.json()
            if not isinstance(users, list) or not users:
                return None
            # Try exact email match first, fall back to first result
            for u in users:
                if u.get("email") == email or u.get("slug") == email.split("@")[0]:
                    return u.get("id")
            return users[0].get("id")
        except requests.exceptions.RequestException as e:
            logger.error("EB user lookup failed for %s: %s", email, e)
            return None

    def get_user_courses(self, wp_user_id: int) -> List[Dict]:
        """
        Fetch the enrolled courses + progress for a WordPress user.

        The /my-courses endpoint returns:
          {
            "enrolled_courses": [{..., "progress": {"percentage": N, "completed": bool, "course_url": "...?mdl_course_id=N"}}],
            ...
          }

        Uses UserProfile.wordpress_id as the identifier.
        """
        result = self._get("/my-courses", params={"user_id": wp_user_id})
        if not isinstance(result, dict):
            return []
        return result.get("enrolled_courses") or []


_eb_client: Optional[EdwiserBridgeAPIClient] = None


def get_edwiser_client() -> EdwiserBridgeAPIClient:
    """Get or create the Edwiser Bridge API client singleton."""
    global _eb_client
    if _eb_client is None:
        _eb_client = EdwiserBridgeAPIClient()
    return _eb_client
