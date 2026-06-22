"""
WordPress Events Calendar API client.

Fetches events from The Events Calendar plugin REST API:
  GET /wp-json/tribe/v1/events/
  GET /wp-json/tribe/v1/events/{id}/

Reuses the same WP_IMAA_* credentials as the user sync client.
"""
import requests
import logging
from django.conf import settings
from typing import Dict, Optional, Any, List
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


class WordPressEventAPIClient:
    """Client for The Events Calendar REST API via standard WordPress endpoint."""

    # Uses /wp/v2/tribe_events (standard WordPress REST API for Events Calendar post type)
    # Falls back to /tribe/v1 if available (custom Events Calendar API)
    WP_V2_TRIBE_EVENTS = "/wp/v2/tribe_events"
    TRIBE_V1_EVENTS = "/tribe/v1/events"

    def __init__(self):
        # Reuse the same base URL + auth already configured for user sync
        self.base_url = settings.WP_IMAA_API_URL or ""
        self.auth_type = settings.WP_IMAA_AUTH_TYPE or "basic"
        self.api_user = settings.WP_IMAA_API_USER or ""
        self.api_password = settings.WP_IMAA_API_PASSWORD or ""

        if not self.base_url:
            raise ValueError("WP_IMAA_API_URL is not configured")

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.api_password}"
        return headers

    def _get_auth(self):
        if self.auth_type == "basic":
            return HTTPBasicAuth(self.api_user, self.api_password)
        return None

    def get_event(self, wp_event_id: int) -> Optional[Dict[str, Any]]:
        """Fetch a single event by WordPress post ID."""
        # Try standard WP REST API endpoint first (/wp/v2/tribe_events)
        url = f"{self.base_url}{self.WP_V2_TRIBE_EVENTS}/{wp_event_id}"
        try:
            resp = requests.get(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                timeout=15
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                logger.debug(f"Event not found at {url}")
                return None
            else:
                resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch WP event {wp_event_id} from {url}: {e}")
            return None

    def list_events(
        self,
        page: int = 1,
        per_page: int = 50,
        start_date: Optional[str] = None,
        status: str = "publish",
    ) -> Optional[Dict[str, Any]]:
        """
        List events with optional filters via standard WordPress REST API.

        Filters:
          - page / per_page: pagination
          - status: "publish" (default), "draft", "private"

        Returns dict with format: {"events": [...], "total": count, "total_pages": pages}
        """
        url = f"{self.base_url}{self.WP_V2_TRIBE_EVENTS}"
        params = {"page": page, "per_page": per_page, "status": status}

        try:
            resp = requests.get(
                url,
                params=params,
                headers=self._get_headers(),
                auth=self._get_auth(),
                timeout=15
            )
            resp.raise_for_status()

            events = resp.json()
            total = int(resp.headers.get("x-wp-total", len(events)))
            total_pages = int(resp.headers.get("x-wp-totalpages", 1))

            return {
                "events": events,
                "total": total,
                "total_pages": total_pages
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list WP events from {url} (page {page}): {e}")
            return None

    def list_recently_modified_events(self, after: str) -> List[Dict[str, Any]]:
        """
        Poll WP REST API for events modified after a given ISO timestamp.
        Uses /wp/v2/tribe_events endpoint with ?modified_after filter.
        """
        url = f"{self.base_url}{self.WP_V2_TRIBE_EVENTS}"
        params = {
            "modified_after": after,
            "per_page": 100,
            "orderby": "modified",
            "order": "desc",
            "status": "publish",
        }
        try:
            resp = requests.get(
                url,
                params=params,
                headers=self._get_headers(),
                auth=self._get_auth(),
                timeout=15
            )
            resp.raise_for_status()
            events = resp.json()
            logger.debug(f"Polled WP events modified after {after}: found {len(events)}")
            return events if isinstance(events, list) else []
        except requests.exceptions.RequestException as exc:
            logger.error(f"Failed to poll recently modified WP events from {url}: {exc}")
            return []


_wp_event_client = None


def get_wordpress_event_client() -> WordPressEventAPIClient:
    """Get or create the singleton WP event API client."""
    global _wp_event_client
    if _wp_event_client is None:
        _wp_event_client = WordPressEventAPIClient()
    return _wp_event_client
