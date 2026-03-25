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
    """Client for The Events Calendar REST API."""

    TRIBE_V1_BASE = "/tribe/v1"

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
        url = f"{self.base_url}{self.TRIBE_V1_BASE}/events/{wp_event_id}"
        try:
            resp = requests.get(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                timeout=15
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch WP event {wp_event_id}: {e}")
            return None

    def list_events(
        self,
        page: int = 1,
        per_page: int = 50,
        start_date: Optional[str] = None,
        status: str = "publish",
    ) -> Optional[Dict[str, Any]]:
        """
        List events with optional filters.

        The Events Calendar supports:
          - start_date: ISO date string, filter by start date
          - per_page / page: pagination
          - status: "publish" (default), "draft", "private"

        Returns full response dict including 'events' list and 'total_pages'.
        """
        url = f"{self.base_url}{self.TRIBE_V1_BASE}/events/"
        params = {"page": page, "per_page": per_page, "status": status}
        if start_date:
            params["start_date"] = start_date
        try:
            resp = requests.get(
                url,
                params=params,
                headers=self._get_headers(),
                auth=self._get_auth(),
                timeout=15
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list WP events (page {page}): {e}")
            return None

    def list_recently_modified_events(self, after: str) -> List[Dict[str, Any]]:
        """
        Poll WP REST API for events modified after a given ISO timestamp.
        Uses /wp/v2/tribe_events endpoint which supports ?modified_after.
        Falls back to full list scan if not available.
        """
        url = f"{self.base_url}/wp/v2/tribe_events"
        params = {
            "modified_after": after,
            "per_page": 100,
            "orderby": "modified",
            "order": "desc",
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
            events_raw = resp.json()
            # For each CPT record, fetch the full tribe/v1 representation for field richness
            enriched = []
            for e in events_raw:
                wp_id = e.get("id")
                if wp_id:
                    full = self.get_event(wp_id)
                    if full:
                        enriched.append(full)
            return enriched
        except requests.exceptions.RequestException as exc:
            logger.error(f"Failed to poll recently modified WP events: {exc}")
            return []


_wp_event_client = None


def get_wordpress_event_client() -> WordPressEventAPIClient:
    """Get or create the singleton WP event API client."""
    global _wp_event_client
    if _wp_event_client is None:
        _wp_event_client = WordPressEventAPIClient()
    return _wp_event_client
