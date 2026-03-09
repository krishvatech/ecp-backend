"""
WordPress API client for IMAA integration.

Handles all API calls to the WordPress IMAA platform:
- User authentication and retrieval
- Profile data fetching
- User metadata syncing
"""
import requests
import logging
from django.conf import settings
from typing import Dict, Optional, Any
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


class WordPressAPIClient:
    """Client for WordPress IMAA REST API integration."""

    def __init__(self):
        self.base_url = settings.WP_IMAA_API_URL or ""
        self.auth_type = settings.WP_IMAA_AUTH_TYPE or "basic"
        self.api_user = settings.WP_IMAA_API_USER or ""
        self.api_password = settings.WP_IMAA_API_PASSWORD or ""

        if not self.base_url:
            raise ValueError("WP_IMAA_API_URL is not configured")

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers based on auth type."""
        headers = {"Content-Type": "application/json"}

        if self.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.api_password}"

        return headers

    def _get_auth(self):
        """Get auth tuple for requests library."""
        if self.auth_type == "basic":
            return HTTPBasicAuth(self.api_user, self.api_password)
        return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Fetch user from WordPress by email.

        Tries multiple search strategies:
        1. Search by username (before @ in email) - WordPress may not expose email field
        2. Search by full email as fallback
        3. Returns user object with id, name, etc., including ACF and custom fields
        """
        try:
            url = f"{self.base_url}/wp/v2/users"
            headers = self._get_headers()
            auth = self._get_auth()

            # Strategy 1: Search by username FIRST (WordPress often doesn't expose email field)
            username = email.split("@")[0] if "@" in email else email
            logger.debug(f"Searching WordPress user by username: {username}")
            params = {
                "search": username,
                "per_page": 100,
            }
            response = requests.get(
                url,
                params=params,
                headers=headers,
                auth=auth,
                timeout=10
            )
            response.raise_for_status()

            users = response.json()
            logger.debug(f"Username search returned {len(users)} results")
            # Filter for exact username match (search returns partial matches)
            exact_match = None
            for user in users:
                if user.get("slug") == username or user.get("username") == username:
                    exact_match = user
                    break

            if exact_match and exact_match.get("id"):
                logger.debug(f"Found user by username search: {exact_match.get('id')}, fields: {list(exact_match.keys())}")
                return exact_match
            elif users and len(users) > 0 and users[0].get("id"):
                # If no exact match but search returned results with ID, use first result
                logger.debug(f"Found user by username search (partial): {users[0].get('id')}, fields: {list(users[0].keys())}")
                return users[0]

            # Strategy 2: Try searching by full email (in case email field is exposed)
            logger.debug(f"Username search failed, trying email search: {email}")
            params = {
                "search": email,
                "per_page": 100,
            }
            response = requests.get(
                url,
                params=params,
                headers=headers,
                auth=auth,
                timeout=10
            )
            response.raise_for_status()

            users = response.json()
            logger.debug(f"Email search returned {len(users)} results")
            if users and len(users) > 0 and users[0].get("id"):
                logger.debug(f"Found user by email search: {users[0].get('id')}, fields: {list(users[0].keys())}")
                return users[0]

            logger.warning(f"No WordPress user found for email: {email}")
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching WordPress user by email {email}: {str(e)}")
            return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Fetch user from WordPress by ID.

        Returns user object with complete profile data.
        """
        try:
            url = f"{self.base_url}/wp/v2/users/{user_id}"
            headers = self._get_headers()
            auth = self._get_auth()

            response = requests.get(
                url,
                headers=headers,
                auth=auth,
                timeout=10
            )
            response.raise_for_status()

            user_data = response.json()
            logger.debug(f"Fetched WordPress user {user_id} with fields: {list(user_data.keys())}")
            return user_data

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching WordPress user {user_id}: {str(e)}")
            return None

    def get_user_meta(self, user_id: int, meta_key: str = "") -> Dict[str, Any]:
        """
        Fetch user metadata from WordPress.

        Returns metadata as dict.
        """
        try:
            url = f"{self.base_url}/wp/v2/users/{user_id}"
            headers = self._get_headers()
            auth = self._get_auth()

            response = requests.get(
                url,
                headers=headers,
                auth=auth,
                timeout=10
            )
            response.raise_for_status()

            user_data = response.json()
            # WordPress user meta would typically be in custom fields
            return user_data.get("meta", {})

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching WordPress user meta for {user_id}: {str(e)}")
            return {}

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate WordPress user and return user data.

        Note: This typically uses JWT or OAuth on WordPress side.
        For now, we use the REST API user endpoint with Basic Auth.
        """
        try:
            url = f"{self.base_url}/wp/v2/users/me"
            headers = self._get_headers()
            auth = HTTPBasicAuth(username, password)

            response = requests.get(
                url,
                headers=headers,
                auth=auth,
                timeout=10
            )
            response.raise_for_status()

            return response.json()

        except requests.exceptions.RequestException as e:
            logger.warning(f"WordPress authentication failed for user {username}: {str(e)}")
            return None

    def validate_webhook_secret(self, payload: str, signature: str) -> bool:
        """
        Validate webhook signature using HMAC.
        """
        import hmac
        import hashlib

        secret = settings.WP_IMAA_WEBHOOK_SECRET_KEY or ""
        if not secret:
            logger.warning("WP_IMAA_WEBHOOK_SECRET_KEY not configured")
            return False

        expected_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_signature, signature)


# Singleton instance
_wp_client = None


def get_wordpress_client() -> WordPressAPIClient:
    """Get or create WordPress API client."""
    global _wp_client
    if _wp_client is None:
        _wp_client = WordPressAPIClient()
    return _wp_client
