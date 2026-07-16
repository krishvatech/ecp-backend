"""
WordPress API client for IMAA integration.

Handles all API calls to the WordPress IMAA platform:
- User authentication and retrieval
- Profile data fetching
- User metadata syncing
"""
import requests
import logging
import math
from django.conf import settings
from typing import Dict, Optional, Any, List
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


class WordPressAPIClient:
    """Client for WordPress IMAA REST API integration.

    By default this client uses the existing WP_IMAA_* settings, which are
    already used by the current MANDA/WordPress user and event integrations.
    Group discovery must use ``for_group_sync()`` so it can safely point to the
    real IMAA WordPress site without changing existing sync behaviour.
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        auth_type: Optional[str] = None,
        api_user: Optional[str] = None,
        api_password: Optional[str] = None,
        config_name: str = "WP_IMAA_API_URL",
    ):
        self.base_url = base_url if base_url is not None else (settings.WP_IMAA_API_URL or "")
        self.auth_type = auth_type if auth_type is not None else (settings.WP_IMAA_AUTH_TYPE or "basic")
        self.api_user = api_user if api_user is not None else (settings.WP_IMAA_API_USER or "")
        self.api_password = api_password if api_password is not None else (settings.WP_IMAA_API_PASSWORD or "")

        if not self.base_url:
            raise ValueError(f"{config_name} is not configured")

    @classmethod
    def for_group_sync(cls) -> "WordPressAPIClient":
        """Build a client for BuddyPress group discovery.

        This intentionally reads WP_IMAA_GROUPS_* settings instead of the
        existing WP_IMAA_* settings, because WP_IMAA_* may already point to
        staging.manda.sg for another integration.
        """
        return cls(
            base_url=getattr(settings, "WP_IMAA_GROUPS_API_URL", "") or "",
            auth_type=getattr(settings, "WP_IMAA_GROUPS_AUTH_TYPE", "basic") or "basic",
            api_user=getattr(settings, "WP_IMAA_GROUPS_API_USER", "") or "",
            api_password=getattr(settings, "WP_IMAA_GROUPS_API_PASSWORD", "") or "",
            config_name="WP_IMAA_GROUPS_API_URL",
        )

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

    def _get_user_resource(self, url: str, params: Optional[Dict[str, Any]] = None):
        """
        GET a WordPress user/users resource preferring context=edit so privileged
        fields (e.g. registered_date) are included in the payload.

        If the authenticated account lacks edit capability, WordPress rejects the
        edit context; in that case we transparently fall back to the default (view)
        context so existing behavior is fully preserved.
        """
        headers = self._get_headers()
        auth = self._get_auth()
        base_params = dict(params or {})
        edit_params = {**base_params, "context": "edit"}

        response = requests.get(
            url, params=edit_params, headers=headers, auth=auth, timeout=10
        )
        if response.status_code in (400, 401, 403):
            # Account may not have edit capability for this resource; retry as view.
            response = requests.get(
                url, params=base_params, headers=headers, auth=auth, timeout=10
            )
        response.raise_for_status()
        return response.json()

    def _get_resource(self, path: str, params: Optional[Dict[str, Any]] = None):
        """
        Generic GET helper for non-user WordPress/BuddyPress REST resources.

        `self.base_url` is expected to be the WordPress REST root, for example:
        https://imaa-institute.org/wp-json
        """
        path = path if path.startswith("/") else f"/{path}"
        url = f"{self.base_url.rstrip('/')}{path}"
        headers = self._get_headers()
        auth = self._get_auth()
        response = requests.get(url, params=params or {}, headers=headers, auth=auth, timeout=20)
        response.raise_for_status()
        return response

    def get_buddypress_groups(self, page: int = 1, per_page: int = 100) -> Dict[str, Any]:
        """
        Fetch one page of BuddyPress groups from WordPress IMAA.

        Works with the standard BuddyPress REST endpoint:
        /wp-json/buddypress/v1/groups
        """
        response = self._get_resource(
            "/buddypress/v1/groups",
            params={"page": page, "per_page": per_page},
        )
        try:
            total = int(response.headers.get("X-WP-Total", "0") or 0)
        except (TypeError, ValueError):
            total = 0
        try:
            total_pages = int(response.headers.get("X-WP-TotalPages", "0") or 0)
        except (TypeError, ValueError):
            total_pages = 0

        data = response.json() if response.content else []
        if not isinstance(data, list):
            data = []

        if not total_pages:
            total_pages = max(1, math.ceil((total or len(data)) / max(per_page, 1)))

        return {
            "results": data,
            "total": total,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page,
        }

    def get_all_buddypress_groups(self, per_page: int = 100, max_pages: int = 50) -> List[Dict[str, Any]]:
        """
        Fetch all available BuddyPress groups up to max_pages.

        This is used only for Phase 1 group discovery. It does not fetch members
        and does not create users.
        """
        all_groups: List[Dict[str, Any]] = []
        page = 1
        while page <= max_pages:
            payload = self.get_buddypress_groups(page=page, per_page=per_page)
            results = payload.get("results") or []
            all_groups.extend(results)

            total_pages = int(payload.get("total_pages") or 1)
            if page >= total_pages or not results:
                break
            page += 1

        return all_groups


    def get_buddypress_group_member_count(self, group_id: int) -> int:
        """
        Return the real BuddyPress group member count.

        The groups list endpoint may return total_member_count=0 for private
        groups, while /groups/<id>/members exposes the count in X-WP-Total.
        We request one member only because only the response header is needed.
        """
        response = self._get_resource(
            f"/buddypress/v1/groups/{int(group_id)}/members",
            params={"page": 1, "per_page": 1},
        )
        try:
            return int(response.headers.get("X-WP-Total", "0") or 0)
        except (TypeError, ValueError):
            return 0


    def get_buddypress_group_members(self, group_id: int, page: int = 1, per_page: int = 100) -> Dict[str, Any]:
        """
        Fetch one page of BuddyPress group members.

        Endpoint:
        /wp-json/buddypress/v1/groups/<group_id>/members
        """
        response = self._get_resource(
            f"/buddypress/v1/groups/{int(group_id)}/members",
            params={"page": page, "per_page": per_page},
        )
        try:
            total = int(response.headers.get("X-WP-Total", "0") or 0)
        except (TypeError, ValueError):
            total = 0
        try:
            total_pages = int(response.headers.get("X-WP-TotalPages", "0") or 0)
        except (TypeError, ValueError):
            total_pages = 0

        data = response.json() if response.content else []
        if not isinstance(data, list):
            data = []

        if not total_pages:
            total_pages = max(1, math.ceil((total or len(data)) / max(per_page, 1)))

        return {
            "results": data,
            "total": total,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page,
        }

    def get_all_buddypress_group_members(self, group_id: int, per_page: int = 100, max_pages: int = 100) -> List[Dict[str, Any]]:
        """Fetch all BuddyPress members for one group up to max_pages."""
        all_members: List[Dict[str, Any]] = []
        page = 1
        while page <= max_pages:
            payload = self.get_buddypress_group_members(group_id=group_id, page=page, per_page=per_page)
            results = payload.get("results") or []
            all_members.extend(results)

            total_pages = int(payload.get("total_pages") or 1)
            if page >= total_pages or not results:
                break
            page += 1

        return all_members

    def get_imaa_connect_group_members(self, group_id: int, page: int = 1, per_page: int = 100) -> Dict[str, Any]:
        """
        Fetch one page of group members from the custom IMAA Connect WP endpoint.

        This endpoint is intentionally preferred for Phase 3 because it returns
        member email addresses needed for Connect user creation and SSO linking.

        Endpoint:
        /wp-json/imaa-connect/v1/groups/<group_id>/members
        """
        response = self._get_resource(
            f"/imaa-connect/v1/groups/{int(group_id)}/members",
            params={"page": page, "per_page": per_page},
        )
        payload = response.json() if response.content else {}

        if isinstance(payload, dict):
            results = payload.get("results") or payload.get("members") or []
            total = payload.get("count") or payload.get("total")
            total_pages = payload.get("total_pages") or payload.get("pages")
        else:
            results = payload if isinstance(payload, list) else []
            total = None
            total_pages = None

        if not isinstance(results, list):
            results = []

        try:
            total = int(total if total is not None else (response.headers.get("X-WP-Total", "0") or 0))
        except (TypeError, ValueError):
            total = 0

        try:
            total_pages = int(total_pages if total_pages is not None else (response.headers.get("X-WP-TotalPages", "0") or 0))
        except (TypeError, ValueError):
            total_pages = 0

        if not total_pages:
            total_pages = max(1, math.ceil((total or len(results)) / max(per_page, 1)))

        return {
            "results": results,
            "total": total,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page,
        }

    def get_all_imaa_connect_group_members(self, group_id: int, per_page: int = 100, max_pages: int = 100) -> List[Dict[str, Any]]:
        """Fetch all custom IMAA Connect group members up to max_pages."""
        all_members: List[Dict[str, Any]] = []
        page = 1
        while page <= max_pages:
            payload = self.get_imaa_connect_group_members(group_id=group_id, page=page, per_page=per_page)
            results = payload.get("results") or []
            all_members.extend(results)

            total_pages = int(payload.get("total_pages") or 1)
            if page >= total_pages or not results:
                break
            page += 1

        return all_members


    def get_imaa_connect_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Fetch one exact WordPress user profile by email from the custom IMAA
        Connect endpoint.

        This endpoint is used by IMAA OAuth login enrichment. It is safer than
        the standard /wp/v2/users search endpoint because WordPress search can
        return partial matches and often does not expose email/profile fields.

        Endpoint:
        /wp-json/imaa-connect/v1/users/by-email?email=<email>
        """
        email = str(email or "").strip().lower()
        if not email or "@" not in email:
            return None

        try:
            response = self._get_resource(
                "/imaa-connect/v1/users/by-email",
                params={"email": email},
            )
            payload = response.json() if response.content else None
            return payload if isinstance(payload, dict) and payload.get("id") else None
        except requests.exceptions.HTTPError as exc:
            status_code = getattr(exc.response, "status_code", None)
            if status_code == 404:
                logger.info("No custom WordPress user profile found for email: %s", email)
            else:
                logger.warning(
                    "Custom WordPress user profile lookup failed for %s: %s",
                    email,
                    exc,
                )
            return None
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "Custom WordPress user profile lookup failed for %s: %s",
                email,
                exc,
            )
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

            # Strategy 1: Search by username FIRST (WordPress often doesn't expose email field)
            username = email.split("@")[0] if "@" in email else email
            logger.debug(f"Searching WordPress user by username: {username}")
            params = {
                "search": username,
                "per_page": 100,
            }
            users = self._get_user_resource(url, params=params)
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
            users = self._get_user_resource(url, params=params)
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
            user_data = self._get_user_resource(url)
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

        Tries, in order:
        1) Basic auth against /wp/v2/users/me
        2) JWT plugin auth: POST /jwt-auth/v1/token then GET /wp/v2/users/me with Bearer token
        """
        url_me = f"{self.base_url}/wp/v2/users/me"
        headers = self._get_headers()

        # Strategy 1: Basic auth
        try:
            response = requests.get(
                url_me,
                headers=headers,
                auth=HTTPBasicAuth(username, password),
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.warning(f"WordPress basic authentication failed for user {username}: {str(e)}")

        # Strategy 2: JWT plugin auth
        try:
            token_url = f"{self.base_url}/jwt-auth/v1/token"
            token_res = requests.post(
                token_url,
                json={"username": username, "password": password},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            token_res.raise_for_status()
            token_payload = token_res.json() if token_res.content else {}
            token = token_payload.get("token")
            if not token:
                logger.warning(f"WordPress JWT token missing for user {username}")
                return None

            me_res = requests.get(
                url_me,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=10,
            )
            me_res.raise_for_status()
            return me_res.json()
        except requests.exceptions.RequestException as e:
            logger.warning(f"WordPress JWT authentication failed for user {username}: {str(e)}")
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
