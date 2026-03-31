"""
Moodle Web Services API client for IMAA LMS integration.

Handles all API calls to https://lms.edtechprof.com via the REST web services API.
Token is scoped to the "Moodle mobile web service" (moodle_mobile_app).
"""
import requests
import logging
from django.conf import settings
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

MOODLE_REST_ENDPOINT = "/webservice/rest/server.php"


class MoodleAPIClient:
    """Client for Moodle Web Services REST API."""

    def __init__(self):
        self.base_url = (settings.MOODLE_URL or "").rstrip("/")
        self.token = settings.MOODLE_TOKEN or ""

        if not self.base_url:
            raise ValueError("MOODLE_URL is not configured")
        if not self.token:
            raise ValueError("MOODLE_TOKEN is not configured")

    def _call(self, function: str, **params) -> Any:
        """Make a Moodle REST API call."""
        url = f"{self.base_url}{MOODLE_REST_ENDPOINT}"
        payload = {
            "wstoken": self.token,
            "wsfunction": function,
            "moodlewsrestformat": "json",
            **params,
        }
        try:
            response = requests.post(url, data=payload, timeout=30)
            response.raise_for_status()
            data = response.json()

            # Moodle returns {"exception": ..., "message": ...} on error
            if isinstance(data, dict) and data.get("exception"):
                logger.error(
                    "Moodle API error for %s: %s",
                    function,
                    data.get("message", "unknown error"),
                )
                return None

            return data
        except requests.exceptions.RequestException as e:
            logger.error("Moodle API request failed for %s: %s", function, e)
            return None

    # ------------------------------------------------------------------
    # Site info
    # ------------------------------------------------------------------

    def get_site_info(self) -> Optional[Dict]:
        """Verify connection and get site metadata."""
        return self._call("core_webservice_get_site_info")

    # ------------------------------------------------------------------
    # Courses & Categories
    # ------------------------------------------------------------------

    def get_categories(self) -> List[Dict]:
        """Fetch all course categories."""
        result = self._call("core_course_get_categories")
        return result if isinstance(result, list) else []

    def get_all_courses(self) -> List[Dict]:
        """
        Fetch all courses from Moodle with overviewfiles (images).
        Uses core_course_search_courses with empty search, paginated.
        core_course_get_courses does NOT return overviewfiles.
        """
        all_courses = []
        page = 0
        per_page = 50

        while True:
            result = self._call(
                "core_course_search_courses",
                criterianame="search",
                criteriavalue="",
                page=page,
                perpage=per_page,
            )
            if not isinstance(result, dict):
                break

            batch = result.get("courses", [])
            if not batch:
                break

            # Filter out site-level course (id=1)
            all_courses.extend([c for c in batch if c.get("id", 0) > 1])

            total = result.get("total", 0)
            if len(all_courses) >= total or len(batch) < per_page:
                break

            page += 1

        return all_courses

    def get_course(self, course_id: int) -> Optional[Dict]:
        """Fetch a single course by Moodle course ID."""
        result = self._call(
            "core_course_get_courses",
            **{"options[ids][0]": course_id},
        )
        if isinstance(result, list) and result:
            return result[0]
        return None

    # ------------------------------------------------------------------
    # User lookup
    # ------------------------------------------------------------------

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Look up a Moodle user by email address."""
        result = self._call(
            "core_user_get_users_by_field",
            field="email",
            **{"values[0]": email},
        )
        if isinstance(result, list) and result:
            return result[0]
        return None

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Look up a Moodle user by username."""
        result = self._call(
            "core_user_get_users_by_field",
            field="username",
            **{"values[0]": username},
        )
        if isinstance(result, list) and result:
            return result[0]
        return None

    # ------------------------------------------------------------------
    # Enrollments
    # ------------------------------------------------------------------

    def get_user_courses(self, moodle_user_id: int) -> List[Dict]:
        """
        Get all courses a user is enrolled in.
        Returns list with: id, fullname, shortname, summary, progress,
        completionhascriteria, lastaccess, overviewfiles (for image).
        """
        result = self._call(
            "core_enrol_get_users_courses",
            userid=moodle_user_id,
            returnusercount=0,
        )
        return result if isinstance(result, list) else []

    def get_enrolled_users(self, course_id: int) -> List[Dict]:
        """Get users enrolled in a specific course."""
        result = self._call(
            "core_enrol_get_enrolled_users",
            courseid=course_id,
        )
        return result if isinstance(result, list) else []

    # ------------------------------------------------------------------
    # Completion
    # ------------------------------------------------------------------

    def get_course_completion(self, user_id: int, course_id: int) -> Optional[Dict]:
        """Get completion status for a user in a course."""
        result = self._call(
            "core_completion_get_course_completion_status",
            courseid=course_id,
            userid=user_id,
        )
        if isinstance(result, dict):
            return result.get("completionstatus")
        return None

    def get_activities_completion(self, course_id: int, user_id: int) -> List[Dict]:
        """Get activity-level completion status for a user in a course."""
        result = self._call(
            "core_completion_get_activities_completion_status",
            courseid=course_id,
            userid=user_id,
        )
        if isinstance(result, dict):
            return result.get("statuses", [])
        return []


# ------------------------------------------------------------------
# Singleton
# ------------------------------------------------------------------

_moodle_client: Optional[MoodleAPIClient] = None


def get_moodle_client() -> MoodleAPIClient:
    """Get or create the Moodle API client singleton."""
    global _moodle_client
    if _moodle_client is None:
        _moodle_client = MoodleAPIClient()
    return _moodle_client
