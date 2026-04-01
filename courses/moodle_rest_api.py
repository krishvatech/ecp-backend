"""
Moodle REST API client for fetching course content (sections, modules, completion).

Moodle is the actual LMS. Edwiser Bridge (EB) syncs course catalogue into WordPress
for the storefront, but EB has no API for content. This client talks directly to
Moodle's web service API to fetch the real course content.

Endpoints used:
  core_course_get_contents                   — sections + modules for a course
  core_completion_get_activities_completion_status — per-module completion for a user
  core_user_get_users_by_field               — look up Moodle user ID by email

Authentication: MOODLE_TOKEN (Moodle web service token, set in settings)
"""
import logging
from typing import Any, Dict, List, Optional

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

MOODLE_REST_PATH = "/webservice/rest/server.php"


class MoodleRestClient:
    """Client for the Moodle REST web service API."""

    def __init__(self):
        base = (settings.MOODLE_URL or "").rstrip("/")
        token = settings.MOODLE_TOKEN or ""
        if not base or not token:
            raise ValueError("MOODLE_URL and MOODLE_TOKEN must be configured in settings")
        self.base_url = base
        self.token = token
        self.endpoint = f"{base}{MOODLE_REST_PATH}"

    def _call(self, wsfunction: str, params: Optional[Dict] = None) -> Any:
        """Execute a Moodle web service function call."""
        payload = {
            "wstoken": self.token,
            "wsfunction": wsfunction,
            "moodlewsrestformat": "json",
            **(params or {}),
        }
        try:
            resp = requests.post(self.endpoint, data=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            # Moodle returns {"exception": "...", "message": "..."} on error
            if isinstance(data, dict) and data.get("exception"):
                logger.error(
                    "Moodle API exception for %s: %s — %s",
                    wsfunction,
                    data.get("errorcode"),
                    data.get("message"),
                )
                return None
            return data
        except requests.exceptions.RequestException as exc:
            logger.error("Moodle REST request failed (%s): %s", wsfunction, exc)
            return None

    # ------------------------------------------------------------------
    # Course content
    # ------------------------------------------------------------------

    def get_course_contents(self, moodle_course_id: int) -> List[Dict]:
        """
        Fetch all sections and their modules for a course.

        Returns a list of section dicts, each containing a 'modules' list.
        Each module dict has: id (cmid), name, modname, url, contents, completion.

        modname values: resource, url, page, quiz, hvp, label, assign, forum, folder
        """
        result = self._call(
            "core_course_get_contents",
            {"courseid": moodle_course_id, "options[0][name]": "includestealthmodules", "options[0][value]": 0},
        )
        if not isinstance(result, list):
            logger.warning("Unexpected response for course %d contents", moodle_course_id)
            return []
        return result

    # ------------------------------------------------------------------
    # User lookup
    # ------------------------------------------------------------------

    def get_user_id_by_email(self, email: str) -> Optional[int]:
        """Look up a Moodle user's internal ID by email address."""
        result = self._call(
            "core_user_get_users_by_field",
            {"field": "email", "values[0]": email},
        )
        if not isinstance(result, list) or not result:
            return None
        return result[0].get("id")

    # ------------------------------------------------------------------
    # Completion status
    # ------------------------------------------------------------------

    def get_activities_completion(self, course_id: int, user_id: int) -> Dict[int, bool]:
        """
        Fetch per-module completion status for a user in a course.

        Returns a dict mapping cmid → completed (bool).
        """
        result = self._call(
            "core_completion_get_activities_completion_status",
            {"courseid": course_id, "userid": user_id},
        )
        if not isinstance(result, dict):
            return {}
        statuses = result.get("statuses") or []
        return {
            s["cmid"]: bool(s.get("state", 0))
            for s in statuses
            if "cmid" in s
        }

    def get_assignment_detail(self, moodle_course_id: int, cmid: int) -> Optional[Dict]:
        """
        Fetch full assignment details (intro HTML, attachments, due date) for a specific cmid.
        Uses mod_assign_get_assignments filtered to the course.
        """
        result = self._call(
            "mod_assign_get_assignments",
            {"courseids[0]": moodle_course_id, "includenotenrolledcourses": 1},
        )
        if not isinstance(result, dict):
            return None
        for course in (result.get("courses") or []):
            for assign in (course.get("assignments") or []):
                if assign.get("cmid") == cmid:
                    return assign
        return None

    def get_quiz_detail(self, moodle_course_id: int, cmid: int) -> Optional[Dict]:
        """Fetch quiz details (name, intro, time limit) for a specific cmid."""
        result = self._call(
            "mod_quiz_get_quizzes_by_courses",
            {"courseids[0]": moodle_course_id},
        )
        if not isinstance(result, dict):
            return None
        for quiz in (result.get("quizzes") or []):
            if quiz.get("coursemodule") == cmid:
                return quiz
        return None

    def mark_activity_complete(self, cmid: int) -> bool:
        """
        Manually mark a module (activity) as complete for the token owner.
        Only works for activities with manual completion enabled.
        Returns True on success.
        """
        result = self._call(
            "core_completion_update_activity_completion_status_manually",
            {"cmid": cmid, "completed": 1},
        )
        return result is not None and not (isinstance(result, dict) and result.get("exception"))


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_moodle_client: Optional[MoodleRestClient] = None


def get_moodle_client() -> MoodleRestClient:
    """Return the shared Moodle REST client, creating it once."""
    global _moodle_client
    if _moodle_client is None:
        _moodle_client = MoodleRestClient()
    return _moodle_client
