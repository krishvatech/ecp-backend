"""
Moodle user account management utilities.

Handles creating Moodle accounts for ECP users and caching moodle_user_id.

Key design principle (matches Edwiser Bridge behaviour):
  - Matching identifier: email address
  - Creation identifier: WordPress username (we use Django username / email prefix)
  - Persistent cached link: UserProfile.moodle_user_id (Moodle numeric ID)
"""
import logging

from django.contrib.auth import get_user_model

from .moodle_api import get_moodle_client

User = get_user_model()
logger = logging.getLogger(__name__)


def get_or_create_moodle_user(user) -> int | None:
    """
    Ensure a Moodle account exists for the given ECP user.

    Flow:
      1. Return cached moodle_user_id from UserProfile if present.
      2. Look up by email in Moodle (same as Edwiser Bridge does).
      3. If found → cache and return.
      4. If not found → create Moodle account via core_user_create_users → cache and return.

    Returns the Moodle user ID (int) or None on failure.
    """
    try:
        profile = user.profile
    except Exception:
        logger.warning("User %s has no profile, cannot sync Moodle account", user.email)
        return None

    # 1. Use cached ID
    if profile.moodle_user_id:
        return profile.moodle_user_id

    try:
        client = get_moodle_client()
    except ValueError as e:
        logger.warning("Moodle not configured: %s", e)
        return None

    # 2. Look up by email
    moodle_user = client.get_user_by_email(user.email)
    if moodle_user:
        moodle_user_id = moodle_user.get("id")
        if moodle_user_id:
            _cache_moodle_id(profile, moodle_user_id)
            logger.info(
                "Linked existing Moodle user %d to ECP user %s",
                moodle_user_id, user.email,
            )
            return moodle_user_id

    # 3. Create Moodle account
    moodle_user_id = _create_moodle_account(client, user)
    if moodle_user_id:
        _cache_moodle_id(profile, moodle_user_id)
    return moodle_user_id


def _create_moodle_account(client, user) -> int | None:
    """
    Create a new Moodle account for an ECP user.
    Uses email as the primary identifier and Django username as Moodle username.
    """
    profile = getattr(user, "profile", None)
    full_name = (profile.full_name if profile else "") or ""
    first_name = full_name.split()[0] if full_name else (user.first_name or "User")
    last_name = " ".join(full_name.split()[1:]) if len(full_name.split()) > 1 else (user.last_name or user.email.split("@")[0])

    # Username: use WordPress username if available, else email prefix (lowercased)
    wp_username = (profile.wordpress_username if profile else "") or ""
    username = (wp_username or user.username or user.email.split("@")[0]).lower()

    result = client._call(
        "core_user_create_users",
        **{
            "users[0][username]": username,
            "users[0][email]": user.email,
            "users[0][firstname]": first_name[:100],
            "users[0][lastname]": last_name[:100] or "User",
            "users[0][auth]": "manual",
            "users[0][password]": "Changeme123!",  # Temporary — user must reset on first Moodle login
        },
    )

    if isinstance(result, list) and result:
        moodle_user_id = result[0].get("id")
        logger.info(
            "Created Moodle account for ECP user %s → moodle_user_id=%s",
            user.email, moodle_user_id,
        )
        return moodle_user_id

    logger.error("Failed to create Moodle account for %s: %s", user.email, result)
    return None


def enrol_user_in_course(user, moodle_course_id: int, role_id: int = 5) -> bool:
    """
    Enroll an ECP user in a Moodle course.
    role_id=5 is the standard 'student' role in Moodle.

    Returns True on success, False on failure.
    """
    moodle_user_id = get_or_create_moodle_user(user)
    if not moodle_user_id:
        logger.warning("Cannot enroll %s — no Moodle account", user.email)
        return False

    try:
        client = get_moodle_client()
    except ValueError:
        return False

    result = client._call(
        "enrol_manual_enrol_users",
        **{
            "enrolments[0][roleid]": role_id,
            "enrolments[0][userid]": moodle_user_id,
            "enrolments[0][courseid]": moodle_course_id,
        },
    )

    # enrol_manual_enrol_users returns null on success
    success = result is None or result == []
    if success:
        logger.info(
            "Enrolled moodle_user_id=%d in moodle_course_id=%d",
            moodle_user_id, moodle_course_id,
        )
    else:
        logger.error(
            "Enrollment failed for moodle_user_id=%d course=%d: %s",
            moodle_user_id, moodle_course_id, result,
        )
    return success


def _cache_moodle_id(profile, moodle_user_id: int):
    profile.moodle_user_id = moodle_user_id
    profile.save(update_fields=["moodle_user_id"])
