"""
Celery tasks for syncing Moodle LMS data into the local database.

Schedule (configured in settings.py):
  - sync_moodle_courses_and_categories: every 6 hours
  - sync_all_user_moodle_enrollments:  every 30 minutes
"""
import logging
from datetime import datetime, timezone

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction

from .models import MoodleCategory, MoodleCourse, MoodleEnrollment
from .moodle_api import get_moodle_client

User = get_user_model()
logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_moodle_courses_and_categories(self):
    """
    Pull all categories and courses from Moodle and upsert into local DB.
    Runs every 6 hours.
    """
    try:
        client = get_moodle_client()
    except ValueError as e:
        logger.warning("Moodle not configured, skipping sync: %s", e)
        return {"skipped": True, "reason": str(e)}

    # --- Sync categories ---
    categories = client.get_categories()
    category_map: dict[int, MoodleCategory] = {}
    for cat in categories:
        moodle_id = cat.get("id")
        if not moodle_id:
            continue
        obj, _ = MoodleCategory.objects.update_or_create(
            moodle_id=moodle_id,
            defaults={
                "name": cat.get("name", "")[:500],
                "parent_moodle_id": cat.get("parent") or None,
                "course_count": cat.get("coursecount", 0),
            },
        )
        category_map[moodle_id] = obj

    logger.info("Synced %d Moodle categories", len(category_map))

    # --- Sync courses ---
    courses = client.get_all_courses()
    synced = 0
    for course in courses:
        moodle_id = course.get("id")
        if not moodle_id:
            continue

        # Extract course image from overviewfiles
        # search_courses returns pluginfile.php URLs — append token for access
        image_url = ""
        for f in course.get("overviewfiles", []):
            if f.get("mimetype", "").startswith("image/"):
                raw_url = f.get("fileurl", "")
                if raw_url and "token=" not in raw_url:
                    image_url = f"{raw_url}?token={settings.MOODLE_TOKEN}"
                else:
                    image_url = raw_url
                break

        cat_id = course.get("categoryid")
        category = category_map.get(cat_id)

        MoodleCourse.objects.update_or_create(
            moodle_id=moodle_id,
            defaults={
                "short_name": course.get("shortname", "")[:255],
                "full_name": course.get("fullname", "")[:500],
                "summary": course.get("summary", ""),
                "category": category,
                "image_url": image_url[:1000],
                "enrolled_user_count": course.get("enrolledusercount", 0),
                "completion_enabled": bool(course.get("enablecompletion", 0)),
                "is_visible": bool(course.get("visible", 1)),
            },
        )
        synced += 1

    logger.info("Synced %d Moodle courses", synced)
    return {"categories": len(category_map), "courses": synced}


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_all_user_moodle_enrollments(self):
    """
    For every ECP user that has a Moodle account (matched by email),
    sync their enrollments + progress into MoodleEnrollment.
    Runs every 30 minutes.
    """
    try:
        client = get_moodle_client()
    except ValueError as e:
        logger.warning("Moodle not configured, skipping enrollment sync: %s", e)
        return {"skipped": True}

    users = User.objects.filter(is_active=True).only("id", "email")
    synced_users = 0
    synced_enrollments = 0

    for user in users:
        count = _sync_user_enrollments(client, user)
        if count is not None:
            synced_users += 1
            synced_enrollments += count

    logger.info(
        "Enrollment sync complete: %d users, %d enrollments",
        synced_users,
        synced_enrollments,
    )
    return {"users": synced_users, "enrollments": synced_enrollments}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def sync_single_user_moodle_enrollments(self, user_id: int):
    """
    Sync Moodle enrollments for a single ECP user.
    Called on login or explicit refresh.
    """
    try:
        client = get_moodle_client()
        user = User.objects.get(id=user_id)
    except (ValueError, User.DoesNotExist) as e:
        logger.warning("Cannot sync enrollments for user %s: %s", user_id, e)
        return {"skipped": True}

    count = _sync_user_enrollments(client, user)
    return {"user_id": user_id, "enrollments": count}


def _sync_user_enrollments(client, user) -> int | None:
    """
    Internal helper: look up user in Moodle by email, fetch their courses,
    and upsert MoodleEnrollment records.

    Uses cached moodle_user_id from UserProfile if available, otherwise
    looks up by email (same matching key Edwiser Bridge uses) and caches it.

    Returns number of enrollments synced, or None if user not found in Moodle.
    """
    # Use cached moodle_user_id if available (avoids repeated email lookups)
    try:
        profile = user.profile
        moodle_user_id = profile.moodle_user_id
    except Exception:
        profile = None
        moodle_user_id = None

    if not moodle_user_id:
        moodle_user = client.get_user_by_email(user.email)
        if not moodle_user:
            return None
        moodle_user_id = moodle_user.get("id")
        if not moodle_user_id:
            return None

        # Cache the Moodle user ID for future syncs
        if profile is not None:
            profile.moodle_user_id = moodle_user_id
            profile.save(update_fields=["moodle_user_id"])
            logger.info("Cached moodle_user_id=%d for user %s", moodle_user_id, user.email)

    moodle_courses = client.get_user_courses(moodle_user_id)
    synced = 0

    for mc in moodle_courses:
        course_id = mc.get("id")
        if not course_id:
            continue

        # Get or create local course record (minimal — full sync runs separately)
        course_obj, _ = MoodleCourse.objects.get_or_create(
            moodle_id=course_id,
            defaults={
                "full_name": mc.get("fullname", "")[:500],
                "short_name": mc.get("shortname", "")[:255],
                "summary": mc.get("summary", ""),
                "completion_enabled": bool(mc.get("completionhascriteria", False)),
            },
        )

        # Extract image (append Moodle token so URL is publicly accessible)
        image_url = ""
        for f in mc.get("overviewfiles", []):
            if f.get("mimetype", "").startswith("image/"):
                raw_url = f.get("fileurl", "")
                if raw_url and "token=" not in raw_url:
                    raw_url = f"{raw_url}?token={settings.MOODLE_TOKEN}"
                image_url = raw_url
                break
        if image_url and not course_obj.image_url:
            # Append token for webservice/pluginfile.php URLs too
            if "token=" not in image_url:
                image_url = f"{image_url}?token={settings.MOODLE_TOKEN}"
            course_obj.image_url = image_url[:1000]
            course_obj.save(update_fields=["image_url"])

        # Progress from Moodle (0–100 float or None)
        progress = mc.get("progress") or 0.0
        completed = progress >= 100.0

        # Last access timestamp
        last_access_ts = mc.get("lastaccess")
        last_access = (
            datetime.fromtimestamp(last_access_ts, tz=timezone.utc)
            if last_access_ts
            else None
        )

        with transaction.atomic():
            MoodleEnrollment.objects.update_or_create(
                user=user,
                course=course_obj,
                defaults={
                    "moodle_user_id": moodle_user_id,
                    "progress": float(progress),
                    "completed": completed,
                    "last_access": last_access,
                },
            )
        synced += 1

    return synced
