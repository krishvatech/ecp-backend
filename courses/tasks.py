"""
Celery tasks for syncing Moodle LMS data into the local database.

Data sources:
  - Edwiser Bridge (EB) WordPress API — course catalogue + enrollments + progress
  - Moodle REST API (direct) — course content: sections, modules, completion

Schedule (configured in settings.py):
  - sync_moodle_courses_and_categories: every 6 hours (via EB)
  - sync_all_user_moodle_enrollments:  every 30 minutes (via EB)
  - sync_course_content:               on demand / after course sync (via Moodle REST)
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from celery import shared_task
from django.contrib.auth import get_user_model
from django.db import transaction

from .models import MoodleCategory, MoodleCourse, MoodleEnrollment, CourseSection, CourseModule, ModuleCompletion
from .edwiser_api import get_edwiser_client
from .moodle_rest_api import get_moodle_client

User = get_user_model()
logger = logging.getLogger(__name__)


def _parse_moodle_course_id(course_url: str) -> int | None:
    """
    Extract Moodle course ID from an Edwiser Bridge course URL.

    EB encodes the Moodle course ID as a query param, e.g.:
      https://imaa-institute.org?mdl_course_id=2
    """
    if not course_url:
        return None
    try:
        qs = parse_qs(urlparse(course_url).query)
        val = qs.get("mdl_course_id", [None])[0]
        return int(val) if val else None
    except (ValueError, TypeError):
        return None


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_moodle_courses_and_categories(self):
    """
    Pull all courses and categories from Edwiser Bridge and upsert into local DB.
    Runs every 6 hours.

    EB API field mapping:
      Course: id→moodle_id, title→full_name, excerpt→summary,
              thumbnail→image_url, link→moodle_url, suspended→(not is_visible)
      Category: id→moodle_id, name→name, count→course_count
    """
    try:
        client = get_edwiser_client()
    except ValueError as e:
        logger.warning("Edwiser Bridge not configured, skipping sync: %s", e)
        return {"skipped": True, "reason": str(e)}

    data = client.get_all_courses()
    courses = data.get("courses") or []
    eb_categories = data.get("categories") or []

    # --- Upsert categories (returned as top-level list from EB) ---
    # Format: {"id": 925, "name": "...", "slug": "...", "count": 15}
    category_map: dict[int, MoodleCategory] = {}
    for cat in eb_categories:
        cat_id = cat.get("id")
        if not cat_id:
            continue
        obj, _ = MoodleCategory.objects.update_or_create(
            moodle_id=cat_id,
            defaults={
                "name": cat.get("name", "")[:500],
                "parent_moodle_id": None,  # EB top-level categories have no parent info
                "course_count": cat.get("count") or 0,
            },
        )
        category_map[cat_id] = obj

    logger.info("Synced %d categories from Edwiser Bridge", len(category_map))

    # --- Upsert courses ---
    # EB uses WordPress post ID as course identifier.
    # moodle_id stores the WP post ID (unique key); moodle_url stores the WP course page link.
    synced = 0
    for course in courses:
        wp_course_id = course.get("id")
        if not wp_course_id:
            continue

        # Resolve category: EB embeds categories as [{"id": N, "name": "..."}]
        course_cats = course.get("categories") or []
        category = None
        if course_cats:
            cat_id = course_cats[0].get("id")
            category = category_map.get(cat_id)

        # suspended=true means the course is hidden/disabled in EB
        is_visible = not bool(course.get("suspended", False))

        MoodleCourse.objects.update_or_create(
            moodle_id=wp_course_id,
            defaults={
                "short_name": course.get("title", "")[:255],
                "full_name": course.get("title", "")[:500],
                "summary": course.get("excerpt") or "",
                "category": category,
                "image_url": (course.get("thumbnail") or "")[:1000],
                "moodle_url": (course.get("link") or "")[:1000],
                "enrolled_user_count": 0,  # not provided by EB catalogue endpoint
                "completion_enabled": False,
                "is_visible": is_visible,
            },
        )
        synced += 1

    logger.info("Synced %d courses via Edwiser Bridge", synced)
    return {"categories": len(category_map), "courses": synced}


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_all_user_moodle_enrollments(self):
    """
    For every active ECP user that has a linked WordPress account,
    sync their Edwiser Bridge enrollments + progress into MoodleEnrollment.
    Runs every 30 minutes.
    """
    try:
        client = get_edwiser_client()
    except ValueError as e:
        logger.warning("Edwiser Bridge not configured, skipping enrollment sync: %s", e)
        return {"skipped": True}

    # Only process users with a known WordPress ID (the EB API key)
    users = (
        User.objects.filter(is_active=True, profile__wordpress_id__isnull=False)
        .select_related("profile")
        .only("id", "email")
    )
    synced_users = 0
    synced_enrollments = 0

    for user in users:
        count = _sync_user_enrollments(client, user)
        if count is not None:
            synced_users += 1
            synced_enrollments += count

    logger.info(
        "EB enrollment sync complete: %d users, %d enrollments",
        synced_users,
        synced_enrollments,
    )
    return {"users": synced_users, "enrollments": synced_enrollments}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def sync_single_user_moodle_enrollments(self, user_id: int):
    """
    Sync Edwiser Bridge enrollments for a single ECP user.
    Called on login or explicit refresh via POST /api/courses/my-courses/refresh/.
    """
    try:
        client = get_edwiser_client()
        user = User.objects.select_related("profile").get(id=user_id)
    except (ValueError, User.DoesNotExist) as e:
        logger.warning("Cannot sync EB enrollments for user %s: %s", user_id, e)
        return {"skipped": True}

    count = _sync_user_enrollments(client, user)
    return {"user_id": user_id, "enrollments": count}


def _sync_user_enrollments(client, user) -> int | None:
    """
    Fetch enrolled courses for a user via Edwiser Bridge using their
    WordPress user ID (UserProfile.wordpress_id).

    EB /my-courses response per course:
      {
        "id": 5988,             <- WP post ID
        "title": "...",
        "thumbnail": "...",
        "link": "...",
        "categories": [...],
        "progress": {
          "percentage": 0,
          "status": "not_started",
          "course_url": "https://imaa-institute.org?mdl_course_id=2",  <- Moodle ID here
          "completed": false
        }
      }

    Returns number of enrollments synced, or None if user has no wordpress_id.
    """
    try:
        profile = user.profile
        # moodle_user_id is repurposed here as the cached imaa-institute.org WP user ID.
        # (Direct Moodle API calls are no longer made; this field is free to reuse.)
        eb_wp_user_id = profile.moodle_user_id
    except Exception:
        profile = None
        eb_wp_user_id = None

    if not eb_wp_user_id:
        # Look up the user on imaa-institute.org by email and cache for future syncs
        eb_wp_user_id = client.get_user_id_by_email(user.email)
        if not eb_wp_user_id:
            logger.debug("User %s not found on imaa-institute.org, skipping", user.email)
            return None
        if profile is not None:
            profile.moodle_user_id = eb_wp_user_id
            profile.save(update_fields=["moodle_user_id"])
            logger.info("Cached EB WP user ID=%d for %s", eb_wp_user_id, user.email)

    eb_courses = client.get_user_courses(eb_wp_user_id)
    synced = 0
    active_course_keys = set()  # track moodle_ids returned by EB API

    for ec in eb_courses:
        wp_course_id = ec.get("id")
        if not wp_course_id:
            continue

        progress_data = ec.get("progress") or {}

        # Extract the Moodle course ID from the EB course_url query param
        # e.g. "https://imaa-institute.org?mdl_course_id=2" → 2
        moodle_id = _parse_moodle_course_id(progress_data.get("course_url"))
        # Fall back to WP post ID if Moodle ID cannot be parsed
        course_key = moodle_id or wp_course_id
        active_course_keys.add(course_key)

        # Resolve local MoodleCourse — minimal create if not yet synced by catalogue task
        course_obj, _ = MoodleCourse.objects.get_or_create(
            moodle_id=course_key,
            defaults={
                "full_name": ec.get("title", "")[:500],
                "short_name": ec.get("title", "")[:255],
                "summary": ec.get("excerpt") or "",
                "image_url": (ec.get("thumbnail") or "")[:1000],
                "moodle_url": (ec.get("link") or progress_data.get("course_url") or "")[:1000],
                "completion_enabled": False,
            },
        )

        # Update image / url if missing on existing record
        updated_fields = []
        if not course_obj.image_url and ec.get("thumbnail"):
            course_obj.image_url = ec["thumbnail"][:1000]
            updated_fields.append("image_url")
        if not course_obj.moodle_url and (ec.get("link") or progress_data.get("course_url")):
            course_obj.moodle_url = (ec.get("link") or progress_data.get("course_url"))[:1000]
            updated_fields.append("moodle_url")
        if updated_fields:
            course_obj.save(update_fields=updated_fields)

        # Progress — EB returns percentage (0–100)
        progress = float(progress_data.get("percentage") or 0.0)
        completed = bool(progress_data.get("completed") or (progress >= 100.0))

        # EB /my-courses does not return last_access
        last_access = None

        # moodle_user_id stores the imaa-institute.org WP user ID (repurposed field, no migration).
        effective_moodle_user_id = eb_wp_user_id or 0

        with transaction.atomic():
            MoodleEnrollment.objects.update_or_create(
                user=user,
                course=course_obj,
                defaults={
                    "moodle_user_id": effective_moodle_user_id,
                    "progress": progress,
                    "completed": completed,
                    "last_access": last_access,
                },
            )
        synced += 1

    # Remove enrollments that are no longer in the EB API response
    # (user was unenrolled from a course on imaa-institute.org)
    deleted, _ = MoodleEnrollment.objects.filter(user=user).exclude(
        course__moodle_id__in=active_course_keys
    ).delete()
    if deleted:
        logger.info(
            "Removed %d stale enrollment(s) for user %s (no longer in EB API)",
            deleted, user.email,
        )

    return synced


# ---------------------------------------------------------------------------
# Course content sync (Moodle REST API)
# ---------------------------------------------------------------------------

@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def sync_course_content(self, course_db_id: int):
    """
    Sync sections and modules for one course from Moodle REST API.
    Called on demand when a user opens the course player.

    Uses MoodleCourse.moodle_id as the Moodle course ID.
    """
    try:
        client = get_moodle_client()
    except ValueError as exc:
        logger.warning("Moodle REST not configured, skipping content sync: %s", exc)
        return {"skipped": True, "reason": str(exc)}

    try:
        course = MoodleCourse.objects.get(pk=course_db_id)
    except MoodleCourse.DoesNotExist:
        logger.warning("Course %d not found, skipping content sync", course_db_id)
        return {"skipped": True}

    return _sync_course_content(client, course)


def _sync_course_content(client, course: MoodleCourse) -> dict:
    """
    Fetch and upsert sections + modules for a course.
    Returns summary dict with section/module counts.
    """
    sections_data = client.get_course_contents(course.moodle_id)
    if not sections_data:
        logger.warning("No content returned for course %d (moodle_id=%d)", course.pk, course.moodle_id)
        return {"sections": 0, "modules": 0}

    section_count = 0
    module_count = 0

    for pos, sec in enumerate(sections_data):
        sec_id = sec.get("id")
        if sec_id is None:
            continue

        sec_name = sec.get("name") or f"Section {pos}"
        # Moodle default section names are numeric strings — replace with topic if blank
        if sec_name.strip().isdigit():
            sec_name = sec.get("section", sec_name)

        section_obj, _ = CourseSection.objects.update_or_create(
            course=course,
            moodle_section_id=sec_id,
            defaults={
                "position": pos,
                "name": str(sec_name)[:500],
                "summary": sec.get("summary") or "",
                "visible": bool(sec.get("visible", True)),
            },
        )
        section_count += 1

        modules_data = sec.get("modules") or []
        for mod_pos, mod in enumerate(modules_data):
            cmid = mod.get("id")
            if not cmid:
                continue

            modname = mod.get("modname") or "other"
            known_types = {"resource", "url", "page", "quiz", "hvp", "label", "assign", "folder", "forum"}
            modtype = modname if modname in known_types else "other"

            # Use uservisible (student perspective) if present; fall back to visible (admin toggle).
            # Store ALL modules regardless — hidden ones show as locked in UI.
            user_visible = mod.get("uservisible")
            if user_visible is None:
                user_visible = bool(mod.get("visible", True))
            else:
                user_visible = bool(user_visible)

            # Extract file content (first downloadable file for resource modules)
            content_url = ""
            content_filename = ""
            content_mimetype = ""
            content_filesize = None

            contents = mod.get("contents") or []
            for c in contents:
                if c.get("type") == "file":
                    raw_url = c.get("fileurl") or ""
                    # Append token if not already present
                    if raw_url and "token=" not in raw_url:
                        sep = "&" if "?" in raw_url else "?"
                        raw_url = f"{raw_url}{sep}token={client.token}"
                    # Remove forcedownload=1 so videos/PDFs open inline instead of downloading
                    if raw_url and "forcedownload=1" in raw_url:
                        parsed = urlparse(raw_url)
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs.pop("forcedownload", None)
                        raw_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                    content_url = raw_url[:2000]
                    content_filename = (c.get("filename") or "")[:500]
                    content_mimetype = (c.get("mimetype") or "")[:200]
                    content_filesize = c.get("filesize")
                    break  # take first file only

            module_url = (mod.get("url") or "")[:2000]

            # For H5P (hvp) modules: construct the Moodle embed URL
            # Moodle doesn't return a file URL for H5P — we build the embed URL from cmid
            if modtype == "hvp" and not module_url and cmid:
                module_url = f"{client.base_url}/mod/hvp/embed.php?id={cmid}"

            with transaction.atomic():
                CourseModule.objects.update_or_create(
                    moodle_module_id=cmid,
                    defaults={
                        "section": section_obj,
                        "name": (mod.get("name") or "")[:500],
                        "modtype": modtype,
                        "position": mod_pos,
                        "visible": user_visible,
                        "module_url": module_url,
                        "content_url": content_url,
                        "content_filename": content_filename,
                        "content_mimetype": content_mimetype,
                        "content_filesize": content_filesize,
                        "completion": mod.get("completion") or 0,
                    },
                )
            module_count += 1

    logger.info(
        "Content sync complete for course %d: %d sections, %d modules",
        course.pk, section_count, module_count,
    )
    return {"sections": section_count, "modules": module_count}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def sync_user_module_completions(self, course_db_id: int, user_id: int):
    """
    Sync per-module completion status for a user in a course from Moodle REST API.
    Called when user opens the course player.
    """
    try:
        client = get_moodle_client()
    except ValueError as exc:
        logger.warning("Moodle REST not configured: %s", exc)
        return {"skipped": True}

    try:
        course = MoodleCourse.objects.get(pk=course_db_id)
        user = User.objects.select_related("profile").get(pk=user_id)
    except (MoodleCourse.DoesNotExist, User.DoesNotExist) as exc:
        logger.warning("Cannot sync completions: %s", exc)
        return {"skipped": True}

    # Look up the real Moodle user ID by email.
    # NOTE: profile.moodle_user_id stores the EB/WordPress user ID (repurposed field),
    # NOT the Moodle LMS user ID — so we must always query Moodle directly here.
    moodle_user_id = client.get_user_id_by_email(user.email)
    if not moodle_user_id:
        logger.debug("Moodle user not found for %s", user.email)
        return {"skipped": True}

    completion_map = client.get_activities_completion(course.moodle_id, moodle_user_id)
    synced = 0

    for cmid, completed in completion_map.items():
        try:
            module = CourseModule.objects.get(moodle_module_id=cmid)
        except CourseModule.DoesNotExist:
            continue
        ModuleCompletion.objects.update_or_create(
            user=user,
            module=module,
            defaults={"completed": completed},
        )
        synced += 1

    logger.info("Synced %d module completions for user %s in course %d", synced, user.email, course.pk)
    return {"synced": synced}
