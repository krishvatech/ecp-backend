"""User lifecycle signals that create durable CRM events after commit."""

import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .events import (
    USER_CREATED,
    USER_DEACTIVATED,
    USER_UPDATED,
    create_user_sync_events,
)
from .tasks import process_crm_sync_event


logger = logging.getLogger(__name__)
User = get_user_model()

USER_FIELDS = frozenset({"first_name", "last_name", "email", "is_active"})
PROFILE_FIELDS = frozenset(
    {
        "company",
        "job_title",
        "location_country",
        "location_country_code",
        "profile_status",
    }
)
DEACTIVATED_PROFILE_STATUSES = frozenset({"suspended", "deceased", "fake", "deleted"})


def _changed_fields(model, instance, field_names) -> set[str]:
    if not instance.pk:
        return set()
    previous = model.objects.filter(pk=instance.pk).values(*field_names).first()
    if previous is None:
        return set()
    return {
        name
        for name in field_names
        if previous.get(name) != getattr(instance, name, None)
    }


def should_sync_user(user) -> bool:
    if not getattr(settings, "CRM_SYNC_ENABLED", False):
        return False
    if not getattr(user, "pk", None) or getattr(user, "_skip_crm_sync", False):
        return False
    if getattr(user, "is_superuser", False):
        return False
    if getattr(user, "is_staff", False) and not getattr(settings, "CRM_SYNC_STAFF_USERS", False):
        return False

    username = str(getattr(user, "username", "") or "").strip().lower()
    email = str(getattr(user, "email", "") or "").strip().lower()
    if not email or email.endswith("@wordpress.local"):
        return False
    if username.startswith(("loadtest", "test-user", "system-", "service-")):
        return False
    if email.startswith("loadtest") or "loadtest." in email:
        return False

    if not getattr(settings, "CRM_SYNC_IMPORTED_USERS", True):
        try:
            if user.profile.wordpress_id:
                return False
        except (AttributeError, ObjectDoesNotExist):
            pass
    return True


def enqueue_user_sync(user_id: int, event_type: str) -> list[int]:
    """Create durable events and best-effort dispatch them to Celery."""
    user = User.objects.filter(pk=user_id).first()
    if user is None or not should_sync_user(user):
        return []

    events = create_user_sync_events(user, event_type)
    event_ids = []
    for event in events:
        event_ids.append(event.pk)
        try:
            process_crm_sync_event.delay(event.pk)
        except Exception:
            # The pending database event is the recovery mechanism. Never make
            # account creation/update fail because the broker is unavailable.
            logger.exception(
                "Could not dispatch CRM event_id=%s; event remains pending",
                event.pk,
            )
    return event_ids


def schedule_user_sync(user_id: int, event_type: str) -> None:
    def _after_commit():
        try:
            enqueue_user_sync(user_id, event_type)
        except Exception:
            logger.exception(
                "Could not create CRM event for user_id=%s event_type=%s",
                user_id,
                event_type,
            )

    transaction.on_commit(_after_commit)


@receiver(pre_save, sender=User, dispatch_uid="crm_integrations.user_pre_save")
def capture_user_crm_changes(sender, instance, raw=False, **kwargs):
    instance._crm_changed_fields = set() if raw else _changed_fields(sender, instance, USER_FIELDS)


@receiver(post_save, sender=User, dispatch_uid="crm_integrations.user_post_save")
def schedule_user_crm_event(sender, instance, created, raw=False, **kwargs):
    if raw or not should_sync_user(instance):
        return
    if created:
        event_type = USER_CREATED
    else:
        changed = getattr(instance, "_crm_changed_fields", set())
        if not changed:
            return
        event_type = USER_DEACTIVATED if "is_active" in changed and not instance.is_active else USER_UPDATED
    schedule_user_sync(instance.pk, event_type)


@receiver(pre_save, sender="users.UserProfile", dispatch_uid="crm_integrations.profile_pre_save")
def capture_profile_crm_changes(sender, instance, raw=False, **kwargs):
    instance._crm_changed_fields = set() if raw else _changed_fields(sender, instance, PROFILE_FIELDS)


@receiver(post_save, sender="users.UserProfile", dispatch_uid="crm_integrations.profile_post_save")
def schedule_profile_crm_event(sender, instance, created, raw=False, **kwargs):
    if raw or created or not should_sync_user(instance.user):
        return
    changed = getattr(instance, "_crm_changed_fields", set())
    if not changed:
        return
    event_type = (
        USER_DEACTIVATED
        if "profile_status" in changed
        and instance.profile_status in DEACTIVATED_PROFILE_STATUSES
        else USER_UPDATED
    )
    schedule_user_sync(instance.user_id, event_type)
