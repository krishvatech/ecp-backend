from django.db.models.signals import post_save, pre_delete, pre_save, post_migrate
from django.dispatch import receiver
from django.db import transaction
from .models import Event, EventParticipant, PostAcceptanceFormTemplate, EventRegistration
from .saleor_sync import sync_event_to_saleor_sync, delete_event_from_saleor
from .services.post_acceptance_forms import is_online_event, trigger_post_acceptance_forms
from .services.role_seeding import seed_default_roles_for_event
import threading
import logging

logger = logging.getLogger(__name__)
from .models import Event, EventParticipant


@receiver(post_migrate)
def ensure_default_event_platforms(sender, app_config=None, **kwargs):
    """Create default event platforms automatically after migrations.

    This avoids requiring a separate seed command when a developer pulls the same
    code and runs migrate. Existing events are backfilled to IMAA Connect so they
    keep showing in the current IMAA Connect UI.
    """
    if not app_config or app_config.name != "events":
        return

    try:
        from django.apps import apps

        EventModel = apps.get_model("events", "Event")
        EventPlatform = apps.get_model("events", "EventPlatform")
        EventPublication = apps.get_model("events", "EventPublication")
    except Exception:
        return

    defaults = [
        ("imaa_connect", "IMAA Connect", 10),
        ("manda", "MANDA", 20),
    ]
    platforms = {}
    for slug, name, display_order in defaults:
        platform, _ = EventPlatform.objects.update_or_create(
            slug=slug,
            defaults={
                "name": name,
                "is_active": True,
                "display_order": display_order,
            },
        )
        platforms[slug] = platform

    imaa_platform = platforms.get("imaa_connect")
    if imaa_platform:
        existing_event_ids = set(
            EventPublication.objects.filter(platform=imaa_platform).values_list("event_id", flat=True)
        )
        EventPublication.objects.bulk_create(
            [
                EventPublication(event_id=event_id, platform=imaa_platform, is_enabled=True)
                for event_id in EventModel.objects.exclude(id__in=existing_event_ids).values_list("id", flat=True)
            ],
            ignore_conflicts=True,
        )


@receiver(post_save, sender=Event)
def seed_event_roles_signal(sender, instance, created, **kwargs):
    """
    Automatically seed default EventRole records when a new Event is created.

    This ensures every event has a standard set of roles available for application tracks.
    Only runs on event creation (created=True), not on updates.
    """
    if not created:
        return  # Only seed on creation, not updates

    # Seed roles in background after transaction commits
    def seed_roles():
        try:
            stats = seed_default_roles_for_event(instance)
            logger.info(f"Seeded roles for event {instance.id}: created={stats['created']}, existing={stats['existing']}")
        except Exception as e:
            logger.error(f"Failed to seed roles for event {instance.id}: {e}", exc_info=True)

    transaction.on_commit(seed_roles)


@receiver(post_save, sender=Event)
def sync_event_to_saleor_signal(sender, instance, created, **kwargs):
    """
    Trigger async Saleor sync when an Event is saved.
    Runs in background Celery task, not blocking the request.
    Only queues if SALEOR_ENABLED is True.
    """
    from django.conf import settings
    if not getattr(settings, "SALEOR_ENABLED", False):
        return

    # Check if we are saving because of the sync itself
    if getattr(instance, "skip_saleor_sync", False):
        return

    # Check if we are saving because of the sync itself (backwards compat/fallback)
    update_fields = kwargs.get("update_fields")
    if update_fields and ("saleor_product_id" in update_fields or "saleor_variant_id" in update_fields):
        return

    # Queue async task to sync to Saleor after transaction commits
    def queue_sync_task():
        from .tasks import sync_event_to_saleor_async
        try:
            sync_event_to_saleor_async.delay(instance.id)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to queue Saleor sync task for event {instance.id}: {e}")

    transaction.on_commit(queue_sync_task)


@receiver(post_save, sender=Event)
def invalidate_event_list_cache_signal(sender, instance, **kwargs):
    """
    Invalidate event list caches when an Event is modified.
    Ensures users see updated event data within the next cache refresh.
    """
    from .cache_utils import invalidate_event_list_caches
    try:
        invalidate_event_list_caches(instance.id)
    except Exception as e:
        logger.warning(f"Failed to invalidate event list cache for event {instance.id}: {e}")


@receiver(post_save, sender=EventParticipant)
def send_event_confirmation_on_create(sender, instance, created, **kwargs):
    """
    Send event confirmation email when a new EventParticipant is created.
    Only sends for staff participants (users with accounts).
    Uses on_commit callback to ensure participant is fully saved before queuing task.
    """
    if not created:
        return  # Only send on creation, not updates

    # Only send to staff participants (users with accounts)
    if instance.participant_type != EventParticipant.PARTICIPANT_TYPE_STAFF:
        return

    if not instance.user or not instance.user.email:
        return

    # Import here to avoid circular imports
    from users.task import send_event_confirmation_task

    # Queue email task AFTER transaction commits (ensures participant is saved)
    def queue_email():
        try:
            send_event_confirmation_task.delay(instance.id)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(
                f"Failed to queue event confirmation email for participant {instance.id}: {e}"
            )

    transaction.on_commit(queue_email)


@receiver(post_save, sender=Event)
def create_post_acceptance_forms_for_event(sender, instance, created, **kwargs):
    """
    Automatically create form templates for in-person and hybrid events.
    This signal runs after an event is created or updated.

    For in-person/hybrid events, creates:
    - Participant Information Form (required for all attendees)
    """
    # Only create forms for in-person or hybrid events
    if is_online_event(instance):
        return

    try:
        # Default form schema for Participant Information
        # Sections are conditional based on event format (see frontend for show/hide logic)
        participant_schema = {
            "sections": [
                {
                    "id": "attendance",
                    "title": "Attendance Information",
                    "showOnlyForHybrid": True,
                    "description": "How will you attend this event?",
                    "fields": [
                        {
                            "id": "attendance_mode",
                            "type": "select",
                            "label": "Will you attend in person or online?",
                            "required": True,
                            "showOnlyForHybrid": True,
                            "options": [
                                {"value": "", "label": "Select an option"},
                                {"value": "in_person", "label": "In person"},
                                {"value": "online", "label": "Online"}
                            ]
                        }
                    ]
                },
                {
                    "id": "accessibility",
                    "title": "Accessibility & Support",
                    "description": "Tell us about any accessibility needs or support you may need",
                    "fields": [
                        {
                            "id": "accessibility_support_needs",
                            "type": "select",
                            "label": "Do you have any accessibility, medical, or other support needs we should be aware of?",
                            "required": True,
                            "options": [
                                {"value": "", "label": "Select an option"},
                                {"value": "yes", "label": "Yes"},
                                {"value": "no", "label": "No"},
                                {"value": "prefer_not_to_say", "label": "Prefer not to say"}
                            ]
                        },
                        {
                            "id": "accessibility_needs_detail",
                            "type": "textarea",
                            "label": "Please describe your accessibility needs",
                            "required": False,
                            "restricted": True,
                            "showIfValue": {"field": "accessibility_support_needs", "value": "yes"}
                        },
                        {
                            "id": "mobility_seating_requirements",
                            "type": "textarea",
                            "label": "Mobility or seating requirements",
                            "required": False,
                            "restricted": True,
                            "showIfValue": {"field": "accessibility_support_needs", "value": "yes"}
                        },
                        {
                            "id": "medical_info_emergency",
                            "type": "textarea",
                            "label": "Relevant medical information for emergencies only",
                            "required": False,
                            "restricted": True,
                            "showIfValue": {"field": "accessibility_support_needs", "value": "yes"}
                        }
                    ]
                },
                {
                    "id": "emergency_contact",
                    "title": "Emergency Contact",
                    "showOnlyForPhysical": True,
                    "description": "In case of emergency during the event",
                    "fields": [
                        {
                            "id": "emergency_contact_name",
                            "type": "text",
                            "label": "Emergency contact name",
                            "required": True,
                            "restricted": True
                        },
                        {
                            "id": "emergency_contact_phone",
                            "type": "tel",
                            "label": "Emergency contact phone",
                            "required": True,
                            "restricted": True
                        },
                        {
                            "id": "emergency_contact_relationship",
                            "type": "select",
                            "label": "Relationship to you",
                            "required": True,
                            "restricted": True,
                            "options": [
                                {"value": "", "label": "Select an option"},
                                {"value": "parent", "label": "Parent"},
                                {"value": "guardian", "label": "Guardian"},
                                {"value": "partner_spouse", "label": "Partner/Spouse"},
                                {"value": "sibling", "label": "Sibling"},
                                {"value": "other_family", "label": "Other family member"},
                                {"value": "friend", "label": "Friend"},
                                {"value": "colleague", "label": "Colleague"},
                                {"value": "other", "label": "Other"}
                            ]
                        },
                        {
                            "id": "emergency_contact_relationship_other",
                            "type": "text",
                            "label": "Please specify relationship",
                            "required": True,
                            "restricted": True,
                            "showIfValue": {"field": "emergency_contact_relationship", "value": "other"}
                        }
                    ]
                },
                {
                    "id": "food_requirements",
                    "title": "Food Requirements",
                    "showOnlyForPhysical": True,
                    "description": "Let us know about any dietary restrictions or preferences",
                    "fields": [
                        {
                            "id": "food_allergies",
                            "type": "multi_select",
                            "label": "Food allergies or intolerances",
                            "required": False,
                            "restricted": True,
                            "options": [
                                {"value": "none", "label": "None"},
                                {"value": "nuts", "label": "Nuts"},
                                {"value": "dairy", "label": "Dairy"},
                                {"value": "gluten", "label": "Gluten"},
                                {"value": "shellfish", "label": "Shellfish"},
                                {"value": "eggs", "label": "Eggs"},
                                {"value": "soy", "label": "Soy"},
                                {"value": "sesame", "label": "Sesame"},
                                {"value": "other", "label": "Other"}
                            ]
                        },
                        {
                            "id": "food_allergies_other",
                            "type": "text",
                            "label": "Please specify other allergies",
                            "required": False,
                            "restricted": True,
                            "showIfIncludes": {"field": "food_allergies", "value": "other"}
                        },
                        {
                            "id": "dietary_restrictions",
                            "type": "multi_select",
                            "label": "Dietary restrictions or preferences",
                            "required": False,
                            "restricted": True,
                            "options": [
                                {"value": "none", "label": "None"},
                                {"value": "vegetarian", "label": "Vegetarian"},
                                {"value": "vegan", "label": "Vegan"},
                                {"value": "halal", "label": "Halal"},
                                {"value": "kosher", "label": "Kosher"},
                                {"value": "pescatarian", "label": "Pescatarian"},
                                {"value": "no_pork", "label": "No pork"},
                                {"value": "no_beef", "label": "No beef"},
                                {"value": "other", "label": "Other"}
                            ]
                        },
                        {
                            "id": "dietary_restrictions_other",
                            "type": "text",
                            "label": "Please specify other restrictions",
                            "required": False,
                            "restricted": True,
                            "showIfIncludes": {"field": "dietary_restrictions", "value": "other"}
                        },
                        {
                            "id": "food_notes",
                            "type": "textarea",
                            "label": "Additional notes about your food requirements",
                            "required": False,
                            "restricted": True
                        }
                    ]
                },
                {
                    "id": "privacy_permissions",
                    "title": "Privacy & Permissions",
                    "description": "Help us understand your preferences for sharing and photography",
                    "fields": [
                        {
                            "id": "share_contact_details",
                            "type": "select",
                            "label": "May we share your contact details with other participants?",
                            "required": True,
                            "options": [
                                {"value": "", "label": "Select an option"},
                                {"value": "yes", "label": "Yes"},
                                {"value": "no", "label": "No"}
                            ]
                        },
                        {
                            "id": "photo_video_consent",
                            "type": "select",
                            "label": "Photography and video consent",
                            "required": True,
                            "options": [
                                {"value": "", "label": "Select an option"},
                                {"value": "yes", "label": "Yes"},
                                {"value": "no", "label": "No"}
                            ]
                        }
                    ]
                },
                {
                    "id": "travel_information",
                    "title": "Travel Information",
                    "showOnlyForPhysical": True,
                    "description": "Help us support your travel arrangements",
                    "fields": [
                        {
                            "id": "travel_arrival_details",
                            "type": "textarea",
                            "label": "Arrival details (date and time)",
                            "required": False
                        },
                        {
                            "id": "travel_departure_details",
                            "type": "textarea",
                            "label": "Departure details (date and time)",
                            "required": False
                        },
                        {
                            "id": "visa_support",
                            "type": "select",
                            "label": "Do you need visa support?",
                            "required": False,
                            "options": [
                                {"value": "", "label": "Select an option"},
                                {"value": "not_required", "label": "Not required"},
                                {"value": "required", "label": "Required"},
                                {"value": "not_yet_sure", "label": "Not yet sure"}
                            ]
                        },
                        {
                            "id": "visa_support_details",
                            "type": "textarea",
                            "label": "What documentation or support do you need?",
                            "required": False,
                            "showIfInList": {"field": "visa_support", "values": ["required", "not_yet_sure"]}
                        }
                    ]
                }
            ]
        }

        # Create or get Participant Information form
        form, form_created = PostAcceptanceFormTemplate.objects.get_or_create(
            event=instance,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            defaults={
                'title': 'Participant Information Form',
                'description': 'Help us plan a better event by sharing your attendance preferences and requirements.',
                'question_schema': participant_schema,
                'is_enabled': True,
                'deadline_days': 7
            }
        )

        if form_created:
            logger.info(
                f"✓ Auto-created Participant Information Form for event '{instance.title}' (id={instance.id})"
            )
        else:
            # Update existing form to ensure it has the schema (in case it was created before)
            if not form.question_schema:
                form.question_schema = participant_schema
                form.save(update_fields=['question_schema'])
                logger.info(
                    f"✓ Updated Participant Information Form schema for event '{instance.title}' (id={instance.id})"
                )

    except Exception as e:
        logger.error(
            f"Failed to create post-acceptance forms for event '{instance.title}' (id={instance.id}): {str(e)}",
            exc_info=True
        )


@receiver(pre_delete, sender=Event)
def delete_event_from_saleor_signal(sender, instance, **kwargs):
    """
    Queue async task to delete Saleor product when event is deleted.
    Runs in background Celery task, not blocking the request.
    Only queues if SALEOR_ENABLED is True.
    """
    from django.conf import settings
    if not getattr(settings, "SALEOR_ENABLED", False):
        return

    from .tasks import delete_event_from_saleor_async
    try:
        delete_event_from_saleor_async.delay(instance.id)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(
            f"Failed to queue Saleor deletion task for event {instance.id}: {e}"
        )


# FIX 7: Use pre_save to track previous status, then check in post_save
@receiver(pre_save, sender=EventRegistration)
def mark_previous_status(sender, instance, **kwargs):
    """Mark the previous attendee_status before saving."""
    if instance.pk:
        try:
            previous = EventRegistration.objects.get(pk=instance.pk)
            instance._previous_attendee_status = previous.attendee_status
        except EventRegistration.DoesNotExist:
            instance._previous_attendee_status = None
    else:
        instance._previous_attendee_status = None


@receiver(post_save, sender=EventRegistration)
def trigger_forms_on_registration_confirmed(sender, instance, created, **kwargs):
    """
    Trigger post-acceptance form assignments when registration transitions to confirmed.

    Only triggers if:
    - New registration created with attendee_status='confirmed', OR
    - Existing registration status changed to 'confirmed'

    FIX 7: Uses pre_save marker to detect actual status transition.
    """
    # Guard: only process if status is confirmed
    if instance.attendee_status != 'confirmed':
        return

    # Check if this is a status transition
    is_transition = False
    if created:
        is_transition = True
    else:
        # FIX 7: Check the previous status we marked in pre_save
        previous_status = getattr(instance, '_previous_attendee_status', None)
        is_transition = previous_status != 'confirmed'

    # Skip if this isn't actually a transition to confirmed
    if not is_transition:
        return

    # Queue form triggers after commit to ensure registration is persisted
    def trigger_forms():
        try:
            from events.services.post_acceptance_forms import trigger_post_acceptance_forms
            trigger_post_acceptance_forms(instance)
        except Exception as e:
            logger.error(
                f"Failed to trigger post-acceptance forms for registration {instance.id}: {e}",
                exc_info=True
            )
            # Don't fail the registration - continue normally

    transaction.on_commit(trigger_forms)
