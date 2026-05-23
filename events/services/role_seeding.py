"""
Service module for seeding default EventRole records.

Handles:
- Creating default event roles when events are created
- Seeding missing roles for existing events
- Preventing duplicate role creation
- Ensuring consistent role configuration across all events
"""
import logging
from events.models import Event, EventRole

logger = logging.getLogger('events')

# Default roles to seed for all events
DEFAULT_ROLES = [
    {
        'key': 'attendee',
        'label': 'Attendee',
        'triggers_promotional_profile': False,
        'visibility': 'public',
        'sort_priority': 10,
    },
    {
        'key': 'speaker',
        'label': 'Speaker',
        'triggers_promotional_profile': True,
        'visibility': 'public',
        'sort_priority': 20,
    },
    {
        'key': 'sponsor',
        'label': 'Sponsor',
        'triggers_promotional_profile': True,
        'visibility': 'public',
        'sort_priority': 30,
    },
    {
        'key': 'sponsor_staff',
        'label': 'Sponsor Staff',
        'triggers_promotional_profile': True,
        'visibility': 'public',
        'sort_priority': 35,
    },
    {
        'key': 'startup',
        'label': 'Start-up',
        'triggers_promotional_profile': True,
        'visibility': 'public',
        'sort_priority': 40,
    },
    {
        'key': 'investor',
        'label': 'Investor',
        'triggers_promotional_profile': True,
        'visibility': 'public',
        'sort_priority': 45,
    },
    {
        'key': 'press',
        'label': 'Press',
        'triggers_promotional_profile': False,
        'visibility': 'public',
        'sort_priority': 50,
    },
    {
        'key': 'researcher',
        'label': 'Researcher',
        'triggers_promotional_profile': False,
        'visibility': 'public',
        'sort_priority': 55,
    },
    {
        'key': 'nominator',
        'label': 'Nominator',
        'triggers_promotional_profile': False,
        'visibility': 'admin_only',
        'sort_priority': 60,
    },
    {
        'key': 'organiser',
        'label': 'Organiser',
        'triggers_promotional_profile': False,
        'visibility': 'admin_only',
        'sort_priority': 65,
    },
    {
        'key': 'moderator',
        'label': 'Moderator',
        'triggers_promotional_profile': False,
        'visibility': 'public',
        'sort_priority': 70,
    },
]


def seed_default_roles_for_event(event):
    """
    Seed default EventRole records for a given event.

    Uses get_or_create by (event, key) to prevent duplicates.
    Only creates missing roles; does not overwrite existing ones.

    Args:
        event (Event): The event to seed roles for

    Returns:
        dict: {
            'created': count of newly created roles,
            'existing': count of roles that already existed,
            'errors': list of error messages
        }
    """
    if not event:
        return {'created': 0, 'existing': 0, 'errors': ['Event is None']}

    stats = {
        'created': 0,
        'existing': 0,
        'errors': []
    }

    for role_data in DEFAULT_ROLES:
        try:
            # Use get_or_create to prevent duplicates
            # Uniqueness is enforced by (event, key) in model Meta
            role, created = EventRole.objects.get_or_create(
                event=event,
                key=role_data['key'],
                defaults={
                    'label': role_data['label'],
                    'triggers_promotional_profile': role_data['triggers_promotional_profile'],
                    'visibility': role_data.get('visibility', 'public'),
                    'sort_priority': role_data.get('sort_priority', 100),
                    'is_system_default': True,
                }
            )

            if created:
                stats['created'] += 1
                logger.info(f"Created default role '{role_data['key']}' for event {event.id}")
            else:
                stats['existing'] += 1

        except Exception as e:
            error_msg = f"Error seeding role '{role_data['key']}' for event {event.id}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            stats['errors'].append(error_msg)

    return stats


def get_or_seed_event_roles(event):
    """
    Get all roles for an event, seeding defaults if none exist.

    This is a fallback mechanism to handle:
    - Existing events created before role seeding was added
    - Edge cases where roles were accidentally deleted
    - API requests for events without roles

    Args:
        event (Event): The event to get/seed roles for

    Returns:
        QuerySet: EventRole.objects.filter(event=event)
    """
    if not event:
        return EventRole.objects.none()

    # Check if event has any roles
    existing_roles = EventRole.objects.filter(event=event)

    if not existing_roles.exists():
        # No roles exist - seed defaults
        logger.info(f"Seeding default roles for event {event.id} (no roles found)")
        seed_default_roles_for_event(event)

    return EventRole.objects.filter(event=event).order_by('sort_priority', 'label')
