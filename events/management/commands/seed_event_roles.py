"""
Management command to seed EventRole models for all events and backfill registrations.

Usage:
    python manage.py seed_event_roles
    python manage.py seed_event_roles --event-id 123
    python manage.py seed_event_roles --backfill-only
    python manage.py seed_event_roles --event-id 123 --backfill-only
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from events.models import Event, EventRole, EventRegistration
import logging

logger = logging.getLogger(__name__)

# Default roles to seed for each event
DEFAULT_ROLES = [
    {
        'key': 'attendee',
        'label': 'Attendee',
        'description': 'Regular event participant',
        'visibility': 'admin_only',
        'sort_priority': 100,
        'badge_color': '#6366f1',
        'badge_style': 'default',
        'triggers_promotional_profile': False,
    },
    {
        'key': 'speaker',
        'label': 'Speaker',
        'description': 'Event speaker or presenter',
        'visibility': 'public',
        'sort_priority': 10,
        'badge_color': '#f59e0b',
        'badge_style': 'filled',
        'triggers_promotional_profile': True,
    },
    {
        'key': 'sponsor',
        'label': 'Sponsor',
        'description': 'Event sponsor or partner',
        'visibility': 'public',
        'sort_priority': 20,
        'badge_color': '#8b5cf6',
        'badge_style': 'filled',
        'triggers_promotional_profile': True,
    },
    {
        'key': 'sponsor_staff',
        'label': 'Sponsor Staff',
        'description': 'Staff member from sponsor organization',
        'visibility': 'public',
        'sort_priority': 25,
        'badge_color': '#a78bfa',
        'badge_style': 'filled',
        'triggers_promotional_profile': True,
    },
    {
        'key': 'press',
        'label': 'Press',
        'description': 'Media or press representative',
        'visibility': 'public',
        'sort_priority': 30,
        'badge_color': '#ec4899',
        'badge_style': 'outlined',
        'triggers_promotional_profile': False,
    },
    {
        'key': 'startup',
        'label': 'Start-up',
        'description': 'Start-up founder or representative',
        'visibility': 'public',
        'sort_priority': 35,
        'badge_color': '#06b6d4',
        'badge_style': 'filled',
        'triggers_promotional_profile': True,
    },
    {
        'key': 'investor',
        'label': 'Investor',
        'description': 'Angel investor or venture capitalist',
        'visibility': 'public',
        'sort_priority': 40,
        'badge_color': '#10b981',
        'badge_style': 'filled',
        'triggers_promotional_profile': True,
    },
    {
        'key': 'researcher',
        'label': 'Researcher',
        'description': 'Academic or research professional',
        'visibility': 'public',
        'sort_priority': 50,
        'badge_color': '#6366f1',
        'badge_style': 'outlined',
        'triggers_promotional_profile': False,
    },
    {
        'key': 'nominator',
        'label': 'Nominator',
        'description': 'Nominator for event awards or selection',
        'visibility': 'admin_only',
        'sort_priority': 60,
        'badge_color': '#ef4444',
        'badge_style': 'outlined',
        'triggers_promotional_profile': False,
    },
    {
        'key': 'organiser',
        'label': 'Organiser',
        'description': 'Event organizer or team member',
        'visibility': 'public',
        'sort_priority': 5,
        'badge_color': '#dc2626',
        'badge_style': 'filled',
        'triggers_promotional_profile': False,
    },
]


class Command(BaseCommand):
    help = 'Seed default EventRole models for all events and backfill existing registrations with Attendee role'

    def add_arguments(self, parser):
        parser.add_argument(
            '--event-id',
            type=int,
            help='Seed roles for a specific event ID (optional)'
        )
        parser.add_argument(
            '--backfill-only',
            action='store_true',
            help='Only backfill existing registrations, do not create new roles'
        )

    def handle(self, *args, **options):
        event_id = options.get('event_id')
        backfill_only = options.get('backfill_only', False)

        # Determine which events to process
        if event_id:
            events = Event.objects.filter(id=event_id)
            if not events.exists():
                raise CommandError(f'Event with ID {event_id} not found')
        else:
            events = Event.objects.all()

        self.stdout.write(self.style.SUCCESS(f'Processing {events.count()} event(s)...'))

        with transaction.atomic():
            # Seed roles for each event
            if not backfill_only:
                self.stdout.write('Creating default roles...')
                roles_created = 0
                for event in events:
                    for role_def in DEFAULT_ROLES:
                        role, created = EventRole.objects.get_or_create(
                            event=event,
                            key=role_def['key'],
                            defaults={
                                'label': role_def['label'],
                                'description': role_def['description'],
                                'visibility': role_def['visibility'],
                                'sort_priority': role_def['sort_priority'],
                                'badge_color': role_def['badge_color'],
                                'badge_style': role_def['badge_style'],
                                'triggers_promotional_profile': role_def['triggers_promotional_profile'],
                                'is_system_default': True,
                            }
                        )
                        if created:
                            roles_created += 1
                self.stdout.write(self.style.SUCCESS(f'Created {roles_created} new roles'))

            # Backfill existing registrations with Attendee role
            self.stdout.write('Backfilling existing registrations with Attendee role...')
            registrations_updated = 0
            for event in events:
                # Get or create the Attendee role for this event
                attendee_role, _ = EventRole.objects.get_or_create(
                    event=event,
                    key='attendee',
                    defaults={
                        'label': 'Attendee',
                        'description': 'Regular event participant',
                        'visibility': 'admin_only',
                        'sort_priority': 100,
                        'badge_color': '#6366f1',
                        'badge_style': 'default',
                        'triggers_promotional_profile': False,
                        'is_system_default': True,
                    }
                )

                # Add Attendee role to all registrations that don't have any roles yet
                registrations = EventRegistration.objects.filter(
                    event=event
                ).exclude(
                    roles__isnull=False  # This excludes registrations that already have roles
                )

                for registration in registrations:
                    registration.roles.add(attendee_role)
                    registrations_updated += 1

            self.stdout.write(self.style.SUCCESS(f'Backfilled {registrations_updated} registrations with Attendee role'))

        self.stdout.write(self.style.SUCCESS('EventRole seeding completed successfully!'))
