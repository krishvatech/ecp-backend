"""
Management command to seed EventApplicationTrack models for all events and backfill registrations.

Usage:
    python manage.py seed_event_application_tracks
    python manage.py seed_event_application_tracks --event-id 123
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from events.models import Event, EventApplicationTrack
import logging

logger = logging.getLogger(__name__)

# Standard application tracks to seed for each event
# Phase 13: Updated submission modes to new taxonomy:
#   - self_submission: Applicant submits themselves (standard form)
#   - confirmed: Confirmed/pre-approved applicant (organization/partner confirmed)
#   - self_nomination: Self-nominated without verification
#   - third_party_nomination: Nominated by someone else
DEFAULT_TRACKS = [
    {
        'key': 'participant',
        'label': 'Participant',
        'short_description': 'General event participant',
        'status': 'open',
        'sort_order': 100,
        'is_active': True,
        'enabled_submission_modes': ['self_submission', 'confirmed'],
        'role_mappings_on_acceptance': ['attendee'],
        'content_surfaces': ['event_page', 'email'],
        'is_system_default': True,
    },
    {
        'key': 'speaker',
        'label': 'Speaker',
        'short_description': 'Speakers and presenters for the event',
        'status': 'open',
        'sort_order': 10,
        'is_active': True,
        'enabled_submission_modes': ['self_submission', 'confirmed', 'third_party_nomination'],
        'role_mappings_on_acceptance': ['speaker', 'attendee'],
        'content_surfaces': ['event_page', 'email', 'application_modal'],
        'is_system_default': True,
    },
    {
        'key': 'startup',
        'label': 'Start-up',
        'short_description': 'Start-up founders and teams',
        'status': 'open',
        'sort_order': 20,
        'is_active': True,
        'enabled_submission_modes': ['self_submission', 'confirmed'],
        'role_mappings_on_acceptance': ['startup', 'attendee'],
        'content_surfaces': ['event_page', 'email', 'application_modal'],
        'is_system_default': True,
    },
    {
        'key': 'investment_opportunity',
        'label': 'Investment Opportunity',
        'short_description': 'Investment opportunities and opportunities to pitch',
        'status': 'open',
        'sort_order': 30,
        'is_active': True,
        'enabled_submission_modes': ['self_submission', 'third_party_nomination'],
        'role_mappings_on_acceptance': ['investor', 'attendee'],
        'content_surfaces': ['event_page', 'email'],
        'is_system_default': True,
    },
    {
        'key': 'research',
        'label': 'Research',
        'short_description': 'Research presentations and academic contributions',
        'status': 'open',
        'sort_order': 40,
        'is_active': True,
        'enabled_submission_modes': ['self_submission', 'confirmed'],
        'role_mappings_on_acceptance': ['researcher', 'attendee'],
        'content_surfaces': ['event_page', 'email'],
        'is_system_default': True,
    },
    {
        'key': 'sponsor',
        'label': 'Sponsor',
        'short_description': 'Sponsorship and partnership opportunities',
        'status': 'open',
        'sort_order': 50,
        'is_active': True,
        'enabled_submission_modes': ['self_submission', 'third_party_nomination'],
        'role_mappings_on_acceptance': ['sponsor', 'sponsor_staff', 'attendee'],
        'content_surfaces': ['event_page', 'email', 'application_modal'],
        'is_system_default': True,
    },
]


class Command(BaseCommand):
    help = 'Seed default EventApplicationTrack models for all events'

    def add_arguments(self, parser):
        parser.add_argument(
            '--event-id',
            type=int,
            help='Seed tracks for a specific event ID (optional)'
        )

    def handle(self, *args, **options):
        event_id = options.get('event_id')

        # Determine which events to process
        if event_id:
            events = Event.objects.filter(id=event_id)
            if not events.exists():
                raise CommandError(f'Event with ID {event_id} not found')
        else:
            events = Event.objects.all()

        self.stdout.write(self.style.SUCCESS(f'Processing {events.count()} event(s)...'))

        with transaction.atomic():
            tracks_created = 0
            for event in events:
                for track_def in DEFAULT_TRACKS:
                    track, created = EventApplicationTrack.objects.get_or_create(
                        event=event,
                        key=track_def['key'],
                        defaults={
                            'label': track_def['label'],
                            'short_description': track_def['short_description'],
                            'status': track_def['status'],
                            'sort_order': track_def['sort_order'],
                            'is_active': track_def['is_active'],
                            'enabled_submission_modes': track_def['enabled_submission_modes'],
                            'role_mappings_on_acceptance': track_def['role_mappings_on_acceptance'],
                            'content_surfaces': track_def['content_surfaces'],
                            'is_system_default': True,
                        }
                    )
                    if created:
                        tracks_created += 1

            self.stdout.write(self.style.SUCCESS(f'Created {tracks_created} new application tracks'))

        self.stdout.write(self.style.SUCCESS('EventApplicationTrack seeding completed successfully!'))
