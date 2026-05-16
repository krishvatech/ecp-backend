"""
Management command to backfill Participant badges for existing registrations.

Assigns the default "Participant" badge to all registrations that:
1. Have no existing badge labels
2. Have status='registered' and attendee_status='confirmed'

Usage:
    python manage.py backfill_participant_badges
    python manage.py backfill_participant_badges --event-id=123
    python manage.py backfill_participant_badges --dry-run
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from events.models import Event, EventRegistration


class Command(BaseCommand):
    help = 'Backfill Participant badges for existing event registrations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--event-id',
            type=int,
            help='Specific event ID to backfill (if not provided, all events are processed)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be updated without making changes',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🏷️  Backfilling Participant Badges\n'))

        event_id = options.get('event_id')
        dry_run = options.get('dry_run')

        # Get events to process
        if event_id:
            try:
                events = Event.objects.filter(id=event_id)
                if not events.exists():
                    self.stdout.write(self.style.ERROR(f'❌ Event with ID {event_id} not found'))
                    return
                self.stdout.write(f'Processing event ID: {event_id}')
            except Event.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'❌ Event with ID {event_id} not found'))
                return
        else:
            events = Event.objects.all()
            self.stdout.write(f'Processing all {events.count()} events')

        total_updated = 0
        total_skipped = 0
        total_errors = 0

        with transaction.atomic():
            for event in events:
                self.stdout.write(f'\n📍 Processing event: {event.title} (ID: {event.id})')

                # Find registrations with no badges
                registrations_without_badges = EventRegistration.objects.filter(
                    event=event,
                    status='registered',
                    attendee_status='confirmed',
                ).exclude(badge_labels__isnull=False)

                count = registrations_without_badges.count()
                if count == 0:
                    self.stdout.write(self.style.WARNING(f'   ⏭️  No registrations without badges'))
                    continue

                self.stdout.write(f'   Found {count} registrations without badges')

                # Get or create Participant badge
                try:
                    participant_badge = event.get_or_create_participant_badge()
                    badge_created = participant_badge.pk is not None
                    self.stdout.write(
                        f'   {"✅ Created" if badge_created else "✓ Using existing"} '
                        f'Participant badge (ID: {participant_badge.id})'
                    )
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'   ❌ Error creating badge: {e}'))
                    total_errors += 1
                    continue

                # Assign badge to registrations
                for registration in registrations_without_badges:
                    try:
                        if not dry_run:
                            registration.badge_labels.add(participant_badge)
                        total_updated += 1
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(
                                f'   ❌ Error assigning badge to registration {registration.id}: {e}'
                            )
                        )
                        total_errors += 1

                if dry_run:
                    self.stdout.write(self.style.WARNING(f'   [DRY RUN] Would assign badge to {count} registrations'))
                    total_updated += count
                else:
                    self.stdout.write(self.style.SUCCESS(f'   ✅ Assigned badge to {count} registrations'))

        # Summary
        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(self.style.SUCCESS(f'✅ Summary:'))
        self.stdout.write(f'   Updated: {total_updated}')
        self.stdout.write(f'   Errors: {total_errors}')
        if dry_run:
            self.stdout.write(self.style.WARNING('   [DRY RUN MODE - No changes were made]'))
