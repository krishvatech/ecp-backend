"""
Management command to seed default pricing tiers for EventApplicationTrack.

Usage:
    python manage.py seed_track_pricing_tiers                      # Seed all tracks
    python manage.py seed_track_pricing_tiers --track-id 123       # Seed specific track
    python manage.py seed_track_pricing_tiers --track-key speaker  # Seed by track key
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from events.models import EventApplicationTrack, TrackPricingTier


class Command(BaseCommand):
    help = 'Seed default pricing tiers for application tracks'

    def add_arguments(self, parser):
        parser.add_argument(
            '--track-id',
            type=int,
            help='Seed tiers for specific track ID'
        )
        parser.add_argument(
            '--track-key',
            type=str,
            help='Seed tiers for specific track key'
        )

    # Default pricing tier definitions
    DEFAULT_TIERS = [
        {
            'key': 'standard',
            'label': 'Standard Ticket',
            'price': 199.00,
            'currency': 'USD',
            'description': 'Standard admission to the event',
            'sort_order': 10,
            'is_default': True,
        },
        {
            'key': 'qualified_pass',
            'label': 'Qualified Attendee Pass',
            'price': 149.00,
            'currency': 'USD',
            'description': 'Special pricing for qualified attendees (students, non-profits)',
            'sort_order': 20,
            'is_default': False,
        },
        {
            'key': 'early_career',
            'label': 'Early Career',
            'price': 99.00,
            'currency': 'USD',
            'description': 'Reduced pricing for early career professionals',
            'sort_order': 30,
            'is_default': False,
        },
        {
            'key': 'academic',
            'label': 'Academic / Student',
            'price': 49.00,
            'currency': 'USD',
            'description': 'Special pricing for students and academic researchers',
            'sort_order': 40,
            'is_default': False,
        },
        {
            'key': 'press',
            'label': 'Press Pass',
            'price': 0.00,
            'currency': 'USD',
            'description': 'Complimentary pass for media and press representatives',
            'sort_order': 50,
            'is_default': False,
            'visibility': 'hidden',
        },
        {
            'key': 'speaker_comp',
            'label': 'Speaker Complimentary',
            'price': 0.00,
            'currency': 'USD',
            'description': 'Complimentary admission for event speakers',
            'sort_order': 60,
            'is_default': False,
            'visibility': 'hidden',
        },
        {
            'key': 'sponsor_allocation',
            'label': 'Sponsor Allocation',
            'price': 0.00,
            'currency': 'USD',
            'description': 'Complimentary passes allocated by sponsors',
            'sort_order': 70,
            'is_default': False,
            'visibility': 'hidden',
        },
    ]

    @transaction.atomic
    def handle(self, *args, **options):
        track_id = options.get('track_id')
        track_key = options.get('track_key')

        # Determine which tracks to seed
        if track_id:
            try:
                tracks = [EventApplicationTrack.objects.get(id=track_id)]
            except EventApplicationTrack.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'Track with ID {track_id} not found'))
                return
        elif track_key:
            tracks = list(EventApplicationTrack.objects.filter(key=track_key))
            if not tracks:
                self.stdout.write(self.style.ERROR(f'No tracks with key "{track_key}" found'))
                return
        else:
            tracks = list(EventApplicationTrack.objects.all())

        total_created = 0

        for track in tracks:
            self.stdout.write(f'\nProcessing track: {track.label} (ID: {track.id}, Key: {track.key})')

            for tier_data in self.DEFAULT_TIERS:
                # Check if tier already exists
                tier_exists = TrackPricingTier.objects.filter(
                    track=track,
                    key=tier_data['key']
                ).exists()

                if tier_exists:
                    self.stdout.write(f'  ⊘ Tier "{tier_data["key"]}" already exists, skipping')
                    continue

                # Create the tier
                tier = TrackPricingTier.objects.create(
                    track=track,
                    key=tier_data['key'],
                    label=tier_data['label'],
                    price=tier_data['price'],
                    currency=tier_data['currency'],
                    description=tier_data.get('description', ''),
                    sort_order=tier_data['sort_order'],
                    is_default=tier_data.get('is_default', False),
                    visibility=tier_data.get('visibility', 'public'),
                )

                status = '✓ Created'
                if tier.is_default:
                    status += ' (DEFAULT)'
                if tier.price == 0:
                    status += ' [FREE]'

                self.stdout.write(f'  {status}: {tier.label} (${tier.price})')
                total_created += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'\n✅ Successfully seeded {total_created} pricing tiers across {len(tracks)} track(s)'
            )
        )
