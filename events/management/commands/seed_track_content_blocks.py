"""
Management command to seed default content blocks for EventApplicationTrack.

Usage:
    python manage.py seed_track_content_blocks                      # Seed all tracks
    python manage.py seed_track_content_blocks --track-id 123       # Seed specific track
    python manage.py seed_track_content_blocks --track-key speaker  # Seed by track key
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from events.models import EventApplicationTrack


class Command(BaseCommand):
    help = 'Seed default content blocks for application tracks'

    def add_arguments(self, parser):
        parser.add_argument(
            '--track-id',
            type=int,
            help='Seed content for specific track ID'
        )
        parser.add_argument(
            '--track-key',
            type=str,
            help='Seed content for specific track key'
        )

    # Default content block definitions organized by track key
    DEFAULT_CONTENT_BLOCKS = {
        'speaker': {
            'landing_page_content': '''# Become a Speaker

Share your expertise and insights with our community! We're looking for passionate speakers who can deliver engaging presentations on topics relevant to our audience.

## What You'll Get
- Platform to reach a large, engaged audience
- Networking opportunities with industry leaders
- Speaker support and resources
- Recognition on our event page

## How to Apply
Fill out the application below with details about your proposed talk, background, and why you'd be a great fit for our event.
''',
            'form_header_notice': '''Please provide details about yourself and your proposed presentation. All fields marked with an asterisk (*) are required.''',
            'confirmation_page_content': '''Thank you for your speaker application! We've received your submission and will review it carefully.

We'll notify you within 2 weeks about the status of your application. If selected, we'll be in touch with next steps and speaker requirements.

In the meantime, feel free to [contact us](mailto:speakers@example.com) if you have any questions.
''',
        },
        'sponsor': {
            'landing_page_content': '''# Become a Sponsor

Grow your brand and connect with our engaged community. We offer flexible sponsorship packages designed to maximize your visibility and impact.

## Sponsorship Opportunities
- Premium brand visibility
- Speaking and networking opportunities
- Custom activation packages
- Lead generation

## Get Started
Apply to become a sponsor of our event. A member of our sponsorship team will follow up with you within 24 hours.
''',
            'form_header_notice': '''Tell us about your organization and sponsorship interests. We'll work with you to create a package that meets your goals.''',
            'confirmation_page_content': '''Thank you for your sponsorship inquiry! We're excited about the possibility of working together.

Our sponsorship team will review your application and contact you shortly to discuss options and pricing. You can expect to hear from us within 1 business day.
''',
        },
        'attendee': {
            'landing_page_content': '''# Register to Attend

Join us for an exciting event bringing together leaders and innovators from across the industry.

## Event Highlights
- Expert speakers and panels
- Networking opportunities
- Hands-on workshops
- Exclusive community access

Register below to secure your spot!
''',
            'form_header_notice': '''Please provide your details to complete your registration. We'll send you a confirmation email with all event details.''',
            'confirmation_page_content': '''Welcome! Your registration is complete.

We've sent a confirmation email to the address you provided. Make sure to check your inbox for:
- Event schedule and agenda
- Location and access details
- Pre-event resources

If you have any questions, please [contact our team](mailto:events@example.com).
''',
        },
    }

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

        total_seeded = 0

        for track in tracks:
            # Check if track already has content (to avoid overwriting)
            if track.landing_page_content or track.form_header_notice or track.confirmation_page_content:
                self.stdout.write(f'⊘ Track "{track.label}" already has content, skipping')
                continue

            # Look up default content for this track's key
            if track.key not in self.DEFAULT_CONTENT_BLOCKS:
                self.stdout.write(f'⊘ No default content for track key "{track.key}", skipping')
                continue

            content = self.DEFAULT_CONTENT_BLOCKS[track.key]

            # Update track with default content
            track.landing_page_content = content['landing_page_content']
            track.form_header_notice = content['form_header_notice']
            track.confirmation_page_content = content['confirmation_page_content']
            track.save()

            self.stdout.write(f'✓ Seeded content for track: {track.label}')
            total_seeded += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'\n✅ Successfully seeded content blocks for {total_seeded} track(s)'
            )
        )
