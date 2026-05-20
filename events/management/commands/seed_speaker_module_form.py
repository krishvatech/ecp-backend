"""
Seed Speaker Module for Promotional Profile Form.

Usage:
    python manage.py seed_speaker_module_form
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from events.models import Event, PostAcceptanceFormTemplate
from events.schemas.promotional_profile_speaker import SPEAKER_MODULE_SCHEMA


class Command(BaseCommand):
    help = 'Seed Speaker Module schema for Promotional Profile form on all events'

    def add_arguments(self, parser):
        parser.add_argument(
            '--event-id',
            type=int,
            help='Seed only for specific event ID'
        )

    def handle(self, *args, **options):
        if options['event_id']:
            events = Event.objects.filter(id=options['event_id'])
        else:
            events = Event.objects.filter(status='live')

        if not events.exists():
            self.stdout.write(self.style.WARNING('No events found'))
            return

        updated_count = 0

        for event in events:
            try:
                template, created = PostAcceptanceFormTemplate.objects.get_or_create(
                    event=event,
                    form_type='promotional_profile',
                    defaults={
                        'title': 'Speaker Profile',
                        'description': 'Please provide your speaker profile information for publication',
                        'question_schema': {
                            'sections': [SPEAKER_MODULE_SCHEMA]
                        },
                        'is_enabled': True,
                        'deadline_days': 14
                    }
                )

                if created:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'✓ Created Promotional Profile form for event {event.id} ({event.title})'
                        )
                    )
                    updated_count += 1
                else:
                    # Update schema if needed
                    if not template.question_schema or 'sections' not in template.question_schema:
                        template.question_schema = {
                            'sections': [SPEAKER_MODULE_SCHEMA]
                        }
                        template.updated_at = timezone.now()
                        template.save(update_fields=['question_schema', 'updated_at'])
                        self.stdout.write(
                            self.style.SUCCESS(
                                f'✓ Updated schema for event {event.id} ({event.title})'
                            )
                        )
                        updated_count += 1

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Error seeding event {event.id}: {str(e)}')
                )

        self.stdout.write(
            self.style.SUCCESS(f'\n✓ Seeding complete: {updated_count} forms processed')
        )
