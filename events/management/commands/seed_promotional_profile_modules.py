"""
Seed all Promotional Profile Modules (Speaker, Sponsor, Startup, Investor).

Usage:
    python manage.py seed_promotional_profile_modules
    python manage.py seed_promotional_profile_modules --event-id=123
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from events.models import Event, PostAcceptanceFormTemplate
from events.schemas.promotional_profile_speaker import SPEAKER_MODULE_SCHEMA
from events.schemas.promotional_profile_modules import (
    SPONSOR_ORGANISATION_MODULE_SCHEMA,
    SPONSOR_STAFF_MODULE_SCHEMA,
    STARTUP_MODULE_SCHEMA,
    INVESTOR_MODULE_SCHEMA,
)


class Command(BaseCommand):
    help = 'Seed all Promotional Profile Modules (Speaker, Sponsor, Startup, Investor) for events'

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
        module_schemas = [
            SPEAKER_MODULE_SCHEMA,
            SPONSOR_ORGANISATION_MODULE_SCHEMA,
            SPONSOR_STAFF_MODULE_SCHEMA,
            STARTUP_MODULE_SCHEMA,
            INVESTOR_MODULE_SCHEMA,
        ]

        for event in events:
            try:
                template, created = PostAcceptanceFormTemplate.objects.get_or_create(
                    event=event,
                    form_type='promotional_profile',
                    defaults={
                        'title': 'Promotional Profile',
                        'description': 'Please provide your promotional profile information (speaker profile, sponsor details, startup pitch, or investor details)',
                        'question_schema': {
                            'sections': module_schemas
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
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'  Modules: Speaker, Sponsor Organisation, Sponsor Staff, Startup, Investor'
                        )
                    )
                    updated_count += 1
                else:
                    # Update schema to include all modules if needed
                    current_sections = template.question_schema.get('sections', [])
                    current_ids = {section.get('id') for section in current_sections}
                    needed_ids = {module.get('id') for module in module_schemas}

                    if current_ids != needed_ids:
                        template.question_schema = {
                            'sections': module_schemas
                        }
                        template.updated_at = timezone.now()
                        template.save(update_fields=['question_schema', 'updated_at'])
                        self.stdout.write(
                            self.style.SUCCESS(
                                f'✓ Updated schema for event {event.id} ({event.title})'
                            )
                        )
                        self.stdout.write(
                            self.style.SUCCESS(
                                f'  All 5 modules now available'
                            )
                        )
                        updated_count += 1
                    else:
                        self.stdout.write(
                            self.style.WARNING(
                                f'- Event {event.id} ({event.title}) already has all modules'
                            )
                        )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Error seeding event {event.id}: {str(e)}')
                )

        self.stdout.write(
            self.style.SUCCESS(f'\n✓ Seeding complete: {updated_count} forms processed')
        )
