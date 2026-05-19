"""
Management command to seed Participant Information Form templates for all events.
Updates existing templates safely without overwriting customizations.

Usage:
    python manage.py seed_participant_information_form
    python manage.py seed_participant_information_form --event-id=5
    python manage.py seed_participant_information_form --sync-schema (safe update)
    python manage.py seed_participant_information_form --force (replace all)
"""
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from events.models import Event, PostAcceptanceFormTemplate, PostAcceptanceFormSubmission
import json
from datetime import timedelta

# Current schema version - increment when schema structure changes
SCHEMA_VERSION = "2.0"

# Latest schema matching signals.py structure
PARTICIPANT_INFORMATION_SCHEMA = {
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
    ],
    "metadata": {
        "version": SCHEMA_VERSION,
        "updated_at": timezone.now().isoformat(),
        "description": "Current schema with showIfValue/showIfIncludes conditionals"
    }
}


class Command(BaseCommand):
    help = 'Seed and manage Participant Information Form templates for events'

    def add_arguments(self, parser):
        parser.add_argument(
            '--event-id',
            type=int,
            help='Specific event ID to seed form for',
        )
        parser.add_argument(
            '--sync-schema',
            action='store_true',
            help='Safely update schema for existing templates if version changed',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Replace all templates (caution: overwrites customizations)',
        )

    def handle(self, *args, **options):
        event_id = options.get('event_id')
        sync_schema = options.get('sync_schema', False)
        force = options.get('force', False)

        if event_id:
            events = Event.objects.filter(id=event_id)
            if not events.exists():
                raise CommandError(f'Event with ID {event_id} does not exist')
        else:
            events = Event.objects.all()

        if not events.exists():
            self.stdout.write(self.style.WARNING('No events found'))
            return

        created_count = 0
        updated_count = 0
        synced_count = 0
        skipped_count = 0

        for event in events:
            template, created = PostAcceptanceFormTemplate.objects.get_or_create(
                event=event,
                form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
                defaults={
                    'title': 'Participant Information Form',
                    'description': 'Help us plan a better event by sharing your attendance preferences and requirements.',
                    'is_enabled': True,
                    'deadline_days': 7,
                    'question_schema': PARTICIPANT_INFORMATION_SCHEMA
                }
            )

            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Created form for event: {event.title}')
                )
            elif force:
                # Check for existing submissions before force-updating
                has_submissions = PostAcceptanceFormSubmission.objects.filter(
                    assignment__form_template=template
                ).exists()

                if has_submissions:
                    skipped_count += 1
                    self.stdout.write(
                        self.style.WARNING(
                            f'⊘ Form for event "{event.title}" has existing submissions. '
                            f'Skipping force update to protect data.'
                        )
                    )
                else:
                    # Force replace (use with caution)
                    template.question_schema = PARTICIPANT_INFORMATION_SCHEMA
                    template.is_enabled = True
                    template.save(update_fields=['question_schema', 'is_enabled'])
                    updated_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'✓ Force updated form for event: {event.title}')
                    )
            elif sync_schema:
                # Safe schema sync - only update if version changed
                current_schema = template.question_schema or {}
                current_version = current_schema.get('metadata', {}).get('version', '1.0')

                if current_version != SCHEMA_VERSION:
                    # Check for existing submissions before syncing
                    has_submissions = PostAcceptanceFormSubmission.objects.filter(
                        assignment__form_template=template
                    ).exists()

                    if has_submissions:
                        skipped_count += 1
                        self.stdout.write(
                            self.style.WARNING(
                                f'⊘ Form for event "{event.title}" has existing submissions. '
                                f'Skipping schema sync to protect data (v{current_version} → v{SCHEMA_VERSION}).'
                            )
                        )
                    else:
                        # Version mismatch and no submissions - safe to update
                        template.question_schema = PARTICIPANT_INFORMATION_SCHEMA
                        template.save(update_fields=['question_schema'])
                        synced_count += 1
                        self.stdout.write(
                            self.style.SUCCESS(
                                f'✓ Schema synced for event: {event.title} '
                                f'(v{current_version} → v{SCHEMA_VERSION})'
                            )
                        )
                else:
                    skipped_count += 1
                    self.stdout.write(
                        self.style.WARNING(
                            f'⊘ Schema already up to date for event: {event.title}'
                        )
                    )
            else:
                skipped_count += 1
                self.stdout.write(
                    self.style.WARNING(f'⊘ Form already exists for event: {event.title}')
                )

        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(
            f'Created: {created_count} | Updated: {updated_count} | '
            f'Synced: {synced_count} | Skipped: {skipped_count}'
        )
        self.stdout.write('=' * 70)

        if created_count > 0:
            self.stdout.write(self.style.SUCCESS('\n✓ Forms created!'))
        if updated_count > 0:
            self.stdout.write(self.style.SUCCESS('\n✓ Forms force-updated (customizations overwritten)!'))
        if synced_count > 0:
            self.stdout.write(self.style.SUCCESS(f'\n✓ {synced_count} templates schema synced!'))
        if skipped_count > 0 and not sync_schema:
            self.stdout.write(self.style.WARNING(
                f'\n⊘ {skipped_count} events already have forms'
            ))
            self.stdout.write('  Use --sync-schema to safely update schema versions')
            self.stdout.write('  Use --force to replace all (overwrites customizations)')
