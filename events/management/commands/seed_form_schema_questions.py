"""
Management command to seed starter questions in the shared question library.

Usage:
    python manage.py seed_form_schema_questions                      # Seed all starter questions
    python manage.py seed_form_schema_questions --clear              # Clear and reseed
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from events.models import SharedQuestionCategory, SharedQuestion


class Command(BaseCommand):
    help = 'Seed starter questions in the shared question library'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing questions and reseed'
        )

    # Starter question definitions organized by category
    CATEGORIES = [
        {
            'name': 'Professional Background',
            'description': 'Questions about professional background and experience',
            'sort_order': 10,
        },
        {
            'name': 'Interest & Engagement',
            'description': 'Questions about interests and engagement',
            'sort_order': 20,
        },
        {
            'name': 'Affiliations',
            'description': 'Questions about affiliations and memberships',
            'sort_order': 30,
        },
    ]

    STARTER_QUESTIONS = [
        {
            'category': 'Professional Background',
            'label': 'Industry',
            'field_type': 'select',
            'help_text': 'What industry do you work in?',
            'placeholder': 'Select your industry',
            'options': [
                {'label': 'Technology', 'value': 'technology'},
                {'label': 'Finance', 'value': 'finance'},
                {'label': 'Healthcare', 'value': 'healthcare'},
                {'label': 'Education', 'value': 'education'},
                {'label': 'Government', 'value': 'government'},
                {'label': 'Consulting', 'value': 'consulting'},
                {'label': 'Startup', 'value': 'startup'},
                {'label': 'Non-profit', 'value': 'non-profit'},
                {'label': 'Other', 'value': 'other'},
            ],
        },
        {
            'category': 'Professional Background',
            'label': 'Role',
            'field_type': 'select',
            'help_text': 'What is your primary role?',
            'placeholder': 'Select your role',
            'options': [
                {'label': 'Executive', 'value': 'executive'},
                {'label': 'Manager', 'value': 'manager'},
                {'label': 'Specialist', 'value': 'specialist'},
                {'label': 'Engineer', 'value': 'engineer'},
                {'label': 'Analyst', 'value': 'analyst'},
                {'label': 'Founder', 'value': 'founder'},
                {'label': 'Investor', 'value': 'investor'},
                {'label': 'Student', 'value': 'student'},
                {'label': 'Other', 'value': 'other'},
            ],
        },
        {
            'category': 'Interest & Engagement',
            'label': 'M&A Project Status',
            'field_type': 'radio_group',
            'help_text': 'Are you involved in any M&A projects currently?',
            'placeholder': '',
            'options': [
                {'label': 'Looking to acquire', 'value': 'looking_to_acquire'},
                {'label': 'Looking to be acquired', 'value': 'looking_to_be_acquired'},
                {'label': 'No current M&A activity', 'value': 'no_activity'},
                {'label': 'Prefer not to say', 'value': 'prefer_not_to_say'},
            ],
        },
        {
            'category': 'Interest & Engagement',
            'label': 'Topic Interest',
            'field_type': 'multi_select',
            'help_text': 'What topics are you most interested in? (Select all that apply)',
            'placeholder': 'Select topics',
            'options': [
                {'label': 'Artificial Intelligence', 'value': 'ai'},
                {'label': 'Climate Tech', 'value': 'climate_tech'},
                {'label': 'Cybersecurity', 'value': 'cybersecurity'},
                {'label': 'Deep Tech', 'value': 'deep_tech'},
                {'label': 'Early Stage Companies', 'value': 'early_stage'},
                {'label': 'ESG', 'value': 'esg'},
                {'label': 'Growth Companies', 'value': 'growth'},
                {'label': 'Startups', 'value': 'startups'},
            ],
        },
        {
            'category': 'Interest & Engagement',
            'label': 'Speaker Interest',
            'field_type': 'checkbox',
            'help_text': 'Are you interested in speaking at our events?',
            'placeholder': '',
            'options': [],
        },
        {
            'category': 'Interest & Engagement',
            'label': 'Speaker Recommendation',
            'field_type': 'text',
            'help_text': 'Do you have any recommendations for speakers we should invite?',
            'placeholder': 'Name of recommended speaker',
            'options': [],
        },
        {
            'category': 'Affiliations',
            'label': 'Jesus College Alumni',
            'field_type': 'checkbox',
            'help_text': 'Are you an alumnus of Jesus College?',
            'placeholder': '',
            'options': [],
        },
        {
            'category': 'Interest & Engagement',
            'label': 'Comments',
            'field_type': 'long_text',
            'help_text': 'Any additional comments or information you\'d like to share?',
            'placeholder': 'Please share any additional details...',
            'options': [],
        },
    ]

    @transaction.atomic
    def handle(self, *args, **options):
        clear_existing = options.get('clear', False)

        if clear_existing:
            self.stdout.write('Clearing existing questions and categories...')
            SharedQuestion.objects.all().delete()
            SharedQuestionCategory.objects.all().delete()

        # Create categories
        categories = {}
        for category_data in self.CATEGORIES:
            category, created = SharedQuestionCategory.objects.get_or_create(
                name=category_data['name'],
                defaults={
                    'description': category_data['description'],
                    'sort_order': category_data['sort_order'],
                }
            )
            categories[category_data['name']] = category
            if created:
                self.stdout.write(f'✓ Created category: {category.name}')
            else:
                self.stdout.write(f'⊘ Category already exists: {category.name}')

        # Create starter questions
        total_created = 0
        for question_data in self.STARTER_QUESTIONS:
            category = categories[question_data['category']]

            question_exists = SharedQuestion.objects.filter(
                category=category,
                label=question_data['label']
            ).exists()

            if question_exists:
                self.stdout.write(f'⊘ Question already exists: {question_data["label"]}')
                continue

            question = SharedQuestion.objects.create(
                category=category,
                label=question_data['label'],
                field_type=question_data['field_type'],
                help_text=question_data.get('help_text', ''),
                placeholder=question_data.get('placeholder', ''),
                options=question_data.get('options', []),
            )

            self.stdout.write(f'✓ Created question: {question.label} ({question.get_field_type_display()})')
            total_created += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'\n✅ Successfully seeded {total_created} starter questions'
            )
        )
