from django.core.management.base import BaseCommand
from django.conf import settings
from cms.models import EmailTemplate
import os


class Command(BaseCommand):
    help = 'Set up email templates for post-acceptance forms with HTML and text bodies'

    def load_template_file(self, filename):
        """Load template content from file."""
        template_dir = os.path.join(settings.BASE_DIR, 'templates', 'emails')
        filepath = os.path.join(template_dir, filename)
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except FileNotFoundError:
            self.stdout.write(
                self.style.WARNING(f'Template file not found: {filepath}')
            )
            return ''

    def handle(self, *args, **options):
        templates = [
            {
                'template_key': 'post_acceptance_form_sent',
                'subject': '{{ event_title }} - Complete Your Participant Information',
                'html_file': 'post_acceptance_form_sent.html',
                'text_file': 'post_acceptance_form_sent.txt',
            },
            {
                'template_key': 'post_acceptance_form_reminder',
                'subject': 'Reminder: Complete Your Form for {{ event_title }}',
                'html_file': 'post_acceptance_form_reminder.html',
                'text_file': 'post_acceptance_form_reminder.txt',
            },
        ]

        for template_data in templates:
            html_body = self.load_template_file(template_data['html_file'])
            text_body = self.load_template_file(template_data['text_file'])

            template, created = EmailTemplate.objects.update_or_create(
                template_key=template_data['template_key'],
                defaults={
                    'subject': template_data['subject'],
                    'html_body': html_body,
                    'text_body': text_body,
                }
            )
            status = 'Created' if created else 'Updated'
            self.stdout.write(
                self.style.SUCCESS(
                    f'{status} EmailTemplate: {template.template_key}'
                )
            )
            self.stdout.write(f'  Subject: {template.subject}')
            if html_body:
                self.stdout.write(f'  HTML body: {len(html_body)} chars')
            if text_body:
                self.stdout.write(f'  Text body: {len(text_body)} chars')
