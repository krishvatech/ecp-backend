"""
Management command to set up Celery Beat schedule for form reminders and data management.
Creates periodic tasks to:
1. Schedule form reminders daily (7 days and 2 days before deadline)
2. Mark lapsed assignments daily (after deadline)
3. Purge restricted form data 30 days after event ends

Usage:
    python manage.py setup_form_reminder_schedule
"""
from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from django.utils import timezone
import json


class Command(BaseCommand):
    help = 'Set up Celery Beat schedule for form reminder tasks'

    def handle(self, *args, **options):
        try:
            # Create crontab schedules
            daily_9am_schedule, _ = CrontabSchedule.objects.get_or_create(
                hour=9,
                minute=0,
                day_of_week='*',
                day_of_month='*',
                month_of_year='*',
                defaults={
                    'timezone': str(timezone.get_current_timezone()),
                }
            )

            daily_10am_schedule, _ = CrontabSchedule.objects.get_or_create(
                hour=10,
                minute=0,
                day_of_week='*',
                day_of_month='*',
                month_of_year='*',
                defaults={
                    'timezone': str(timezone.get_current_timezone()),
                }
            )

            # Task 1: Schedule form reminders daily at 9 AM
            task1, created1 = PeriodicTask.objects.update_or_create(
                name='Schedule Form Reminders',
                defaults={
                    'task': 'events.tasks.schedule_form_reminders',
                    'crontab': daily_9am_schedule,
                    'enabled': True,
                    'description': 'Finds incomplete form assignments and schedules reminder emails 7 and 2 days before deadline'
                }
            )

            # Task 2: Mark lapsed assignments daily at 9 AM
            task2, created2 = PeriodicTask.objects.update_or_create(
                name='Mark Lapsed Form Assignments',
                defaults={
                    'task': 'events.tasks.mark_lapsed_form_assignments',
                    'crontab': daily_9am_schedule,
                    'enabled': True,
                    'description': 'Marks form assignments as lapsed when deadline passes'
                }
            )

            # Task 3: Purge restricted form data daily at 10 AM
            task3, created3 = PeriodicTask.objects.update_or_create(
                name='Purge Expired Form Data',
                defaults={
                    'task': 'events.tasks.purge_expired_form_data',
                    'crontab': daily_10am_schedule,
                    'enabled': True,
                    'description': 'Purges restricted form data (emergency contact, medical, dietary) 30 days after event ends'
                }
            )

            self.stdout.write(self.style.SUCCESS('✓ Celery Beat schedule created!'))
            self.stdout.write(f'\n  Task 1: {task1.name}')
            self.stdout.write(f'    - Runs daily at 9:00 AM')
            self.stdout.write(f'    - Schedules reminders 7 and 2 days before deadline')
            self.stdout.write(f'    - Status: {"Created" if created1 else "Updated"}')

            self.stdout.write(f'\n  Task 2: {task2.name}')
            self.stdout.write(f'    - Runs daily at 9:00 AM')
            self.stdout.write(f'    - Marks incomplete assignments as lapsed after deadline')
            self.stdout.write(f'    - Status: {"Created" if created2 else "Updated"}')

            self.stdout.write(f'\n  Task 3: {task3.name}')
            self.stdout.write(f'    - Runs daily at 10:00 AM')
            self.stdout.write(f'    - Purges restricted data 30 days after event ends')
            self.stdout.write(f'    - Status: {"Created" if created3 else "Updated"}')

            self.stdout.write('\n' + '=' * 70)
            self.stdout.write('⚠️  Important: Make sure Celery Beat is running!')
            self.stdout.write('   Start with: celery -A ecp_backend beat -l info')
            self.stdout.write('=' * 70)

        except Exception as e:
            raise CommandError(f'Failed to set up Celery Beat schedule: {str(e)}')
