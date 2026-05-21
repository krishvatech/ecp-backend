"""
Management command to create load test users for live meeting performance testing.

Creates Django users, Cognito accounts, and event registrations in batches.
Idempotent: can be run multiple times safely.

Usage:
    python manage.py create_load_test_users --count 150 --event-id 547 \
        --email-domain loadtest.local --password "Test@123456"

The command generates:
- Django users: loadtest001@loadtest.local, loadtest002@loadtest.local, etc.
- Cognito users with the specified password
- Event registrations for the given event
- CSV file: /tmp/live_meeting_load_test_users.csv
"""
import logging
import csv
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.contrib.auth.models import User
from django.utils import timezone
from events.models import Event, EventRegistration
from users.models import UserProfile
from users.email_utils import create_cognito_user, set_cognito_user_password

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Create load test users for live meeting performance testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=10,
            help='Number of test users to create (default: 10)',
        )
        parser.add_argument(
            '--event-id',
            type=int,
            required=True,
            help='Event ID to register users for',
        )
        parser.add_argument(
            '--email-domain',
            type=str,
            default='loadtest.local',
            help='Email domain for test users (default: loadtest.local)',
        )
        parser.add_argument(
            '--password',
            type=str,
            required=True,
            help='Password for test users (must meet Cognito requirements)',
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=10,
            help='Batch size for database transactions (default: 10)',
        )
        parser.add_argument(
            '--output-dir',
            type=str,
            default='load_test_data',
            help='Directory to store CSV file (default: load_test_data in project root)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without making changes',
        )

    def handle(self, *args, **options):
        count = options['count']
        event_id = options['event_id']
        email_domain = options['email_domain'].strip()
        password = options['password']
        batch_size = options['batch_size']
        output_dir = options['output_dir'].strip()
        dry_run = options.get('dry_run', False)

        # Validate inputs
        if count < 1:
            raise CommandError('Count must be at least 1')
        if not password or len(password) < 8:
            raise CommandError('Password must be at least 8 characters')

        # Get event
        try:
            event = Event.objects.get(id=event_id)
        except Event.DoesNotExist:
            raise CommandError(f'Event with ID {event_id} not found')

        self.stdout.write(self.style.SUCCESS(f'\n=== Load Test User Creation ===\n'))
        self.stdout.write(f'Event: {event.title} (ID: {event.id})')
        self.stdout.write(f'Count: {count}')
        self.stdout.write(f'Email Domain: {email_domain}')
        self.stdout.write(f'Batch Size: {batch_size}')
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE'))
        self.stdout.write('')

        if dry_run:
            self._dry_run_mode(count, email_domain, event, output_dir)
            return

        # Confirm
        confirm = input('Ready to create test users. Type "yes" to confirm: ').strip().lower()
        if confirm != 'yes':
            raise CommandError('Cancelled')

        # Create users in batches
        stats = {
            'created': 0,
            'updated': 0,
            'registered': 0,
            'skipped': 0,
            'cognito_created': 0,
            'cognito_failed': 0,
            'csv_rows': [],
        }

        csv_rows = []

        try:
            for batch_start in range(0, count, batch_size):
                batch_end = min(batch_start + batch_size, count)
                batch_count = batch_end - batch_start

                self.stdout.write(f'\nProcessing batch {batch_start + 1}-{batch_end}...')

                with transaction.atomic():
                    for i in range(batch_start, batch_end):
                        user_num = i + 1
                        email = f'loadtest{user_num:03d}@{email_domain}'
                        username = f'loadtest{user_num:03d}'

                        result = self._create_or_update_user(
                            username=username,
                            email=email,
                            password=password,
                            event=event,
                            stats=stats,
                        )

                        if result:
                            row = {'email': email, 'password': password}
                            csv_rows.append(row)
                            stats['csv_rows'].append(row)

                self.stdout.write(
                    self.style.SUCCESS(f'  ✓ Batch {batch_start + 1}-{batch_end} completed')
                )

            # Write CSV file
            csv_path = self._write_csv_file(csv_rows, output_dir)

            # Print summary
            self._print_summary(stats, csv_path, count)

            logger.info(
                f'Load test users created: created={stats["created"]}, '
                f'updated={stats["updated"]}, registered={stats["registered"]}'
            )

        except Exception as e:
            logger.error(f'Error creating load test users: {str(e)}')
            self.stdout.write(self.style.ERROR(f'\n❌ Error: {str(e)}'))
            raise

    def _dry_run_mode(self, count, email_domain, event, output_dir):
        """Show what would be created without making changes."""
        self.stdout.write('Sample users that would be created:')
        for i in range(min(5, count)):
            user_num = i + 1
            email = f'loadtest{user_num:03d}@{email_domain}'
            self.stdout.write(f'  - {email}')

        if count > 5:
            self.stdout.write(f'  ... and {count - 5} more')

        self.stdout.write(f'\nAll {count} users would be registered for event: {event.title}')

        csv_filename = 'live_meeting_load_test_users.csv'
        csv_path = f'{output_dir}/{csv_filename}'
        self.stdout.write(f'CSV would be written to: {csv_path}')
        self.stdout.write(self.style.WARNING('\nDRY RUN - No changes made\n'))

    def _create_or_update_user(self, username, email, password, event, stats):
        """
        Create or update a single test user and register for event.
        Returns True if successful, False if skipped.
        """
        try:
            # Create or get Django user
            user, user_created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': email,
                    'first_name': 'LoadTest',
                    'last_name': f'User {username.replace("loadtest", "")}',
                }
            )

            if user_created:
                stats['created'] += 1
                user.set_password(password)
                user.save()
            else:
                # Update existing user's password and email
                user.email = email
                user.set_password(password)
                user.save()
                stats['updated'] += 1

            # Create or update user profile
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.full_name = f'LoadTest User {username.replace("loadtest", "")}'
            profile.save(update_fields=['full_name'])

            # Create Cognito user
            cognito_success = create_cognito_user(
                username=username,
                email=email,
                temp_password=password,
                first_name='LoadTest',
                last_name=f'User {username.replace("loadtest", "")}',
            )

            if cognito_success:
                stats['cognito_created'] += 1
            else:
                stats['cognito_failed'] += 1
                logger.warning(f'Failed to create Cognito user: {username}')

            # Register user for event
            registration, reg_created = EventRegistration.objects.get_or_create(
                event=event,
                user=user,
                defaults={
                    'status': 'registered',
                    'attendee_status': 'confirmed',
                    'admission_status': 'admitted',
                    'admitted_at': timezone.now(),
                    'was_ever_admitted': True,
                }
            )

            if reg_created:
                stats['registered'] += 1
            else:
                # Update admission status if needed
                if registration.admission_status != 'admitted':
                    registration.admission_status = 'admitted'
                    registration.admitted_at = timezone.now()
                    registration.was_ever_admitted = True
                    registration.save(update_fields=['admission_status', 'admitted_at', 'was_ever_admitted'])
                    stats['registered'] += 1

            return True

        except Exception as e:
            logger.error(f'Error creating/updating user {username}: {str(e)}')
            stats['skipped'] += 1
            return False

    def _write_csv_file(self, csv_rows, output_dir):
        """Write credentials CSV file to specified directory."""
        import os
        from pathlib import Path

        # Create output directory if it doesn't exist
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        csv_path = output_path / 'live_meeting_load_test_users.csv'

        try:
            with open(csv_path, 'w', newline='') as csvfile:
                fieldnames = ['email', 'password']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_rows)

            logger.info(f'CSV file written: {csv_path}')
            return str(csv_path)

        except Exception as e:
            logger.error(f'Error writing CSV file: {str(e)}')
            raise CommandError(f'Failed to write CSV file: {str(e)}')

    def _print_summary(self, stats, csv_path, total_count):
        """Print execution summary."""
        csv_rows_count = len(stats.get('csv_rows', []))
        self.stdout.write(self.style.SUCCESS(f'\n=== Summary ===\n'))
        self.stdout.write(f'Django Users:')
        self.stdout.write(f'  Created: {stats["created"]}')
        self.stdout.write(f'  Updated: {stats["updated"]}')
        self.stdout.write(f'  Skipped: {stats["skipped"]}')
        self.stdout.write(f'\nCognito Users:')
        self.stdout.write(f'  Created/Updated: {stats["cognito_created"]}')
        if stats['cognito_failed'] > 0:
            self.stdout.write(
                self.style.WARNING(f'  Failed: {stats["cognito_failed"]}')
            )
        self.stdout.write(f'\nEvent Registrations:')
        self.stdout.write(f'  Registered: {stats["registered"]}')
        self.stdout.write(f'\nCredentials CSV:')
        self.stdout.write(f'  Path: {csv_path}')
        self.stdout.write(f'  Rows: {csv_rows_count}')
        self.stdout.write(self.style.SUCCESS(f'\n✅ Load test users created successfully!\n'))
