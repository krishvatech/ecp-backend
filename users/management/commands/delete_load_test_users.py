"""
Management command to delete load test users created by create_load_test_users.py

Deletes all users matching pattern: loadtest*@loadtest.local

Usage:
    python manage.py delete_load_test_users
    python manage.py delete_load_test_users --email-domain loadtest.local
    python manage.py delete_load_test_users --force (skip confirmation)
"""
import logging
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Delete all load test users created by create_load_test_users.py'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email-domain',
            type=str,
            default='loadtest.local',
            help='Email domain to match (default: loadtest.local)',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Skip confirmation prompt',
        )

    def handle(self, *args, **options):
        email_domain = options['email_domain'].strip()
        force = options['force']

        # Find all load test users
        users = User.objects.filter(email__endswith=f'@{email_domain}')
        count = users.count()

        if count == 0:
            self.stdout.write(
                self.style.SUCCESS(f'✅ No load test users found with domain: @{email_domain}')
            )
            return

        # Show users to be deleted
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(
            self.style.WARNING(f'🗑️  About to delete {count} load test user(s):')
        )
        self.stdout.write('=' * 70 + '\n')

        for user in users[:10]:  # Show first 10
            self.stdout.write(f'  • {user.username} ({user.email}) - ID: {user.id}')

        if count > 10:
            self.stdout.write(f'  ... and {count - 10} more')

        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(self.style.WARNING('⚠️  This action is PERMANENT:'))
        self.stdout.write('  • Users will be removed from Django database')
        self.stdout.write('  • Users will be removed from AWS Cognito')
        self.stdout.write('  • Users will be removed from Saleor')
        self.stdout.write('  • Event registrations will be deleted\n')

        # Confirm deletion
        if not force:
            confirm = input(
                self.style.ERROR(f'Type "delete {count} load test users" to confirm: ')
            )
            if confirm != f'delete {count} load test users':
                self.stdout.write(self.style.SUCCESS('❌ Deletion cancelled.'))
                return

        # Perform deletion
        self.stdout.write(
            self.style.WARNING(f'\n🔄 Deleting {count} load test user(s)...\n')
        )

        deleted = 0
        failed = 0

        for user in users:
            try:
                username = user.username
                email = user.email
                user_id = user.id

                user.delete()

                deleted += 1
                self.stdout.write(
                    self.style.SUCCESS(
                        f'✅ Deleted: {username} ({email}) - ID: {user_id}'
                    )
                )

            except Exception as e:
                failed += 1
                self.stdout.write(
                    self.style.ERROR(f'❌ Failed to delete {user.username}: {e}')
                )

        # Summary
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(self.style.SUCCESS(f'✅ Deleted: {deleted}'))
        if failed:
            self.stdout.write(self.style.ERROR(f'❌ Failed: {failed}'))
        self.stdout.write(f'📊 Total processed: {deleted + failed}')
        self.stdout.write('=' * 70 + '\n')

        logger.info(f'Load test users deleted: {deleted} deleted, {failed} failed')
