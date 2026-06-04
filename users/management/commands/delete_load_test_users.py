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
        batch_size = 10

        # Find all load test users and fetch IDs upfront to avoid queryset issues during deletion
        users_qs = User.objects.filter(email__endswith=f'@{email_domain}')
        user_ids = list(users_qs.values_list('id', flat=True))
        count = len(user_ids)

        if count == 0:
            self.stdout.write(
                self.style.SUCCESS(f'✅ No load test users found with domain: @{email_domain}')
            )
            return

        # Show users to be deleted
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(
            self.style.WARNING(f'🗑️  About to delete {count} load test user(s) in batches of {batch_size}:')
        )
        self.stdout.write('=' * 70 + '\n')

        # Preview first 10 users
        users_preview = User.objects.filter(id__in=user_ids[:10])
        for user in users_preview:
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

        # Perform batch deletion
        self.stdout.write(
            self.style.WARNING(f'\n🔄 Deleting {count} load test user(s) in batches of {batch_size}...\n')
        )

        deleted = 0
        failed = 0
        batch_num = 1
        total_batches = (count + batch_size - 1) // batch_size

        # Process users in batches using user IDs
        for batch_start in range(0, count, batch_size):
            batch_end = min(batch_start + batch_size, count)
            batch_user_ids = user_ids[batch_start:batch_end]
            batch_users = User.objects.filter(id__in=batch_user_ids)
            batch_deleted = 0
            batch_failed = 0

            self.stdout.write(
                self.style.WARNING(f'\n📦 Batch {batch_num}/{total_batches} ({batch_start + 1}-{batch_end}):')
            )

            for user in batch_users:
                try:
                    username = user.username
                    email = user.email
                    user_id = user.id

                    user.delete()

                    batch_deleted += 1
                    deleted += 1
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'  ✅ Deleted: {username} ({email}) - ID: {user_id}'
                        )
                    )

                except Exception as e:
                    batch_failed += 1
                    failed += 1
                    self.stdout.write(
                        self.style.ERROR(f'  ❌ Failed to delete {user.username}: {e}')
                    )

            # Batch summary
            self.stdout.write(
                self.style.SUCCESS(
                    f'  Batch {batch_num} complete: {batch_deleted} deleted, {batch_failed} failed'
                )
            )
            batch_num += 1

        # Final summary
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(self.style.SUCCESS(f'✅ Total Deleted: {deleted}'))
        if failed:
            self.stdout.write(self.style.ERROR(f'❌ Total Failed: {failed}'))
        self.stdout.write(f'📊 Total processed: {deleted + failed}/{count}')
        self.stdout.write('=' * 70 + '\n')

        logger.info(f'Load test users deleted: {deleted} deleted, {failed} failed (batch size: {batch_size})')
