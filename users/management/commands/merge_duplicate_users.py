"""
Management command to merge duplicate user accounts.

Safely merges a secondary user account into a primary user account.
This handles all related data including CognitoIdentity records.

Usage:
    python manage.py merge_duplicate_users <primary_user_id> <secondary_user_id>
    python manage.py merge_duplicate_users 78 80  # Merge user 80 into user 78
"""
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.contrib.auth.models import User
from users.models import CognitoIdentity, UserProfile
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Merge a secondary user account into a primary user account'

    def add_arguments(self, parser):
        parser.add_argument('primary_user_id', type=int, help='ID of the user to keep')
        parser.add_argument('secondary_user_id', type=int, help='ID of the user to merge into primary')
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be merged without actually doing it',
        )

    def handle(self, *args, **options):
        primary_id = options['primary_user_id']
        secondary_id = options['secondary_user_id']
        dry_run = options.get('dry_run', False)

        # Validate
        if primary_id == secondary_id:
            raise CommandError('Primary and secondary user IDs must be different')

        try:
            primary_user = User.objects.get(id=primary_id)
        except User.DoesNotExist:
            raise CommandError(f'Primary user with ID {primary_id} not found')

        try:
            secondary_user = User.objects.get(id=secondary_id)
        except User.DoesNotExist:
            raise CommandError(f'Secondary user with ID {secondary_id} not found')

        self.stdout.write(self.style.SUCCESS('=== User Merge Summary ===\n'))
        self.stdout.write(f'Primary User (will keep):')
        self.stdout.write(f'  ID: {primary_user.id}')
        self.stdout.write(f'  Email: {primary_user.email}')
        self.stdout.write(f'  Username: {primary_user.username}\n')

        self.stdout.write(f'Secondary User (will merge):')
        self.stdout.write(f'  ID: {secondary_user.id}')
        self.stdout.write(f'  Email: {secondary_user.email}')
        self.stdout.write(f'  Username: {secondary_user.username}\n')

        # Count related objects
        cognito_count = CognitoIdentity.objects.filter(user=secondary_user).count()
        self.stdout.write(f'Data to merge:')
        self.stdout.write(f'  Cognito Identities: {cognito_count}')
        self.stdout.write('')

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN - No changes made\n'))
            return

        # Confirm
        self.stdout.write(self.style.WARNING(
            'WARNING: This operation cannot be undone!\n'
            'All data from the secondary user will be transferred to the primary user.\n'
        ))
        confirm = input('Type "yes" to confirm merge: ').strip().lower()
        if confirm != 'yes':
            raise CommandError('Merge cancelled')

        # Perform merge
        try:
            with transaction.atomic():
                # 1. Merge CognitoIdentity records
                cognito_records = CognitoIdentity.objects.filter(user=secondary_user)
                for record in cognito_records:
                    # Check if this cognito_sub already exists for primary user
                    existing = CognitoIdentity.objects.filter(
                        user=primary_user,
                        cognito_sub=record.cognito_sub
                    ).exists()

                    if existing:
                        self.stdout.write(
                            self.style.WARNING(
                                f'Skipping duplicate cognito_sub {record.cognito_sub}'
                            )
                        )
                        record.delete()
                    else:
                        # Update to point to primary user
                        record.user = primary_user
                        record.save(update_fields=['user'])
                        self.stdout.write(f'Merged cognito identity: {record.cognito_sub}')

                # 2. Delete the secondary user (cascade will handle related models)
                secondary_username = secondary_user.username
                secondary_user.delete()

                logger.info(
                    f'Successfully merged user {secondary_id} ({secondary_username}) '
                    f'into user {primary_id} ({primary_user.username})'
                )

                self.stdout.write(
                    self.style.SUCCESS(
                        f'\n✅ Successfully merged user {secondary_id} into user {primary_id}'
                    )
                )

        except Exception as e:
            logger.error(f'Error during merge: {str(e)}')
            raise CommandError(f'Error during merge: {str(e)}')
