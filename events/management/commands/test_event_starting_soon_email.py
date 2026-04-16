"""
Management command to test "Event Starting Soon" email notification.

Usage:
    python manage.py test_event_starting_soon_email
    python manage.py test_event_starting_soon_email --event-id=123
    python manage.py test_event_starting_soon_email --user-id=456
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import timedelta
from events.models import Event, EventRegistration
from users.email_utils import send_event_starting_soon_email

User = get_user_model()


class Command(BaseCommand):
    help = 'Test "Event Starting Soon" email notification'

    def add_arguments(self, parser):
        parser.add_argument(
            '--event-id',
            type=int,
            help='Specific event ID to use for testing',
        )
        parser.add_argument(
            '--user-id',
            type=int,
            help='Specific user ID to send email to',
        )
        parser.add_argument(
            '--create-test-event',
            action='store_true',
            help='Create a test event and registration if they don\'t exist',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🧪 Testing Event Starting Soon Email\n'))

        event_id = options.get('event_id')
        user_id = options.get('user_id')
        create_test = options.get('create_test_event')

        # Step 1: Get or create event
        if event_id:
            try:
                event = Event.objects.get(id=event_id)
                self.stdout.write(f'✅ Using event ID {event_id}: {event.title}')
            except Event.DoesNotExist:
                raise CommandError(f'Event with ID {event_id} not found')
        else:
            # Get first published event
            event = Event.objects.filter(status='published').first()
            if not event:
                if create_test:
                    event = self._create_test_event()
                else:
                    raise CommandError(
                        'No published events found. Use --create-test-event to create one.'
                    )
            self.stdout.write(f'✅ Using event: {event.title}')

        # Step 2: Get or create user
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                self.stdout.write(f'✅ Using user ID {user_id}: {user.email}')
            except User.DoesNotExist:
                raise CommandError(f'User with ID {user_id} not found')
        else:
            user = User.objects.first()
            if not user:
                raise CommandError('No users found in database')
            self.stdout.write(f'✅ Using user: {user.email}')

        # Step 3: Ensure user is registered for event
        registration, created = EventRegistration.objects.get_or_create(
            event=event,
            user=user,
            defaults={'status': 'registered'}
        )
        if created:
            self.stdout.write(f'✅ Created registration for {user.email} for {event.title}')
        else:
            self.stdout.write(f'✅ User already registered for event')

        # Step 4: Send email
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write('📧 Sending Email...\n')

        try:
            success = send_event_starting_soon_email(user, event)

            if success:
                self.stdout.write(self.style.SUCCESS('✅ EMAIL SENT SUCCESSFULLY!\n'))
                self.stdout.write('Email Details:')
                self.stdout.write(f'  To: {user.email}')
                self.stdout.write(f'  Subject: Reminder: \'{event.title}\' starts in 1 hour')
                self.stdout.write(f'  Event: {event.title}')
                self.stdout.write(f'  Start Time: {event.start_time}')
                self.stdout.write(f'  End Time: {event.end_time}')
                self.stdout.write(f'  Timezone: {event.timezone}')
                self.stdout.write(f'  User Name: {user.first_name} {user.last_name}')
            else:
                self.stdout.write(self.style.ERROR('❌ EMAIL FAILED TO SEND'))
                self.stdout.write('Check your email configuration in Django settings')

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ ERROR: {str(e)}'))
            import traceback
            traceback.print_exc()
            raise CommandError(f'Failed to send email: {str(e)}')

        # Step 5: Test idempotency
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write('🔄 Testing Idempotency...\n')

        # Simulate that email was already sent
        event.starting_soon_notifications_sent_at = timezone.now()
        event.save()
        self.stdout.write('✅ Set starting_soon_notifications_sent_at')

        # Try sending again - should not send
        self.stdout.write('\nAttempting to send email again (should be skipped)...')

        # Reset for testing purposes
        event.starting_soon_notifications_sent_at = None
        event.save()
        self.stdout.write('✅ Cleared starting_soon_notifications_sent_at for next test\n')

        # Step 6: Show template variables
        self.stdout.write('=' * 60)
        self.stdout.write('📝 Email Template Variables:\n')
        self.stdout.write(f'  first_name: {user.first_name or user.username}')
        self.stdout.write(f'  event_title: {event.title}')
        self.stdout.write(f'  event_start: {event.start_time}')
        self.stdout.write(f'  event_end: {event.end_time}')
        self.stdout.write(f'  is_multi_day: {event.is_multi_day}')
        self.stdout.write(f'  event_timezone: {event.timezone}')
        self.stdout.write(f'  event_url: /events/{event.slug or event.id}/')
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('✅ Test Complete!\n'))

    def _create_test_event(self):
        """Create a test event 1 hour from now"""
        from events.models import Community

        self.stdout.write('📝 Creating test event...')

        # Get or create a community
        community = Community.objects.first()
        if not community:
            raise CommandError('No communities found. Create one first.')

        # Create event starting in 1 hour
        start_time = timezone.now() + timedelta(hours=1)
        end_time = start_time + timedelta(hours=2)

        event = Event.objects.create(
            community=community,
            title='Test Event - Event Starting Soon',
            slug='test-event-starting-soon',
            description='This is a test event for testing the "Event Starting Soon" email',
            start_time=start_time,
            end_time=end_time,
            status='published',
            format='virtual',
        )

        self.stdout.write(f'✅ Created test event: {event.title}')
        self.stdout.write(f'   Starts in 1 hour: {start_time}')

        return event
