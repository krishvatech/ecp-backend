"""
Phase 12: Communication templates tests
Tests for configurable email templates with track, mode, outcome, and tier support.
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.core import mail
from django.utils import timezone
from events.models import (
    Event, EventApplication, EventApplicationTrack, EventApplicationTrackApplication,
    EventRegistration, TrackPricingTier, EventEmailTemplate
)
from community.models import Community
from events.services.communication import (
    build_email_context, send_application_decision_email, send_nominator_acknowledgement_email,
    send_nominator_outcome_email, send_reminder_to_complete_email
)


class EmailContextBuildingTestCase(TestCase):
    """Test context variable building for email templates."""

    def setUp(self):
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('applicant@test.com', 'applicant@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            start_time=timezone.now(),
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
        )
        self.tier_free = TrackPricingTier.objects.create(
            track=self.track,
            label='Free Tier',
            price=0.00,
        )
        self.tier_paid = TrackPricingTier.objects.create(
            track=self.track,
            label='Paid Tier',
            price=99.99,
        )

    def test_context_includes_applicant_name(self):
        """Test that applicant name is included in context."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            first_name='Jane',
            last_name='Smith',
            email='jane@test.com',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_free,
        )
        context = build_email_context(track_app)
        self.assertEqual(context['applicant_first_name'], 'Jane')
        self.assertEqual(context['applicant_last_name'], 'Smith')
        self.assertEqual(context['applicant_name'], 'Jane Smith')

    def test_context_includes_event_details(self):
        """Test that event details are included in context."""
        app = EventApplication.objects.create(
            event=self.event,
            email='jane@test.com',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_free,
        )
        context = build_email_context(track_app)
        self.assertEqual(context['event_name'], 'Test Event')
        self.assertEqual(context['track_label'], 'Speaker Track')

    def test_context_tier_pricing_free(self):
        """Test that free tier is correctly identified."""
        app = EventApplication.objects.create(
            event=self.event,
            email='jane@test.com',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_free,
        )
        context = build_email_context(track_app)
        self.assertEqual(context['tier_cost_type'], 'free')
        self.assertEqual(context['tier_price'], 0.0)

    def test_context_tier_pricing_paid(self):
        """Test that paid tier is correctly identified."""
        app = EventApplication.objects.create(
            event=self.event,
            email='jane@test.com',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_paid,
        )
        context = build_email_context(track_app)
        self.assertEqual(context['tier_cost_type'], 'paid')
        self.assertEqual(context['tier_price'], 99.99)

    def test_context_nominator_info_present(self):
        """Test that nominator info is included for third-party nominations."""
        app = EventApplication.objects.create(
            event=self.event,
            email='nominee@test.com',
            nomination_mode='third_party_nomination',
            nominator_name='John Nominator',
            nominator_email='john@test.com',
            nominee_name='Jane Nominee',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_free,
        )
        context = build_email_context(track_app)
        self.assertEqual(context['nominator_name'], 'John Nominator')
        self.assertEqual(context['nominee_name'], 'Jane Nominee')


class ApplicationDecisionEmailTestCase(TestCase):
    """Test application decision email sending."""

    def setUp(self):
        mail.outbox = []
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('applicant@test.com', 'applicant@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            start_time=timezone.now(),
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
        )
        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0.00,
        )

    def test_accepted_email_sent_to_applicant(self):
        """Test that accepted email is sent to applicant."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier,
        )
        result = send_application_decision_email(track_app, 'accept')
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['applicant@test.com'])

    def test_declined_email_sent_to_applicant(self):
        """Test that declined email is sent to applicant."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
        )
        result = send_application_decision_email(track_app, 'decline')
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)

    def test_waitlisted_email_sent_to_applicant(self):
        """Test that waitlisted email is sent to applicant."""
        app = EventApplication.objects.create(
            event=self.event,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
        )
        result = send_application_decision_email(track_app, 'waitlist')
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)

    def test_email_not_sent_if_opted_out(self):
        """Test that email is not sent if opted out."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            opt_out_automated_communication=True,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
        )
        result = send_application_decision_email(track_app, 'accept')
        self.assertFalse(result)
        self.assertEqual(len(mail.outbox), 0)

    def test_email_includes_custom_message(self):
        """Test that custom message is included in email."""
        app = EventApplication.objects.create(
            event=self.event,
            email='applicant@test.com',
            rejection_message='Great effort, apply next year!',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
        )
        result = send_application_decision_email(track_app, 'decline', 'Better luck next time!')
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        # Custom message should be in email
        self.assertIn('Better luck next time!', mail.outbox[0].body)

    def test_email_includes_payment_link_placeholder(self):
        """Test that payment link placeholder is included for paid tiers."""
        tier_paid = TrackPricingTier.objects.create(
            track=self.track,
            label='Paid',
            price=99.99,
        )
        app = EventApplication.objects.create(
            event=self.event,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=tier_paid,
        )
        result = send_application_decision_email(track_app, 'accept')
        self.assertTrue(result)
        # Payment placeholder should be in email
        self.assertIn('payment', mail.outbox[0].body.lower())

    def test_guest_applicant_email_sent(self):
        """Test that email is sent to guest applicant (no user account)."""
        app = EventApplication.objects.create(
            event=self.event,
            user=None,  # Guest
            first_name='Guest',
            last_name='User',
            email='guest@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
        )
        result = send_application_decision_email(track_app, 'accept')
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['guest@test.com'])

    def test_outcome_type_normalization(self):
        """Test that outcome types are normalized (accept → accepted, etc.)."""
        app = EventApplication.objects.create(
            event=self.event,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
        )
        # Test different outcome formats
        result1 = send_application_decision_email(track_app, 'accept')
        result2 = send_application_decision_email(track_app, 'accepted')
        self.assertTrue(result1)
        self.assertTrue(result2)
        self.assertEqual(len(mail.outbox), 2)


class NominatorEmailTestCase(TestCase):
    """Test nominator-facing email sending."""

    def setUp(self):
        mail.outbox = []
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            start_time=timezone.now(),
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
        )
        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0.00,
        )

    def test_nominator_acknowledgement_sent(self):
        """Test that nominator acknowledgement email is sent."""
        app = EventApplication.objects.create(
            event=self.event,
            email='nominee@test.com',
            submission_mode='third_party_nomination',
            nominator_name='John Nominator',
            nominator_email='john@test.com',
            nominee_name='Jane Nominee',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
        )
        result = send_nominator_acknowledgement_email(track_app)
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['john@test.com'])

    def test_nominator_acknowledgement_includes_details(self):
        """Test that nominator acknowledgement includes nomination details."""
        app = EventApplication.objects.create(
            event=self.event,
            email='nominee@test.com',
            submission_mode='third_party_nomination',
            nominator_name='John Nominator',
            nominator_email='john@test.com',
            nominee_name='Jane Nominee',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
        )
        result = send_nominator_acknowledgement_email(track_app)
        self.assertTrue(result)
        self.assertIn('Jane Nominee', mail.outbox[0].body)
        self.assertIn('Test Event', mail.outbox[0].body)

    def test_nominator_acceptance_notification_sent(self):
        """Test that nominator acceptance notification is sent."""
        app = EventApplication.objects.create(
            event=self.event,
            email='nominee@test.com',
            submission_mode='third_party_nomination',
            nominator_name='John Nominator',
            nominator_email='john@test.com',
            nominee_name='Jane Nominee',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier,
            status='accepted',
        )
        result = send_nominator_outcome_email(track_app, 'accepted')
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['john@test.com'])

    def test_nominator_decline_notification_sent(self):
        """Test that nominator decline notification is sent."""
        app = EventApplication.objects.create(
            event=self.event,
            email='nominee@test.com',
            submission_mode='third_party_nomination',
            nominator_name='John Nominator',
            nominator_email='john@test.com',
            nominee_name='Jane Nominee',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='declined',
        )
        result = send_nominator_outcome_email(track_app, 'declined')
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)

    def test_nominator_email_not_sent_if_no_email(self):
        """Test that nominator email is not sent if no email provided."""
        app = EventApplication.objects.create(
            event=self.event,
            email='nominee@test.com',
            submission_mode='third_party_nomination',
            nominator_name='John Nominator',
            nominator_email='',  # Empty
            nominee_name='Jane Nominee',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
        )
        result = send_nominator_acknowledgement_email(track_app)
        self.assertFalse(result)
        self.assertEqual(len(mail.outbox), 0)

    def test_nominator_acceptance_includes_tier_info(self):
        """Test that acceptance notification includes tier information."""
        tier_paid = TrackPricingTier.objects.create(
            track=self.track,
            label='Paid Tier',
            price=99.99,
        )
        app = EventApplication.objects.create(
            event=self.event,
            email='nominee@test.com',
            submission_mode='third_party_nomination',
            nominator_name='John Nominator',
            nominator_email='john@test.com',
            nominee_name='Jane Nominee',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=tier_paid,
            status='accepted',
        )
        result = send_nominator_outcome_email(track_app, 'accepted')
        self.assertTrue(result)
        self.assertIn('Paid Tier', mail.outbox[0].body)
        self.assertIn('99.99', mail.outbox[0].body)


class ReminderEmailTestCase(TestCase):
    """Test reminder to complete registration emails."""

    def setUp(self):
        mail.outbox = []
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('applicant@test.com', 'applicant@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            start_time=timezone.now(),
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
        )
        self.tier_paid = TrackPricingTier.objects.create(
            track=self.track,
            label='Paid',
            price=99.99,
        )
        self.tier_free = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0.00,
        )

    def test_reminder_sent_for_paid_tier(self):
        """Test that reminder is sent for paid tier."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_paid,
        )
        result = send_reminder_to_complete_email(track_app)
        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)

    def test_reminder_not_sent_for_free_tier(self):
        """Test that reminder is not sent for free tier."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_free,
        )
        result = send_reminder_to_complete_email(track_app)
        self.assertFalse(result)
        self.assertEqual(len(mail.outbox), 0)

    def test_reminder_respects_opt_out(self):
        """Test that reminder respects opt-out flag."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            opt_out_automated_communication=True,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_paid,
        )
        result = send_reminder_to_complete_email(track_app)
        self.assertFalse(result)
        self.assertEqual(len(mail.outbox), 0)

    def test_reminder_includes_payment_info(self):
        """Test that reminder includes payment information."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_paid,
        )
        result = send_reminder_to_complete_email(track_app)
        self.assertTrue(result)
        email_body = mail.outbox[0].body
        self.assertIn('99.99', email_body)
        self.assertIn('Paid', email_body)


class EventEmailTemplateTestCase(TestCase):
    """Test event-specific email template configuration."""

    def setUp(self):
        mail.outbox = []
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            start_time=timezone.now(),
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
        )
        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0.00,
        )

    def test_event_specific_template_used(self):
        """Test that event-specific template is used if available."""
        # Create event-specific template
        EventEmailTemplate.objects.create(
            event=self.event,
            template_key='application_accepted_applicant',
            subject='Custom: You are in!',
            html_body='<p>Custom HTML body</p>',
            text_body='Custom text body',
            is_active=True,
        )

        app = EventApplication.objects.create(
            event=self.event,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier,
        )
        result = send_application_decision_email(track_app, 'accept')
        self.assertTrue(result)
        # Should use custom subject
        self.assertIn('Custom', mail.outbox[0].subject)

    def test_inactive_template_skipped(self):
        """Test that inactive templates are skipped."""
        # Create inactive event-specific template
        EventEmailTemplate.objects.create(
            event=self.event,
            template_key='application_accepted_applicant',
            subject='Inactive template',
            html_body='<p>Inactive</p>',
            text_body='Inactive',
            is_active=False,
        )

        app = EventApplication.objects.create(
            event=self.event,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier,
        )
        result = send_application_decision_email(track_app, 'accept')
        self.assertTrue(result)
        # Should not use inactive template
        self.assertNotIn('Inactive', mail.outbox[0].subject)


class Phase11Phase12IntegrationTestCase(TestCase):
    """Test integration between Phase 11 (attendee directory) and Phase 12 (email templates)."""

    def setUp(self):
        mail.outbox = []
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('applicant@test.com', 'applicant@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            start_time=timezone.now(),
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
        )
        self.tier_paid = TrackPricingTier.objects.create(
            track=self.track,
            label='Paid',
            price=99.99,
        )

    def test_acceptance_creates_registration_and_sends_email(self):
        """Test that acceptance creates registration and sends email."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            opt_out_automated_communication=False,
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            accepted_tier=self.tier_paid,
        )

        # Send acceptance email (would be called by Phase 10 accept endpoint)
        result = send_application_decision_email(track_app, 'accept')
        self.assertTrue(result)

        # Verify email was sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('applicant@test.com', mail.outbox[0].to)

        # Email should mention payment (due to paid tier from Phase 11)
        self.assertIn('payment', mail.outbox[0].body.lower())
