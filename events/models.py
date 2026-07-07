"""
Models for the events app.
An `Event` is associated with a single community and has a state
machine to represent its current status.  Slugs are automatically
generated based on the title and community ID.  The creator of the
event is stored in the `created_by` field.
"""
from django.db import models
from django.db.models import F
from django.db.models.functions import Upper
from django.contrib.auth.models import User
from community.models import Community
from django.utils.text import slugify
from django.conf import settings
from django.core.exceptions import ValidationError
import os, uuid
def event_preview_upload_to(instance, filename):
    """
    Save preview images directly under:
      media_previews/event/<file>
    (No tmp/, no <id>/, no preview/ subfolder)
    """
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "preview"
    return f"previews/event/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"

def lounge_table_icon_upload_to(instance, filename):
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "table"
    return f"lounge/tables/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"

def event_participant_image_upload_to(instance, filename):
    """Upload path for event-specific participant images."""
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "participant"
    return f"events/participants/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"


# Backward-compatibility for historical migrations (e.g. events.0115) that
# import this symbol from events.models at import time.
def series_cover_upload_to(instance, filename):
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "series-cover"
    return f"previews/series/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"

class Event(models.Model):
    """Represents an event within an community."""
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
        ("live", "Live"),
        ("ended", "Ended"),
        ("cancelled", "Cancelled"),
    ]
    FORMAT_CHOICES = [
        ("in_person", "In-Person"),
        ("virtual", "Virtual"),
        ("hybrid", "Hybrid"),
    ]
    community = models.ForeignKey(
        Community,
        on_delete=models.CASCADE,
        related_name="events"
    )
    title = models.CharField(max_length=255)
    slug = models.CharField(max_length=255, unique=True, blank=True)
    canonical_event_id = models.UUIDField(
        default=uuid.uuid4,
        db_index=True,
        editable=False,
        help_text="Shared event UUID used to identify the same event across platforms.",
    )
    description = models.TextField(blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    timezone = models.CharField(max_length=64, default=settings.TIME_ZONE, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="draft")
    is_live = models.BooleanField(default=False)
    is_on_break = models.BooleanField(default=False)
    is_multi_day = models.BooleanField(
        default=False,
        help_text="True if this event spans multiple calendar days"
    )

    # Cancellation fields
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="cancelled_events")
    cancellation_message = models.TextField(blank=True, default="")
    recommended_event = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="recommended_from_cancelled"
    )

    # Admin visibility control
    is_hidden = models.BooleanField(
        default=False,
        help_text="When True, the event is hidden from the platform for all non-admin users."
    )

    # New fields
    category = models.CharField(max_length=100, blank=True)
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES, default="virtual")
    location = models.CharField(max_length=255, blank=True)
    location_city = models.CharField(max_length=255, blank=True)
    location_country = models.CharField(max_length=255, blank=True)
    venue_name = models.CharField(max_length=255, blank=True, help_text="Venue name (e.g., Hotel, Office building)")
    venue_address = models.CharField(max_length=500, blank=True, help_text="Exact venue address - only shown to registered/accepted members")
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        default=None,
        help_text="Null for paid events (price managed in Product Management). 0.00 for free events."
    )
    currency = models.CharField(
        max_length=3,
        default="USD",
        editable=False,
        help_text="Currency code (ISO 4217). Always USD (US Dollar)"
    )
    is_free = models.BooleanField(default=False)
    price_label = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Optional display label (e.g. 'By application only', 'GBP 500'). Informational only — does not trigger payment."
    )
    price_display_label = models.CharField(
        max_length=200,
        blank=True,
        default="",
        help_text="Fallback label shown when Saleor is unavailable (e.g. 'From £500'). Used if allow_manual_price_display is True or as last resort."
    )
    allow_manual_price_display = models.BooleanField(
        default=False,
        help_text="When True, always show price_display_label instead of fetching from Saleor."
    )
    REGISTRATION_TYPE_CHOICES = [
        ('open', 'Open Registration'),
        ('apply', 'Application Required'),
    ]
    registration_type = models.CharField(
        max_length=20,
        choices=REGISTRATION_TYPE_CHOICES,
        default='open',
        help_text="Registration flow: 'open' for instant registration, 'apply' for application review"
    )
    preapproval_code_enabled = models.BooleanField(default=False)
    preapproval_allowlist_enabled = models.BooleanField(default=False)
    attendee_marker_enabled = models.BooleanField(default=False)
    attendee_marker_label = models.CharField(max_length=255, blank=True, default="")
    attending_count = models.PositiveIntegerField(default=0)
    max_participants = models.PositiveIntegerField(
        null=True, 
        blank=True, 
        help_text="Maximum number of participants allowed (null for unlimited)"
    )
    cpd_cpe_minutes = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Total eligible learning minutes for CPD/CPE credit calculation",
    )
    cpd_cpe_minutes_per_credit = models.PositiveIntegerField(
        default=60,
        help_text="How many minutes equal 1 CPD/CPE credit",
    )
    show_cpd_cpe = models.BooleanField(
        default=True,
        help_text="Whether to display CPD/CPE credits on event details and cards",
    )
    preview_image = models.ImageField(
        upload_to=event_preview_upload_to,
        blank=True,
        null=True,
    )
    cover_image = models.ImageField(
        upload_to=event_preview_upload_to,
        blank=True,
        null=True,
        help_text="Displayed when host is disconnected or event is not live"
    )
    waiting_room_image = models.ImageField(
        upload_to=event_preview_upload_to,
        blank=True,
        null=True,
        help_text="Replaces the clock in waiting room if uploaded"
    )
    waiting_room_enabled = models.BooleanField(
        default=False,
        help_text="If True, participants enter waiting room until admitted by host",
    )
    lounge_enabled_waiting_room = models.BooleanField(
        default=True,
        help_text="Allow waiting room participants to access Social Lounge",
    )
    networking_tables_enabled_waiting_room = models.BooleanField(
        default=True,
        help_text="Allow waiting room participants to join networking tables",
    )
    auto_admit_seconds = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="If set, auto-admit participants after N seconds of waiting",
    )
    waiting_room_grace_period_minutes = models.PositiveIntegerField(
        default=0,
        help_text="Minutes after start_time where participants can join freely without waiting room approval",
    )
    attendees = models.ManyToManyField(
        User,
        through='EventRegistration',
        through_fields=('event', 'user'),
        related_name='events_joined',
        blank=True,
    )
    # Speaker & Recording
    active_speaker = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="active_events",
    )
    recording_url = models.URLField(blank=True)
    replay_available = models.BooleanField(default=False)
    replay_availability_duration = models.CharField(max_length=100, blank=True, null=True)
    replay_notifications_sent_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Set when replay notifications are dispatched. Null = never sent."
    )
    starting_soon_notifications_sent_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Set when 1-hour-before-event emails are sent. Null = never sent."
    )
    replay_expiring_notifications_sent_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Set when replay-expiring-soon emails are sent. Null = never sent."
    )
    replay_visible_to_participants = models.BooleanField(
        default=False,
        help_text="If False, only host can download/see recording. If True, participants can access after notifications sent."
    )
    replay_publishing_mode = models.CharField(
        max_length=20,
        choices=[
            ("manual_review", "Manual Review"),
            ("auto_publish", "Auto Publish"),
        ],
        default="manual_review",
        help_text="Whether to auto-publish recording once available, or hold for host review."
    )
    # RTK live meeting fields
    rtk_meeting_id = models.CharField(max_length=255, blank=True, null=True)
    rtk_meeting_title = models.CharField(max_length=255, blank=True, null=True)
    # Cloudflare RealtimeKit recording control fields
    rtk_recording_id = models.CharField(max_length=255, blank=True, null=True)
    is_recording = models.BooleanField(default=False)
    recording_paused_at = models.DateTimeField(null=True, blank=True)

    # Saleor integration fields
    saleor_product_id = models.CharField(max_length=255, blank=True, null=True)
    saleor_variant_id = models.CharField(max_length=255, blank=True, null=True)

    # WordPress Events Calendar sync fields
    wordpress_event_id = models.PositiveIntegerField(
        null=True,
        blank=True,
        unique=True,
        db_index=True,
        help_text="The Events Calendar (WordPress) post ID for this event"
    )
    wordpress_event_url = models.URLField(
        blank=True,
        help_text="Canonical URL of this event on the WordPress site"
    )
    wordpress_synced_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of the last successful sync from WordPress"
    )
    wordpress_sync_status = models.CharField(
        max_length=20,
        blank=True,
        choices=[
            ("synced", "Synced"),
            ("pending", "Pending"),
            ("error", "Error"),
            ("skipped", "Skipped"),
        ],
        help_text="Last sync result from WordPress"
    )
    wp_sync_locked = models.BooleanField(
        default=False,
        help_text="When True, WordPress sync will not overwrite manual edits to this event"
    )

    # Legacy Agora recording fields (no longer used)
    # Meta
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_events")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    live_started_at = models.DateTimeField(null=True, blank=True)
    live_ended_at = models.DateTimeField(null=True, blank=True)
    idle_started_at = models.DateTimeField(null=True, blank=True)
    ended_by_host = models.BooleanField(default=False)

    # WebinarSeries association
    series = models.ForeignKey(
        'EventSeries',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="child_events",
        help_text="Parent series if this event is part of a webinar series"
    )
    series_order = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="1-indexed position of this event within its series"
    )
    series_session_label = models.CharField(
        max_length=255,
        blank=True,
        help_text="Display label like 'Session 1: Introduction' for this event"
    )

    # Lounge Settings
    lounge_enabled_before = models.BooleanField(default=False)
    lounge_before_buffer = models.PositiveIntegerField(default=30)  # minutes
    lounge_enabled_during = models.BooleanField(default=True)
    lounge_enabled_breaks = models.BooleanField(default=False)
    lounge_enabled_after = models.BooleanField(default=False)
    lounge_after_buffer = models.PositiveIntegerField(default=30)  # minutes
    lounge_enabled_speed_networking = models.BooleanField(
        default=False,
        help_text="Allow participants to access Social Lounge when leaving Speed Networking",
    )
    lounge_table_capacity = models.IntegerField(default=4, help_text="Max participants per table in Social Lounge")  # ✅ NEW

    # Breakout Late Joiner Settings
    auto_assign_late_joiners = models.BooleanField(
        default=False,
        help_text="Automatically assign new participants to breakout rooms during active sessions"
    )
    auto_assign_strategy = models.CharField(
        max_length=20,
        choices=[
            ('least', 'Least participants'),
            ('round_robin', 'Round-robin distribution'),
            ('sequential', 'Sequential room mapping'),
        ],
        default='least',
        help_text="Strategy for automatic assignment of late joiners"
    )
    breakout_rooms_active = models.BooleanField(
        default=False,
        help_text="Flag to track if breakout rooms are currently active"
    )

    # Break Mode Fields
    break_started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the current break was started (None = not on break)"
    )
    break_duration_seconds = models.PositiveIntegerField(
        default=600,
        help_text="Planned break length in seconds (default 10 min)"
    )
    break_celery_task_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Celery task ID for auto-end break, stored for revocation on manual end"
    )

    # Participant List Visibility Settings
    show_participants_before_event = models.BooleanField(
        default=True,
        help_text="Allow participants to see the participant list before the event starts"
    )
    show_participants_after_event = models.BooleanField(
        default=False,
        help_text="Allow participants to see the participant list after the event ends"
    )
    show_registered_participant_count = models.BooleanField(
        default=True,
        help_text="Show the number of registered participants on event cards"
    )
    show_guest_participant_count = models.BooleanField(
        default=False,
        help_text="Show the number of guest participants on event cards"
    )
    show_public_hosts = models.BooleanField(
        default=True,
        help_text="Allow host-role participants to appear publicly on event cards and participant lists"
    )
    show_public_speakers = models.BooleanField(
        default=True,
        help_text="Allow speaker-role participants to appear publicly on event cards and participant lists"
    )
    show_public_moderators = models.BooleanField(
        default=False,
        help_text="Allow moderator-role participants to appear publicly on event cards and participant lists"
    )
    qna_moderation_enabled = models.BooleanField(
        default=False,
        help_text="Require host approval before Q&A questions are visible to attendees."
    )
    qna_anonymous_mode = models.BooleanField(
        default=False,
        help_text="Force all Q&A questions to be submitted anonymously."
    )

    qna_ai_public_suggestions_enabled = models.BooleanField(
        default=False,
        help_text="When True, host can generate and publish AI-driven question suggestions for all participants."
    )
    pre_event_qna_enabled = models.BooleanField(
        default=False,
        help_text="When True, registered users can submit questions before the event starts.",
    )

    # Multi-day Sessions Settings
    hours_calculation_session_types = models.JSONField(
        default=list,
        blank=True,
        help_text="List of session types to include in hours calculation. Valid values: 'main', 'breakout', 'workshop', 'networking'. Defaults to ['main', 'breakout', 'workshop']"
    )
    total_hours_override_minutes = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="Host-set total hours in minutes; overrides automatic session sum when has_total_hours_override is True"
    )
    has_total_hours_override = models.BooleanField(
        default=False,
        help_text="If True, use total_hours_override_minutes instead of calculated session total"
    )

    # Speed Networking Match History Visibility Settings
    show_speed_networking_match_history = models.BooleanField(
        default=True,
        help_text="Allow participants to view their speed networking match list after the event ends"
    )

    # ===== External Streaming Platform Configuration =====
    STREAMING_PLATFORM_CHOICES = [
        ('native', 'Our Platform (RTK)'),
        ('zoom', 'Zoom'),
        ('google_meet', 'Google Meet'),
        ('microsoft_teams', 'Microsoft Teams'),
    ]

    use_external_streaming = models.BooleanField(
        default=False,
        help_text="If True, use external streaming platform instead of native RTK"
    )
    external_streaming_platform = models.CharField(
        max_length=20,
        choices=STREAMING_PLATFORM_CHOICES,
        default='native',
        help_text="Which external platform to use (only used if use_external_streaming=True)"
    )
    external_streaming_url = models.URLField(
        blank=True,
        max_length=2048,
        help_text="Direct join URL for the external streaming platform"
    )
    external_streaming_meeting_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Meeting ID for the external platform (e.g., Zoom meeting ID)"
    )
    external_streaming_password = models.CharField(
        max_length=255,
        blank=True,
        help_text="Password to access the external meeting (stored as plaintext - consider encryption)"
    )
    external_streaming_other_details = models.TextField(
        blank=True,
        help_text="Additional login instructions or details for attendees"
    )
    external_streaming_host_link = models.URLField(
        blank=True,
        max_length=2048,
        help_text="Separate host/moderator join link for the external platform"
    )

    # Pinning/Promotion fields
    is_pinned = models.BooleanField(default=False, db_index=True)
    pin_priority = models.PositiveIntegerField(
        default=100,
        db_index=True,
        help_text="Lower number appears first among pinned events."
    )
    pinned_at = models.DateTimeField(null=True, blank=True)
    pinned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="pinned_events",
    )

    # Featured event for landing page hero
    is_featured = models.BooleanField(
        default=False,
        db_index=True,
        help_text="When True, this event is displayed as the featured hero event on the landing page. Only one upcoming event should be featured at a time."
    )

    # Post-event Replay Access
    replay_enabled = models.BooleanField(
        default=False,
        help_text="When True, non-registered users can sign up for replay access after event ends."
    )
    replay_video_url = models.URLField(
        blank=True, null=True,
        help_text="Full replay video URL (admin-set). Only shown to registered users."
    )
    youtube_summary_url = models.URLField(
        blank=True, null=True,
        help_text="Optional YouTube teaser/summary video URL. Shown publicly."
    )
    linkedin_summary_url = models.URLField(
        blank=True, null=True,
        help_text="Optional LinkedIn teaser/summary video URL. Shown publicly."
    )
    replay_cta_text = models.CharField(
        max_length=255,
        blank=True,
        default="Sign up to watch full replay",
        help_text="CTA text shown to non-registered users on replay-enabled past event page."
    )

    class Meta:
        ordering = ["-created_at"]

    def clean(self):
        """Validate price."""
        from django.core.exceptions import ValidationError

        # Validate price is not negative
        if self.price and self.price < 0:
            raise ValidationError("Price cannot be negative.")

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils import timezone
            # Generate slug from title + year for better SEO
            year = self.start_time.year if self.start_time else timezone.now().year
            base_slug = slugify(f"{self.title}-{year}")
            # Ensure slug doesn't exceed max_length minus room for suffix
            base_slug = base_slug[:240]
            slug = base_slug
            suffix = 2
            while Event.objects.filter(slug=slug).exclude(pk=self.pk if self.pk else None).exists():
                slug = f"{base_slug}-{suffix}"
                suffix += 1
            self.slug = slug

        # Ensure default currency is set
        if not self.currency:
            self.currency = "SGD"

        super().save(*args, **kwargs)
    def __str__(self) -> str:
        return f"{self.title} ({self.community.name})"

    # ===== Computed Properties for Multi-Day Sessions =====
    @property
    def has_sessions(self):
        """Check if this event has sessions."""
        return self.sessions.exists()

    @property
    def next_session(self):
        """Get the next upcoming session."""
        from django.utils import timezone
        return self.sessions.filter(start_time__gte=timezone.now()).order_by('start_time').first()

    @property
    def current_live_session(self):
        """Get the currently live session, if any."""
        return self.sessions.filter(is_live=True).first()

    @property
    def is_any_session_live(self):
        """Check if any session is currently live."""
        return self.sessions.filter(is_live=True).exists()

    def calculate_total_hours(self):
        """
        Calculate total event hours from sessions minus breaks.
        Returns minutes. If has_total_hours_override is True, returns the override value.
        """
        if self.has_total_hours_override and self.total_hours_override_minutes is not None:
            return self.total_hours_override_minutes
        session_types = self.hours_calculation_session_types or ["main", "breakout", "workshop"]
        return sum(
            s.effective_duration_minutes()
            for s in self.sessions.filter(session_type__in=session_types)
        )

    def get_or_create_participant_badge(self):
        """Get or create the default 'Participant' badge for this event."""
        badge, created = self.badge_labels.get_or_create(
            name='Participant',
            defaults={'color': '#9CA3AF'}
        )
        return badge

    def has_valid_application_tracks(self):
        """
        Check if this event has at least one valid application track.
        A valid track must have:
        - is_active = True
        - status = open
        - label and key (non-empty)
        - at least one submission mode in enabled_submission_modes
        - at least one active pricing tier
        - at least one role mapping
        """
        if self.registration_type != 'apply':
            return True

        for track in self.application_tracks.filter(is_active=True, status='open'):
            has_label = bool(track.label and track.label.strip())
            has_key = bool(track.key and track.key.strip())
            has_modes = bool(track.enabled_submission_modes and len(track.enabled_submission_modes) > 0)
            has_pricing = track.pricing_tiers.filter(is_active=True).exists()
            has_roles = bool(track.role_mappings_on_acceptance and len(track.role_mappings_on_acceptance) > 0)

            if has_label and has_key and has_modes and has_pricing and has_roles:
                return True

        return False




IMAA_CONNECT_PLATFORM_SLUG = "imaa_connect"
MANDA_PLATFORM_SLUG = "manda"


class EventPlatform(models.Model):
    """Platform where an IMAA Connect event can be published.

    For now this supports IMAA Connect and MANDA. More platforms can be added
    from the database/admin later without changing frontend code.
    """

    slug = models.SlugField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    display_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["display_order", "name"]
        indexes = [models.Index(fields=["slug", "is_active"])]

    def __str__(self):
        return self.name


class EventPublication(models.Model):
    """Where an event should be visible.

    The checkbox controls visibility only. Registration remains handled by the
    platform where the user opens the event. Participant sync is intentionally
    left for the later shared-Cognito phase.
    """

    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="publications",
    )
    platform = models.ForeignKey(
        EventPlatform,
        on_delete=models.CASCADE,
        related_name="event_publications",
    )
    is_enabled = models.BooleanField(default=True)
    last_synced_at = models.DateTimeField(null=True, blank=True)
    external_event_id = models.CharField(max_length=100, blank=True, default="")
    sync_status = models.CharField(max_length=50, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["platform__display_order", "platform__name"]
        constraints = [
            models.UniqueConstraint(
                fields=["event", "platform"],
                name="uniq_event_publication_platform",
            )
        ]
        indexes = [
            models.Index(fields=["is_enabled"]),
        ]

    def __str__(self):
        return f"{self.event_id} on {self.platform.slug}"



class PlatformSyncJob(models.Model):
    """Outbox job for syncing IMAA Connect event changes to another platform.

    Participant jobs are defined now but intentionally not used until both
    platforms share Cognito, because duplicate checks must use
    canonical_event_id + cognito_sub instead of email.
    """

    class JobType(models.TextChoices):
        EVENT_UPSERT = "event_upsert", "Event upsert"
        EVENT_DISABLE = "event_disable", "Event disable"
        PARTICIPANT_UPSERT = "participant_upsert", "Participant upsert"
        PARTICIPANT_CANCEL = "participant_cancel", "Participant cancel"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="platform_sync_jobs")
    platform = models.ForeignKey(EventPlatform, on_delete=models.CASCADE, related_name="sync_jobs")
    job_type = models.CharField(max_length=40, choices=JobType.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True)
    payload = models.JSONField(default=dict, blank=True)
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=5)
    next_attempt_at = models.DateTimeField(auto_now_add=True, db_index=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["next_attempt_at", "id"]
        indexes = [
            models.Index(fields=["platform", "job_type", "status"]),
            models.Index(fields=["event", "platform", "job_type"]),
        ]

    def __str__(self):
        return f"{self.job_type} for {self.event} on {self.platform} ({self.status})"

    def mark_processing(self):
        from django.utils import timezone

        self.status = self.Status.PROCESSING
        self.locked_at = timezone.now()
        self.save(update_fields=["status", "locked_at", "updated_at"])

    def mark_succeeded(self):
        from django.utils import timezone

        self.status = self.Status.SUCCEEDED
        self.processed_at = timezone.now()
        self.last_error = ""
        self.save(update_fields=["status", "processed_at", "last_error", "updated_at"])

    def mark_failed(self, error, *, retry_delay_seconds=300):
        from django.utils import timezone

        self.attempts += 1
        self.status = self.Status.FAILED
        self.last_error = str(error)[:4000]
        self.locked_at = None
        self.next_attempt_at = timezone.now() + timezone.timedelta(seconds=retry_delay_seconds)
        self.save(update_fields=[
            "attempts", "status", "last_error", "locked_at", "next_attempt_at", "updated_at",
        ])



class ExternalEventMapping(models.Model):
    """Map an event received from an external source to a local IMAA Connect event.

    This is used for MANDA -> IMAA Connect event sharing. It intentionally maps
    events only. Participant/user sync must wait until both platforms use the
    same Cognito user pool, so duplicate registration checks can use
    canonical_event_id + cognito_sub instead of email.
    """

    SOURCE_MANDA = "manda"
    SOURCE_PLATFORM_CHOICES = [
        (SOURCE_MANDA, "MANDA"),
    ]

    source_platform = models.CharField(
        max_length=50,
        choices=SOURCE_PLATFORM_CHOICES,
        default=SOURCE_MANDA,
        db_index=True,
    )
    source_event_id = models.CharField(
        max_length=64,
        db_index=True,
        help_text="Event ID from the source platform, for example MANDA Event ID.",
    )
    canonical_event_id = models.UUIDField(
        db_index=True,
        help_text="Shared event UUID used to identify the same event across platforms.",
    )
    local_event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="external_mappings",
    )
    is_active = models.BooleanField(default=True)
    last_payload = models.JSONField(default=dict, blank=True)
    last_synced_at = models.DateTimeField(null=True, blank=True)
    disabled_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["source_platform", "source_event_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["source_platform", "source_event_id"],
                name="uniq_external_event_source_id",
            ),
            models.UniqueConstraint(
                fields=["source_platform", "canonical_event_id"],
                name="uniq_external_event_canonical_id",
            ),
        ]
        indexes = [
            models.Index(fields=["source_platform", "is_active"]),
        ]

    def __str__(self):
        return f"{self.source_platform}:{self.source_event_id} -> {self.local_event_id}"

class ExternalParticipantMapping(models.Model):
    """Map a participant received from MANDA to a local IMAA Connect registration.

    Participant sync is intentionally identity-based. The stable duplicate key is
    canonical_event_id + cognito_sub, while email/name are display metadata only.
    """

    SOURCE_MANDA = "manda"
    SOURCE_PLATFORM_CHOICES = [
        (SOURCE_MANDA, "MANDA"),
    ]

    source_platform = models.CharField(
        max_length=50,
        choices=SOURCE_PLATFORM_CHOICES,
        default=SOURCE_MANDA,
        db_index=True,
    )
    source_participant_id = models.CharField(
        max_length=64,
        db_index=True,
        help_text="Participant/attendee ID from the source platform.",
    )
    canonical_event_id = models.UUIDField(
        db_index=True,
        help_text="Shared event UUID used to identify the same event across platforms.",
    )
    cognito_sub = models.CharField(
        max_length=128,
        db_index=True,
        help_text="Stable Cognito subject for the participant identity.",
    )
    local_registration = models.ForeignKey(
        "EventRegistration",
        on_delete=models.CASCADE,
        related_name="external_participant_mappings",
    )
    is_active = models.BooleanField(default=True)
    last_payload = models.JSONField(default=dict, blank=True)
    last_source_updated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["source_platform", "source_participant_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["source_platform", "source_participant_id"],
                name="uniq_external_participant_source_id",
            ),
            models.UniqueConstraint(
                fields=["source_platform", "canonical_event_id", "cognito_sub"],
                name="uniq_external_participant_identity",
            ),
        ]
        indexes = [
            models.Index(fields=["source_platform", "is_active"]),
            models.Index(fields=["canonical_event_id", "cognito_sub"]),
        ]

    def __str__(self):
        return f"{self.source_platform}:{self.source_participant_id} -> {self.local_registration_id}"


class EventEmailTemplate(models.Model):
    """Per-event customizable email templates for registration confirmations and application decisions."""
    TEMPLATE_KEY_CHOICES = [
        # Phase 1-11: Registration templates
        ("user_registration_acknowledgement", "User Registration Acknowledgement"),
        ("guest_registration_acknowledgement", "Guest Registration Acknowledgement"),
        ("event_confirmation", "Event Confirmation (Speaker/Host)"),
        ("event_starting_soon", "Event Starting Soon (1 Hour Before)"),
        ("event_join_confirmation", "Event Join Confirmation"),
        ("event_cancelled", "Event Cancelled"),
        ("event_invite", "Event Invite"),
        ("application_acknowledgement", "Application Acknowledgement"),
        ("application_approved", "Application Approved"),
        ("application_declined", "Application Declined"),
        ("replay_no_show", "Replay: No Show"),
        ("replay_partial", "Replay: Partial Attendance"),
        ("replay_expiring_soon", "Replay Expiring Soon"),
        ("post_event_qna_answer", "Post-Event Q&A Answer"),
        ("networking_meeting_request", "Networking Meeting Request"),
        ("networking_meeting_accepted", "Networking Meeting Accepted"),
        ("networking_meeting_declined", "Networking Meeting Declined"),
        ("networking_meeting_suggested", "Networking Meeting Suggested"),
        ("networking_meeting_cancelled", "Networking Meeting Cancelled"),
        ("networking_meeting_reminder", "Networking Meeting Reminder"),

        # Phase 12: Application decision templates (Applicant)
        ("application_accepted_applicant", "Application Accepted (Applicant)"),
        ("application_accepted_payment_pending", "Application Accepted - Payment Pending (Applicant)"),
        ("payment_confirmed_applicant", "Payment Confirmed (Applicant)"),
        ("application_declined_applicant", "Application Declined (Applicant)"),
        ("application_waitlisted_applicant", "Application Waitlisted (Applicant)"),
        ("application_reminder_to_complete", "Reminder to Complete Registration"),

        # Phase 12: Application decision templates (Nominator)
        ("application_acknowledgement_nominator", "Application Submission Acknowledgement (Nominator)"),
        ("application_accepted_nominator", "Nominee Accepted Notification (Nominator)"),
        ("application_declined_nominator", "Nominee Declined Notification (Nominator)"),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="email_template_overrides")
    template_key = models.CharField(max_length=80, choices=TEMPLATE_KEY_CHOICES)
    subject = models.CharField(max_length=250)
    html_body = models.TextField()
    text_body = models.TextField(blank=True)
    editor_json = models.JSONField(null=True, blank=True)
    mjml_body = models.TextField(blank=True)
    editor_type = models.CharField(max_length=50, default="templatical")
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="event_email_templates_updated"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [['event', 'template_key']]
        verbose_name = "Event Email Template"
        verbose_name_plural = "Event Email Templates"

    def __str__(self):
        return f"{self.get_template_key_display()} - {self.event.title}"


class LoungeTable(models.Model):
    """Represents a virtual table in the Social Lounge."""
    TABLE_CATEGORY_CHOICES = [
        ("LOUNGE", "Social Lounge"),
        ("BREAKOUT", "Breakout Room"),
    ]
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="lounge_tables")
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=20, choices=TABLE_CATEGORY_CHOICES, default="LOUNGE")
    max_seats = models.IntegerField(default=4)
    rtk_meeting_id = models.CharField(max_length=255, blank=True, null=True)
    icon = models.ImageField(upload_to=lounge_table_icon_upload_to, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.event.title}"

class LoungeParticipant(models.Model):
    """Tracks which user is sitting at which lounge table."""
    table = models.ForeignKey(LoungeTable, on_delete=models.CASCADE, related_name="participants")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    seat_index = models.IntegerField()
    joined_at = models.DateTimeField(auto_now_add=True)

    # Track the RTK participant ID for accurate removal
    rtk_participant_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="ID of participant in RTK meeting. Used for proper cleanup on leave."
    )

    class Meta:
        unique_together = ("table", "seat_index")
        # Also ensure a user can only be at one table per event if required,
        # but for now we'll enforce unique seating via seat_index.
        indexes = [
            models.Index(fields=["user", "table"], name="lpart_user_table_idx"),
        ]

    def __str__(self):
        return f"{self.user.username} at {self.table.name}"
    
class EventRegistration(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='registrations')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_registrations')
    
    STATUS_CHOICES = [
        ('registered', 'Registered'),
        ('cancellation_requested', 'Cancellation Requested'),
        ('cancelled', 'Cancelled'),
        ('deregistered', 'Deregistered'),
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='registered')
    attendee_status = models.CharField(
        max_length=20,
        choices=[
            ("confirmed", "Confirmed"),
            ("payment_pending", "Payment Pending"),
            ("cancelled", "Cancelled"),
        ],
        default="confirmed",
        db_index=True,
        help_text="Application/payment state: confirmed, payment_pending, or cancelled",
    )
    registered_at = models.DateTimeField(auto_now_add=True)
    joined_live = models.BooleanField(default=False)
    watched_replay = models.BooleanField(default=False)
    is_online = models.BooleanField(default=False)
    online_count = models.PositiveIntegerField(default=0)
    admission_status = models.CharField(
        max_length=20,
        choices=[
            ("waiting", "Waiting for host admission"),
            ("admitted", "Admitted to live meeting"),
            ("rejected", "Host rejected participation"),
            ("left_waiting", "Participant left waiting room voluntarily"),
        ],
        default="waiting",
        db_index=True,
        help_text="Only used if event has waiting_room_enabled=True",
    )
    admitted_at = models.DateTimeField(null=True, blank=True)
    admitted_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="admissions_reviewed",
    )
    rejected_at = models.DateTimeField(null=True, blank=True)
    rejected_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="admissions_rejected",
    )
    rejection_reason = models.TextField(blank=True)
    waiting_started_at = models.DateTimeField(null=True, blank=True)
    joined_live_at = models.DateTimeField(null=True, blank=True)
    current_mood = models.CharField(
        max_length=32,
        null=True,
        blank=True,
        db_index=True,
        help_text="Current mood emoji for this user in this event",
    )
    mood_updated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time current_mood was updated",
    )

    # Session tracking for auto-rejoin support
    was_ever_admitted = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Has this user been admitted in this event session?"
    )
    session_token = models.CharField(
        max_length=64,
        unique=True,
        blank=True,
        null=True,
        db_index=True,
        help_text="Unique token per admitted session for rejoin detection"
    )
    current_session_started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When user was first admitted in current session"
    )
    last_reconnect_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Track last rejoin attempt to detect disconnects"
    )
    last_breakout_table = models.ForeignKey(
        'LoungeTable',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='previous_occupants',
        help_text="Last breakout room assigned to this user (for auto-rejoin)"
    )

    # Moderation
    is_banned = models.BooleanField(default=False)

    # Participant Location Tracking
    LOCATION_CHOICES = [
        ("pre_event", "Pre-Event (not joined)"),
        ("social_lounge", "Social Lounge"),
        ("waiting_room", "Waiting Room"),
        ("main_room", "Main Room"),
        ("breakout_room", "Breakout Room"),
    ]
    current_location = models.CharField(
        max_length=20,
        choices=LOCATION_CHOICES,
        default="pre_event",
        db_index=True,
        help_text="Participant's current location within the event ecosystem",
    )
    badge_labels = models.ManyToManyField(
        'EventBadgeLabel',
        blank=True,
        related_name='registrations',
    )

    # Post-acceptance form writeback fields
    directory_visibility = models.BooleanField(
        default=False,
        help_text='Whether contact details can be shared with other attendees'
    )
    photo_video_consent = models.CharField(
        max_length=20,
        choices=[
            ('full', 'Yes, use my image in all materials'),
            ('social_only', 'Yes, but only on social media'),
            ('no', 'No, do not use my image'),
        ],
        default='no',
        blank=True,
        help_text='Photo and video consent from form'
    )
    visa_support_requested = models.BooleanField(
        default=False,
        help_text='Whether participant requested visa support or invitation letter'
    )
    participant_information_completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When participant completed information form'
    )
    accessibility_need_declared = models.BooleanField(
        default=False,
        help_text='Whether participant declared accessibility or support needs in form'
    )
    attendance_mode = models.CharField(
        max_length=20,
        choices=[
            ('in_person', 'In Person'),
            ('online', 'Online'),
            ('hybrid_not_selected', 'Hybrid Event - Not Yet Selected'),
        ],
        default='hybrid_not_selected',
        blank=True,
        help_text='Attendance mode selected by participant in hybrid events'
    )

    # Promotional Profile specific fields
    promotional_profile_completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When promotional profile was completed'
    )
    display_consent = models.CharField(
        max_length=20,
        choices=[
            ('yes', 'Yes, display profile publicly'),
            ('no', 'No, do not display'),
            ('pending', 'Not yet answered'),
        ],
        default='pending',
        blank=True,
        help_text='Whether attendee consents to public profile display'
    )

    # Restricted data retention override
    restricted_data_retention_required = models.BooleanField(
        default=False,
        help_text='If True, skip automatic purge of restricted form data (used for legal/compliance holds)'
    )
    restricted_data_retention_reason = models.TextField(
        blank=True,
        help_text='Reason for retaining restricted data (legal reference, compliance note, etc.)'
    )

    # Attendee roles (many-to-many)
    roles = models.ManyToManyField(
        'EventRole',
        blank=True,
        related_name='registrations',
        help_text='Roles held by this attendee in this event (e.g., Speaker, Sponsor, Attendee)'
    )

    # Phase 11: Payment tracking (for marking payment_pending → confirmed)
    marked_paid_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='marked_paid_registrations',
        help_text='Admin user who manually marked this registration as paid'
    )
    marked_paid_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When this registration was manually marked as paid'
    )
    payment_reference = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text='Payment reference (invoice number, check number, etc.)'
    )

    class Meta:
        db_table = 'event_registrations'
        unique_together = ('event', 'user')
        indexes = [
            models.Index(fields=['event', 'user']),
            models.Index(fields=['user']),
            models.Index(fields=["event", "user", "status", "is_banned"], name="evtreg_user_status_ban_idx"),
            models.Index(fields=["event", "status", "user"], name="evtreg_event_status_user_idx"),
            models.Index(fields=["event", "joined_live", "id"], name="evtreg_joined_live_idx"),
            models.Index(fields=["event", "is_online", "id"], name="evtreg_online_idx"),
            models.Index(fields=["event", "current_location", "id"], name="evtreg_location_idx"),
            models.Index(fields=["event", "admission_status", "waiting_started_at"], name="evtreg_wait_queue_idx"),
        ]
    def __str__(self):
        return f'{self.user_id} -> {self.event_id}'


class EventRole(models.Model):
    """
    Defines attendee roles available for an event.
    Each role can be assigned to multiple attendees.
    Examples: Attendee, Speaker, Sponsor, Press, Researcher, etc.
    """
    VISIBILITY_CHOICES = [
        ('public', 'Public - Visible to all participants'),
        ('admin_only', 'Admin Only - Hidden from attendees'),
        ('restricted', 'Restricted - Visible only to specific roles'),
    ]

    BADGE_STYLE_CHOICES = [
        ('filled', 'Filled'),
        ('outlined', 'Outlined'),
        ('default', 'Default'),
    ]

    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name='roles',
        help_text='The event this role is defined for'
    )
    key = models.CharField(
        max_length=50,
        help_text='Unique system identifier for this role (e.g., "speaker", "sponsor")'
    )
    label = models.CharField(
        max_length=100,
        help_text='Display name for this role (e.g., "Speaker", "Conference Sponsor")'
    )
    description = models.TextField(
        blank=True,
        help_text='Description of what this role entails'
    )
    visibility = models.CharField(
        max_length=20,
        choices=VISIBILITY_CHOICES,
        default='public',
        help_text='Who can see this role displayed'
    )
    sort_priority = models.IntegerField(
        default=100,
        help_text='Sort order when displaying roles (lower numbers appear first)'
    )
    badge_color = models.CharField(
        max_length=50,
        blank=True,
        default='',
        help_text='Color for role badge (hex code like #FF5733 or color name like "blue")'
    )
    badge_style = models.CharField(
        max_length=20,
        choices=BADGE_STYLE_CHOICES,
        default='default',
        help_text='Visual style for the role badge'
    )
    triggers_promotional_profile = models.BooleanField(
        default=False,
        help_text='Whether attendees with this role must complete promotional profile form'
    )
    is_system_default = models.BooleanField(
        default=False,
        help_text='Whether this is a system-provided default role'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'event_roles'
        unique_together = ('event', 'key')
        ordering = ['sort_priority', 'label']
        indexes = [
            models.Index(fields=['event', 'key']),
            models.Index(fields=['triggers_promotional_profile']),
        ]

    def __str__(self):
        return f"{self.label} ({self.event.title})"


class EventAttendeeOrigin(models.Model):
    """
    Phase 11: Tracks origin metadata for each role an attendee has at an event.
    When an application is accepted, an EventAttendeeOrigin record is created
    for each role assigned, storing track, submission_mode, tier, and reviewer info.

    One record per EventRegistration + EventRole + EventApplicationTrack combination
    (unique_together constraint). This allows the same user to have the same role
    from multiple different tracks (e.g., accepted as Speaker via both Track A and Track B).
    """
    registration = models.ForeignKey(
        EventRegistration,
        on_delete=models.CASCADE,
        related_name='origins',
        help_text='The registration this origin belongs to'
    )
    role = models.ForeignKey(
        EventRole,
        on_delete=models.CASCADE,
        help_text='The role this origin is for'
    )

    # Track and submission information
    track = models.ForeignKey(
        'EventApplicationTrack',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text='Which application track this came from'
    )
    submission_mode = models.CharField(
        max_length=50,
        blank=True,
        default='',
        help_text='Submission mode: self_submission, confirmed, self_nomination, third_party_nomination'
    )

    # Acceptance decision metadata
    accepted_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='accepted_attendee_origins',
        help_text='Admin user who accepted this application'
    )
    accepted_at = models.DateTimeField(
        help_text='When this application was accepted'
    )
    accepted_tier = models.ForeignKey(
        'TrackPricingTier',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text='Tier that was selected on acceptance (free or paid)'
    )

    # Third-party nomination metadata (if applicable)
    nominator_name = models.CharField(
        max_length=255,
        blank=True,
        help_text='Name of nominator if third_party_nomination mode'
    )
    nominator_email = models.EmailField(
        blank=True,
        help_text='Email of nominator if third_party_nomination mode'
    )

    # Status
    status = models.CharField(
        max_length=50,
        default='active',
        choices=[
            ('active', 'Active'),
            ('cancelled', 'Cancelled'),
        ],
        help_text='Origin status (active or cancelled)'
    )

    # FIX 1: Per-track/origin payment status
    origin_status = models.CharField(
        max_length=50,
        default='confirmed',
        choices=[
            ('confirmed', 'Confirmed'),
            ('payment_pending', 'Payment Pending'),
            ('cancelled', 'Cancelled'),
        ],
        help_text='Payment/confirmation status for this origin (per-track)'
    )
    marked_paid_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='marked_paid_origins',
        help_text='Admin user who marked this origin as paid'
    )
    marked_paid_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When this origin was marked as paid'
    )
    payment_reference = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text='Optional payment reference number'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'event_attendee_origins'
        unique_together = ('registration', 'role', 'track')
        indexes = [
            models.Index(fields=['registration', 'role', 'track']),
            models.Index(fields=['track', 'submission_mode']),
            models.Index(fields=['status']),
            models.Index(fields=['accepted_at']),
        ]

    def __str__(self):
        return f"{self.registration.user.username} - {self.role.label} ({self.track.label if self.track else 'Manual'})"


class EventApplicationTrack(models.Model):
    """
    Defines application tracks for an event.
    Tracks allow organizers to create different application flows (e.g., Speaker, Startup, Sponsor).
    Each track can have different forms, pre-approval rules, and role assignments.
    """
    STATUS_CHOICES = [
        ('open', 'Open - Accepting new applications'),
        ('closed', 'Closed - No new applications'),
        ('invite_only', 'Invite Only - Selected applicants only'),
    ]

    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name='application_tracks',
        help_text='The event this track is for'
    )
    key = models.CharField(
        max_length=50,
        help_text='Unique system identifier (e.g., "speaker", "startup")'
    )
    label = models.CharField(
        max_length=100,
        help_text='Display name (e.g., "Speaker Application")'
    )
    short_description = models.TextField(
        blank=True,
        help_text='Brief description of what this track is for'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='open',
        help_text='Whether this track is accepting applications'
    )
    sort_order = models.IntegerField(
        default=0,
        help_text='Display order (lower numbers appear first)'
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text='Whether this track is enabled for the event'
    )

    # Submission configuration
    enabled_submission_modes = models.JSONField(
        default=list,
        blank=True,
        help_text='Submission modes: ["self_submission", "confirmed", "self_nomination", "third_party_nomination"]'
    )

    # Form configuration (per-track form schema)
    form_schema = models.JSONField(
        default=dict,
        blank=True,
        help_text='Custom form questions/schema for this track'
    )

    # Pre-approval configuration
    preapproval_configuration = models.JSONField(
        default=dict,
        blank=True,
        help_text='Pre-approval rules: {codes_enabled, allowlist_enabled, auto_approve}'
    )

    # Role mappings when applicant is approved
    role_mappings_on_acceptance = models.JSONField(
        default=list,
        blank=True,
        help_text='Roles to assign on acceptance: ["speaker", "sponsor", etc.]'
    )

    # Content surfaces (where to display this track)
    content_surfaces = models.JSONField(
        default=list,
        blank=True,
        help_text='Where to show this track: ["event_page", "email", "application_modal"]'
    )

    # Phase 6: Per-track content blocks
    landing_page_content = models.TextField(
        blank=True,
        default='',
        help_text='Markdown content displayed above track CTA on public event page'
    )
    form_header_notice = models.TextField(
        blank=True,
        default='',
        help_text='Markdown notice displayed at top of application form'
    )
    confirmation_page_content = models.TextField(
        blank=True,
        default='',
        help_text='Markdown content displayed after successful application submission'
    )

    # System tracking
    is_system_default = models.BooleanField(
        default=False,
        help_text='Whether this is a platform-provided default track'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'event_application_tracks'
        unique_together = ('event', 'key')
        ordering = ['sort_order', 'label']
        indexes = [
            models.Index(fields=['event', 'key']),
            models.Index(fields=['event', 'is_active']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.label} ({self.event.title})"


class TrackPricingTier(models.Model):
    """
    Pricing tiers for application tracks.
    Allows different pricing options when accepting applications to a track.
    Phase 4: Track-specific pricing configuration.
    """
    VISIBILITY_CHOICES = [
        ('public', 'Public - Visible to all applicants'),
        ('hidden', 'Hidden - Not shown, internal use only'),
        ('admin_only', 'Admin Only - Only visible in admin interface'),
    ]

    track = models.ForeignKey(
        EventApplicationTrack,
        on_delete=models.CASCADE,
        related_name='pricing_tiers',
        help_text='The application track this pricing tier belongs to'
    )
    key = models.CharField(
        max_length=50,
        help_text='Unique identifier per track (e.g., "standard", "early_career")'
    )
    label = models.CharField(
        max_length=100,
        help_text='Display name (e.g., "Standard Pass", "Early Career Pricing")'
    )
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        help_text='Price amount. 0 means free tier.'
    )
    currency = models.CharField(
        max_length=3,
        default='USD',
        help_text='ISO 4217 currency code (USD, EUR, GBP, etc.)'
    )
    visibility = models.CharField(
        max_length=20,
        choices=VISIBILITY_CHOICES,
        default='public',
        help_text='Visibility level of this tier'
    )
    is_default = models.BooleanField(
        default=False,
        help_text='If True, this is the default tier selected for new acceptances. Only one per track.'
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text='If False, tier is disabled and cannot be selected'
    )
    sort_order = models.IntegerField(
        default=0,
        help_text='Display order (ascending)'
    )
    description = models.TextField(
        blank=True,
        default='',
        help_text='Detailed description of what this tier includes'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'track_pricing_tiers'
        unique_together = ('track', 'key')
        ordering = ['sort_order', 'label']
        indexes = [
            models.Index(fields=['track', 'is_active']),
            models.Index(fields=['track', 'is_default']),
            models.Index(fields=['price']),
        ]

    def __str__(self):
        return f"{self.label} ({self.track.label}) - {self.price} {self.currency}"

    def is_paid(self):
        """Returns True if this tier has a price > 0."""
        return self.price > 0

    def is_free(self):
        """Returns True if this tier is free (price = 0)."""
        return self.price == 0

    def save(self, *args, **kwargs):
        """Ensure only one default tier per track."""
        if self.is_default:
            # Remove default flag from other tiers in this track
            TrackPricingTier.objects.filter(
                track=self.track,
                is_default=True
            ).exclude(pk=self.pk).update(is_default=False)
        super().save(*args, **kwargs)


class SharedQuestionCategory(models.Model):
    """
    Categories for shared reusable form questions.
    Phase 5: Shared question library for form builders.
    """
    name = models.CharField(
        max_length=100,
        help_text='Category name (e.g., "Personal", "Professional")'
    )
    description = models.TextField(
        blank=True,
        default='',
        help_text='Category description'
    )
    sort_order = models.IntegerField(
        default=0,
        help_text='Display order (ascending)'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'shared_question_categories'
        ordering = ['sort_order', 'name']

    def __str__(self):
        return self.name


class SharedQuestion(models.Model):
    """
    Reusable form questions in a shared library.
    Can be inserted into form schemas by administrators.
    Phase 5: Shared question library.
    """
    FIELD_TYPES = [
        ('text', 'Text'),
        ('long_text', 'Long Text'),
        ('email', 'Email'),
        ('url', 'URL'),
        ('phone', 'Phone'),
        ('number', 'Number'),
        ('date', 'Date'),
        ('select', 'Select'),
        ('multi_select', 'Multi Select'),
        ('radio_group', 'Radio Group'),
        ('checkbox_group', 'Checkbox Group'),
        ('checkbox', 'Checkbox'),
        ('file_upload', 'File Upload'),
    ]

    category = models.ForeignKey(
        SharedQuestionCategory,
        on_delete=models.CASCADE,
        related_name='questions',
        help_text='Category this question belongs to'
    )
    label = models.CharField(
        max_length=255,
        help_text='Question label/title'
    )
    field_type = models.CharField(
        max_length=50,
        choices=FIELD_TYPES,
        help_text='Type of form field'
    )
    help_text = models.TextField(
        blank=True,
        default='',
        help_text='Help text shown below the question'
    )
    placeholder = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text='Placeholder text for input fields'
    )
    options = models.JSONField(
        default=list,
        blank=True,
        help_text='Options for select/radio/checkbox fields: [{label, value}, ...]'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'shared_questions'
        ordering = ['category__sort_order', 'id']
        indexes = [
            models.Index(fields=['category', 'field_type']),
        ]

    def __str__(self):
        return f"{self.label} ({self.get_field_type_display()})"


class FormField(models.Model):
    """
    Form fields for an application track.
    Stores form schema for dynamically rendering application forms.
    Can reference a SharedQuestion or be custom-defined.
    Phase 5: Dynamic form schema system.
    """
    FIELD_TYPES = [
        ('text', 'Text'),
        ('long_text', 'Long Text'),
        ('email', 'Email'),
        ('url', 'URL'),
        ('phone', 'Phone'),
        ('number', 'Number'),
        ('date', 'Date'),
        ('select', 'Select'),
        ('multi_select', 'Multi Select'),
        ('radio_group', 'Radio Group'),
        ('checkbox_group', 'Checkbox Group'),
        ('checkbox', 'Checkbox'),
        ('file_upload', 'File Upload'),
    ]

    PROFILE_BINDING_MODES = [
        ('always_show', 'Always Show'),
        ('prefill_if_present', 'Prefill If Present'),
        ('hide_if_present', 'Hide If Present'),
        ('require_if_absent', 'Require If Absent'),
    ]

    track = models.ForeignKey(
        EventApplicationTrack,
        on_delete=models.CASCADE,
        related_name='form_fields',
        help_text='The application track this field belongs to'
    )
    shared_question = models.ForeignKey(
        SharedQuestion,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='form_fields',
        help_text='Reference to shared question library (if created from library)'
    )

    field_type = models.CharField(
        max_length=50,
        choices=FIELD_TYPES,
        help_text='Type of form field'
    )
    label = models.CharField(
        max_length=255,
        help_text='Field label/question text'
    )
    help_text = models.TextField(
        blank=True,
        default='',
        help_text='Help text shown below the field'
    )
    placeholder = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text='Placeholder text for input fields'
    )
    required = models.BooleanField(
        default=False,
        help_text='If True, this field must be filled'
    )
    options = models.JSONField(
        default=list,
        blank=True,
        help_text='Options for select/radio/checkbox fields: [{label, value}, ...]'
    )

    min_length = models.IntegerField(
        null=True,
        blank=True,
        help_text='Minimum length for text fields'
    )
    max_length = models.IntegerField(
        null=True,
        blank=True,
        help_text='Maximum length for text fields'
    )
    min_value = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        null=True,
        blank=True,
        help_text='Minimum value for number/date fields'
    )
    max_value = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        null=True,
        blank=True,
        help_text='Maximum value for number/date fields'
    )

    profile_binding = models.CharField(
        max_length=100,
        blank=True,
        default='',
        help_text='Profile field path to bind to (e.g., "user.first_name")'
    )
    profile_binding_mode = models.CharField(
        max_length=50,
        choices=PROFILE_BINDING_MODES,
        default='always_show',
        help_text='How to handle profile binding'
    )

    conditional_visibility = models.JSONField(
        default=dict,
        blank=True,
        help_text='Conditional visibility logic: {if: {...}, then: visible}'
    )

    visibility_per_mode = models.JSONField(
        default=dict,
        blank=True,
        help_text='Visibility per submission mode: {self_submission: true, confirmed: false, ...}'
    )

    visible_in_review_list = models.BooleanField(
        default=True,
        help_text='Show this field in acceptance list'
    )
    visible_in_review_detail = models.BooleanField(
        default=True,
        help_text='Show this field in acceptance detail'
    )

    sort_order = models.IntegerField(
        default=0,
        help_text='Display order (ascending)'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'form_fields'
        unique_together = [('track', 'label')]
        ordering = ['sort_order', 'id']
        indexes = [
            models.Index(fields=['track', 'sort_order']),
            models.Index(fields=['track', 'field_type']),
        ]

    def __str__(self):
        return f"{self.label} ({self.track.label})"


class EventBadgeLabel(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='badge_labels')
    name = models.CharField(max_length=100)
    color = models.CharField(max_length=7, default='#6366f1', help_text='Hex color code e.g. #6366f1')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('event', 'name')
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.event_id})"


class WaitingRoomAuditLog(models.Model):
    ACTION_CHOICES = [
        ("entered", "Participant entered waiting room"),
        ("admitted", "Host admitted participant"),
        ("rejected", "Host rejected participant"),
        ("timed_out", "Participant timeout"),
        ("left", "Participant left waiting room"),
        ("bulk_admitted", "Host admitted batch of participants"),
        ("auto_readmitted", "System auto-readmitted previously admitted participant"),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="waiting_room_logs")
    participant = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    performed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="waiting_room_actions",
        help_text="Which host/admin performed this action",
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]


class AssistanceRequestLog(models.Model):
    """Audit log for audience assistance requests sent to hosts/moderators."""
    STATUS_CHOICES = [
        ("sent", "Sent"),
        ("resolved", "Resolved"),
        ("rejected", "Rejected"),
        ("rate_limited", "Rate limited"),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="assistance_requests")
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name="assistance_requests_sent")
    message = models.TextField()
    recipient_count = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="sent")
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event", "created_at"]),
            models.Index(fields=["requester", "created_at"]),
        ]

    def __str__(self):
        return f"Assistance request by {self.requester_id} for event {self.event_id}"


# ============================================================
# ============= Waiting Room Announcement Model ==============
# ============================================================
class WaitingRoomAnnouncement(models.Model):
    """
    ✅ NEW: Announcements sent by host to waiting room participants.

    These are persistent announcements with full CRUD support:
    - Host can edit announcement text (broadcasts update to all waiting users)
    - Host can delete announcement (broadcasts delete to all waiting users)
    - Soft-delete via is_deleted flag for audit trail
    - Broadcasts via WebSocket for real-time updates
    """
    event = models.ForeignKey(
        Event, on_delete=models.CASCADE, related_name="waiting_room_announcements"
    )
    message = models.TextField(max_length=1000)
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="sent_announcements"
    )
    sender_name = models.CharField(max_length=255, default="Host")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)  # soft delete

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event", "is_deleted", "-created_at"]),
        ]

    def __str__(self):
        return f"[Event {self.event_id}] {self.sender_name}: {self.message[:50]}"


# ============================================================
# ================= Breakout Joiner Model ====================
# ============================================================

class BreakoutJoiner(models.Model):
    """
    Tracks participants who join while breakout rooms are active.
    Manages the assignment state and notification flow for late joiners.
    """
    STATUS_WAITING = 'waiting'
    STATUS_ASSIGNED = 'assigned'
    STATUS_MAIN_ROOM = 'main_room'
    STATUS_AUTO_ASSIGNED = 'auto_assigned'
    STATUS_EXPIRED = 'expired'

    STATUS_CHOICES = [
        (STATUS_WAITING, 'Waiting for assignment'),
        (STATUS_ASSIGNED, 'Assigned to breakout room'),
        (STATUS_MAIN_ROOM, 'Remains in main room'),
        (STATUS_AUTO_ASSIGNED, 'Automatically assigned'),
        (STATUS_EXPIRED, 'Assignment expired - breakout ended'),
    ]

    ASSIGNMENT_METHOD_CHOICES = [
        ('manual', 'Host assigned manually'),
        ('auto', 'System auto-assigned'),
        ('none', 'No assignment made'),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='late_joiners')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='breakout_joiner_registrations')
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_WAITING,
        db_index=True
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    assigned_at = models.DateTimeField(null=True, blank=True)
    notified_host_at = models.DateTimeField(null=True, blank=True)
    assigned_room = models.ForeignKey(
        LoungeTable,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='late_joiners'
    )
    assigned_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='breakout_assignments_made'
    )
    assignment_method = models.CharField(
        max_length=20,
        choices=ASSIGNMENT_METHOD_CHOICES,
        default='none'
    )
    host_notified = models.BooleanField(default=False)
    notification_sent_count = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ('event', 'user')
        indexes = [
            models.Index(fields=['event', 'status']),
            models.Index(fields=['event', 'joined_at']),
        ]

    def __str__(self):
        return f"{self.user.username} late joiner for {self.event.title}"


# ============================================================
# ================= Speed Networking Models ==================
# ============================================================

class SpeedNetworkingSession(models.Model):
    """
    Represents a Speed Networking session within an Event.
    """
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('ACTIVE', 'Active'),
        ('ENDED', 'Ended'),
    ]

    MATCHING_STRATEGY_CHOICES = [
        ('rule_only', 'Rule-Based Only'),
        ('criteria_only', 'Criteria-Based Only'),
        ('both', 'Both Systems (Recommended)'),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='speed_networking_sessions')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_speed_networking_sessions')

    name = models.CharField(max_length=255, default="Speed Networking Session")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    duration_minutes = models.IntegerField(default=5, help_text="Duration of each round in minutes")
    buffer_seconds = models.IntegerField(
        default=15,
        help_text="Seconds to show the transition screen between rounds (0 to disable)."
    )

    # Matching Strategy (NEW)
    matching_strategy = models.CharField(
        max_length=50,
        choices=MATCHING_STRATEGY_CHOICES,
        default='both',
        help_text="Which matching system to use"
    )
    criteria_config = models.JSONField(
        default=dict,
        blank=True,
        help_text="Criteria matching configuration (weights, thresholds, etc)"
    )
    config_version = models.IntegerField(
        default=1,
        help_text="Incremented each time criteria_config changes (for tracking updates)"
    )

    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Session {self.id} for {self.event.title}"


class SpeedNetworkingMatch(models.Model):
    """
    Represents a single match between two participants in a session.
    """
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('COMPLETED', 'Completed'),
        ('SKIPPED', 'Skipped'),
    ]

    session = models.ForeignKey(SpeedNetworkingSession, on_delete=models.CASCADE, related_name='matches')
    participant_1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='speed_networking_matches_as_p1')
    participant_2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='speed_networking_matches_as_p2')

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    rtk_room_name = models.CharField(max_length=255, blank=True, null=True, help_text="RTK meeting ID for this match")

    # Match Quality Scores (NEW)
    match_score = models.FloatField(
        default=0,
        help_text="Overall match quality score (0-100) from criteria matching"
    )
    match_breakdown = models.JSONField(
        default=dict,
        blank=True,
        help_text="Score breakdown: {'skill': 75, 'experience': 85, 'location': 90, 'education': 80}"
    )
    rule_compliance = models.BooleanField(
        default=True,
        help_text="Whether this match complies with all rules"
    )

    # Config version tracking (ADDED)
    config_version = models.IntegerField(
        default=1,
        help_text="Version of criteria_config used to calculate this match score"
    )
    match_probability = models.FloatField(
        default=0,
        help_text="Match success probability (0-100) calculated from score"
    )
    last_recalculated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when match score was last recalculated with updated config"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    # Time extension fields (for participant mutual extension feature)
    extension_requested_p1 = models.BooleanField(default=False, help_text="Participant 1 has requested time extension")
    extension_requested_p2 = models.BooleanField(default=False, help_text="Participant 2 has requested time extension")
    extension_applied = models.BooleanField(default=False, help_text="Extension has been approved by both participants")
    extended_by_seconds = models.IntegerField(default=0, help_text="Number of seconds added to this match via extension")

    class Meta:
        # Performance indexes (ADDED)
        indexes = [
            models.Index(fields=['session', 'status', '-created_at']),
            models.Index(fields=['participant_1', 'session']),
            models.Index(fields=['participant_2', 'session']),
            models.Index(fields=['config_version']),
        ]

    def __str__(self):
        return f"Match {self.id}: {self.participant_1} vs {self.participant_2}"


class SpeedNetworkingQueue(models.Model):
    """
    Tracks users currently waiting in the speed networking lobby/queue.
    """
    session = models.ForeignKey(SpeedNetworkingSession, on_delete=models.CASCADE, related_name='queue')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='speed_networking_queue_entries')
    
    is_active = models.BooleanField(default=True, help_text="True if user is currently looking for a match")
    current_match = models.ForeignKey(SpeedNetworkingMatch, on_delete=models.SET_NULL, null=True, blank=True, related_name='active_queue_entries')
    
    joined_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('session', 'user')
        # Performance indexes (ADDED)
        indexes = [
            models.Index(fields=['session', 'is_active']),
            models.Index(fields=['session', 'current_match']),
        ]

    interests = models.ManyToManyField(
        'SpeedNetworkingInterestTag',
        blank=True,
        related_name='queue_entries',
        help_text="Interests this user is looking for / offering in this session"
    )

    def __str__(self):
        return f"{self.user} in Queue for Session {self.session_id}"


class SpeedNetworkingInterestTag(models.Model):
    """
    Host-defined interest tags for a speed networking session.
    Tags are grouped by 'category' and each has a 'side' (offer/seek/both).
    Complementary matching pairs a 'seek' tag with its 'offer' counterpart in the same category.

    Example:
        category='investment', side='seek', label='Looking for investors'
        category='investment', side='offer', label='Offering investment opportunities'
    """
    SIDE_CHOICES = [
        ('offer', 'Offering'),
        ('seek', 'Seeking'),
        ('both', 'Both / Open'),
    ]

    session = models.ForeignKey(
        SpeedNetworkingSession,
        on_delete=models.CASCADE,
        related_name='interest_tags'
    )
    label = models.CharField(max_length=100, help_text="Display label, e.g. 'Looking for investors'")
    category = models.CharField(max_length=50, help_text="Groups complementary tags, e.g. 'investment'")
    side = models.CharField(max_length=10, choices=SIDE_CHOICES, default='both')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('session', 'label')
        ordering = ['category', 'side']
        indexes = [
            models.Index(fields=['session', 'is_active']),
        ]

    def __str__(self):
        return f"[{self.session_id}] {self.label} ({self.category}/{self.side})"


class EventParticipant(models.Model):
    """
    Hybrid model supporting staff users, external guest speakers, and virtual speaker profiles.

    For staff participants: Links to User account, optionally override bio/image per event
    For guest participants: Standalone data without User account (useful for external speakers)
    For virtual participants: Links to VirtualSpeaker profile (reusable across events)
    """

    PARTICIPANT_TYPE_STAFF = 'staff'
    PARTICIPANT_TYPE_GUEST = 'guest'
    PARTICIPANT_TYPE_VIRTUAL = 'virtual'
    PARTICIPANT_TYPE_CHOICES = [
        (PARTICIPANT_TYPE_STAFF, 'Staff Member'),
        (PARTICIPANT_TYPE_GUEST, 'Guest Speaker'),
        (PARTICIPANT_TYPE_VIRTUAL, 'Virtual Speaker'),
    ]

    # Stage participation roles
    ROLE_SPEAKER = 'speaker'
    ROLE_MODERATOR = 'moderator'
    ROLE_HOST = 'host'

    # Promotional profile roles (for post-acceptance form)
    ROLE_SPONSOR = 'sponsor'
    ROLE_SPONSOR_STAFF = 'sponsor_staff'
    ROLE_STARTUP = 'startup'
    ROLE_INVESTOR = 'investor'

    ROLE_CHOICES = [
        (ROLE_SPEAKER, 'Speaker'),
        (ROLE_MODERATOR, 'Moderator'),
        (ROLE_HOST, 'Host'),
        (ROLE_SPONSOR, 'Sponsor'),
        (ROLE_SPONSOR_STAFF, 'Sponsor Staff'),
        (ROLE_STARTUP, 'Start-up'),
        (ROLE_INVESTOR, 'Investor'),
    ]

    # Mapping of roles to promotional profile modules
    ROLE_MODULE_MAP = {
        ROLE_SPEAKER: 'speaker',
        ROLE_SPONSOR: 'sponsor',
        ROLE_SPONSOR_STAFF: 'sponsor_staff',
        ROLE_STARTUP: 'startup',
        ROLE_INVESTOR: 'investor',
    }

    # Roles that trigger promotional profile creation
    TRIGGERS_PROMOTIONAL_PROFILE_ROLES = [
        ROLE_SPEAKER,
        ROLE_SPONSOR,
        ROLE_SPONSOR_STAFF,
        ROLE_STARTUP,
        ROLE_INVESTOR,
    ]

    # Core fields
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name='participants',
        help_text="The event this participant is associated with"
    )
    participant_type = models.CharField(
        max_length=20,
        choices=PARTICIPANT_TYPE_CHOICES,
        default=PARTICIPANT_TYPE_STAFF,
        help_text="Type of participant (staff user or external guest)"
    )
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        help_text="Role of the participant in this event"
    )
    display_order = models.PositiveIntegerField(
        default=0,
        help_text="Order in which participants are displayed (lower = earlier)"
    )

    # Staff participant field (optional)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='event_participations',
        help_text="User account (required for staff type)"
    )

    # Staff-specific customization fields
    event_bio = models.TextField(
        blank=True,
        help_text="Event-specific bio override for staff members"
    )
    event_image = models.ImageField(
        upload_to=event_participant_image_upload_to,
        blank=True,
        null=True,
        help_text="Event-specific image override for staff members"
    )

    # Guest participant fields (only used when participant_type='guest')
    guest_name = models.CharField(
        max_length=255,
        blank=True,
        help_text="Full name of guest speaker"
    )
    guest_email = models.EmailField(
        blank=True,
        help_text="Email of guest speaker"
    )
    guest_bio = models.TextField(
        blank=True,
        help_text="Bio of guest speaker"
    )
    guest_image = models.ImageField(
        upload_to=event_participant_image_upload_to,
        blank=True,
        null=True,
        help_text="Profile image of guest speaker"
    )

    # Virtual participant field (for reusable virtual speaker profiles)
    virtual_speaker = models.ForeignKey(
        'VirtualSpeaker',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='event_participations',
        help_text="Linked VirtualSpeaker profile (only for virtual type)"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_order', 'created_at']
        indexes = [
            models.Index(fields=['event', 'role']),
            models.Index(fields=['participant_type']),
            models.Index(fields=['event', 'display_order']),
            models.Index(fields=["event", "role", "participant_type", "user"], name="evtpart_host_user_idx"),
            models.Index(
                F("event"),
                F("role"),
                F("participant_type"),
                Upper("guest_email"),
                name="evtpart_guest_up_idx",
            ),
        ]
        verbose_name = 'Event Participant'
        verbose_name_plural = 'Event Participants'

    def clean(self):
        """Validate participant based on type"""
        from django.core.exceptions import ValidationError

        if self.participant_type == self.PARTICIPANT_TYPE_STAFF:
            if not self.user:
                raise ValidationError("Staff participants must have a user assigned")
        elif self.participant_type == self.PARTICIPANT_TYPE_GUEST:
            if not self.guest_name:
                raise ValidationError("Guest speakers must have a name")
        elif self.participant_type == self.PARTICIPANT_TYPE_VIRTUAL:
            if not self.virtual_speaker:
                raise ValidationError("Virtual participants must have a VirtualSpeaker assigned")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        name = self.get_name()
        return f"{name} - {self.get_role_display()} at {self.event.title}"

    # Helper methods for frontend/serializers
    def get_name(self):
        """Get participant name with fallback logic"""
        if self.virtual_speaker:
            return self.virtual_speaker.name
        if self.user:
            return self.user.get_full_name() or self.user.username
        return self.guest_name

    def get_email(self):
        """Get participant email"""
        if self.virtual_speaker and self.virtual_speaker.converted_user:
            return self.virtual_speaker.converted_user.email
        if self.user:
            return self.user.email
        return self.guest_email

    def get_bio(self):
        """Get bio with fallback logic"""
        if self.event_bio:
            return self.event_bio
        if self.virtual_speaker:
            return self.virtual_speaker.bio or ""
        if self.user and hasattr(self.user, 'profile'):
            return self.user.profile.bio or ""
        return self.guest_bio or ""

    def get_image_url(self):
        """Get image URL with fallback logic"""
        if self.event_image:
            return self.event_image.url
        if self.virtual_speaker and self.virtual_speaker.profile_image:
            return self.virtual_speaker.profile_image.url
        if self.user and hasattr(self.user, 'profile'):
            profile = self.user.profile
            if getattr(profile, 'user_image', None):
                return profile.user_image.url
            if getattr(profile, 'avatar', None):
                avatar = profile.avatar
                return avatar.url if hasattr(avatar, "url") else str(avatar)
            if getattr(profile, 'image', None):
                image = profile.image
                return image.url if hasattr(image, "url") else str(image)
        if self.user and getattr(self.user, 'avatar', None):
            avatar = self.user.avatar
            return avatar.url if hasattr(avatar, "url") else str(avatar)
        return self.guest_image.url if self.guest_image else None


# ============================================================
# ================= Event Session Models ====================
# ============================================================

class EventSession(models.Model):
    """Represents a session within a multi-day event."""
    SESSION_TYPE_CHOICES = [
        ("main", "Main Session"),
        ("breakout", "Breakout Session"),
        ("workshop", "Workshop"),
        ("networking", "Networking"),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="sessions")
    session_date = models.DateField(
        null=True,
        blank=True,
        help_text="Calendar day this session belongs to (auto-populated from start_time)"
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    session_type = models.CharField(max_length=20, choices=SESSION_TYPE_CHOICES, default="main")
    display_order = models.PositiveIntegerField(default=0, help_text="Order in which sessions appear")

    # Live meeting
    is_live = models.BooleanField(default=False)
    live_started_at = models.DateTimeField(null=True, blank=True)
    live_ended_at = models.DateTimeField(null=True, blank=True)

    # RTK integration
    use_parent_meeting = models.BooleanField(
        default=True,
        help_text="If True, use parent event's RTK meeting. If False, create separate meeting."
    )
    rtk_meeting_id = models.CharField(max_length=255, blank=True, null=True)
    recording_url = models.URLField(blank=True)

    # Duration override fields
    duration_minutes_override = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="Manually set session duration in minutes; overrides (end_time - start_time)"
    )
    has_duration_override = models.BooleanField(
        default=False,
        help_text="If True, use duration_minutes_override instead of computed duration"
    )

    # Location information
    room = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Room or location for the session"
    )
    location_note = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Additional location details (e.g., Floor 2, Building A)"
    )

    # Session image (portrait orientation)
    session_image = models.ImageField(
        upload_to='session_images/',
        blank=True,
        null=True,
        help_text="Portrait orientation image for session preview"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_order', 'start_time']
        indexes = [
            models.Index(fields=['event', 'start_time']),
            models.Index(fields=['event', 'is_live']),
        ]

    def computed_duration_minutes(self):
        if self.end_time and self.start_time:
            return int((self.end_time - self.start_time).total_seconds() / 60)
        return 0

    def effective_duration_minutes(self):
        base = self.duration_minutes_override if self.has_duration_override else self.computed_duration_minutes()
        total_breaks = sum(b.duration_minutes for b in self.session_breaks.all())
        return max(0, base - total_breaks)

    def save(self, *args, **kwargs):
        # Auto-populate session_date from start_time if not explicitly set
        if self.start_time and not self.session_date:
            self.session_date = self.start_time.date()
        super().save(*args, **kwargs)
        # NOTE: Do NOT auto-update parent Event.start_time/end_time here.
        # Event times are owned by the Event, not by sessions.
        # Sessions are independent and sessions should never modify parent event times.

    def __str__(self):
        return f"{self.title} - {self.event.title}"


class EventSessionBookmark(models.Model):
    """Allows users to bookmark/save sessions they want to attend."""
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="session_bookmarks")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="session_bookmarks")
    session = models.ForeignKey(EventSession, on_delete=models.CASCADE, related_name="bookmarks")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('event', 'user', 'session')
        indexes = [models.Index(fields=['event', 'user']), models.Index(fields=['session'])]

    def __str__(self):
        return f"{self.user.username} bookmarked {self.session.title}"


class SessionBreak(models.Model):
    BREAK_TYPE_CHOICES = [
        ("lunch", "Lunch Break"),
        ("coffee", "Coffee Break"),
        ("networking", "Networking Break"),
        ("other", "Other"),
    ]
    session = models.ForeignKey(
        EventSession, on_delete=models.CASCADE, related_name="session_breaks"
    )
    label = models.CharField(max_length=100, blank=True, default="")
    break_type = models.CharField(max_length=20, choices=BREAK_TYPE_CHOICES, default="other")
    duration_minutes = models.PositiveIntegerField(help_text="Break length in minutes")
    break_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["break_order", "created_at"]

    def __str__(self):
        return f"{self.label or self.break_type} - {self.duration_minutes}m"


class SessionParticipant(models.Model):
    """Links speakers/moderators to specific sessions (mirrors EventParticipant)."""

    PARTICIPANT_TYPE_STAFF = 'staff'
    PARTICIPANT_TYPE_GUEST = 'guest'
    PARTICIPANT_TYPE_VIRTUAL = 'virtual'
    PARTICIPANT_TYPE_CHOICES = [
        (PARTICIPANT_TYPE_STAFF, 'Staff Member'),
        (PARTICIPANT_TYPE_GUEST, 'Guest Speaker'),
        (PARTICIPANT_TYPE_VIRTUAL, 'Virtual Speaker'),
    ]

    ROLE_SPEAKER = 'speaker'
    ROLE_MODERATOR = 'moderator'
    ROLE_HOST = 'host'
    ROLE_CHOICES = [
        (ROLE_SPEAKER, 'Speaker'),
        (ROLE_MODERATOR, 'Moderator'),
        (ROLE_HOST, 'Host'),
    ]

    session = models.ForeignKey(EventSession, on_delete=models.CASCADE, related_name='participants')
    participant_type = models.CharField(max_length=20, choices=PARTICIPANT_TYPE_CHOICES, default=PARTICIPANT_TYPE_STAFF)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    display_order = models.PositiveIntegerField(default=0)

    # Staff participant
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='session_participations')
    session_bio = models.TextField(blank=True, help_text="Session-specific bio override")
    session_image = models.ImageField(upload_to=event_participant_image_upload_to, blank=True, null=True)

    # Guest participant
    guest_name = models.CharField(max_length=255, blank=True)
    guest_email = models.EmailField(blank=True)
    guest_bio = models.TextField(blank=True)
    guest_image = models.ImageField(upload_to=event_participant_image_upload_to, blank=True, null=True)

    # Virtual participant field (for reusable virtual speaker profiles)
    virtual_speaker = models.ForeignKey(
        'VirtualSpeaker',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='session_participations',
        help_text="Linked VirtualSpeaker profile (only for virtual type)"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_order', 'created_at']
        indexes = [
            models.Index(fields=['session', 'role']),
            models.Index(fields=['participant_type']),
        ]

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.participant_type == self.PARTICIPANT_TYPE_STAFF and not self.user:
            raise ValidationError("Staff participants must have a user assigned")
        elif self.participant_type == self.PARTICIPANT_TYPE_GUEST and not self.guest_name:
            raise ValidationError("Guest speakers must have a name")
        elif self.participant_type == self.PARTICIPANT_TYPE_VIRTUAL and not self.virtual_speaker:
            raise ValidationError("Virtual participants must have a VirtualSpeaker assigned")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.get_name()} - {self.get_role_display()} at {self.session.title}"

    # Helper methods (mirror EventParticipant)
    def get_name(self):
        if self.virtual_speaker:
            return self.virtual_speaker.name
        if self.user:
            return self.user.get_full_name() or self.user.username
        return self.guest_name

    def get_email(self):
        if self.virtual_speaker and self.virtual_speaker.converted_user:
            return self.virtual_speaker.converted_user.email
        if self.user:
            return self.user.email
        return self.guest_email

    def get_bio(self):
        if self.session_bio:
            return self.session_bio
        if self.virtual_speaker:
            return self.virtual_speaker.bio or ""
        if self.user and hasattr(self.user, 'profile'):
            return self.user.profile.bio or ""
        return self.guest_bio or ""

    def get_image_url(self):
        if self.session_image:
            return self.session_image.url
        if self.virtual_speaker and self.virtual_speaker.profile_image:
            return self.virtual_speaker.profile_image.url
        if self.user and hasattr(self.user, 'profile'):
            profile = self.user.profile
            if getattr(profile, 'user_image', None):
                return profile.user_image.url
            if getattr(profile, 'avatar', None):
                avatar = profile.avatar
                return avatar.url if hasattr(avatar, "url") else str(avatar)
            if getattr(profile, 'image', None):
                image = profile.image
                return image.url if hasattr(image, "url") else str(image)
        if self.user and getattr(self.user, 'avatar', None):
            avatar = self.user.avatar
            return avatar.url if hasattr(avatar, "url") else str(avatar)
        return self.guest_image.url if self.guest_image else None


# ============================================================================
# ================= Virtual Speaker Profile Model =======================
# ============================================================================

def virtual_speaker_image_upload_to(instance, filename):
    """Upload path for virtual speaker profile images."""
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "speaker"
    return f"virtual-speakers/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"


class VirtualSpeaker(models.Model):
    """
    Reusable virtual speaker profile (no email required initially).
    Can be assigned to multiple events and later converted to a real user account.
    """
    STATUS_ACTIVE = 'active'
    STATUS_CONVERTED = 'converted'
    STATUS_CHOICES = [
        ('active', 'Active Virtual Speaker'),
        ('converted', 'Converted to User'),
    ]

    community = models.ForeignKey(
        Community,
        on_delete=models.CASCADE,
        related_name='virtual_speakers',
        help_text="Community this speaker belongs to"
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_virtual_speakers',
        help_text="Organizer who created this virtual speaker"
    )

    # Profile fields (reusable across events)
    name = models.CharField(
        max_length=255,
        help_text="Full name"
    )
    job_title = models.CharField(
        max_length=255,
        blank=True,
        help_text="Job title or role"
    )
    company = models.CharField(
        max_length=255,
        blank=True,
        help_text="Company or organization"
    )
    bio = models.TextField(
        blank=True,
        help_text="Biography or description"
    )
    profile_image = models.ImageField(
        upload_to=virtual_speaker_image_upload_to,
        blank=True,
        null=True,
        help_text="Profile picture"
    )

    # Conversion lifecycle
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_ACTIVE,
        db_index=True,
        help_text="Current status of the virtual speaker"
    )
    converted_user = models.OneToOneField(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='virtual_speaker_origin',
        help_text="Real user account this was converted to"
    )
    converted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this was converted to a real user"
    )
    invited_email = models.EmailField(
        blank=True,
        help_text="Email address used for conversion"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['community', 'status']),
            models.Index(fields=['community', 'name']),
        ]
        verbose_name = 'Virtual Speaker'
        verbose_name_plural = 'Virtual Speakers'

    def __str__(self):
        status_label = f" ({self.get_status_display()})" if self.status == 'converted' else ""
        return f"{self.name}{status_label}"


class SessionAttendance(models.Model):
    """Tracks which users attended which sessions."""

    session = models.ForeignKey(EventSession, on_delete=models.CASCADE, related_name='attendances')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='session_attendances')

    joined_at = models.DateTimeField(auto_now_add=True)
    left_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.PositiveIntegerField(default=0)
    is_online = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('session', 'user')
        indexes = [
            models.Index(fields=['session', 'is_online']),
            models.Index(fields=['user']),
        ]

    def __str__(self):
        return f"{self.user.username} attended {self.session.title}"


# ============================================================================
# ============== RULE-BASED MATCHING MODELS (BOTH SYSTEMS) =================
# ============================================================================

class SpeedNetworkingRule(models.Model):
    """
    Rule-based matching rules for speed networking.
    Supports positive (INCLUDE) and negative (EXCLUDE) rules.
    """
    RULE_TYPE_CHOICES = [
        ('POSITIVE', 'Positive Matching (INCLUDE)'),
        ('NEGATIVE', 'Negative Matching (EXCLUDE)'),
    ]

    CATEGORY_CHOICES = [
        ('USER_TYPE', 'User Type (host/speaker/attendee)'),
        ('TICKET_TIER', 'Ticket Tier (VIP/Premium/Gold/Basic)'),
        ('CUSTOM_FIELD', 'Custom Registration Field'),
    ]

    session = models.ForeignKey(
        SpeedNetworkingSession,
        on_delete=models.CASCADE,
        related_name='matching_rules'
    )

    name = models.CharField(max_length=255, help_text="e.g., 'VIP with Recruiters'")
    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)

    # Segment A (source)
    segment_a_type = models.CharField(max_length=100)
    segment_a_values = models.JSONField(
        default=list,
        help_text="Values matching this segment (e.g., ['VIP', 'Premium'])"
    )

    # Segment B (target) - NOT used in negative rules
    segment_b_type = models.CharField(max_length=100, blank=True, null=True)
    segment_b_values = models.JSONField(
        default=list,
        blank=True,
        null=True,
        help_text="For positive rules only"
    )

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('session', 'name')
        ordering = ['created_at']

    def __str__(self):
        return f"{self.name} ({self.get_rule_type_display()})"


class UserMatchingProfile(models.Model):
    """
    Rule-based: User attributes for rule-based matching.
    Stores ticket tier, user type, and custom fields.
    """
    session = models.ForeignKey(SpeedNetworkingSession, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    # Matching attributes
    user_type = models.CharField(max_length=50, blank=True)
    ticket_tier = models.CharField(max_length=50, blank=True)

    # Custom field values (JSON)
    custom_fields = models.JSONField(default=dict)

    # Computed state
    can_match = models.BooleanField(default=True)
    computed_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('session', 'user')

    def __str__(self):
        return f"{self.user.username} rule profile for session {self.session_id}"


class MatchHistory(models.Model):
    """
    Rule-based: Complete history of all matches.
    Prevents immediate re-matching within 24 hours.
    """
    session = models.ForeignKey(SpeedNetworkingSession, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='match_history')
    matched_with = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='matched_with_history'
    )

    match_record = models.ForeignKey(
        SpeedNetworkingMatch,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    matched_at = models.DateTimeField(auto_now_add=True)
    duration_seconds = models.IntegerField(null=True, blank=True)

    class Meta:
        unique_together = ('session', 'user', 'matched_with')
        indexes = [
            models.Index(fields=['session', 'user']),
            models.Index(fields=['matched_at']),
        ]

    def __str__(self):
        return f"{self.user.username} matched with {self.matched_with.username}"


# ============================================================================
# ============== CRITERIA-BASED MATCHING MODELS (BOTH SYSTEMS) =============
# ============================================================================

class UserCriteriaProfile(models.Model):
    """
    Criteria-based: User profile with skill, experience, location, education.
    Used for quality-based matching (similarity scoring).
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='speed_networking_criteria_profile'
    )

    # Skills (JSON)
    skills = models.JSONField(
        default=list,
        help_text="[{'name': 'Python', 'level': 1-4, 'years': 5}, ...]"
    )

    # Experience
    experience_years = models.IntegerField(default=0)
    experience_level = models.IntegerField(
        choices=[
            (0, 'Student'),
            (1, 'Junior'),
            (2, 'Mid-level'),
            (3, 'Senior'),
            (4, 'Expert'),
        ],
        default=0
    )

    # Location
    location_city = models.CharField(max_length=255, blank=True)
    location_country = models.CharField(max_length=255, blank=True)
    location_latitude = models.FloatField(null=True, blank=True)
    location_longitude = models.FloatField(null=True, blank=True)
    location_timezone = models.CharField(max_length=50, blank=True, default='UTC')

    # Education
    education_degree = models.CharField(max_length=255, blank=True)
    education_field = models.CharField(max_length=255, blank=True)
    education_level = models.IntegerField(
        choices=[
            (0, 'High School'),
            (1, "Bachelor's"),
            (2, "Master's"),
            (3, 'PhD'),
            (4, 'Professional Cert'),
        ],
        default=1
    )
    education_institution = models.CharField(max_length=255, blank=True)

    # Matching preferences
    preferred_match_type = models.CharField(
        max_length=50,
        choices=[
            ('mentorship', 'Mentorship (learn from senior)'),
            ('peer', 'Peer Learning (same level)'),
            ('collaboration', 'Collaboration (build together)'),
            ('mixed', 'Mixed (any type)'),
        ],
        default='mixed'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def to_dict(self):
        """Convert to dictionary for matching engine."""
        return {
            'user_id': self.user_id,
            'skills': self.skills or [],
            'experience_years': self.experience_years,
            'experience_level': self.experience_level,
            'location': {
                'city': self.location_city,
                'country': self.location_country,
                'lat': self.location_latitude,
                'lon': self.location_longitude,
                'timezone': self.location_timezone,
            },
            'education': {
                'degree': self.education_degree,
                'field': self.education_field,
                'level': self.education_level,
                'institution': self.education_institution,
            },
            'preferred_match_type': self.preferred_match_type,
        }

    def __str__(self):
        return f"{self.user.username}'s Speed Networking Profile"


class GuestAttendee(models.Model):
    """
    Represents a guest (unauthenticated) attendee for an event.
    Guests join with minimal info (name, email, role) using a temporary JWT.
    When they register, converted_user is set and the JWT is invalidated.
    """
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="guest_attendees"
    )
    email = models.EmailField()
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    job_title = models.CharField(
        max_length=255,
        blank=True,
        help_text="Current role or job title"
    )
    company = models.CharField(
        max_length=255,
        blank=True,
        help_text="Guest's company or organization"
    )

    # JWT token management
    token_jti = models.CharField(
        max_length=64,
        blank=True,
        help_text="JWT ID for token revocation"
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Token expiration time"
    )

    # Conversion tracking (when guest registers)
    converted_user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="converted_from_guest",
        help_text="Django user account created when guest registers"
    )
    converted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when guest converted to registered user"
    )

    # Participation tracking
    created_at = models.DateTimeField(auto_now_add=True)
    joined_live = models.BooleanField(default=False)
    joined_live_at = models.DateTimeField(null=True, blank=True)

    # Email verification
    email_verified = models.BooleanField(
        default=False,
        help_text="True if email has been verified via OTP"
    )

    # Follow-up tracking
    follow_up_sent_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when follow-up email was sent to encourage signup"
    )

    LOCATION_CHOICES = [
        ("main_room", "Main Room"),
        ("social_lounge", "Social Lounge"),
        ("breakout_room", "Breakout Room"),
    ]
    current_location = models.CharField(
        max_length=32,
        default="main_room",
        choices=LOCATION_CHOICES
    )
    lounge_table = models.ForeignKey(
        "LoungeTable",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="guest_attendees",
        help_text="Current lounge/breakout table for this guest (if seated).",
    )
    rtk_participant_id = models.CharField(
        max_length=64,
        blank=True,
        help_text="RTK SDK participant ID"
    )

    # Moderation
    is_banned = models.BooleanField(
        default=False,
        help_text="True if this guest has been banned from this event"
    )

    class Meta:
        db_table = "guest_attendees"
        unique_together = ("event", "email")
        indexes = [
            models.Index(fields=["event"]),
            models.Index(fields=["email"]),
            models.Index(fields=["token_jti"]),
        ]

    def get_display_name(self):
        """Return full name or email if name not available."""
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name or self.email

    def __str__(self):
        return f"{self.get_display_name()} (Guest) - {self.event.title}"


class GuestProfileAuditLog(models.Model):
    FIELD_FIRST_NAME = "first_name"
    FIELD_LAST_NAME = "last_name"
    FIELD_EMAIL = "email"
    FIELD_COMPANY = "company"
    FIELD_JOB_TITLE = "job_title"
    FIELD_ACCOUNT_EMAIL = "account_email"

    FIELD_CHOICES = [
        (FIELD_FIRST_NAME, "First Name"),
        (FIELD_LAST_NAME, "Last Name"),
        (FIELD_EMAIL, "Email"),
        (FIELD_COMPANY, "Company"),
        (FIELD_JOB_TITLE, "Job Title"),
        (FIELD_ACCOUNT_EMAIL, "Account Email"),
    ]

    SOURCE_GUEST_JOIN = "guest_join"
    SOURCE_PROFILE_EDIT = "profile_edit"
    SOURCE_SIGNUP = "signup_conversion"

    SOURCE_CHOICES = [
        (SOURCE_GUEST_JOIN, "Guest Join"),
        (SOURCE_PROFILE_EDIT, "Profile Edit"),
        (SOURCE_SIGNUP, "Signup Conversion"),
    ]

    guest = models.ForeignKey(
        GuestAttendee,
        on_delete=models.CASCADE,
        related_name="audit_logs",
    )
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="guest_audit_logs",
    )
    field_name = models.CharField(max_length=50, choices=FIELD_CHOICES)
    old_value = models.TextField(blank=True, default="")
    new_value = models.TextField(blank=True, default="")
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES, default=SOURCE_PROFILE_EDIT)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "guest_profile_audit_logs"
        ordering = ["-changed_at", "-id"]
        indexes = [
            models.Index(fields=["event", "-changed_at"]),
            models.Index(fields=["guest", "-changed_at"]),
        ]

    def __str__(self):
        return f"{self.guest_id}:{self.field_name}:{self.source}"


class GuestEmailOTP(models.Model):
    """
    Short-lived one-time passcodes (OTP) for verifying guest email addresses
    before allowing event access.

    When a guest joins, they provide an email, we send them a 6-digit OTP,
    and they must verify it before receiving a guest JWT token.
    """
    email = models.EmailField(db_index=True)
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="guest_otps",
        help_text="The event for which this OTP was issued"
    )
    code = models.CharField(
        max_length=6,
        help_text="6-digit numeric OTP code"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text="OTP expires after 10 minutes"
    )
    used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when OTP was verified (null if not yet used)"
    )
    attempt_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of verification attempts (to prevent brute-force)"
    )

    class Meta:
        db_table = "guest_email_otps"
        indexes = [
            models.Index(fields=["email", "event", "created_at"]),
            models.Index(fields=["event", "used_at"]),
        ]

    @property
    def is_valid(self):
        """Check if OTP is still valid (not expired and not yet used)."""
        from django.utils import timezone
        return self.used_at is None and timezone.now() < self.expires_at

    @property
    def is_expired(self):
        """Check if OTP has expired."""
        from django.utils import timezone
        return timezone.now() > self.expires_at

    def mark_as_used(self):
        """Mark the OTP as used."""
        from django.utils import timezone
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])

    def __str__(self):
        return f"OTP for {self.email} - {self.event.title}"


class EventApplication(models.Model):
    """
    Represents an application to an event with 'apply' registration type.
    Tracks applicants (authenticated users or guests) and their application status.
    """
    APPLICATION_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('declined', 'Declined'),
        ('cancelled', 'Cancelled/Withdrawn'),
    ]

    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name='applications',
        help_text="The event this application is for"
    )
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='event_applications',
        help_text="Authenticated user (null if guest application)"
    )

    # Application information (always collected)
    first_name = models.CharField(max_length=150, blank=True, default='')
    last_name = models.CharField(max_length=150, blank=True, default='')
    email = models.EmailField(blank=True, default='')
    job_title = models.CharField(max_length=200, blank=True, default='')
    company_name = models.CharField(max_length=200, blank=True, default='')
    linkedin_url = models.URLField(blank=True, default='')
    attendee_marker_value = models.BooleanField(default=False)
    comments = models.TextField(blank=True, default='')

    # Application track and submission mode (Phase 3)
    application_track = models.ForeignKey(
        'EventApplicationTrack',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='applications',
        help_text='The application track/type this application is for'
    )
    SUBMISSION_MODE_SELF = 'self_submission'
    SUBMISSION_MODE_CONFIRMED = 'confirmed'
    SUBMISSION_MODE_SELF_NOMINATION = 'self_nomination'
    SUBMISSION_MODE_THIRD_PARTY = 'third_party_nomination'
    SUBMISSION_MODE_CHOICES = [
        (SUBMISSION_MODE_SELF, 'Self Submission'),
        (SUBMISSION_MODE_CONFIRMED, 'Confirmed'),
        (SUBMISSION_MODE_SELF_NOMINATION, 'Self Nomination'),
        (SUBMISSION_MODE_THIRD_PARTY, 'Third Party Nomination'),
    ]
    submission_mode = models.CharField(
        max_length=50,
        choices=SUBMISSION_MODE_CHOICES,
        default=SUBMISSION_MODE_SELF,
        help_text='How the applicant is submitting (self, confirmed, nominated, etc.)'
    )

    # Mode-specific fields (Phase 3)
    # For third_party_nomination mode:
    nominator_name = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text='Name of person nominating (third_party_nomination mode)'
    )
    nominator_email = models.EmailField(
        blank=True,
        default='',
        help_text='Email of person nominating (third_party_nomination mode)'
    )
    nominee_name = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text='Name of nominated person (third_party_nomination mode)'
    )
    nominee_email = models.EmailField(
        blank=True,
        default='',
        help_text='Email of nominated person (third_party_nomination mode)'
    )
    nominee_details = models.JSONField(
        default=dict,
        blank=True,
        help_text='Additional details about nominee (JSONField)'
    )

    # For confirmed mode:
    sponsor_organization = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text='Sponsoring/partner organization name (confirmed mode)'
    )

    # Application status
    status = models.CharField(
        max_length=20,
        choices=APPLICATION_STATUS_CHOICES,
        default='pending'
    )
    applied_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='reviewed_applications'
    )
    rejection_message = models.TextField(blank=True, default='')
    is_preapproved = models.BooleanField(default=False, db_index=True)
    PREAPPROVAL_SOURCE_NONE = "none"
    PREAPPROVAL_SOURCE_CODE = "code"
    PREAPPROVAL_SOURCE_EMAIL = "email"
    PREAPPROVAL_SOURCE_CHOICES = [
        (PREAPPROVAL_SOURCE_NONE, "None"),
        (PREAPPROVAL_SOURCE_CODE, "Code"),
        (PREAPPROVAL_SOURCE_EMAIL, "Email"),
    ]
    preapproval_source = models.CharField(
        max_length=20,
        choices=PREAPPROVAL_SOURCE_CHOICES,
        default=PREAPPROVAL_SOURCE_NONE,
        db_index=True,
    )
    preapproval_code = models.ForeignKey(
        "events.EventPreApprovalCode",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="applications",
    )
    preapproval_allowlist_entry = models.ForeignKey(
        "events.EventPreApprovalAllowlist",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="applications",
    )
    preapproved_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When this application was cancelled/withdrawn by applicant'
    )

    # Phase 7: Multi-track support
    selected_tracks = models.JSONField(
        default=list,
        blank=True,
        help_text='List of track IDs selected in this multi-track application'
    )

    # Phase 12: Communication preferences
    opt_out_automated_communication = models.BooleanField(
        default=False,
        help_text='If True, applicant has opted out of automated emails (accept/decline/waitlist notifications)'
    )

    @classmethod
    def get_latest_active_application(cls, event, user=None, email=None):
        """
        Get the latest active application for a user/email to an event.
        Prioritizes active statuses (pending/pre_approved/accepted) over declined/cancelled.

        Active child statuses: pending, pre_approved, accepted, waitlisted
        Reusable (terminal) statuses: declined, cancelled
        """
        if user:
            apps = cls.objects.filter(event=event, user=user).prefetch_related('track_applications')
        elif email:
            apps = cls.objects.filter(event=event, email=email).prefetch_related('track_applications')
        else:
            return None

        apps = apps.order_by('-applied_at')

        # Find the first app with active children, or fallback to most recent
        for app in apps:
            track_apps = list(app.track_applications.all())
            if not track_apps:
                # Legacy app without children - check parent status
                if app.status in ['pending', 'approved', 'pre_approved']:
                    return app
            else:
                # Check child statuses
                child_statuses = [ta.status for ta in track_apps]
                blocking_statuses = ['pending', 'pre_approved', 'accepted', 'waitlisted']
                if any(status in blocking_statuses for status in child_statuses):
                    return app

        # No active app found - return most recent as fallback
        return apps.first() if apps.exists() else None

    class Meta:
        db_table = 'event_applications'
        unique_together = ('event', 'email')
        ordering = ['-applied_at']
        indexes = [
            models.Index(fields=['event', 'status']),
            models.Index(fields=['email']),
        ]

    def __str__(self):
        return f"{self.first_name} {self.last_name} → {self.event.title} ({self.status})"


class EventPreApprovalCode(models.Model):
    STATUS_ACTIVE = "active"
    STATUS_USED = "used"
    STATUS_REVOKED = "revoked"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_USED, "Used"),
        (STATUS_REVOKED, "Revoked"),
    ]

    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="preapproval_codes",
    )
    code = models.CharField(max_length=100)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_ACTIVE,
        db_index=True,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_preapproval_codes",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    used_by_application = models.ForeignKey(
        "events.EventApplication",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="used_preapproval_codes",
    )
    used_by_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="used_preapproval_codes",
    )
    used_by_email = models.EmailField(blank=True, default="")
    used_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="revoked_preapproval_codes",
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, default="")

    # Phase 8: Track + Mode scoping
    track = models.ForeignKey(
        EventApplicationTrack,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="preapproval_codes",
        help_text="Track this code applies to. Null = applies to all tracks at event level.",
    )
    submission_mode = models.CharField(
        max_length=50,
        blank=True,
        default="",
        help_text="Submission mode this code applies to. Empty = applies to all modes for the track.",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["event", "track", "submission_mode", "code"],
                name="unique_preapproval_code_per_track_mode",
            )
        ]
        indexes = [
            models.Index(fields=["event", "status"]),
            models.Index(fields=["event", "code"]),
            models.Index(fields=["track", "submission_mode", "status"]),
        ]

    def save(self, *args, **kwargs):
        if self.code:
            self.code = self.code.strip()
        super().save(*args, **kwargs)


class EventPreApprovalAllowlist(models.Model):
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="preapproval_allowlist",
    )
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.EmailField(db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_preapproval_allowlist_entries",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    removed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="removed_preapproval_allowlist_entries",
    )
    removed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, default="")

    # Phase 8: Track + Mode scoping
    track = models.ForeignKey(
        EventApplicationTrack,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="preapproval_allowlist",
        help_text="Track this entry applies to. Null = applies to all tracks at event level.",
    )
    submission_mode = models.CharField(
        max_length=50,
        blank=True,
        default="",
        help_text="Submission mode this entry applies to. Empty = applies to all modes for the track.",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["event", "track", "submission_mode", "email"],
                condition=models.Q(is_active=True),
                name="unique_active_allowlist_email_per_track_mode",
            )
        ]
        indexes = [
            models.Index(fields=["event", "email"]),
            models.Index(fields=["event", "is_active"]),
            models.Index(fields=["track", "submission_mode", "is_active"]),
        ]

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.strip().lower()
        super().save(*args, **kwargs)


class EventApplicationTrackApplication(models.Model):
    """
    Phase 7: Per-track application data within an overall event application.
    Allows applicants to apply to multiple tracks simultaneously.
    """
    STATUS_PENDING = 'pending'
    STATUS_PRE_APPROVED = 'pre_approved'
    STATUS_ACCEPTED = 'accepted'
    STATUS_DECLINED = 'declined'
    STATUS_WAITLISTED = 'waitlisted'
    STATUS_CANCELLED = 'cancelled'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_PRE_APPROVED, 'Pre-Approved'),
        (STATUS_ACCEPTED, 'Accepted'),
        (STATUS_DECLINED, 'Declined'),
        (STATUS_WAITLISTED, 'Waitlisted'),
        (STATUS_CANCELLED, 'Cancelled/Withdrawn'),
    ]

    # Core relationships
    application = models.ForeignKey(
        EventApplication,
        on_delete=models.CASCADE,
        related_name='track_applications'
    )
    track = models.ForeignKey(
        EventApplicationTrack,
        on_delete=models.CASCADE,
        related_name='track_applications'
    )

    # Submission details
    submission_mode = models.CharField(
        max_length=50,
        default='self_submission',
        help_text='Submission mode for this track application'
    )
    status = models.CharField(
        max_length=50,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
        help_text='Current application status for this track'
    )
    tier_preference = models.ForeignKey(
        TrackPricingTier,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text='Preferred pricing tier for this track'
    )

    # Form data
    form_answers = models.JSONField(
        default=dict,
        blank=True,
        help_text='Track-specific form field answers'
    )
    file_uploads = models.JSONField(
        default=dict,
        blank=True,
        help_text='File upload metadata and URLs'
    )

    # Review tracking
    reviewed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When this track application was reviewed'
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_track_applications',
        help_text='Admin user who reviewed this application'
    )

    # Phase 10: Decision tracking
    accepted_tier = models.ForeignKey(
        TrackPricingTier,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='accepted_track_applications',
        help_text='Tier selected by reviewer on acceptance (may differ from tier_preference)'
    )
    accepted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When this application was accepted'
    )
    declined_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When this application was declined'
    )
    waitlisted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When this application was waitlisted'
    )
    cancelled_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When this application was cancelled/withdrawn by applicant'
    )
    cancellation_reason = models.CharField(
        max_length=50,
        blank=True,
        default='',
        choices=[
            ('registration_cancelled', 'Registration Cancelled'),
            ('user_withdrawal', 'User Withdrawal'),
            ('admin_cancellation', 'Admin Cancellation'),
        ],
        help_text='Reason for cancellation'
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'event_application_track_applications'
        unique_together = [('application', 'track')]
        indexes = [
            models.Index(fields=['application', 'status']),
            models.Index(fields=['track', 'status']),
            models.Index(fields=['application', 'created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.application.email} → {self.track.label} ({self.get_status_display()})"


class TrackApplicationListVisibilityField(models.Model):
    """
    Phase 9: Configurable list view columns for review queue.
    Allows admins to customize which fields are visible in the review queue list.
    """
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name='track_app_list_fields'
    )
    field_name = models.CharField(
        max_length=100,
        help_text='Field name: email, first_name, last_name, submission_mode, status, tier_preference, etc.'
    )
    label = models.CharField(max_length=200, help_text='Display label for this column')
    sort_order = models.PositiveIntegerField(default=0, help_text='Order in which column appears')
    is_visible = models.BooleanField(default=True, help_text='Whether column is shown in list view')
    is_sortable = models.BooleanField(default=False, help_text='Whether column can be sorted')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [['event', 'field_name']]
        ordering = ['sort_order', 'field_name']
        indexes = [
            models.Index(fields=['event', 'is_visible']),
        ]

    def __str__(self):
        return f"{self.event.title} - {self.label}"


class SaleorChannel(models.Model):
    ALLOCATION_STRATEGY_CHOICES = [
        ("PRIORITIZE_SORTING_ORDER", "Prioritize Sorting Order"),
        ("PRIORITIZE_HIGH_STOCK", "Prioritize High Stock"),
    ]

    saleor_id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    slug = models.CharField(max_length=255, unique=True)
    currency = models.CharField(max_length=10)
    is_active = models.BooleanField(default=True)
    default_country = models.CharField(max_length=10, blank=True, null=True)
    countries = models.JSONField(default=list, blank=True)
    warehouse_ids = models.JSONField(default=list, blank=True)
    allocation_strategy = models.CharField(
        max_length=50,
        choices=ALLOCATION_STRATEGY_CHOICES,
        default="PRIORITIZE_SORTING_ORDER",
        blank=True,
    )
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.currency})"


class SaleorWarehouse(models.Model):
    CLICK_AND_COLLECT_CHOICES = [
        ("local", "Local"),
        ("all", "All"),
        ("disabled", "Disabled"),
    ]

    saleor_id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    slug = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)

    # Address fields
    company_name = models.CharField(max_length=255, blank=True, null=True)
    street_address_1 = models.CharField(max_length=255, blank=True, null=True)
    street_address_2 = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=255, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    country_code = models.CharField(max_length=10, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    country_area = models.CharField(max_length=255, blank=True, null=True)
    phone = models.CharField(max_length=50, blank=True, null=True)

    # Settings
    click_and_collect = models.CharField(
        max_length=20,
        choices=CLICK_AND_COLLECT_CHOICES,
        default="disabled"
    )
    is_private = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    shipping_zone_ids = models.JSONField(default=list, blank=True)

    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class SaleorShippingZone(models.Model):
    saleor_id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_default = models.BooleanField(default=False)
    countries = models.JSONField(default=list, blank=True)
    channel_ids = models.JSONField(default=list, blank=True)
    warehouse_ids = models.JSONField(default=list, blank=True)
    shipping_methods = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class SaleorProductType(models.Model):
    saleor_id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255)
    kind = models.CharField(max_length=50, default="NORMAL")
    is_shipping_required = models.BooleanField(default=False)
    tax_class_id = models.CharField(max_length=255, blank=True, null=True)
    tax_class_name = models.CharField(max_length=255, blank=True, null=True)
    product_attribute_ids = models.JSONField(default=list, blank=True)
    variant_attribute_ids = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    private_metadata = models.JSONField(default=dict, blank=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class SaleorStaffUser(models.Model):
    saleor_id = models.CharField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField()
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    permissions = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["first_name", "last_name"]

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class SaleorPermissionGroup(models.Model):
    saleor_id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    permissions = models.JSONField(default=list, blank=True)
    user_count = models.IntegerField(default=0)
    metadata = models.JSONField(default=dict, blank=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class EventSeries(models.Model):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
        ("archived", "Archived"),
    ]
    REGISTRATION_MODE_CHOICES = [
        ("full_series_only", "Full Series Only"),
        ("per_session_only", "Per Session Only"),
        ("both", "Both Series and Per-Session"),
    ]
    VISIBILITY_CHOICES = [
        ("public", "Public"),
        ("private", "Private"),
    ]

    community = models.ForeignKey(
        Community,
        on_delete=models.CASCADE,
        related_name="event_series"
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="created_series"
    )
    title = models.CharField(max_length=255)
    slug = models.CharField(
        max_length=255,
        unique=True,
        blank=True,
        help_text="Auto-generated from title + year with collision detection"
    )
    description = models.TextField(blank=True)
    cover_image = models.ImageField(
        upload_to=series_cover_upload_to,
        blank=True,
        null=True
    )
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default="draft",
        db_index=True
    )
    registration_mode = models.CharField(
        max_length=30,
        choices=REGISTRATION_MODE_CHOICES,
        default="both",
        help_text="Control whether users can register for full series, individual events, or both"
    )
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.0,
        help_text="Series-level price (currently used for free series only)"
    )
    currency = models.CharField(
        max_length=3,
        default="USD",
        editable=False
    )
    is_free = models.BooleanField(default=True)
    visibility = models.CharField(
        max_length=16,
        choices=VISIBILITY_CHOICES,
        default="public"
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Custom metadata for series (JSON)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["community", "status"]),
            models.Index(fields=["slug"]),
        ]

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.slug:
            from datetime import datetime
            year = datetime.now().year
            base_slug = f"{slugify(self.title)}-{year}"
            slug = base_slug
            counter = 1
            while EventSeries.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)


class SeriesRegistration(models.Model):
    STATUS_CHOICES = [
        ("registered", "Registered"),
        ("cancelled", "Cancelled"),
    ]

    series = models.ForeignKey(
        EventSeries,
        on_delete=models.CASCADE,
        related_name="series_registrations"
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="series_registrations"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="registered",
        db_index=True
    )
    registered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("series", "user")
        ordering = ["-registered_at"]
        indexes = [
            models.Index(fields=["series", "status"]),
            models.Index(fields=["user"]),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.series.title}"


class EventSaleorDiscount(models.Model):
    REWARD_VALUE_TYPE_CHOICES = [
        ("PERCENTAGE", "Percentage"),
        ("FIXED", "Fixed Amount"),
    ]

    BADGE_LABEL_CHOICES = [
        ("early_bird", "Early Bird"),
        ("bundle_price", "Bundle Price"),
    ]

    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="saleor_discounts"
    )
    saleor_promotion_id = models.CharField(
        max_length=255,
        unique=True,
        help_text="Saleor Promotion GraphQL ID"
    )
    saleor_rule_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Saleor Promotion Rule ID"
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    discount_type = models.CharField(
        max_length=30,
        default="CATALOGUE",
        editable=False,
        help_text="Discount type (always CATALOGUE)"
    )
    channel_id = models.CharField(
        max_length=255,
        help_text="Saleor GraphQL channel ID"
    )
    channel_name = models.CharField(max_length=255, blank=True)
    channel_slug = models.CharField(max_length=255, blank=True)
    currency = models.CharField(max_length=10, blank=True)
    reward_value_type = models.CharField(
        max_length=20,
        choices=REWARD_VALUE_TYPE_CHOICES
    )
    reward_value = models.DecimalField(max_digits=10, decimal_places=2)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    badge_label = models.CharField(
        max_length=20,
        choices=BADGE_LABEL_CHOICES
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this discount is currently active"
    )
    created_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_saleor_discounts"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_sync_error = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event"]),
            models.Index(fields=["saleor_promotion_id"]),
            models.Index(fields=["channel_id"]),
            models.Index(fields=["badge_label"]),
        ]

    def __str__(self):
        return f"{self.name} - {self.event.title}"


class EventNetworkingSettings(models.Model):
    event = models.OneToOneField(Event, on_delete=models.CASCADE, related_name="networking_settings")
    enabled = models.BooleanField(default=False)
    duration_options_minutes = models.JSONField(default=list, help_text="List of available meeting durations in minutes")
    allowed_windows = models.JSONField(
        default=list,
        help_text="List of available time windows with format: [{'date': 'YYYY-MM-DD', 'start': 'HH:MM', 'end': 'HH:MM'}]"
    )
    reminder_minutes_before = models.PositiveIntegerField(default=5, help_text="Minutes before meeting to send reminders")
    sms_enabled = models.BooleanField(default=False, help_text="Enable SMS reminders for meetings")
    max_meetings_per_attendee_per_day = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Maximum number of networking meetings per attendee per day (null for unlimited)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Event Networking Settings"

    def __str__(self):
        return f"Networking Settings for {self.event.title}"

    def save(self, *args, **kwargs):
        if self.duration_options_minutes is None:
            self.duration_options_minutes = [5, 10, 15]
        if self.allowed_windows is None:
            self.allowed_windows = []
        super().save(*args, **kwargs)


class NetworkingTable(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="networking_tables")
    table_number = models.PositiveIntegerField(help_text="Table number/identifier")
    name = models.CharField(max_length=255, blank=True, help_text="Optional table name")
    location_note = models.TextField(blank=True, help_text="Optional location notes or description")
    is_active = models.BooleanField(default=True, help_text="Whether this table is available for meetings")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("event", "table_number")
        indexes = [
            models.Index(fields=["event", "table_number"]),
            models.Index(fields=["event", "is_active"]),
        ]

    def __str__(self):
        return f"Table {self.table_number} - {self.event.title}"


class NetworkingMeeting(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("accepted", "Accepted"),
        ("declined", "Declined"),
        ("suggested", "Suggested"),
        ("cancelled", "Cancelled"),
        ("expired", "Expired"),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="networking_meetings")
    requester = models.ForeignKey(
        EventRegistration,
        on_delete=models.CASCADE,
        related_name="requested_networking_meetings",
        help_text="The attendee who requested the meeting"
    )
    recipient = models.ForeignKey(
        EventRegistration,
        on_delete=models.CASCADE,
        related_name="received_networking_meetings",
        help_text="The attendee being requested for a meeting"
    )
    duration_minutes = models.PositiveIntegerField(help_text="Duration of meeting in minutes")
    start_time = models.DateTimeField(help_text="Scheduled start time of the meeting")
    end_time = models.DateTimeField(help_text="Scheduled end time of the meeting")
    table = models.ForeignKey(
        NetworkingTable,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="networking_meetings",
        help_text="Assigned networking table for this meeting"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending",
        db_index=True,
        help_text="Current status of the meeting request"
    )
    message = models.TextField(blank=True, help_text="Optional message from requester")
    suggested_start_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Suggested alternative start time"
    )
    suggested_end_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Suggested alternative end time"
    )
    suggested_by = models.ForeignKey(
        EventRegistration,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="suggested_networking_meetings",
        help_text="Who suggested the alternative time"
    )
    accepted_at = models.DateTimeField(null=True, blank=True, help_text="When the meeting was accepted")
    declined_at = models.DateTimeField(null=True, blank=True, help_text="When the meeting was declined")
    cancelled_at = models.DateTimeField(null=True, blank=True, help_text="When the meeting was cancelled")
    reminder_task_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Celery task ID for reminder notification"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    requester_seen_at = models.DateTimeField(null=True, blank=True, help_text="When requester last viewed their notifications")
    recipient_seen_at = models.DateTimeField(null=True, blank=True, help_text="When recipient last viewed their notifications")

    class Meta:
        indexes = [
            models.Index(fields=["event", "status"]),
            models.Index(fields=["requester", "status"]),
            models.Index(fields=["recipient", "status"]),
            models.Index(fields=["start_time", "end_time"]),
            models.Index(fields=["table", "start_time", "end_time"]),
        ]

    def clean(self):
        from django.utils import timezone

        # Self-meeting prevention
        if self.requester_id == self.recipient_id:
            raise ValidationError("Cannot request a meeting with yourself.")

        # Event registration checks
        if self.requester.event_id != self.event_id:
            raise ValidationError("Requester must be registered for this event.")

        if self.recipient.event_id != self.event_id:
            raise ValidationError("Recipient must be registered for this event.")

        # Table validation
        if self.table and self.table.event_id != self.event_id:
            raise ValidationError("Table must belong to this event.")

        # Time validation
        if self.end_time <= self.start_time:
            raise ValidationError("End time must be after start time.")

        # Duration validation
        expected_duration = (self.end_time - self.start_time).total_seconds() / 60
        if abs(expected_duration - self.duration_minutes) > 0.5:
            raise ValidationError(f"Duration mismatch: duration_minutes ({self.duration_minutes}) does not match time window ({int(expected_duration)} minutes).")

        # Past meeting prevention (only for new/pending/suggested meetings)
        if self.status in ['pending', 'suggested']:
            if self.start_time < timezone.now():
                raise ValidationError("Cannot create a meeting in the past.")

        # Event bounds check
        if self.event.start_time and self.start_time < self.event.start_time:
            raise ValidationError("Meeting must start after event begins.")
        if self.event.end_time and self.end_time > self.event.end_time:
            raise ValidationError("Meeting must end before event ends.")

    def __str__(self):
        return f"Meeting: {self.requester.user.username} + {self.recipient.user.username} - {self.event.title}"


class PostAcceptanceFormTemplate(models.Model):
    FORM_TYPE_PARTICIPANT_INFORMATION = 'participant_information'
    FORM_TYPE_PROMOTIONAL_PROFILE = 'promotional_profile'
    FORM_TYPE_CHOICES = [
        (FORM_TYPE_PARTICIPANT_INFORMATION, 'Participant Information'),
        (FORM_TYPE_PROMOTIONAL_PROFILE, 'Promotional Profile'),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='post_acceptance_form_templates')
    form_type = models.CharField(max_length=50, choices=FORM_TYPE_CHOICES)
    title = models.CharField(max_length=255, blank=True, help_text='Form title displayed to attendees')
    description = models.TextField(blank=True, help_text='Form description and instructions')
    question_schema = models.JSONField(default=dict, blank=True, help_text='Form questions and structure')
    is_enabled = models.BooleanField(default=True, help_text='Whether this form type is enabled for this event')
    deadline_days = models.PositiveIntegerField(default=7, help_text='Days after assignment deadline')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'post_acceptance_form_templates'
        unique_together = ('event', 'form_type')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event', 'form_type']),
            models.Index(fields=['is_enabled']),
        ]

    def __str__(self):
        return f"{self.get_form_type_display()} - {self.event.title}"


class PostAcceptanceFormAssignment(models.Model):
    STATUS_NOT_STARTED = 'not_started'
    STATUS_IN_PROGRESS = 'in_progress'
    STATUS_COMPLETED = 'completed'
    STATUS_LAPSED = 'lapsed'
    STATUS_CHOICES = [
        (STATUS_NOT_STARTED, 'Not Started'),
        (STATUS_IN_PROGRESS, 'In Progress'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_LAPSED, 'Lapsed'),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='post_acceptance_form_assignments')
    form_template = models.ForeignKey(PostAcceptanceFormTemplate, on_delete=models.CASCADE, related_name='assignments')
    event_registration = models.ForeignKey(EventRegistration, on_delete=models.CASCADE, related_name='post_acceptance_form_assignments')

    form_type = models.CharField(max_length=50, choices=PostAcceptanceFormTemplate.FORM_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_NOT_STARTED, db_index=True)

    deadline = models.DateTimeField(help_text='Deadline for form completion')
    # FIX 9: Allow edits to completed forms until this date (defaults to event start)
    editable_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Allow editing completed forms until this date (defaults to event start)'
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    reminders_sent = models.PositiveIntegerField(default=0)
    last_reminder_sent_at = models.DateTimeField(null=True, blank=True)

    # Promotional Profile specific fields
    active_modules = models.JSONField(
        default=list,
        blank=True,
        help_text='List of active modules for promotional profile (e.g., ["speaker", "sponsor"])'
    )
    module_completion_status = models.JSONField(
        default=dict,
        blank=True,
        help_text='Per-module completion tracking (e.g., {"speaker": true, "sponsor": false})'
    )

    manual_completed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='manually_completed_assignments',
        help_text='Admin who manually marked assignment as complete'
    )
    manual_completed_at = models.DateTimeField(null=True, blank=True, help_text='When admin manually marked complete')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'post_acceptance_form_assignments'
        unique_together = ('event_registration', 'form_type')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event', 'status']),
            models.Index(fields=['event_registration', 'form_type']),
            models.Index(fields=['status']),
            models.Index(fields=['deadline']),
        ]

    def __str__(self):
        return f"{self.get_form_type_display()} - {self.event_registration.user.username} - {self.status}"

    def get_form_type_display(self):
        return dict(PostAcceptanceFormTemplate.FORM_TYPE_CHOICES).get(self.form_type, self.form_type)


class PostAcceptanceFormSubmission(models.Model):
    assignment = models.OneToOneField(PostAcceptanceFormAssignment, on_delete=models.CASCADE, related_name='submission')
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'post_acceptance_form_submissions'
        ordering = ['-submitted_at']

    def __str__(self):
        return f"Submission for {self.assignment}"


class PostAcceptanceFormAnswer(models.Model):
    submission = models.ForeignKey(PostAcceptanceFormSubmission, on_delete=models.CASCADE, related_name='answers')
    question_key = models.CharField(max_length=100, help_text='Unique question identifier within form type')
    form_type = models.CharField(
        max_length=50,
        default='participant_information',
        help_text='Form type: participant_information, promotional_profile, etc.'
    )
    answer_text = models.TextField(blank=True)
    answer_data = models.JSONField(default=dict, blank=True, help_text='Complex answer data (for checkboxes, multi-select, etc.)')
    answer_file = models.FileField(null=True, blank=True, upload_to='form_answers/%Y/%m/%d/', help_text='Uploaded file (for headshot, slide deck, etc.)')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'post_acceptance_form_answers'
        unique_together = ('submission', 'question_key', 'form_type')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['submission', 'form_type']),
            models.Index(fields=['form_type']),
        ]

    def __str__(self):
        return f"Answer {self.question_key} - {self.submission}"


class PostAcceptanceFormAnswerFile(models.Model):
    """
    File attachment for form answers.

    Supports multiple files per answer (e.g., multiple founder photos, multiple deliverables).
    Links to PostAcceptanceFormAnswer via foreign key.
    """
    answer = models.ForeignKey(
        PostAcceptanceFormAnswer,
        on_delete=models.CASCADE,
        related_name='files',
        help_text='Parent form answer'
    )
    file = models.FileField(
        upload_to='form_answers/%Y/%m/%d/',
        help_text='Uploaded file'
    )
    file_order = models.PositiveIntegerField(
        default=0,
        help_text='Order of file in list (for multiple files per question)'
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'post_acceptance_form_answer_files'
        ordering = ['file_order', 'uploaded_at']
        indexes = [
            models.Index(fields=['answer']),
            models.Index(fields=['answer', 'file_order']),
        ]

    def __str__(self):
        return f"File for {self.answer.question_key} - {self.file.name}"


class PostAcceptanceFormDraft(models.Model):
    assignment = models.OneToOneField(PostAcceptanceFormAssignment, on_delete=models.CASCADE, related_name='draft')
    draft_data = models.JSONField(default=dict, blank=True, help_text='Partial form answers')
    saved_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'post_acceptance_form_drafts'

    def __str__(self):
        return f"Draft for {self.assignment}"


class AdminAuditLog(models.Model):
    """
    Audit log for admin access to restricted attendee data.
    Tracks viewing, exporting, and modifying sensitive information.
    """
    ACTION_CHOICES = [
        ('view_restricted', 'Viewed restricted details'),
        ('export_restricted', 'Exported restricted data'),
        ('manual_mark_complete', 'Marked assignment complete'),
        ('export_promotional', 'Exported promotional profiles'),
        ('send_reminders', 'Sent form reminders'),
        ('export_production', 'Exported for production handoff'),
        ('purge_restricted', 'Purged restricted form data'),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='form_audit_logs')
    performed_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='form_audit_actions'
    )
    assignment = models.ForeignKey(
        PostAcceptanceFormAssignment,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    details = models.JSONField(
        default=dict,
        blank=True,
        help_text='Additional context (e.g., assignment IDs, export format)'
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = 'admin_audit_logs'
        indexes = [
            models.Index(fields=['event', 'performed_by', '-created_at']),
            models.Index(fields=['action', '-created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_action_display()} by {self.performed_by.email} on {self.event.title}"


class PostAcceptanceReminderLog(models.Model):
    assignment = models.ForeignKey(PostAcceptanceFormAssignment, on_delete=models.CASCADE, related_name='reminder_logs')
    reminder_number = models.PositiveIntegerField(help_text='Which reminder (1st, 2nd, etc.)')
    sent_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'post_acceptance_reminder_logs'
        ordering = ['-sent_at']
        indexes = [
            models.Index(fields=['assignment', 'reminder_number']),
        ]

    def __str__(self):
        return f"Reminder {self.reminder_number} - {self.assignment}"


class EventFormCustomization(models.Model):
    """
    Per-event customization for post-acceptance forms.

    Allows organisers to:
    - Enable/disable sections (Accessibility, Emergency Contact, etc.)
    - Add custom questions
    - Change field requirements
    - Edit help text
    - Modify select options
    - Set deadlines
    - Configure file specifications
    - Configure reminder cadence
    """
    FORM_TYPE_CHOICES = [
        ('participant_information', 'Participant Information'),
        ('promotional_profile', 'Promotional Profile'),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='form_customizations')
    form_type = models.CharField(max_length=50, choices=FORM_TYPE_CHOICES)

    # Section enablement (Participant Information specific)
    enable_accessibility_section = models.BooleanField(default=True)
    enable_emergency_contact_section = models.BooleanField(default=True)
    enable_food_requirements_section = models.BooleanField(default=True)
    enable_privacy_permissions_section = models.BooleanField(default=True)
    enable_travel_information_section = models.BooleanField(default=True)

    # Customization of fields
    field_overrides = models.JSONField(
        default=dict,
        blank=True,
        help_text='Field-level customizations: {field_id: {required, help_text, options, ...}}'
    )

    # Custom questions
    custom_questions = models.JSONField(
        default=list,
        blank=True,
        help_text='List of custom questions [{id, type, label, required, options, show_if, ...}]'
    )

    # Deadlines
    form_deadline = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Overall deadline for this form type'
    )

    # Promotional Profile module deadlines
    module_deadlines = models.JSONField(
        default=dict,
        blank=True,
        help_text='Module-specific deadlines: {speaker: ISO8601, sponsor: ISO8601, ...}'
    )

    # File specifications
    file_specs = models.JSONField(
        default=dict,
        blank=True,
        help_text='File requirements per field: {headshot: {max_size, formats, ...}, ...}'
    )

    # Reminder configuration
    reminder_schedule = models.JSONField(
        default=dict,
        blank=True,
        help_text='Reminder cadence: {first_reminder_days: 14, second_reminder_days: 3, ...}'
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='form_customizations_updated'
    )

    class Meta:
        db_table = 'event_form_customizations'
        unique_together = [['event', 'form_type']]
        indexes = [
            models.Index(fields=['event', 'form_type']),
        ]

    def __str__(self):
        return f"Form Customization: {self.event.title} - {self.get_form_type_display()}"

    def get_section_config(self):
        """Return all section enable/disable settings."""
        return {
            'accessibility': self.enable_accessibility_section,
            'emergency_contact': self.enable_emergency_contact_section,
            'food_requirements': self.enable_food_requirements_section,
            'privacy_permissions': self.enable_privacy_permissions_section,
            'travel_information': self.enable_travel_information_section,
        }

    def get_field_override(self, field_id):
        """Get customization for specific field."""
        return self.field_overrides.get(field_id, {})

    def add_custom_question(self, question_config):
        """Add a custom question."""
        if not question_config.get('id'):
            question_config['id'] = f"custom_{len(self.custom_questions)}"
        self.custom_questions.append(question_config)
        self.save()

    def remove_custom_question(self, question_id):
        """Remove a custom question by ID."""
        self.custom_questions = [q for q in self.custom_questions if q.get('id') != question_id]
        self.save()
