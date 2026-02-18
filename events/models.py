"""
Models for the events app.
An `Event` is associated with a single community and has a state
machine to represent its current status.  Slugs are automatically
generated based on the title and community ID.  The creator of the
event is stored in the `created_by` field.
"""
from django.db import models
from django.contrib.auth.models import User
from community.models import Community
from django.utils.text import slugify
from django.conf import settings
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

class Event(models.Model):
    """Represents an event within an community."""
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
        ("live", "Live"),
        ("ended", "Ended"),
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
    slug = models.SlugField(max_length=255, unique=True, blank=True)
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
    # New fields
    category = models.CharField(max_length=100, blank=True)
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES, default="in_person")
    location = models.CharField(max_length=255, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    is_free = models.BooleanField(default=False)
    attending_count = models.PositiveIntegerField(default=0)
    max_participants = models.PositiveIntegerField(
        null=True, 
        blank=True, 
        help_text="Maximum number of participants allowed (null for unlimited)"
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
    # Dyte live meeting fields
    dyte_meeting_id = models.CharField(max_length=255, blank=True, null=True)
    dyte_meeting_title = models.CharField(max_length=255, blank=True, null=True)
    # Cloudflare RealtimeKit recording control fields
    rtk_recording_id = models.CharField(max_length=255, blank=True, null=True)
    is_recording = models.BooleanField(default=False)
    recording_paused_at = models.DateTimeField(null=True, blank=True)

    # Saleor integration fields
    saleor_product_id = models.CharField(max_length=255, blank=True, null=True)
    saleor_variant_id = models.CharField(max_length=255, blank=True, null=True)

    # Legacy Agora recording fields (no longer used)
    # Meta
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_events")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    live_started_at = models.DateTimeField(null=True, blank=True)
    live_ended_at = models.DateTimeField(null=True, blank=True)
    idle_started_at = models.DateTimeField(null=True, blank=True)
    ended_by_host = models.BooleanField(default=False)

    # Lounge Settings
    lounge_enabled_before = models.BooleanField(default=False)
    lounge_before_buffer = models.PositiveIntegerField(default=30)  # minutes
    lounge_enabled_during = models.BooleanField(default=True)
    lounge_enabled_breaks = models.BooleanField(default=False)
    lounge_enabled_after = models.BooleanField(default=False)
    lounge_after_buffer = models.PositiveIntegerField(default=30)  # minutes
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

    # Participant List Visibility Settings
    show_participants_before_event = models.BooleanField(
        default=True,
        help_text="Allow participants to see the participant list before the event starts"
    )
    show_participants_after_event = models.BooleanField(
        default=False,
        help_text="Allow participants to see the participant list after the event ends"
    )

    class Meta:
        ordering = ["-created_at"]
    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.title}-{self.community_id}")
            slug = base_slug
            suffix = 1
            while Event.objects.filter(slug=slug).exists():
                slug = f"{base_slug}-{suffix}"
                suffix += 1
            self.slug = slug
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
    dyte_meeting_id = models.CharField(max_length=255, blank=True, null=True)
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

    # Track the Dyte participant ID for accurate removal
    dyte_participant_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="ID of participant in Dyte meeting. Used for proper cleanup on leave."
    )

    class Meta:
        unique_together = ("table", "seat_index")
        # Also ensure a user can only be at one table per event if required,
        # but for now we'll enforce unique seating via seat_index.

    def __str__(self):
        return f"{self.user.username} at {self.table.name}"
    
class EventRegistration(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='registrations')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_registrations')
    
    STATUS_CHOICES = [
        ('registered', 'Registered'),
        ('cancellation_requested', 'Cancellation Requested'),
        ('cancelled', 'Cancelled'),
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='registered')
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

    class Meta:
        db_table = 'event_registrations'
        unique_together = ('event', 'user')                 
        indexes = [
            models.Index(fields=['event', 'user']),
            models.Index(fields=['user']),
        ]
    def __str__(self):
        return f'{self.user_id} -> {self.event_id}'


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
    dyte_room_name = models.CharField(max_length=255, blank=True, null=True, help_text="Dyte meeting ID for this match")

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

    def __str__(self):
        return f"{self.user} in Queue for Session {self.session_id}"


class EventParticipant(models.Model):
    """
    Hybrid model supporting both staff users and external guest speakers.

    For staff participants: Links to User account, optionally override bio/image per event
    For guest participants: Standalone data without User account (useful for external speakers)
    """

    PARTICIPANT_TYPE_STAFF = 'staff'
    PARTICIPANT_TYPE_GUEST = 'guest'
    PARTICIPANT_TYPE_CHOICES = [
        (PARTICIPANT_TYPE_STAFF, 'Staff Member'),
        (PARTICIPANT_TYPE_GUEST, 'Guest Speaker'),
    ]

    ROLE_SPEAKER = 'speaker'
    ROLE_MODERATOR = 'moderator'
    ROLE_HOST = 'host'

    ROLE_CHOICES = [
        (ROLE_SPEAKER, 'Speaker'),
        (ROLE_MODERATOR, 'Moderator'),
        (ROLE_HOST, 'Host'),
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

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_order', 'created_at']
        indexes = [
            models.Index(fields=['event', 'role']),
            models.Index(fields=['participant_type']),
            models.Index(fields=['event', 'display_order']),
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

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        name = self.get_name()
        return f"{name} - {self.get_role_display()} at {self.event.title}"

    # Helper methods for frontend/serializers
    def get_name(self):
        """Get participant name with fallback logic"""
        if self.user:
            return self.user.get_full_name() or self.user.username
        return self.guest_name

    def get_email(self):
        """Get participant email"""
        if self.user:
            return self.user.email
        return self.guest_email

    def get_bio(self):
        """Get bio with fallback logic"""
        if self.event_bio:
            return self.event_bio
        if self.user and hasattr(self.user, 'profile'):
            return self.user.profile.bio or ""
        return self.guest_bio or ""

    def get_image_url(self):
        """Get image URL with fallback logic"""
        if self.event_image:
            return self.event_image.url
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

    # Dyte integration
    use_parent_meeting = models.BooleanField(
        default=True,
        help_text="If True, use parent event's Dyte meeting. If False, create separate meeting."
    )
    dyte_meeting_id = models.CharField(max_length=255, blank=True, null=True)
    recording_url = models.URLField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_order', 'start_time']
        indexes = [
            models.Index(fields=['event', 'start_time']),
            models.Index(fields=['event', 'is_live']),
        ]

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


class SessionParticipant(models.Model):
    """Links speakers/moderators to specific sessions (mirrors EventParticipant)."""

    PARTICIPANT_TYPE_STAFF = 'staff'
    PARTICIPANT_TYPE_GUEST = 'guest'
    PARTICIPANT_TYPE_CHOICES = [
        (PARTICIPANT_TYPE_STAFF, 'Staff Member'),
        (PARTICIPANT_TYPE_GUEST, 'Guest Speaker'),
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

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.get_name()} - {self.get_role_display()} at {self.session.title}"

    # Helper methods (mirror EventParticipant)
    def get_name(self):
        if self.user:
            return self.user.get_full_name() or self.user.username
        return self.guest_name

    def get_email(self):
        if self.user:
            return self.user.email
        return self.guest_email

    def get_bio(self):
        if self.session_bio:
            return self.session_bio
        if self.user and hasattr(self.user, 'profile'):
            return self.user.profile.bio or ""
        return self.guest_bio or ""

    def get_image_url(self):
        if self.session_image:
            return self.session_image.url
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
