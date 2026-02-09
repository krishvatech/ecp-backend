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
    # New fields
    category = models.CharField(max_length=100, blank=True)
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES, default="in_person")
    location = models.CharField(max_length=255, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    is_free = models.BooleanField(default=False)
    attending_count = models.PositiveIntegerField(default=0)
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
        default="admitted",
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

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='speed_networking_sessions')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_speed_networking_sessions')
    
    name = models.CharField(max_length=255, default="Speed Networking Session")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    duration_minutes = models.IntegerField(default=5, help_text="Duration of each round in minutes")
    
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
    
    created_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)

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
        if self.user and hasattr(self.user, 'profile') and self.user.profile.user_image:
            return self.user.profile.user_image.url
        return self.guest_image.url if self.guest_image else None
