"""Shared access helpers for the Event Companion (IPDT-769).

Centralizes the "who may use 1:1 networking for this event" rule so every
networking endpoint agrees and no endpoint can silently self-enroll a caller.

Networking actions need a real ``EventRegistration`` (it is the FK on
``NetworkingMeeting``). Registrations are created only by the trusted
acceptance / registration workflows (application approval, open registration,
invite acceptance). This module therefore *looks up* a caller's registration
and never creates one: an organizer previewing the directory is not
auto-enrolled, and an unauthorized account cannot acquire a registration just
by calling a networking API.

Read-only queries over existing models; no schema changes.
"""
from events.models import EventRegistration


def get_networking_registration(user, event):
    """Return the caller's active registration for ``event``, or ``None``.

    "Active" means an ``EventRegistration`` with ``status='registered'`` — the
    same signal the Companion directory uses to list a participant. Cancelled,
    deregistered or cancellation-requested registrations are excluded.

    Never creates a registration. Callers should return a controlled 403 when
    this returns ``None``.
    """
    if not (user and getattr(user, "is_authenticated", False) and event):
        return None
    return (
        EventRegistration.objects
        .filter(event=event, user=user, status="registered")
        .first()
    )
