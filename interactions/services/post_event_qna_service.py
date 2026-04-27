"""Service for publishing post-event Q&A answers and sending notifications."""

from django.utils import timezone
from django.contrib.auth import get_user_model
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from friends.models import Notification
from events.models import EventRegistration

User = get_user_model()


def publish_post_event_answer(question, answer_text, answered_by):
    """
    Publish a post-event answer to a question.

    Args:
        question: The Question instance to answer.
        answer_text: The answer text (non-empty string).
        answered_by: The User who is answering.

    Returns:
        The updated Question instance.
    """
    question.answer_text = answer_text
    question.is_answered = True
    question.answered_by = answered_by
    question.answered_at = timezone.now()
    question.answered_phase = "post_event"
    question.save(
        update_fields=["answer_text", "is_answered", "answered_by", "answered_at", "answered_phase"]
    )

    # Broadcast via WebSocket to all connected clients for this event.
    _broadcast_answer_update(question)

    return question


def _broadcast_answer_update(question):
    """Broadcast the answered question update to Q&A WebSocket clients."""
    try:
        channel_layer = get_channel_layer()
        # Determine the correct Q&A group based on lounge table
        if question.lounge_table_id:
            group_name = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group_name = f"event_qna_{question.event_id}_main"
        payload = {
            "question_id": question.id,
            "is_answered": question.is_answered,
            "answered_at": question.answered_at.isoformat(),
            "answered_by": question.answered_by_id,
            "answer_text": question.answer_text,
            "answered_phase": question.answered_phase,
            "requires_followup": question.requires_followup,
        }
        async_to_sync(channel_layer.group_send)(
            group_name,
            {"type": "qna.answered", "payload": payload},
        )
    except Exception as e:
        # Log but don't fail if WebSocket broadcast fails.
        print(f"Error broadcasting answer update: {e}")


def resolve_notification_recipients(question, notify_author, notify_interested, notify_all_participants, answering_user):
    """
    Resolve the set of users who should be notified about the answer.

    Deduplicates recipients across categories and removes the answering user.

    Args:
        question: The Question instance.
        notify_author: Boolean, whether to notify the question author.
        notify_interested: Boolean, whether to notify upvoters.
        notify_all_participants: Boolean, whether to notify all event participants.
        answering_user: The User who is answering (to exclude from notifications).

    Returns:
        A set of User IDs to notify.
    """
    recipient_ids = set()

    # Notify the question author.
    if notify_author and question.user_id:
        recipient_ids.add(question.user_id)

    # Notify upvoters (interested participants).
    if notify_interested:
        upvoter_ids = set(question.upvoters.values_list("id", flat=True))
        recipient_ids.update(upvoter_ids)

    # Notify all event participants.
    if notify_all_participants:
        all_participant_ids = set(
            EventRegistration.objects.filter(
                event=question.event,
                status="registered"
            ).values_list("user_id", flat=True)
        )
        recipient_ids.update(all_participant_ids)

    # Remove the answering user (don't self-notify).
    recipient_ids.discard(answering_user.id)

    return recipient_ids


def send_answer_notifications(question, answering_user, recipient_ids):
    """
    Dispatch notification tasks for each recipient.

    In-app notifications are created immediately. Email notifications are dispatched via Celery task.

    Args:
        question: The Question instance.
        answering_user: The User who answered.
        recipient_ids: Iterable of User IDs to notify.
    """
    from interactions.tasks import send_post_event_answer_email_task

    recipient_ids = list(recipient_ids)

    # Create in-app notifications immediately.
    for recipient_id in recipient_ids:
        Notification.objects.create(
            recipient_id=recipient_id,
            actor=answering_user,
            kind="event",
            title=f"Your Q&A question has been answered",
            description=f"On {question.event.title}: {question.content[:100]}...",
            data={
                "event_id": question.event_id,
                "event_slug": question.event.slug,
                "notification_type": "post_event_qna_answer",
                "question_id": question.id,
            },
        )

    # Dispatch email notifications via Celery (for better performance).
    if recipient_ids:
        send_post_event_answer_email_task.delay(
            question_id=question.id,
            answering_user_id=answering_user.id,
            recipient_ids=recipient_ids,
        )
