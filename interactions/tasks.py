"""Celery tasks for interactions app (notifications, etc.)."""

from celery import shared_task
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.cache import cache
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from users.email_utils import send_template_email
from .models import Question
from events.models import Event

User = get_user_model()


@shared_task
def send_post_event_answer_email_task(question_id, answering_user_id, recipient_ids):
    """
    Send post-event answer notification emails to specified recipients.

    This task is dispatched asynchronously to avoid blocking the API response.

    Args:
        question_id: The Question ID.
        answering_user_id: The User ID of the answerer.
        recipient_ids: List of User IDs to send emails to.
    """
    try:
        question = Question.objects.get(id=question_id)
        answering_user = User.objects.get(id=answering_user_id)
    except (Question.DoesNotExist, User.DoesNotExist):
        return

    # Get recipient user objects.
    recipients = User.objects.filter(id__in=recipient_ids)

    answering_user_name = answering_user.get_full_name() or answering_user.username or answering_user.email

    # Send email to each recipient.
    frontend_base = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173/').rstrip('/')
    event_url = f"{frontend_base}/events/{question.event.slug}#qna"

    for recipient in recipients:
        context = {
            "recipient_name": recipient.first_name or recipient.username or "Participant",
            "event_name": question.event.title,
            "question_text": question.content,
            "answer_text": question.answer_text,
            "answering_user_name": answering_user_name,
            "event_url": event_url,
        }
        send_template_email(
            template_key="post_event_qna_answer",
            to_email=recipient.email,
            context=context,
            subject_override=f"Your Q&A Question Has Been Answered — {question.event.title}",
            fail_silently=True,
        )


@shared_task(bind=True, max_retries=0)
def auto_group_questions_task(self, event_id):
    """
    Automatically generates AI group suggestions for ungrouped questions when
    threshold is reached. Broadcasts notification to host via WebSocket.

    Args:
        event_id: The event ID.
    """
    import logging
    from .ai_grouping import suggest_groups

    logger = logging.getLogger(__name__)
    logger.info(f"[CELERY-AUTO-GROUP] Task started for event {event_id}")

    try:
        # Count ungrouped questions (same filter as question creation trigger)
        ungrouped_count = Question.objects.filter(
            event_id=event_id,
            is_hidden=False,
            is_seed=False,
            moderation_status__in=["approved", "pending"],
        ).exclude(group_membership__isnull=False).count()

        logger.info(f"[CELERY-AUTO-GROUP] Event {event_id}: Found {ungrouped_count} ungrouped questions")

        if ungrouped_count < 2:
            logger.info(f"[CELERY-AUTO-GROUP] Not enough questions to group for event {event_id}")
            return

        # Get event and host
        event = Event.objects.select_related("created_by").get(id=event_id)
        if not event.created_by:
            logger.info(f"[CELERY-AUTO-GROUP] No host found for event {event_id}")
            return

        logger.info(f"[CELERY-AUTO-GROUP] Calling suggest_groups() for event {event_id} with host {event.created_by.id}")

        # Generate AI suggestions (creates QnAQuestionGroupSuggestion records with status="pending")
        suggestions = suggest_groups(event_id, event.created_by)
        if not suggestions:
            logger.info(f"[CELERY-AUTO-GROUP] No suggestions generated for event {event_id}")
            return

        logger.info(f"[CELERY-AUTO-GROUP] ✅ Generated {len(suggestions)} suggestion(s) for event {event_id}")

        # Broadcast notification to host
        channel_layer = get_channel_layer()
        group_name = f"event_qna_{event_id}_shared"
        logger.info(f"[CELERY-AUTO-GROUP] Broadcasting to group {group_name}")
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_suggestions_ready",
                "payload": {
                    "type": "qna.group_suggestions_ready",
                    "count": len(suggestions),
                    "event_id": event_id,
                }
            }
        )
        logger.info(f"[CELERY-AUTO-GROUP] ✅ Broadcast complete for event {event_id}")
    except Exception as e:
        logger.error(f"[CELERY-AUTO-GROUP] ❌ Error in auto_group_questions_task: {str(e)}", exc_info=True)
