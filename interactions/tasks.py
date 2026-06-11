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
            "app_name": "IMAA Connect",
            "recipient_name": recipient.first_name or recipient.username or "Participant",
            "event_name": question.event.title,
            "event_title": question.event.title,
            "question_text": question.content,
            "answer_text": question.answer_text,
            "answering_user_name": answering_user_name,
            "event_url": event_url,
            "support_email": getattr(settings, "SUPPORT_EMAIL", getattr(settings, "DEFAULT_FROM_EMAIL", "")),
        }
        send_template_email(
            template_key="post_event_qna_answer",
            to_email=recipient.email,
            context=context,
            subject_override=f"Your Q&A Question Has Been Answered — {question.event.title}",
            fail_silently=True,
            event=question.event,
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


@shared_task(bind=True, max_retries=3)
def persist_chat_message_to_db(self, event_id, message_uuid, message_dict):
    """
    Persist chat message to database after Redis queue.
    Called asynchronously after message is broadcast via WebSocket.

    Retries with exponential backoff on failure.
    Max retries: 3 (5s, 25s, 125s delays)

    Args:
        event_id: Event ID
        message_uuid: Message UUID (for deduplication)
        message_dict: Dict with message data {user_id, content, created_at, uuid}
    """
    import logging
    from .models import ChatMessage
    from events.redis_messages import remove_from_pending

    logger = logging.getLogger(__name__)

    try:
        # Idempotent create: retries/replays must not duplicate messages.
        message, created = ChatMessage.objects.get_or_create(
            external_id=str(message_uuid),
            defaults={
                'event_id': event_id,
                'user_id': message_dict.get('user_id'),
                'content': message_dict.get('content'),
                'created_at': message_dict.get('created_at'),
            },
        )

        # Remove from Redis pending list
        remove_from_pending(event_id, message_uuid, is_qna=False)

        logger.info(f"✓ Persisted chat message {message_uuid} to DB (id={message.id})")
        return {'status': 'saved', 'db_id': message.id, 'uuid': str(message_uuid)}

    except Exception as exc:
        logger.error(
            f"Failed to persist chat message {message_uuid} (attempt {self.request.retries + 1}/4): {exc}",
            exc_info=True
        )
        # Retry with exponential backoff: 5s, 25s, 125s
        countdown = 5 ** (self.request.retries + 1)
        raise self.retry(exc=exc, countdown=countdown)


@shared_task(bind=True, max_retries=3)
def persist_qna_question_to_db(self, event_id, question_uuid, question_dict):
    """
    Persist Q&A question to database after Redis queue.
    Called asynchronously after question is broadcast via WebSocket.

    Retries with exponential backoff on failure.
    Max retries: 3 (5s, 25s, 125s delays)

    Args:
        event_id: Event ID
        question_uuid: Question UUID (for deduplication)
        question_dict: Dict with question data {user_id, content, created_at, uuid, ...}
    """
    import logging
    from .models import Question
    from events.redis_messages import remove_from_pending

    logger = logging.getLogger(__name__)

    try:
        # Idempotent create: retries/replays must not duplicate questions.
        question, created = Question.objects.get_or_create(
            external_id=str(question_uuid),
            defaults={
                'event_id': event_id,
                'user_id': question_dict.get('user_id'),
                'guest_asker_id': question_dict.get('guest_asker_id'),
                'content': question_dict.get('content'),
                'lounge_table_id': question_dict.get('lounge_table_id'),
                'is_anonymous': question_dict.get('is_anonymous', False),
                'created_at': question_dict.get('created_at'),
                'moderation_status': question_dict.get('moderation_status', 'pending'),
            },
        )

        # Remove from Redis pending list
        remove_from_pending(event_id, question_uuid, is_qna=True)

        logger.info(f"✓ Persisted Q&A question {question_uuid} to DB (id={question.id})")
        return {'status': 'saved', 'db_id': question.id, 'uuid': str(question_uuid)}

    except Exception as exc:
        logger.error(
            f"Failed to persist Q&A question {question_uuid} (attempt {self.request.retries + 1}/4): {exc}",
            exc_info=True
        )
        # Retry with exponential backoff: 5s, 25s, 125s
        countdown = 5 ** (self.request.retries + 1)
        raise self.retry(exc=exc, countdown=countdown)


@shared_task(bind=True, max_retries=3)
def persist_qna_reply_to_db(self, event_id, reply_uuid, reply_dict):
    """
    Persist Q&A reply to database after Redis queue.
    Called asynchronously after reply is broadcast via WebSocket.

    Retries with exponential backoff on failure.
    Max retries: 3 (5s, 25s, 125s delays)

    Args:
        event_id: Event ID
        reply_uuid: Reply UUID (for deduplication)
        reply_dict: Dict with reply data {question_id, user_id, content, created_at, uuid, ...}
    """
    import logging
    from .models import QnAReply
    from events.redis_messages import remove_from_pending

    logger = logging.getLogger(__name__)

    try:
        # Idempotent create: retries/replays must not duplicate replies.
        reply, created = QnAReply.objects.get_or_create(
            external_id=str(reply_uuid),
            defaults={
                'question_id': reply_dict.get('question_id'),
                'event_id': event_id,
                'user_id': reply_dict.get('user_id'),
                'guest_asker_id': reply_dict.get('guest_asker_id'),
                'content': reply_dict.get('content'),
                'lounge_table_id': reply_dict.get('lounge_table_id'),
                'is_anonymous': reply_dict.get('is_anonymous', False),
                'created_at': reply_dict.get('created_at'),
                'moderation_status': reply_dict.get('moderation_status', 'pending'),
            },
        )

        # Remove from Redis pending list
        remove_from_pending(event_id, reply_uuid, is_qna=True)

        logger.info(f"✓ Persisted Q&A reply {reply_uuid} to DB (id={reply.id})")
        return {'status': 'saved', 'db_id': reply.id, 'uuid': str(reply_uuid)}

    except Exception as exc:
        logger.error(
            f"Failed to persist Q&A reply {reply_uuid} (attempt {self.request.retries + 1}/4): {exc}",
            exc_info=True
        )
        # Retry with exponential backoff: 5s, 25s, 125s
        countdown = 5 ** (self.request.retries + 1)
        raise self.retry(exc=exc, countdown=countdown)
