"""Celery tasks for interactions app (notifications, etc.)."""

from celery import shared_task
from django.contrib.auth import get_user_model
from django.conf import settings
from users.email_utils import send_template_email
from .models import Question

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
