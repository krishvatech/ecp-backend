import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event
from interactions.models import Question, QuestionUpvote, QnAReply, QnAReplyUpvote

User = get_user_model()


@pytest.fixture
def setup_qna(db):
    host = User.objects.create_user(username="qna_host_soft", password="pw")
    attendee = User.objects.create_user(username="qna_attendee_soft", password="pw")
    voter = User.objects.create_user(username="qna_voter_soft", password="pw")
    community = Community.objects.create(name="QnA Soft Delete", owner=host, description="")
    community.members.add(attendee, voter)
    event = Event.objects.create(
        title="QnA Soft Delete Event",
        community=community,
        created_by=host,
        status="live",
    )
    question = Question.objects.create(
        event=event,
        user=attendee,
        content="Will this remain in the database?",
        moderation_status="approved",
    )
    QuestionUpvote.objects.create(question=question, user=voter)
    reply = QnAReply.objects.create(
        question=question,
        event=event,
        user=voter,
        content="Yes, it should remain.",
        moderation_status="approved",
    )
    QnAReplyUpvote.objects.create(reply=reply, user=attendee)
    return host, attendee, voter, event, question, reply


def client_for(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.mark.django_db
def test_question_delete_preserves_question_reply_and_votes(setup_qna):
    host, attendee, voter, event, question, reply = setup_qna
    response = client_for(attendee).delete(
        f"/api/interactions/questions/{question.id}/",
        {"reason": "No longer needed"},
        format="json",
    )
    assert response.status_code == 204
    question.refresh_from_db()
    assert question.is_deleted is True
    assert question.deleted_at is not None
    assert question.deleted_by_id == attendee.id
    assert question.deletion_reason == "No longer needed"
    assert QuestionUpvote.objects.filter(question=question, user=voter).exists()
    assert QnAReply.objects.filter(pk=reply.id).exists()
    assert QnAReplyUpvote.objects.filter(reply=reply, user=attendee).exists()
    list_response = client_for(host).get(
        f"/api/interactions/questions/?event_id={event.id}&legacy=true"
    )
    assert list_response.status_code == 200
    assert question.id not in [row["id"] for row in list_response.json()]


@pytest.mark.django_db
def test_deleted_question_rejects_new_reply_and_upvote(setup_qna):
    host, attendee, voter, event, question, reply = setup_qna
    question.is_deleted = True
    question.save(update_fields=["is_deleted"])
    assert client_for(voter).post(
        f"/api/interactions/questions/{question.id}/replies/",
        {"content": "This must not be accepted"},
        format="json",
    ).status_code == 404
    assert client_for(voter).post(
        f"/api/interactions/questions/{question.id}/upvote/", {}, format="json"
    ).status_code == 404


@pytest.mark.django_db
def test_reply_delete_preserves_reply_and_upvote_but_hides_from_list(setup_qna):
    host, attendee, voter, event, question, reply = setup_qna
    response = client_for(voter).delete(
        f"/api/interactions/replies/{reply.id}/",
        {"reason": "Duplicate answer"},
        format="json",
    )
    assert response.status_code == 200
    reply.refresh_from_db()
    assert reply.is_deleted is True
    assert reply.deleted_at is not None
    assert reply.deleted_by_id == voter.id
    assert reply.deletion_reason == "Duplicate answer"
    assert QnAReplyUpvote.objects.filter(reply=reply, user=attendee).exists()
    list_response = client_for(host).get(
        f"/api/interactions/questions/{question.id}/replies/?legacy=true"
    )
    assert list_response.status_code == 200
    assert reply.id not in [row["id"] for row in list_response.json()]


@pytest.mark.django_db
def test_deleted_reply_cannot_be_edited_upvoted_or_moderated(setup_qna):
    host, attendee, voter, event, question, reply = setup_qna
    reply.is_deleted = True
    reply.save(update_fields=["is_deleted"])
    owner_client = client_for(voter)
    assert owner_client.patch(
        f"/api/interactions/replies/{reply.id}/",
        {"content": "Changed"},
        format="json",
    ).status_code == 404
    assert owner_client.post(
        f"/api/interactions/replies/{reply.id}/upvote/", {}, format="json"
    ).status_code == 404
    assert client_for(host).post(
        f"/api/interactions/replies/{reply.id}/approve/", {}, format="json"
    ).status_code == 404
