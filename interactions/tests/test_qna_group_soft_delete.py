import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event
from interactions.models import Question, QnAQuestionGroup, QnAQuestionGroupMembership

User = get_user_model()


@pytest.fixture
def host(db):
    return User.objects.create_user(username="qna_group_delete_host", password="pw")


@pytest.fixture
def event(host):
    community = Community.objects.create(
        name="Q&A Group Delete Community", owner_id=host.id, description=""
    )
    return Event.objects.create(
        title="Q&A Group Delete Event",
        community=community,
        created_by=host,
        status="live",
    )


@pytest.fixture
def questions(event, host):
    return [
        Question.objects.create(event=event, user=host, content="Question one"),
        Question.objects.create(event=event, user=host, content="Question two"),
    ]


@pytest.fixture
def group(event, host, questions):
    value = QnAQuestionGroup.objects.create(
        event=event, created_by=host, title="Related questions"
    )
    for index, question in enumerate(questions):
        QnAQuestionGroupMembership.objects.create(
            group=value, question=question, added_by=host, display_order=index
        )
    return value


@pytest.mark.django_db
def test_delete_qna_group_is_soft_and_preserves_questions(group, questions, host):
    client = APIClient()
    client.force_authenticate(user=host)

    response = client.delete(
        f"/api/interactions/qna-groups/{group.id}/",
        {"reason": "Duplicate grouping"},
        format="json",
    )

    assert response.status_code == 200
    group.refresh_from_db()
    assert group.is_deleted is True
    assert group.deleted_by_id == host.id
    assert group.deletion_reason == "Duplicate grouping"
    assert group.question_ids_snapshot == [question.id for question in questions]
    assert QnAQuestionGroupMembership.objects.filter(group=group).count() == 2
    assert Question.objects.filter(id__in=[question.id for question in questions]).count() == 2


@pytest.mark.django_db
def test_soft_deleted_qna_group_is_hidden_from_list(group, host):
    group.is_deleted = True
    group.save(update_fields=["is_deleted"])

    client = APIClient()
    client.force_authenticate(user=host)
    response = client.get(f"/api/interactions/qna-groups/?event_id={group.event_id}")

    assert response.status_code == 200
    payload = response.json()
    rows = payload.get("results", payload)
    assert all(row["id"] != group.id for row in rows)
