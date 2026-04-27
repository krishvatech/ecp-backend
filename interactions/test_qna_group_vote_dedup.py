"""
Tests for deduplicated vote aggregation in Q&A question groups.

Covers:
  1. aggregated_vote_count deduplicates when one user upvotes multiple sub-questions
  2. aggregated_vote_count handles multiple DIFFERENT users correctly (counts each once)
  3. Guest deduplication: one guest upvotes multiple sub-questions → count == 1
  4. Mixed user + guest without overlap → correct total
  5. Upvote REST response includes group_id, group_vote_count, user_has_voted_in_group
  6. Ungrouped question returns group_id: null in upvote response

Run with:
  pytest interactions/test_qna_group_vote_dedup.py -v
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from community.models import Community
from events.models import Event, GuestAttendee
from interactions.models import (
    Question,
    QuestionUpvote,
    QuestionGuestUpvote,
    QnAQuestionGroup,
    QnAQuestionGroupMembership,
)

User = get_user_model()


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def community(db):
    owner = User.objects.create_user(username="group_vote_host", password="pw")
    org = Community.objects.create(name="GVOrg", owner_id=owner.id, description="")
    return org


@pytest.fixture
def host(community):
    return User.objects.get(username="group_vote_host")


@pytest.fixture
def event(community, host):
    return Event.objects.create(
        title="Group Vote Dedup Test",
        community=community,
        created_by=host,
        status="live",
    )


@pytest.fixture
def user_a(community):
    u = User.objects.create_user(username="gv_user_a", password="pw")
    community.members.add(u)
    return u


@pytest.fixture
def user_b(community):
    u = User.objects.create_user(username="gv_user_b", password="pw")
    community.members.add(u)
    return u


@pytest.fixture
def guest_a(event):
    return GuestAttendee.objects.create(
        event=event,
        first_name="GuestA",
        last_name="Vote",
        email="guest_a@example.com",
    )


@pytest.fixture
def q1(event, user_a):
    return Question.objects.create(event=event, user=user_a, content="Sub-question 1")


@pytest.fixture
def q2(event, user_a):
    return Question.objects.create(event=event, user=user_a, content="Sub-question 2")


@pytest.fixture
def q3(event, user_b):
    return Question.objects.create(event=event, user=user_b, content="Sub-question 3")


@pytest.fixture
def group(event, host, q1, q2):
    """A group containing q1 and q2."""
    g = QnAQuestionGroup.objects.create(event=event, created_by=host, title="Test Group")
    QnAQuestionGroupMembership.objects.create(group=g, question=q1, added_by=host)
    QnAQuestionGroupMembership.objects.create(group=g, question=q2, added_by=host)
    return g


def _client(user):
    c = APIClient()
    c.force_authenticate(user=user)
    return c


def _upvote_url(question_id):
    return f"/api/interactions/questions/{question_id}/upvote/"


# ─────────────────────────────────────────────────────────────────────────────
# 1. One user upvotes multiple sub-questions → group count == 1
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_aggregated_vote_count_deduplicates_user(group, q1, q2, user_b):
    """
    User B upvotes both q1 and q2 (both in the same group).
    The group's aggregated_vote_count must be 1, not 2.
    """
    QuestionUpvote.objects.create(question=q1, user=user_b)
    QuestionUpvote.objects.create(question=q2, user=user_b)

    group.refresh_from_db()
    assert group.aggregated_vote_count == 1, (
        "One user voting on two sub-questions should count as 1 unique voter, not 2"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Two different users each upvote different sub-questions → count == 2
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_aggregated_vote_count_no_overlap(group, q1, q2, user_a, user_b):
    """
    User A upvotes q1 only, User B upvotes q2 only.
    The group's aggregated_vote_count must be 2.
    """
    QuestionUpvote.objects.create(question=q1, user=user_a)
    QuestionUpvote.objects.create(question=q2, user=user_b)

    group.refresh_from_db()
    assert group.aggregated_vote_count == 2


# ─────────────────────────────────────────────────────────────────────────────
# 3. Guest deduplication: one guest upvotes multiple sub-questions → count == 1
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_aggregated_vote_count_guest_dedup(group, q1, q2, guest_a):
    """
    The same guest upvotes q1 and q2 (both in the same group).
    The group's aggregated_vote_count must be 1.
    """
    QuestionGuestUpvote.objects.create(question=q1, guest=guest_a)
    QuestionGuestUpvote.objects.create(question=q2, guest=guest_a)

    group.refresh_from_db()
    assert group.aggregated_vote_count == 1, (
        "One guest voting on two sub-questions should count as 1 unique voter"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Mixed user + guest without overlap → correct total
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_aggregated_vote_count_mixed_user_and_guest(group, q1, q2, user_b, guest_a):
    """
    User B upvotes q1, Guest A upvotes q2. No overlap.
    The group's aggregated_vote_count must be 2.
    """
    QuestionUpvote.objects.create(question=q1, user=user_b)
    QuestionGuestUpvote.objects.create(question=q2, guest=guest_a)

    group.refresh_from_db()
    assert group.aggregated_vote_count == 2


# ─────────────────────────────────────────────────────────────────────────────
# 5. Empty group → count == 0
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_aggregated_vote_count_empty_group(event, host):
    """A group with no memberships should return 0."""
    g = QnAQuestionGroup.objects.create(event=event, created_by=host, title="Empty Group")
    assert g.aggregated_vote_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 6. Upvote REST response includes group context when question is in a group
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_upvote_response_includes_group_context(group, q1, user_b):
    """
    POST /questions/{id}/upvote/ on a question that is in a group must include
    group_id, group_vote_count, and user_has_voted_in_group in the response.
    """
    res = _client(user_b).post(_upvote_url(q1.id), format="json")
    assert res.status_code == 200
    data = res.json()
    assert data["group_id"] == group.id, "group_id must be returned"
    assert data["group_vote_count"] is not None, "group_vote_count must be returned"
    assert "user_has_voted_in_group" in data, "user_has_voted_in_group must be returned"
    # After upvoting q1, the user has voted in the group
    assert data["user_has_voted_in_group"] is True


@pytest.mark.django_db
def test_upvote_response_group_count_is_deduplicated(group, q1, q2, user_b):
    """
    If user_b upvotes both q1 and q2, the group_vote_count returned on the
    second upvote response must still be 1 (deduplicated), not 2.
    """
    _client(user_b).post(_upvote_url(q1.id), format="json")  # upvote q1
    res = _client(user_b).post(_upvote_url(q2.id), format="json")  # upvote q2
    assert res.status_code == 200
    data = res.json()
    assert data["group_vote_count"] == 1, (
        f"Expected group_vote_count=1 (one unique voter), got {data['group_vote_count']}"
    )
    assert data["user_has_voted_in_group"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 7. Ungrouped question returns group_id: null
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_upvote_response_no_group_context_when_ungrouped(event, user_a, user_b):
    """
    POST /questions/{id}/upvote/ on a question NOT in any group must return
    group_id: null.
    """
    standalone_q = Question.objects.create(
        event=event, user=user_a, content="Standalone ungrouped question"
    )
    res = _client(user_b).post(_upvote_url(standalone_q.id), format="json")
    assert res.status_code == 200
    data = res.json()
    assert data["group_id"] is None, "Ungrouped question must return group_id: null"
    assert data["group_vote_count"] is None
    assert data["user_has_voted_in_group"] is None
