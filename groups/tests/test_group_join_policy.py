import pytest
from rest_framework.test import APIRequestFactory

from groups.models import Group
from groups.serializers import GroupSerializer


@pytest.fixture
def rf():
    return APIRequestFactory()


def _make_request(rf, user, method="post", path="/api/groups/"):
    req = getattr(rf, method)(path)
    req.user = user
    return req


def _serialize_create(data, user, rf):
    req = _make_request(rf, user, "post")
    return GroupSerializer(data=data, context={"request": req})


def _serialize_update(instance, data, user, rf):
    req = _make_request(rf, user, "patch", f"/api/groups/{instance.id}/")
    return GroupSerializer(instance=instance, data=data, context={"request": req}, partial=True)


def _make_group(user, community, **kwargs):
    defaults = dict(
        name="Parent",
        slug="parent",
        description="desc",
        visibility=Group.VISIBILITY_PUBLIC,
        join_policy=Group.JOIN_OPEN,
        created_by=user,
        community=community,
    )
    defaults.update(kwargs)
    return Group.objects.create(**defaults)


@pytest.mark.django_db
def test_parent_public_allows_open_approval_invite(user, community, rf):
    for policy in [Group.JOIN_OPEN, Group.JOIN_APPROVAL, Group.JOIN_INVITE]:
        data = {
            "name": f"Parent {policy}",
            "slug": f"parent-{policy}",
            "description": "desc",
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": policy,
            "community_id": community.id,
        }
        ser = _serialize_create(data, user, rf)
        assert ser.is_valid(), ser.errors
        ser.save()


@pytest.mark.django_db
def test_parent_private_invite_only(user, community, rf):
    ok = _serialize_create(
        {
            "name": "Private Invite",
            "slug": "private-invite",
            "description": "desc",
            "visibility": Group.VISIBILITY_PRIVATE,
            "join_policy": Group.JOIN_INVITE,
            "community_id": community.id,
        },
        user,
        rf,
    )
    assert ok.is_valid(), ok.errors

    bad_approval = _serialize_create(
        {
            "name": "Private Approval",
            "slug": "private-approval",
            "description": "desc",
            "visibility": Group.VISIBILITY_PRIVATE,
            "join_policy": Group.JOIN_APPROVAL,
            "community_id": community.id,
        },
        user,
        rf,
    )
    assert not bad_approval.is_valid()
    assert bad_approval.errors["join_policy"][0] == "Private groups must be 'invite'."

    bad_open = _serialize_create(
        {
            "name": "Private Open",
            "slug": "private-open",
            "description": "desc",
            "visibility": Group.VISIBILITY_PRIVATE,
            "join_policy": Group.JOIN_OPEN,
            "community_id": community.id,
        },
        user,
        rf,
    )
    assert not bad_open.is_valid()
    assert bad_open.errors["join_policy"][0] == "Private groups must be 'invite'."


@pytest.mark.django_db
def test_subgroup_open_only_when_parent_public_open(user, community, rf):
    parent_open = _make_group(
        user,
        community,
        name="Parent Open",
        slug="parent-open",
        visibility=Group.VISIBILITY_PUBLIC,
        join_policy=Group.JOIN_OPEN,
    )

    ok = _serialize_create(
        {
            "name": "Sub Open",
            "slug": "sub-open",
            "description": "desc",
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
            "parent_id": parent_open.id,
        },
        user,
        rf,
    )
    assert ok.is_valid(), ok.errors

    parent_approval = _make_group(
        user,
        community,
        name="Parent Approval",
        slug="parent-approval",
        visibility=Group.VISIBILITY_PUBLIC,
        join_policy=Group.JOIN_APPROVAL,
    )
    bad = _serialize_create(
        {
            "name": "Sub Open Bad",
            "slug": "sub-open-bad",
            "description": "desc",
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
            "parent_id": parent_approval.id,
        },
        user,
        rf,
    )
    assert not bad.is_valid()
    assert bad.errors["join_policy"][0] == "Subgroups under non-open parents cannot be 'open'."


@pytest.mark.django_db
def test_subgroup_private_invite_only(user, community, rf):
    parent = _make_group(
        user,
        community,
        name="Parent Any",
        slug="parent-any",
        visibility=Group.VISIBILITY_PUBLIC,
        join_policy=Group.JOIN_OPEN,
    )

    ok = _serialize_create(
        {
            "name": "Sub Private",
            "slug": "sub-private",
            "description": "desc",
            "visibility": Group.VISIBILITY_PRIVATE,
            "join_policy": Group.JOIN_INVITE,
            "parent_id": parent.id,
        },
        user,
        rf,
    )
    assert ok.is_valid(), ok.errors

    bad = _serialize_create(
        {
            "name": "Sub Private Bad",
            "slug": "sub-private-bad",
            "description": "desc",
            "visibility": Group.VISIBILITY_PRIVATE,
            "join_policy": Group.JOIN_APPROVAL,
            "parent_id": parent.id,
        },
        user,
        rf,
    )
    assert not bad.is_valid()
    assert bad.errors["join_policy"][0] == "Private groups must be 'invite'."


@pytest.mark.django_db
def test_parent_update_blocked_when_subgroup_open(user, community, rf):
    parent = _make_group(
        user,
        community,
        name="Parent",
        slug="parent-block",
        visibility=Group.VISIBILITY_PUBLIC,
        join_policy=Group.JOIN_OPEN,
    )
    Group.objects.create(
        name="Sub Open",
        slug="sub-open-block",
        description="desc",
        visibility=Group.VISIBILITY_PUBLIC,
        join_policy=Group.JOIN_OPEN,
        parent=parent,
        created_by=user,
        community=community,
    )

    ser = _serialize_update(parent, {"join_policy": Group.JOIN_APPROVAL}, user, rf)
    assert not ser.is_valid()
    assert "Parent groups with public subgroups set to 'open' cannot be changed to non-open. Update subgroups first." in str(
        ser.errors["join_policy"][0]
    )
