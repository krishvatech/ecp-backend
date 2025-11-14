from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver

from .models import GroupMembership, Group, GroupNotification



def _admin_and_owner_ids(group: Group):
    """
    Owner/creator + active admins/moderators of the group (user IDs).
    """
    admin_roles = [GroupMembership.ROLE_ADMIN, GroupMembership.ROLE_MODERATOR]
    active_ids = GroupMembership.objects.filter(
        group_id=group.id,
        status=GroupMembership.STATUS_ACTIVE,
        role__in=admin_roles,
    ).values_list("user_id", flat=True)
    ids = set(active_ids)
    owner_id = getattr(group, "owner_id", None) or getattr(group, "created_by_id", None)
    if owner_id:
        ids.add(int(owner_id))
    return ids


@receiver(pre_save, sender=GroupMembership)
def _store_prev_status(sender, instance: GroupMembership, **kwargs):
    # remember previous status so we can detect PENDING->ACTIVE
    if instance.id:
        try:
            prev = GroupMembership.objects.only("status").get(id=instance.id)
            instance._prev_status = prev.status
        except GroupMembership.DoesNotExist:
            instance._prev_status = None
    else:
        instance._prev_status = None


@receiver(post_save, sender=GroupMembership)
def _notify_on_membership_change(sender, instance: GroupMembership, created, **kwargs):
    """
    Create group notifications when:
      1) A user REQUESTS to join a group.
      2) A membership becomes ACTIVE:
         - open-join / approved request  → member_joined
         - admin added member            → member_added
    """
    # recipients: owner/admin/mods (exclude the actor)
    try:
        group = instance.group
        actor = instance.user
        recipients = _admin_and_owner_ids(group)
        if getattr(actor, "id", None):
            recipients.discard(int(actor.id))
    except Exception:
        return

    # 1) user REQUESTED to join (PENDING + not an admin invite)
    if created and instance.status == GroupMembership.STATUS_PENDING and not instance.invited_by_id:
        payload = {
            "type": "group_join_request",
            "group_id": group.id,
            "group_name": getattr(group, "name", None),
            "user_id": getattr(actor, "id", None),
        }
        for rid in recipients:
            GroupNotification.objects.create(
                recipient_id=rid,
                actor=actor if getattr(actor, "id", None) else None,
                group=group,
                kind=GroupNotification.KIND_JOIN_REQUEST,
                title="Join request",
                description=f"{actor or 'Someone'} requested to join {getattr(group, 'name', 'your group')}",
                state="pending",
                data=payload,
            )

    # 2) membership became ACTIVE (open-join OR approved request OR admin added)
    became_active = (
        instance.status == GroupMembership.STATUS_ACTIVE
        and (created or getattr(instance, "_prev_status", None) == GroupMembership.STATUS_PENDING)
    )
    if became_active:
        inviter = getattr(instance, "invited_by", None)

        # CASE A: admin added this member directly (created + invited_by set + inviter != user)
        if created and inviter and getattr(inviter, "id", None) != getattr(actor, "id", None):
            notif_type = "group_member_added"
            kind = GroupNotification.KIND_MEMBER_ADDED
            title = "Member added"

            added_user_name = str(actor) if actor else "a member"
            inviter_name = str(inviter)
            description = f"{inviter_name} added {added_user_name} to {getattr(group, 'name', 'your group')}"
            actor_for_notif = inviter
        # CASE B: normal join / approved request
        else:
            notif_type = "group_member_joined"
            kind = GroupNotification.KIND_MEMBER_JOINED
            title = "New group member"

            member_name = str(actor) if actor else "Someone"
            description = f"{member_name} joined {getattr(group, 'name', 'your group')}"
            actor_for_notif = actor

        payload = {
            "type": notif_type,
            "group_id": group.id,
            "group_name": getattr(group, "name", None),
            "user_id": getattr(actor, "id", None),
        }

        for rid in recipients:
            GroupNotification.objects.create(
                recipient_id=rid,
                actor=actor_for_notif if getattr(actor_for_notif, "id", None) else None,
                group=group,
                kind=kind,
                title=title,
                description=description,
                data=payload,
            )

@receiver(post_save, sender=Group)
def _notify_on_group_created(sender, instance: Group, created, **kwargs):
    """
    Notify relevant admins when a new group is created.
    Recipients:
      - community.owner (if any)
      - group.owner / group.created_by
    """
    if not created:
        return

    group = instance
    actor = getattr(group, "created_by", None)
    community = getattr(group, "community", None)

    recipients = set()

    # Community owner
    if community and getattr(community, "owner_id", None):
        recipients.add(int(community.owner_id))

    # Group owner / creator
    if getattr(group, "owner_id", None):
        recipients.add(int(group.owner_id))
    elif getattr(group, "created_by_id", None):
        recipients.add(int(group.created_by_id))

    if not recipients:
        return

    payload = {
        "type": "group_created",
        "group_id": group.id,
        "group_name": getattr(group, "name", None),
        "community_id": getattr(community, "id", None) if community else None,
        "community_name": getattr(community, "name", None) if community else None,
        "creator_id": getattr(actor, "id", None),
    }

    for rid in recipients:
        GroupNotification.objects.create(
            recipient_id=rid,
            actor=actor if getattr(actor, "id", None) else None,
            group=group,
            kind=GroupNotification.KIND_GROUP_CREATED,
            title="New group created",
            description=f"{actor or 'Someone'} created the group {getattr(group, 'name', '')}",
            data=payload,
        )
