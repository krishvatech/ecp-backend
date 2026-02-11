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


# -------- GroupMembership: remember previous status (existing code) --------
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


# -------- Group: remember previous visibility/join_policy (NEW) --------
@receiver(pre_save, sender=Group)
def _store_prev_group_state(sender, instance: Group, **kwargs):
    """
    Remember old visibility / join_policy so we can detect changes in post_save.
    """
    if instance.pk:
        try:
            prev = Group.objects.only("visibility", "join_policy").get(pk=instance.pk)
            instance._prev_visibility = prev.visibility
            instance._prev_join_policy = prev.join_policy
        except Group.DoesNotExist:
            instance._prev_visibility = None
            instance._prev_join_policy = None
    else:
        instance._prev_visibility = None
        instance._prev_join_policy = None


# -------- GroupMembership: create notifications when membership changes (existing code) --------
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
        was_pending = getattr(instance, "_prev_status", None) == GroupMembership.STATUS_PENDING

        # CASE A: admin added this member directly (created + invited_by set + inviter != user)
        if created and inviter and getattr(inviter, "id", None) != getattr(actor, "id", None):
            notif_type = "group_member_added"
            kind = GroupNotification.KIND_MEMBER_ADDED
            title = "Member added"

            added_user_name = str(actor) if actor else "a member"
            inviter_name = str(inviter)
            description = f"{inviter_name} added {added_user_name} to {getattr(group, 'name', 'your group')}"
            actor_for_notif = inviter

            # NEW: Notify the user that they were added to the group (for invite-only groups)
            if actor and getattr(actor, "id", None) and group.join_policy in [Group.JOIN_INVITE]:
                from friends.models import Notification
                Notification.objects.create(
                    recipient=actor,
                    actor=inviter,
                    kind="group",
                    title="Added to Group",
                    description=f"{inviter_name} added you to {getattr(group, 'name', 'the group')}",
                    state="added",
                    data={
                        "type": "group_member_added",
                        "group_id": group.id,
                        "group_name": getattr(group, "name", None),
                        "added_by_id": getattr(inviter, "id", None),
                        "added_by_name": inviter_name,
                    }
                )

        # CASE B: normal join / approved request
        else:
            notif_type = "group_member_joined"
            kind = GroupNotification.KIND_MEMBER_JOINED
            title = "New group member"

            member_name = str(actor) if actor else "Someone"
            description = f"{member_name} joined {getattr(group, 'name', 'your group')}"
            actor_for_notif = actor

            # NEW: Notify the user that their join request was approved
            was_pending = getattr(instance, "_prev_status", None) == GroupMembership.STATUS_PENDING
            if was_pending and actor and getattr(actor, "id", None):
                from friends.models import Notification
                Notification.objects.create(
                    recipient=actor,
                    actor=None,  # System notification
                    kind="group",
                    title="Join Request Approved",
                    description=f"Your request to join {getattr(group, 'name', 'the group')} has been approved!",
                    state="approved",
                    data={
                        "type": "group_join_approved",
                        "group_id": group.id,
                        "group_name": getattr(group, "name", None),
                    }
                )


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


# -------- GroupMembership: propagate ADMIN role to sub-groups (NEW) --------
@receiver(post_save, sender=GroupMembership)
def _propagate_admin_to_subgroups(sender, instance: GroupMembership, created, **kwargs):
    """
    If a user is ADMIN in a group (and ACTIVE), ensure they are ADMIN in all of that
    group's sub-groups (and their children via cascading saves).
    """
    # Only for ACTIVE admins
    if instance.role != GroupMembership.ROLE_ADMIN or instance.status != GroupMembership.STATUS_ACTIVE:
        return

    group = getattr(instance, "group", None)
    if not group or not getattr(group, "id", None):
        return

    subgroups = Group.objects.filter(parent=group)
    if not subgroups.exists():
        return

    for sg in subgroups:
        m, created_child = GroupMembership.objects.get_or_create(
            group=sg,
            user_id=instance.user_id,
            defaults={
                "role": GroupMembership.ROLE_ADMIN,
                "status": GroupMembership.STATUS_ACTIVE,
                "invited_by_id": getattr(instance, "invited_by_id", None),
            },
        )
        # If membership already exists, upgrade it to ADMIN + ACTIVE if needed
        updates = {}
        if m.role != GroupMembership.ROLE_ADMIN:
            updates["role"] = GroupMembership.ROLE_ADMIN
        if m.status != GroupMembership.STATUS_ACTIVE:
            updates["status"] = GroupMembership.STATUS_ACTIVE
        if updates:
            GroupMembership.objects.filter(pk=m.pk).update(**updates)


# -------- Group: notifications when a group is created (existing code) --------
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

    # NEW: Automatically add the creator as an ADMIN member if not already
    if created and group.created_by_id:
        GroupMembership.objects.get_or_create(
            group=group,
            user_id=group.created_by_id,
            defaults={
                "role": GroupMembership.ROLE_ADMIN,
                "status": GroupMembership.STATUS_ACTIVE,
            }
        )


# -------- Group: keep sub-groups admins in sync (no visibility/join_policy sync) --------
@receiver(post_save, sender=Group)
def _sync_subgroups_on_group_change(sender, instance: Group, created, **kwargs):
    """
    When a new sub-group is created, copy ACTIVE admins of the parent
    into the new sub-group.

    NOTE: We intentionally do NOT sync visibility/join_policy from parent
    to sub-groups. Sub-groups are independently configurable and validated
    by serializer rules.
    """
    group = instance

    # --- (A) If this is a NEW sub-group, copy parent admins into it ---
    if created and group.parent_id:
        parent_id = group.parent_id

        # Copy ACTIVE admins from parent to this new sub-group
        admin_qs = GroupMembership.objects.filter(
            group_id=parent_id,
            role=GroupMembership.ROLE_ADMIN,
            status=GroupMembership.STATUS_ACTIVE,
        ).values_list("user_id", flat=True)

        for uid in admin_qs:
            GroupMembership.objects.get_or_create(
                group=group,
                user_id=uid,
                defaults={
                    "role": GroupMembership.ROLE_ADMIN,
                    "status": GroupMembership.STATUS_ACTIVE,
                },
            )
