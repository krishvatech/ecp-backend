from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver

from friends.models import Notification
from .models import GroupMembership, Group


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
    # recipients: owner/admin/mods (exclude actor)
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
            Notification.objects.create(
                recipient_id=rid,
                actor=actor if getattr(actor, "id", None) else None,
                kind="system",
                title="Join request",
                description=f"{getattr(actor, 'get_full_name', lambda: '')() or getattr(actor, 'username', 'Someone')} requested to join {getattr(group, 'name', 'your group')}",
                state="pending",
                data=payload,
            )

    # 2) membership became ACTIVE (open-join OR approved request)
    became_active = (
        instance.status == GroupMembership.STATUS_ACTIVE
        and (created or getattr(instance, "_prev_status", None) == GroupMembership.STATUS_PENDING)
    )
    if became_active:
        payload = {
            "type": "group_member_joined",
            "group_id": group.id,
            "group_name": getattr(group, "name", None),
            "user_id": getattr(actor, "id", None),
        }
        for rid in recipients:
            Notification.objects.create(
                recipient_id=rid,
                actor=actor if getattr(actor, "id", None) else None,
                kind="system",
                title="New group member",
                description=f"{getattr(actor, 'get_full_name', lambda: '')() or getattr(actor, 'username', 'Someone')} joined {getattr(group, 'name', 'your group')}",
                data=payload,
            )
