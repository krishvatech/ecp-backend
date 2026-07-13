from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from uuid import UUID, uuid4

from django.core.cache import cache
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .models import Group


@dataclass(frozen=True)
class GroupSoftDeleteResult:
    root_group_id: int
    deleted_group_ids: tuple[int, ...]
    deletion_batch_id: UUID

    @property
    def deleted_count(self) -> int:
        return len(self.deleted_group_ids)

    @property
    def deleted_descendant_count(self) -> int:
        return max(0, self.deleted_count - 1)


def collect_primary_group_tree_ids(root_group_id: int) -> list[int]:
    """Return root + active primary descendants without following secondary links."""
    collected: list[int] = []
    frontier = [int(root_group_id)]
    seen: set[int] = set()

    while frontier:
        current = [group_id for group_id in frontier if group_id not in seen]
        if not current:
            break
        seen.update(current)
        collected.extend(current)
        frontier = list(
            Group.all_objects.filter(
                parent_id__in=current,
                is_deleted=False,
            ).values_list("id", flat=True)
        )

    return collected


@transaction.atomic
def soft_delete_group_tree(
    group: Group,
    *,
    actor,
    reason: str = "",
    deletion_source: str = Group.DELETION_SOURCE_CONNECT,
) -> GroupSoftDeleteResult:
    """Soft-delete a group and its primary descendants while retaining all rows."""
    if group.is_deleted:
        batch_id = group.deletion_batch_id or uuid4()
        return GroupSoftDeleteResult(group.id, (group.id,), batch_id)

    now = timezone.now()
    batch_id = uuid4()
    group_ids = collect_primary_group_tree_ids(group.id)
    normalized_reason = (reason or "").strip()

    Group.all_objects.filter(pk=group.id, is_deleted=False).update(
        is_deleted=True,
        deleted_at=now,
        deleted_by=actor,
        deletion_reason=normalized_reason,
        deletion_source=deletion_source,
        deletion_batch_id=batch_id,
    )

    descendant_ids = [group_id for group_id in group_ids if group_id != group.id]
    if descendant_ids:
        child_reason = normalized_reason or f'Parent group "{group.name}" was deleted.'
        Group.all_objects.filter(pk__in=descendant_ids, is_deleted=False).update(
            is_deleted=True,
            deleted_at=now,
            deleted_by=actor,
            deletion_reason=child_reason,
            deletion_source=Group.DELETION_SOURCE_PARENT,
            deletion_batch_id=batch_id,
        )

    # Conversation rows are retained, but invalidate any cached unread badge so
    # the removed group chat disappears immediately for existing members.
    from .models import GroupMembership

    member_ids = GroupMembership.objects.filter(
        group_id__in=group_ids,
    ).values_list("user_id", flat=True).distinct()
    cache_keys = [f"messaging:unread-count:{user_id}" for user_id in member_ids]
    if cache_keys:
        cache.delete_many(cache_keys)

    return GroupSoftDeleteResult(group.id, tuple(group_ids), batch_id)


@transaction.atomic
def restore_group_deletion_batches(groups: Iterable[Group]) -> int:
    """Restore selected groups and every group from their deletion batches."""
    group_list = list(groups)
    if not group_list:
        return 0

    batch_ids = {
        group.deletion_batch_id
        for group in group_list
        if group.deletion_batch_id is not None
    }
    direct_ids = {
        group.id
        for group in group_list
        if group.deletion_batch_id is None
    }

    lookup = Q()
    if batch_ids:
        lookup |= Q(deletion_batch_id__in=batch_ids)
    if direct_ids:
        lookup |= Q(id__in=direct_ids)

    return Group.all_objects.filter(lookup, is_deleted=True).update(
        is_deleted=False,
        deleted_at=None,
        deleted_by=None,
        deletion_reason="",
        deletion_source="",
        deletion_batch_id=None,
    )
