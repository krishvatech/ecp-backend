from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.contenttypes.models import ContentType

from activity_feed.models import FeedItem
from engagements.models import Reaction, Comment
from friends.models import Notification


def _recipient_for_reaction(obj: Reaction):
    """
    For FeedItem likes -> notify the actor (post owner).
    For Comment likes -> notify the comment author.
    """
    try:
        ct = obj.content_type
        # FeedItem target
        if ct == ContentType.objects.get_for_model(FeedItem):
            feed = FeedItem.objects.select_related("actor").only("id", "actor_id").get(id=obj.object_id)
            return feed.actor, feed.id
        # Comment target
        if ct == ContentType.objects.get_for_model(Comment):
            c = Comment.objects.select_related("user").only("id", "user_id", "content_type_id", "object_id").get(id=obj.object_id)
            # If the comment was on a FeedItem, include that id in data
            feed_id = None
            if c.content_type_id == ContentType.objects.get_for_model(FeedItem).id:
                feed_id = c.object_id
            return c.user, feed_id
    except (FeedItem.DoesNotExist, Comment.DoesNotExist):
        pass
    return None, None


@receiver(post_save, sender=Reaction)
def notify_on_like(sender, instance: Reaction, created, **kwargs):
    # Only when a new reaction is created (toggle off does nothing)
    if not created:
        return

    # current reaction key from DB, e.g. "like", "intriguing", "spot_on", ...
    reaction_key = (getattr(instance, "reaction", "") or "").lower()

    # Map reaction → label with emoji for notifications
    # (keys here should match the values stored in Reaction.reaction field)
    reaction_labels = {
        "like": "👍 Like",
        "intriguing": "🤔 Intriguing",
        "spot_on": "🎯 Spot On",
        "validated": "🧠 Validated",
        "debatable": "🤷 Debatable",
    }

    # If reaction is something unexpected, skip
    if reaction_key not in reaction_labels:
        return

    recipient, feed_id = _recipient_for_reaction(instance)
    if not recipient or recipient_id_eq(recipient, instance.user_id):
        return

    # ---------- HERE IS THE PART YOU WERE ASKING "WHERE" ----------
    # Title appears as: "reacted 👍 Like to your post" or "reacted 🤔 Intriguing to your comment"
    is_comment = instance.content_type == ContentType.objects.get_for_model(Comment)
    label = reaction_labels[reaction_key]

    if is_comment:
        title = f"reacted {label} to your comment"
    else:
        title = f"reacted {label} to your post"

    # You can later swap this to post title if needed
    description = f"Post #{feed_id}" if feed_id is not None else ""

    Notification.objects.create(
        recipient=recipient,
        actor=instance.user,
        kind="reaction",
        title=title,
        description=description,
        data={
            # IMPORTANT: store actual reaction type, not hard-coded "like"
            "reaction": reaction_key,
            "content_type_id": instance.content_type_id,
            "object_id": instance.object_id,
            **({"feed_item_id": feed_id} if feed_id else {}),
        },
    )



def _recipient_for_comment(obj: Comment):
    """
    New top-level comment on a FeedItem -> notify post owner.
    Reply to a comment -> notify parent comment author.
    """
    # If this is a reply, notify parent comment author
    if obj.parent_id:
        try:
            parent = Comment.objects.select_related("user").only("user_id", "id").get(id=obj.parent_id)
            return parent.user, None, True  # (recipient, feed_id, is_reply)
        except Comment.DoesNotExist:
            return None, None, False

    # Otherwise, top-level on a FeedItem
    if obj.content_type == ContentType.objects.get_for_model(FeedItem):
        try:
            feed = FeedItem.objects.select_related("actor").only("id", "actor_id").get(id=obj.object_id)
            return feed.actor, feed.id, False
        except FeedItem.DoesNotExist:
            return None, None, False

    return None, None, False


@receiver(post_save, sender=Comment)
def notify_on_comment(sender, instance: Comment, created, **kwargs):
    if not created:
        return

    recipient, feed_id, is_reply = _recipient_for_comment(instance)
    if not recipient or recipient_id_eq(recipient, instance.user_id):
        return

    title = "replied to your comment" if is_reply else "commented on your post"
    description = f"Post #{feed_id}" if feed_id is not None else ""  # ✅ never None

    Notification.objects.create(
        recipient=recipient,
        actor=instance.user,
        kind="comment",
        title=title,
        description=description,
        data={
            "comment_id": instance.id,
            "content_type_id": instance.content_type_id,
            "object_id": instance.object_id,
            **({"feed_item_id": feed_id} if feed_id else {}),
        },
    )


def recipient_id_eq(user_obj, user_id):
    try:
        return int(getattr(user_obj, "id", 0)) == int(user_id)
    except Exception:
        return False
