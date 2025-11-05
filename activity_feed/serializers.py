from rest_framework import serializers
from .models import FeedItem
from groups.models import Group
from django.apps import apps
from django.contrib.contenttypes.models import ContentType

class FeedItemSerializer(serializers.ModelSerializer):
    actor_name = serializers.SerializerMethodField()
    actor_username = serializers.SerializerMethodField()
    group_id = serializers.IntegerField(source="group.id", read_only=True)  
    community_name = serializers.SerializerMethodField()
    community_cover_url = serializers.SerializerMethodField()

    class Meta:
        model = FeedItem
        fields = [
            "id", "community_id","community_name", "community_cover_url", "event_id",
            "actor_id", "actor_name", "actor_username",
            "verb", "target_content_type_id", "target_object_id",
            "metadata", "created_at","group_id",
        ]
        
    def get_community_name(self, obj):
        cid = getattr(obj, "community_id", None)
        if not cid:
            return None
        names = (self.context or {}).get("community_names") or {}
        try:
            return names.get(int(cid))
        except Exception:
            return None

    def get_community_cover_url(self, obj):
        cid = getattr(obj, "community_id", None)
        if not cid:
            return None
        covers = (self.context or {}).get("community_covers") or {}
        try:
            return covers.get(int(cid))
        except Exception:
            return None

    def get_actor_name(self, obj):
        u = getattr(obj, "actor", None)
        if not u:
            return None

        # try common fields in a sensible order
        # 1) Django full name
        try:
            full = u.get_full_name()
            if full:
                return full
        except Exception:
            pass

        # 2) custom fields that projects often use
        for attr in ("name", "display_name"):
            val = getattr(u, attr, None)
            if val:
                return val

        # 3) first + last
        first = getattr(u, "first_name", "") or ""
        last = getattr(u, "last_name", "") or ""
        fl = f"{first} {last}".strip()
        if fl:
            return fl

        # 4) fall back to username, then "User #id"
        return getattr(u, "username", None) or f"User #{getattr(u, 'pk', obj.actor_id)}"

    def get_actor_username(self, obj):
        u = getattr(obj, "actor", None)
        return getattr(u, "username", None) if u else None

    def to_representation(self, instance):
        data = super().to_representation(instance)
        m = dict(data.get("metadata") or {})
        
        # Ensure group_id exists in metadata for older frontends
        if not m.get("group_id") and getattr(instance, "group_id", None):
            m["group_id"] = instance.group_id

        # ---- group name / cover (your existing code) ----
        gid = m.get("group_id")
        if gid:
            try:
                gid_int = int(gid)
            except Exception:
                gid_int = None
            names  = (self.context or {}).get("group_names")  or {}
            covers = (self.context or {}).get("group_covers") or {}
            m["group_name"]      = names.get(gid_int)
            m["group_cover_url"] = covers.get(gid_int)

        # ---- ensure polls include ids + counts (and poll_id/group_id) ----
        try:
            if (m.get("type") or "").lower() == "poll":
                GroupPoll = apps.get_model("groups", "GroupPoll")
                GroupPollOption = apps.get_model("groups", "GroupPollOption")
                ct_poll = ContentType.objects.get_for_model(GroupPoll)

                poll = None
                if instance.target_content_type_id == ct_poll.id:
                    poll = GroupPoll.objects.get(pk=instance.target_object_id)
                elif m.get("poll_id"):
                    poll = GroupPoll.objects.get(pk=m["poll_id"])

                if poll:
                    m.setdefault("poll_id",  poll.id)
                    m.setdefault("group_id", getattr(poll, "group_id", None))
                    # options as objects with ids + vote counts
                    try:
                        opts_qs = poll.options.order_by("index")
                    except Exception:
                        opts_qs = poll.options.all()
                    m["options"] = [
                        {
                            "id": o.id,
                            "text": getattr(o, "text", None) or getattr(o, "label", None) or str(o),
                            "vote_count": getattr(o, "votes", None).count() if hasattr(o, "votes") else 0,
                        }
                        for o in opts_qs
                    ]
                    # is_closed if you have such a field
                    m["is_closed"] = bool(getattr(poll, "is_closed", False))

                    # which options THIS user has voted for (nice UX for disabling buttons)
                    req = self.context.get("request") if self.context else None
                    if req and getattr(req, "user", None) and req.user.is_authenticated:
                        m["user_votes"] = list(
                            poll.votes.filter(user_id=req.user.id).values_list("option_id", flat=True)
                        )
        except Exception:
            # never break the feed on metadata enrichment
            pass

        data["metadata"] = m
        return data
    
