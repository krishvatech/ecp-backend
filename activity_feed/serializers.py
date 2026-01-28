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
    actor_avatar = serializers.SerializerMethodField(read_only=True)
    moderation_status = serializers.CharField(read_only=True)
    is_under_review = serializers.SerializerMethodField()
    is_removed = serializers.SerializerMethodField()
    can_engage = serializers.SerializerMethodField()
    is_blurred = serializers.SerializerMethodField()

    class Meta:
        model = FeedItem
        fields = [
            "id", "community_id","community_name", "community_cover_url", "event_id",
            "actor_id", "actor_name", "actor_username","actor_avatar",
            "verb", "target_content_type_id", "target_object_id",
            "metadata", "created_at","group_id",
            "moderation_status", "is_under_review", "is_removed", "can_engage", "is_blurred",
        ]
        
    def _abs_url(self, val):
        """
        Turn a File/ImageField or relative path into an absolute URL.
        If it's already absolute (http/https), return as-is.
        """
        if not val:
            return ""
        # File/ImageField -> .url
        if hasattr(val, "url"):
            val = val.url

        val = str(val)
        # already absolute?
        if val.startswith("http://") or val.startswith("https://"):
            return val

        # ensure leading slash for request.build_absolute_uri
        if not val.startswith("/"):
            val = "/" + val

        req = self.context.get("request")
        return req.build_absolute_uri(val) if req else val

    def _pick_user_photo(self, user):
        """
        Try common fields where your app may store the profile image.
        (You said your DB column is `user_image`.)
        """
        prof = getattr(user, "profile", None)
        candidates = [
            getattr(user, "user_image", None),      # ← your column
            getattr(user, "avatar", None),
            getattr(user, "photo", None),
            getattr(user, "image", None),
            getattr(user, "image_url", None),
            getattr(prof, "user_image", None) if prof else None,
            getattr(prof, "avatar", None) if prof else None,
            getattr(prof, "photo", None) if prof else None,
            getattr(prof, "image", None) if prof else None,
            getattr(prof, "image_url", None) if prof else None,
        ]
        for c in candidates:
            if c:
                return c
        return None

    # ---- field resolvers -------------------------------------------------
    def get_actor_avatar(self, obj):
        """
        Build absolute avatar URL for the actor of this feed item.
        Frontend reads this as `item.actor_avatar`.
        """
        user = getattr(obj, "actor", None)  # FeedItem.actor -> User FK
        if not user:
            return ""
        raw = self._pick_user_photo(user)
        return self._abs_url(raw)
        
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

    def _viewer_is_staff(self):
        req = self.context.get("request")
        user = getattr(req, "user", None) if req else None
        return bool(user and user.is_authenticated and (user.is_staff or user.is_superuser))

    def _viewer_is_author(self, obj):
        req = self.context.get("request")
        user = getattr(req, "user", None) if req else None
        return bool(user and user.is_authenticated and getattr(obj, "actor_id", None) == user.id)

    def get_is_under_review(self, obj):
        return getattr(obj, "moderation_status", None) == getattr(obj, "MOD_STATUS_UNDER_REVIEW", "under_review")

    def get_is_removed(self, obj):
        return getattr(obj, "moderation_status", None) == getattr(obj, "MOD_STATUS_REMOVED", "removed")

    def get_can_engage(self, obj):
        return not self.get_is_under_review(obj) and not self.get_is_removed(obj)

    def get_is_blurred(self, obj):
        if not self.get_is_under_review(obj):
            return False
        # Blur for everyone except author or staff
        return not (self._viewer_is_staff() or self._viewer_is_author(obj))

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
                Poll = apps.get_model("activity_feed", "Poll")
                PollOption = apps.get_model("activity_feed", "PollOption")
                ct_poll = ContentType.objects.get_for_model(Poll)

                poll = None
                if instance.target_content_type_id == ct_poll.id:
                    poll = Poll.objects.get(pk=instance.target_object_id)
                elif m.get("poll_id"):
                    poll = Poll.objects.get(pk=m["poll_id"])

                if poll:
                    m.setdefault("poll_id", poll.id)
                    m.setdefault("group_id", getattr(poll, "group_id", None))
                    m.setdefault("community_id", getattr(poll, "community_id", None))

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
                    m["is_closed"] = bool(getattr(poll, "is_closed", False))

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
    
