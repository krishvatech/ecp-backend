"""
Permissions for the blog APIs.

Blog management is limited to Django superusers (``is_superuser``). Staff
without superuser rights get no management access. The project already has
this rule in ``moderation.permissions.IsSuperuser``, so it is reused here
instead of being copied again.
"""
from moderation.permissions import IsSuperuser

__all__ = ["IsSuperuser"]
