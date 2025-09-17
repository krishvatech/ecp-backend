"""Activity feed app package

This app stores and exposes a simple feed of recent actions taken on
the platform.  Feed items are created asynchronously from other
apps via Celery tasks (see ``activity_feed.tasks``).  Each feed
item references its actor and target via Django’s generic
relationships and may contain arbitrary metadata for richer
presentation in the client.
"""

default_app_config = "activity_feed.apps.ActivityFeedConfig"
