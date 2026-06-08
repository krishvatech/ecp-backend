from celery import shared_task
import logging

logger = logging.getLogger(__name__)


@shared_task
def sync_user_to_saleor_async(user_id):
    """
    Async background task to sync a user to Saleor.
    Runs in Celery worker, not in request cycle.
    Only executes if SALEOR_ENABLED is True.
    """
    from django.conf import settings
    from django.contrib.auth import get_user_model
    from .saleor_sync import sync_user_to_saleor_sync

    if not getattr(settings, "SALEOR_ENABLED", False):
        logger.info(f"Saleor integration disabled. Skipping sync_user_to_saleor_async for user {user_id}.")
        return {"skipped": True, "reason": "Saleor integration disabled"}

    User = get_user_model()

    try:
        user = User.objects.get(id=user_id)
        sync_user_to_saleor_sync(user)
        logger.info(f"Successfully synced user {user.email} to Saleor (async)")
    except User.DoesNotExist:
        logger.warning(f"User {user_id} not found for Saleor sync")
    except Exception as e:
        logger.error(f"Failed to sync user {user_id} to Saleor: {e}")
