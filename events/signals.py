from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.db import transaction
from .models import Event, EventParticipant
from .saleor_sync import sync_event_to_saleor_sync, delete_event_from_saleor
import threading

@receiver(post_save, sender=Event)
def sync_event_to_saleor_signal(sender, instance, created, **kwargs):
    """
    Trigger sync to Saleor when an Event is saved.
    We run this in a thread to avoid blocking the main save response too long,
    although 'synchronous' was requested, a short thread detach is usually 
    better UX for Admin. But user asked for SYNC logic.
    
    Let's keep it truly synchronous as requested in plan, or lightweight sync.
    Actually, to prevent 'recursion' (save calls sync, sync calls save),
    we must be careful.
    """
    
    # Check if we are saving because of the sync itself
    if getattr(instance, "skip_saleor_sync", False):
        return

    # Check if we are saving because of the sync itself (backwards compat/fallback)
    update_fields = kwargs.get("update_fields")
    if update_fields and ("saleor_product_id" in update_fields or "saleor_variant_id" in update_fields):
        return

    # To avoid blocking the browser for 3-5 seconds while creating products,
    # let's use a standard sync call but inside a transaction on_commit if possible,
    # OR just call it.
    
    # User requested flow: "Create events --> sync to saleor DB".
    # Implementation:
    try:
        sync_event_to_saleor_sync(instance)
    except Exception as e:
        print(f"Error syncing event {instance.id} to Saleor: {e}")


@receiver(post_save, sender=EventParticipant)
def send_event_confirmation_on_create(sender, instance, created, **kwargs):
    """
    Send event confirmation email when a new EventParticipant is created.
    Only sends for staff participants (users with accounts).
    Uses on_commit callback to ensure participant is fully saved before queuing task.
    """
    if not created:
        return  # Only send on creation, not updates

    # Only send to staff participants (users with accounts)
    if instance.participant_type != EventParticipant.PARTICIPANT_TYPE_STAFF:
        return

    if not instance.user or not instance.user.email:
        return

    # Import here to avoid circular imports
    from users.task import send_event_confirmation_task

    # Queue email task AFTER transaction commits (ensures participant is saved)
    def queue_email():
        try:
            send_event_confirmation_task.delay(instance.id)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(
                f"Failed to queue event confirmation email for participant {instance.id}: {e}"
            )

    transaction.on_commit(queue_email)


@receiver(pre_delete, sender=Event)
def delete_event_from_saleor_signal(sender, instance, **kwargs):
    """
    Delete Saleor product when event is permanently deleted.
    Only deletes from Saleor if the event has a saleor_product_id.
    """
    try:
        delete_event_from_saleor(instance)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(
            f"Error deleting event {instance.id} from Saleor: {e}"
        )
