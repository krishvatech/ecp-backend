from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Event
from .saleor_sync import sync_event_to_saleor_sync
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
    # A simple way is to check if update_fields only contains saleor_*
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
