from celery import shared_task
from django.utils import timezone
import logging

logger = logging.getLogger('events')

@shared_task
def example_cleanup_task() -> str:
    """Return a string with the current timestamp to verify Celery runs."""
    return f"Cleanup ran at {timezone.now().isoformat()}"


@shared_task(bind=True, max_retries=5)
def check_recording_task(self, event_id):
    """
    Check if recording is available in S3 for an ended event.
    Called 2-5 minutes after meeting ends to allow Agora processing time.
    """
    from .models import Event
    import boto3
    from botocore.config import Config
    import os
    
    try:
        event = Event.objects.get(id=event_id)
        
        if event.status != 'ended':
            logger.info(f"Event {event_id} is not ended, skipping recording check")
            return
        
        if event.recording_url:
            logger.info(f"Event {event_id} already has recording URL: {event.recording_url}")
            return
        
        # S3 Configuration
        bucket = os.getenv('AWS_BUCKET_NAME', 'events-agora-recordings')
        prefix = f"recordings/event-{event.id}/"
        
        s3_client = boto3.client(
            's3',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name='eu-central-1',
            config=Config(signature_version='s3v4')
        )
        
        response = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix)
        
        if 'Contents' not in response:
            logger.warning(f"No recording files found for event {event_id} yet, will retry")
            # Retry after 3 minutes
            raise self.retry(countdown=180, exc=Exception("Recording not ready"))
        
        # Find MP4 file
        mp4_file = None
        for obj in response['Contents']:
            if obj['Key'].endswith('.mp4'):
                mp4_file = obj['Key']
                break
        
        if mp4_file:
            event.recording_url = mp4_file
            event.save(update_fields=['recording_url', 'updated_at'])
            logger.info(f"✅ Recording found and saved for event {event_id}: {mp4_file}")
        else:
            logger.warning(f"MP4 file not found for event {event_id}, retrying...")
            raise self.retry(countdown=180, exc=Exception("MP4 not found"))
            
    except Event.DoesNotExist:
        logger.error(f"Event {event_id} not found")
    except self.MaxRetriesExceededError:
        logger.error(f"Max retries exceeded for event {event_id} recording check")
    except Exception as e:
        logger.exception(f"Error checking recording for event {event_id}: {e}")
        # Retry on unexpected errors
        try:
            raise self.retry(countdown=180, exc=e)
        except self.MaxRetriesExceededError:
            pass
