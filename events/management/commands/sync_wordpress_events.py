"""
Management command to import/sync events from WordPress The Events Calendar.

Usage:
    python manage.py sync_wordpress_events                      # Import all published events
    python manage.py sync_wordpress_events --wp-id 2117         # Sync single WP event by ID
    python manage.py sync_wordpress_events --page 1 --per-page 50  # Paginated import
    python manage.py sync_wordpress_events --force              # Force re-sync even if recently synced
"""
import logging
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from events.wordpress_event_api import get_wordpress_event_client
from events.wordpress_event_sync import get_wordpress_event_sync_service

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Sync events from WordPress The Events Calendar plugin"

    def add_arguments(self, parser):
        parser.add_argument(
            '--wp-id',
            type=int,
            help='Sync a single WordPress event by ID'
        )
        parser.add_argument(
            '--page',
            type=int,
            default=1,
            help='Start page for pagination (default: 1)'
        )
        parser.add_argument(
            '--per-page',
            type=int,
            default=50,
            help='Number of events per page (default: 50, max: 100)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force re-sync even if recently synced'
        )

    def handle(self, *args, **options):
        # Check if WordPress sync is enabled
        if not getattr(settings, "WP_SYNC_ENABLED", True):
            raise CommandError("WordPress event sync is disabled (WP_SYNC_ENABLED=False)")

        # Check if required settings are configured
        if not settings.WP_IMAA_API_URL:
            raise CommandError("WP_IMAA_API_URL is not configured")

        if not getattr(settings, "WP_SYNC_SERVICE_ACCOUNT_ID"):
            raise CommandError("WP_SYNC_SERVICE_ACCOUNT_ID is not configured")

        if not getattr(settings, "WP_SYNC_DEFAULT_COMMUNITY_ID"):
            raise CommandError("WP_SYNC_DEFAULT_COMMUNITY_ID is not configured")

        try:
            wp_id = options.get('wp_id')
            page = options.get('page', 1)
            per_page = options.get('per_page', 50)
            force = options.get('force', False)

            # Validate per_page
            if per_page > 100:
                per_page = 100
                self.stdout.write(self.style.WARNING(f"per_page limited to 100"))

            client = get_wordpress_event_client()
            service = get_wordpress_event_sync_service()

            if wp_id:
                # Sync single event
                self.stdout.write(f"Syncing WordPress event {wp_id}...")
                wp_event = client.get_event(wp_id)
                if not wp_event:
                    raise CommandError(f"WordPress event {wp_id} not found")

                event, action = service.sync_from_wp_data(wp_event)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✓ Synced WP event {wp_id}: {action} (Django event ID: {event.id})"
                    )
                )
            else:
                # Bulk import with pagination
                self.stdout.write(
                    f"Importing WordPress events (page {page}, {per_page} per page)..."
                )

                synced = 0
                created = 0
                updated = 0
                cancelled = 0
                skipped = 0
                errors = 0

                current_page = page
                while True:
                    self.stdout.write(f"  Fetching page {current_page}...")

                    response = client.list_events(
                        page=current_page,
                        per_page=per_page,
                        status="publish"
                    )

                    if not response:
                        self.stdout.write(self.style.WARNING("No response from WordPress API"))
                        break

                    events = response.get("events", [])
                    total_pages = response.get("total_pages", 1)

                    if not events:
                        self.stdout.write("No more events to import")
                        break

                    for wp_event in events:
                        wp_id_item = wp_event.get("id")
                        try:
                            event, action = service.sync_from_wp_data(wp_event)

                            if action == "created":
                                created += 1
                                synced += 1
                                self.stdout.write(f"    ✓ CREATED WP {wp_id_item} → Event {event.id}")
                            elif action == "updated":
                                updated += 1
                                synced += 1
                                self.stdout.write(f"    ✓ UPDATED WP {wp_id_item} → Event {event.id}")
                            elif action == "cancelled":
                                cancelled += 1
                                synced += 1
                                self.stdout.write(f"    ✓ CANCELLED WP {wp_id_item} → Event {event.id}")
                            elif action == "skipped":
                                skipped += 1
                                self.stdout.write(f"    - SKIPPED WP {wp_id_item} ({action})")
                            else:
                                errors += 1
                                self.stdout.write(
                                    self.style.ERROR(f"    ✗ ERROR WP {wp_id_item}: {action}")
                                )
                        except Exception as e:
                            errors += 1
                            self.stdout.write(
                                self.style.ERROR(f"    ✗ EXCEPTION WP {wp_id_item}: {str(e)}")
                            )

                    # Check if there are more pages
                    if current_page >= total_pages:
                        break

                    current_page += 1

                # Summary
                self.stdout.write("")
                self.stdout.write(self.style.SUCCESS("=" * 60))
                self.stdout.write(self.style.SUCCESS("IMPORT SUMMARY"))
                self.stdout.write(self.style.SUCCESS("=" * 60))
                self.stdout.write(f"  Total synced:   {synced}")
                self.stdout.write(self.style.SUCCESS(f"  Created:        {created}"))
                self.stdout.write(self.style.SUCCESS(f"  Updated:        {updated}"))
                self.stdout.write(self.style.SUCCESS(f"  Cancelled:      {cancelled}"))
                self.stdout.write(f"  Skipped:        {skipped}")
                if errors > 0:
                    self.stdout.write(self.style.ERROR(f"  Errors:         {errors}"))
                self.stdout.write(self.style.SUCCESS("=" * 60))

        except Exception as e:
            logger.exception(f"Error during WordPress event sync: {e}")
            raise CommandError(str(e))
