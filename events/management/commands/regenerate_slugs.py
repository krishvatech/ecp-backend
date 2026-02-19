from django.core.management.base import BaseCommand
from django.utils.text import slugify
from events.models import Event


class Command(BaseCommand):
    help = 'Regenerate event slugs to title-year format (e.g., digital-marketing-summit-2026)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be changed without making actual changes',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))
            self.stdout.write('')

        events = Event.objects.all()
        total = events.count()

        if total == 0:
            self.stdout.write(self.style.WARNING('No events found to regenerate slugs'))
            return

        self.stdout.write(f'Processing {total} event(s)...\n')

        updated_count = 0
        skipped_count = 0
        error_count = 0

        for idx, event in enumerate(events, 1):
            old_slug = event.slug

            try:
                # Clear the slug so the save() method regenerates it
                event.slug = ''

                if dry_run:
                    # Simulate the slug generation logic from models.py
                    from django.utils import timezone
                    year = event.start_time.year if event.start_time else timezone.now().year
                    base_slug = slugify(f"{event.title}-{year}")[:240]
                    new_slug = base_slug
                    suffix = 2

                    # Check for collisions
                    while Event.objects.filter(slug=new_slug).exclude(pk=event.pk).exists():
                        new_slug = f"{base_slug}-{suffix}"
                        suffix += 1

                    # Show preview
                    if old_slug != new_slug:
                        self.stdout.write(
                            f'[{idx}/{total}] {event.title} (ID: {event.id})\n'
                            f'  Old: {old_slug}\n'
                            f'  New: {new_slug}'
                        )
                        updated_count += 1
                    else:
                        skipped_count += 1
                else:
                    # Actually save the event which will regenerate the slug
                    event.save()
                    new_slug = event.slug

                    if old_slug != new_slug:
                        self.stdout.write(
                            f'[{idx}/{total}] ✓ {event.title} (ID: {event.id})\n'
                            f'  {old_slug} → {new_slug}'
                        )
                        updated_count += 1
                    else:
                        skipped_count += 1

            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(
                        f'[{idx}/{total}] ✗ Error processing event ID {event.id}: {str(e)}'
                    )
                )

        # Summary
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write('SUMMARY')
        self.stdout.write('=' * 70)
        self.stdout.write(f'Total events: {total}')
        self.stdout.write(self.style.SUCCESS(f'Updated: {updated_count}'))
        self.stdout.write(f'Skipped (no change needed): {skipped_count}')

        if error_count > 0:
            self.stdout.write(self.style.ERROR(f'Errors: {error_count}'))

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    '\nDRY RUN - No changes were made. '
                    'Run without --dry-run to apply changes.'
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS('\nSlug regeneration completed successfully!')
            )
