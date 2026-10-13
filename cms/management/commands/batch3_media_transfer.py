"""Copy the Testimonials and Contact Us original images to the media bucket. Dry run unless --apply.

    python manage.py batch3_media_transfer [--images-dir ~/imaa-batch3-media] [--manifest batch3-media.json]
    python manage.py batch3_media_transfer --apply --confirm <token>

The same command as team_media_transfer (inventory by SHA-256 and dimensions, no overwrites:
``If-None-Match: *`` on every PutObject, 412/409 stop the run, token-confirmed uploads, nothing
deleted), for the originals listed in cms/testimonials_content/testimonials.json and
cms/contact_page_content/contact.json. The binaries are not in Git: --images-dir holds them in
``testimonials/`` and ``contact/`` sub-directories (default ~/imaa-batch3-media). Originals that the
About import already put in the bucket are reported as present and never uploaded again.
"""

import hashlib
from pathlib import Path

from django.core.management.base import CommandError

from cms.contact_page_content import ContactContentError, load_contact_content
from cms.management.commands.team_media_transfer import Command as TeamMediaTransfer
from cms.testimonials_content import TestimonialsContentError, load_testimonials_content

DEFAULT_IMAGES_DIR = Path.home() / "imaa-batch3-media"


class Command(TeamMediaTransfer):
    help = "Inventory (and, with --apply, upload) the Testimonials and Contact Us original images in the media storage."
    label = "Testimonials + Contact Us"
    token_prefix = "batch3-media"

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument("--images-dir", default=str(DEFAULT_IMAGES_DIR),
                            help="Directory with testimonials/ and contact/ (the approved image files).")

    def handle(self, *args, **options):
        self.images_root = Path(options["images_dir"]).expanduser()
        return super().handle(*args, **options)

    def load_content(self):
        try:
            testimonials = load_testimonials_content(images_dir=self.images_root / "testimonials")
            contact = load_contact_content(images_dir=self.images_root / "contact")
        except (TestimonialsContentError, ContactContentError) as exc:
            raise CommandError(f"The approved files are not available or do not match the content; nothing was uploaded: {exc}") from exc
        media, seen = [], set()
        for package, data in (("testimonials", testimonials), ("contact", contact)):
            for item in data["media"]:
                if item["file"] in seen:  # the same original listed by both packages (About's shared images)
                    continue
                seen.add(item["file"])
                media.append({**item, "package": package})
        self._dirs = {m["file"]: m["package"] for m in media}
        combined = hashlib.sha256(f"{testimonials['content_sha256']}|{contact['content_sha256']}".encode()).hexdigest()
        return {"content_sha256": combined, "media": media}

    def media_path(self, item):
        return self.images_root / self._dirs[item["file"]] / item["file"]
