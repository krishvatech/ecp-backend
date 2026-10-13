"""Copy the Our Team original images to the media bucket, for import_team_page. Dry run unless --apply.

    python manage.py team_media_transfer [--manifest team-media.json]     # inventory + manifest, read-only
    python manage.py team_media_transfer --apply --confirm <token>        # upload the missing originals

Run where the approved image files are (cms/team_page_content/images/, not in Git) with the
settings of the target environment's storage (the S3 bucket). Runbook: docs/team-page-import-runbook.md.

* Inventory: every approved original (team.json; the local file must match its SHA-256 and its
  dimensions) is looked
  up at ``original_images/<file name>`` in the configured storage and downloaded when present:
  ``present`` (same SHA-256: reused, nothing to do), ``missing`` (to upload) or ``conflict``
  (different content: never overwritten; the whole run is refused).
* The dry run never writes; it prints (and with --manifest saves) the manifest and a token.
* --apply uploads only the ``missing`` objects, only with the token of a dry run whose inventory is
  unchanged, and only to S3: each PutObject carries the HTTP condition ``If-None-Match: *``, so S3
  itself refuses to create the object when one already exists at the key (412) or a concurrent
  write to it is in progress (409) — atomic, no check-then-write window. The pinned botocore has no
  ``IfNoneMatch`` parameter, so the header is added to the PutObject request before it is signed
  (``_if_none_match``). A 412/409 stops the run without overwriting anything. CacheControl as the
  project's storage settings; each upload is verified afterwards (size and MD5 ETag). Nothing is
  deleted or renamed.
* Local development (cms.local_safety: PostgreSQL on this machine, local file storage, not the
  production settings; with the dev settings run with ``AWS_BUCKET_NAME=``): --apply copies the
  missing originals into the local media folder instead, each created exclusively (``O_EXCL``, the
  local equivalent of ``If-None-Match: *``) and verified by SHA-256 afterwards. Any other storage
  that is not S3 is refused.
"""

import hashlib
import json
import mimetypes
import os
from contextlib import contextmanager
from io import BytesIO

from botocore.exceptions import ClientError

from django.conf import settings
from django.core.files.storage import storages
from django.core.management.base import BaseCommand, CommandError
from willow.image import Image as WillowImage

from cms.local_safety import LOCAL_STORAGE_CLASSES, local_environment_problems
from cms.team_page_content import IMAGES_DIR, TeamContentError, load_team_content

STORAGE_FOLDER = "original_images"
PRESENT, MISSING, CONFLICT = "present", "missing", "conflict"
CONDITION_FAILED = (409, 412)  # ConditionalRequestConflict, PreconditionFailed
mimetypes.add_type("image/webp", ".webp")


@contextmanager
def _if_none_match(client):
    """While active, every PutObject sent by ``client`` carries ``If-None-Match: *``.

    Added on ``before-sign`` so the header is part of the SigV4 signature; registered only for the
    duration of one upload and always removed afterwards (other uses of the client are unaffected).
    """
    def add_condition(request, **kwargs):
        request.headers["If-None-Match"] = "*"

    event, unique_id = "before-sign.s3.PutObject", "cms-team-media-transfer-if-none-match"
    client.meta.events.register(event, add_condition, unique_id=unique_id)
    try:
        yield
    finally:
        client.meta.events.unregister(event, unique_id=unique_id)


class Command(BaseCommand):
    help = "Inventory (and, with --apply, upload) the Our Team original images in the media storage."
    label = "Our Team"
    token_prefix = "team-media"

    # Extension points (batch3_media_transfer reuses this command for other content packages).
    def load_content(self):
        try:
            return load_team_content()  # the local files must be the approved ones
        except TeamContentError as exc:
            raise CommandError(f"The approved files are not available or do not match team.json; nothing was uploaded: {exc}") from exc

    def media_path(self, item):
        return IMAGES_DIR / item["file"]

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Inventory only (the default).")
        mode.add_argument("--apply", action="store_true", help="Upload the missing originals; needs --confirm.")
        parser.add_argument("--confirm", help="With --apply: the token printed by the dry run.")
        parser.add_argument("--manifest", help="Write the manifest (JSON) to this path.")

    def handle(self, *args, **options):
        apply = options["apply"]
        if apply and not options["confirm"]:
            raise CommandError("--apply needs --confirm (the token printed by the dry run); nothing was uploaded.")
        storage = storages["default"]
        bucket = getattr(storage, "bucket_name", None)
        region = getattr(storage, "region_name", None) or getattr(settings, "AWS_S3_REGION_NAME", None)
        self.stdout.write(self.style.MIGRATE_HEADING(f"{self.label} originals: {'UPLOAD' if apply else 'DRY RUN (read-only)'}"))
        self.stdout.write(f"Storage: {type(storage).__name__}{' bucket ' + bucket if bucket else ''}{' region ' + region if region and bucket else ''}"
                          f"{' prefix ' + repr(storage.location) if getattr(storage, 'location', '') else ''}")
        content = self.load_content()

        manifest = [self._inventory(storage, item) for item in content["media"]]
        token = self._token(manifest, f"{bucket}@{region}" if bucket else None, content)
        counts = {state: sum(1 for e in manifest if e["status"] == state) for state in (PRESENT, MISSING, CONFLICT)}
        for entry in manifest:
            if entry["status"] != PRESENT:
                self.stdout.write(f"  {entry['status']:<8} {entry['key']}  ({entry['bytes']} bytes)")
        self.stdout.write(f"{len(manifest)} originals: {counts[PRESENT]} already present (identical), "
                          f"{counts[MISSING]} missing (to upload), {counts[CONFLICT]} conflicts")
        if options["manifest"]:
            with open(options["manifest"], "w") as fh:
                json.dump({"bucket": bucket, "content_sha256": content["content_sha256"], "token": token, "objects": manifest}, fh, indent=1)
            self.stdout.write(f"Manifest written to {options['manifest']}")
        self.stdout.write(f"Confirmation token: {token}")
        if counts[CONFLICT]:
            raise CommandError("Refused: objects with different content exist at the target keys; nothing was uploaded.")
        if not apply:
            if counts[MISSING]:
                self.stdout.write(f"Review the manifest. To upload the {counts[MISSING]} missing originals: "
                                  f"python manage.py {self.__module__.rsplit('.', 1)[-1]} --apply --confirm {token}")
            else:
                self.stdout.write(self.style.SUCCESS("All originals are present; nothing to upload."))
            return
        if options["confirm"] != token:
            raise CommandError("Refused: the token does not match this storage and inventory (run the dry run again); nothing was uploaded.")
        local = isinstance(storage, LOCAL_STORAGE_CLASSES) and hasattr(storage, "path")
        if local:
            problems = local_environment_problems()
            if problems:
                raise CommandError(f"Refused: not a local development environment ({'; '.join(problems)}); nothing was copied.")
        elif not hasattr(storage, "connection") or not bucket:
            raise CommandError("Refused: uploads are only supported to S3 storage or local development media; nothing was uploaded.")
        uploaded = 0
        for entry in manifest:
            if entry["status"] == MISSING:
                (self._store_local if local else self._upload)(storage, entry)
                uploaded += 1
                self.stdout.write(f"  {'copied' if local else 'uploaded'} + verified  {entry['key']}")
        self.stdout.write(self.style.SUCCESS(f"Uploaded {uploaded} originals; {counts[PRESENT]} were already present."))

    def _inventory(self, storage, item):
        data = self.media_path(item).read_bytes()
        size = WillowImage.open(BytesIO(data)).get_size()
        if size != (item["width"], item["height"]):
            raise CommandError(f"{item['file']} is {size[0]}x{size[1]}, the approved content says {item['width']}x{item['height']}; nothing was uploaded.")
        key = f"{STORAGE_FOLDER}/{item['file']}"
        entry = {"key": key, "file": item["file"], "sha256": item["sha256"], "bytes": len(data),
                 "md5": hashlib.md5(data).hexdigest()}
        if not storage.exists(key):
            entry["status"] = MISSING
        else:
            with storage.open(key, "rb") as fh:
                entry["status"] = PRESENT if hashlib.sha256(fh.read()).hexdigest() == item["sha256"] else CONFLICT
        return entry

    def _token(self, manifest, bucket, content):
        state = json.dumps([bucket, content["content_sha256"], [(e["key"], e["sha256"], e["status"]) for e in manifest]])
        return f"{self.token_prefix}-{hashlib.sha256(state.encode()).hexdigest()[:16]}"

    def _store_local(self, storage, entry):
        """Local development media: create the file exclusively (never overwrite) and verify it."""
        data = self.media_path(entry).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise CommandError(f"{entry['file']} changed since the inventory; stopped.")
        target = storage.path(entry["key"])
        os.makedirs(os.path.dirname(target), exist_ok=True)
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError as exc:
            raise CommandError(f"{entry['key']}: a file appeared at this path; it was not overwritten. Stopped.") from exc
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        with storage.open(entry["key"], "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != entry["sha256"]:
                raise CommandError(f"Verification failed for {entry['key']} after copying; stopped.")

    def _upload(self, storage, entry):
        client = storage.connection.meta.client
        cache_control = (getattr(settings, "AWS_S3_OBJECT_PARAMETERS", {}) or {}).get("CacheControl", "max-age=86400")
        data = self.media_path(entry).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise CommandError(f"{entry['file']} changed since the inventory; stopped.")
        try:
            with _if_none_match(client):
                client.put_object(Bucket=storage.bucket_name, Key=entry["key"], Body=data, CacheControl=cache_control,
                                  ContentType=mimetypes.guess_type(entry["key"])[0] or "application/octet-stream")
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            code = exc.response.get("Error", {}).get("Code", "")
            if status in CONDITION_FAILED or code in ("PreconditionFailed", "ConditionalRequestConflict"):
                raise CommandError(
                    f"{entry['key']}: S3 refused the upload ({status} {code}): an object exists or is being written at this "
                    "key; it was not overwritten. Stopped; run the dry run again to review the inventory."
                ) from exc
            raise
        head = client.head_object(Bucket=storage.bucket_name, Key=entry["key"])
        if head["ContentLength"] != entry["bytes"] or head["ETag"].strip('"') != entry["md5"]:
            raise CommandError(f"Verification failed for {entry['key']} after upload; stopped.")
