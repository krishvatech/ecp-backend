"""Import the approved Testimonials and Contact Us content. Preview unless --apply.

    python manage.py import_batch3_content                        # preview (same as --dry-run)
    python manage.py import_batch3_content --dry-run [--publish]  # read-only; prints a confirmation token
    python manage.py import_batch3_content --apply --confirm <token> [--publish] --backup-snapshot <rds-snapshot-id>
    python manage.py import_batch3_content --prepare-renditions    # after the import: the pages' image renditions

Sources: cms/testimonials_content/testimonials.json and cms/contact_page_content/contact.json. The
image binaries are NOT needed: originals must already be in storage at ``original_images/<file>``
(``batch3_media_transfer``). Runbook: docs/batch3-public-pages-runbook.md. Nothing runs this
automatically.

* Programmes: matched by slug; new ones created (a code used by another slug is a conflict).
* Testimonials: matched by WordPress ID, then slug (the 10 the About import created are reused).
  Existing testimonials are never overwritten: only the new archive fields that are still empty are
  filled (programmes, published_at). New testimonials are created with all their fields.
* Pages: a TestimonialsPage at /testimonials/ and a ContactPage at /contact-us/ under the IMAA
  Connect HomePage are created when absent; an existing page only gets its empty fields filled.
  --publish publishes them; otherwise they are saved as drafts.
* Images: never uploaded or overwritten; each original this run needs is downloaded once and must
  match the approved SHA-256 and dimensions (as import_team_page).
* Same safety as import_team_page: SELECT-only preview, confirmation token, verified backup on
  remote databases, one transaction, page and conflicts re-checked under a lock, idempotent reruns.
"""

import hashlib
import json
import time
from datetime import datetime

from django.apps import apps
from django.core.exceptions import ValidationError
from django.core.files.storage import storages
from django.core.management.base import CommandError
from django.db import connection, transaction
from wagtail.blocks import StreamValue
from wagtail.images import get_image_model
from wagtail.log_actions import log
from wagtail.models import Page

from cms.about_blocks import RICH_TEXT_FEATURES
from cms.about_page_import import sections_raw, stats_raw
from cms.contact_page_content import ContactContentError, load_contact_content
from cms.editor_checks import draftail_problem
from cms.local_safety import LOCAL_STORAGE_CLASSES, describe_environment
from cms.management.commands.import_about_page import MediaFile, _is_local_database
from cms.management.commands.import_team_page import Command as TeamImport
from cms.public_page_setup import DryRunWriteGuard, editor_line_breaks, media_collection, resolve_site_and_root, rich_text_is_empty
from cms.testimonials_content import TestimonialsContentError, load_testimonials_content

STORAGE_FOLDER = "original_images"
EMPTY, SAME, KEPT = "empty", "same", "kept"
PAGES = {
    # page key -> (model name, slug, text fields, rich fields {model field: package field}, stream fields, image fields)
    "testimonials": ("TestimonialsPage", "testimonials", ("hero_title", "hero_intro"), {}, ("sections",), {}),
    "contact": ("ContactPage", "contact-us", ("hero_title", "hero_intro", "form_heading", "success_message"),
                {"form_intro": "form_intro_html", "consent_text": "consent_html"}, ("stats", "sections"), {"form_image": "form_image"}),
}


class PagePlan:
    def __init__(self, key):
        self.key, self.page, self.current, self.fields, self.seo, self.blockers = key, None, None, {}, {}, []


class Command(TeamImport):
    """Reuses import_team_page's storage checks, page blockers and backup verification (inherited)."""

    help = "Import the approved Testimonials and Contact Us content from storage-verified originals. Preview unless --apply."

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true", help="Read-only preview (the default).")
        mode.add_argument("--apply", action="store_true", help="Import; needs --confirm and, on a remote database, a verified backup.")
        parser.add_argument("--publish", action="store_true", help="Publish both pages (otherwise saved as drafts).")
        parser.add_argument("--confirm", help="With --apply: the confirmation token printed by the preview.")
        parser.add_argument("--prepare-renditions", action="store_true", help="Generate the pages' image renditions (adds only).")
        parser.add_argument("--backup-snapshot", help="With --apply on a remote database: the RDS snapshot taken before the import.")
        parser.add_argument("--db-instance", help="RDS DB instance or cluster identifier, when the host is not its endpoint (RDS Proxy).")
        parser.add_argument("--backup-max-age-hours", type=float, default=24)
        parser.add_argument("--backup-verified-externally", action="store_true")

    # -- entry point ------------------------------------------------------------------------

    def handle(self, *args, **options):
        apply, publish = options["apply"], options["publish"]
        self.stdout.write(self.style.MIGRATE_HEADING(f"Import Testimonials + Contact Us: {'APPLY' if apply else 'PREVIEW (read-only, no changes)'}"))
        self.stdout.write(describe_environment())
        if apply and not options["confirm"]:
            raise CommandError("--apply needs --confirm (the token printed by the preview); nothing was changed.")
        if apply and not _is_local_database() and not options["backup_snapshot"]:
            raise CommandError("--apply on this database needs --backup-snapshot <RDS snapshot ID>; nothing was changed.")
        content, stored = self._load()
        missing = self._schema_missing()
        if missing:
            raise CommandError(f"Refused, nothing was changed: the database schema is not ready: {'; '.join(missing)}.")
        if options["prepare_renditions"] and not apply:
            self._prepare_renditions()
            return

        with connection.execute_wrapper(DryRunWriteGuard()):
            plan = self._plan(content, stored)
        token = self._token(plan, content, publish)
        self._report(plan, token, publish)
        if plan["blockers"]:
            raise CommandError(f"Refused, nothing was changed: {'; '.join(plan['blockers'])}.")
        if self._nothing_to_do(plan, publish):
            self.stdout.write(self.style.SUCCESS("Already imported: the approved Testimonials and Contact content is present; nothing to do."))
            if apply and options["prepare_renditions"]:
                self._prepare_renditions()
            return
        if not apply:
            self.stdout.write("Review the plan above. To import it, run:")
            self.stdout.write(f"  python manage.py import_batch3_content --apply --confirm {token}{' --publish' if publish else ''}"
                              f"{'' if _is_local_database() else ' --backup-snapshot <rds-snapshot-id>'}")
            return
        if options["confirm"] != token:
            raise CommandError("Refused, nothing was changed: the confirmation token does not match this database, the pages, "
                               "the existing records and the content (run the preview again).")
        backup = self._verify_backup(options)
        self.stdout.write(self.style.SUCCESS(self._apply(content, stored, plan, token, publish, backup)))
        if options["prepare_renditions"]:
            self._prepare_renditions()

    # -- content ----------------------------------------------------------------------------

    def _load(self):
        try:
            testimonials = load_testimonials_content()
            contact = load_contact_content()
        except (TestimonialsContentError, ContactContentError) as exc:
            raise CommandError(f"Approved content is invalid, nothing was changed: {exc}") from exc
        stored, problems = {}, []
        for location, html in [(f"quote:{t['slug']}", t["quote_html"]) for t in testimonials["testimonials"]] + [
                ("contact.form_intro_html", contact["page"]["form_intro_html"]), ("contact.consent_html", contact["page"]["consent_html"])]:
            value = editor_line_breaks(html or "")
            problem = draftail_problem(value, RICH_TEXT_FEATURES) if value else None
            if problem:
                problems.append(f"{location}: {problem}")
            stored[location] = value
        if problems:
            raise CommandError(f"Approved rich text is not editor-safe, nothing was changed: {'; '.join(problems[:3])}.")
        public = sum(1 for t in testimonials["testimonials"] if t.get("is_public", True))
        self.stdout.write(f"  ok: testimonials content (sha256 {testimonials['content_sha256'][:12]}): {len(testimonials['testimonials'])} "
                          f"testimonials ({public} public), {len(testimonials['programmes'])} programmes, {len(testimonials['media'])} media")
        self.stdout.write(f"  ok: contact content (sha256 {contact['content_sha256'][:12]}): {len(contact['form']['countries'])} "
                          f"countries, {len(contact['media'])} media; {len(stored)} rich-text values load in the Wagtail editor")
        return {"testimonials": testimonials, "contact": contact}, stored

    @staticmethod
    def _schema_missing():
        missing = []
        for name in ("Programme", "Testimonial", "TestimonialsPage", "ContactPage"):
            try:
                model = apps.get_model("cms", name)
            except LookupError:
                missing.append(f"model cms.{name}")
                continue
            with connection.cursor() as cursor:
                if model._meta.db_table not in connection.introspection.table_names(cursor):
                    missing.append(f"database table {model._meta.db_table}")
        if not missing:
            with connection.cursor() as cursor:
                columns = {c.name for c in connection.introspection.get_table_description(cursor, "cms_testimonial")}
            missing += [f"database column cms_testimonial.{c}" for c in ("published_at", "is_public") if c not in columns]
        return missing

    # -- inspection (read-only) ---------------------------------------------------------------

    def _plan(self, content, stored):
        Programme, Testimonial = apps.get_model("cms", "Programme"), apps.get_model("cms", "Testimonial")
        site, root = resolve_site_and_root()
        plan = {"site": site, "root": root, "blockers": [], "pages": {}, "programmes_new": [], "programmes_kept": [],
                "testimonials_new": [], "testimonials_fill": [], "testimonials_kept": [], "media": {}}
        for key, (model_name, slug, *_rest) in PAGES.items():
            plan["pages"][key] = self._plan_page(plan, key, content, stored)

        tdata = content["testimonials"]
        by_slug, by_code = {p.slug: p for p in Programme.objects.all()}, {p.code: p for p in Programme.objects.all()}
        for programme in tdata["programmes"]:
            if programme["slug"] in by_slug:
                plan["programmes_kept"].append(programme["slug"])
            elif programme["code"] in by_code:
                plan["blockers"].append(f"programme code '{programme['code']}' is used by slug '{by_code[programme['code']].slug}', not '{programme['slug']}'")
            else:
                plan["programmes_new"].append(programme)
        by_wp = {t.wordpress_id: t for t in Testimonial.objects.exclude(wordpress_id=None).prefetch_related("programmes")}
        by_tslug = {t.slug: t for t in Testimonial.objects.prefetch_related("programmes")}
        for item in tdata["testimonials"]:
            wp, sl = by_wp.get(item["wordpress_id"]), by_tslug.get(item["slug"])
            if wp is not None and sl is not None and wp.pk != sl.pk:
                plan["blockers"].append(f"{item['name']}: WordPress ID {item['wordpress_id']} is #{wp.pk} but slug '{item['slug']}' is #{sl.pk}")
            elif wp is None and sl is not None and sl.wordpress_id not in (None, item["wordpress_id"]):
                plan["blockers"].append(f"{item['name']}: slug '{item['slug']}' belongs to WordPress ID {sl.wordpress_id}")
            elif wp or sl:
                existing = wp or sl
                fill = [name for name, empty in (("programmes", not existing.programmes.all() and item["programmes"]),
                                                  ("published_at", existing.published_at is None)) if empty]
                (plan["testimonials_fill"] if fill else plan["testimonials_kept"]).append((item, existing, fill))
            else:
                plan["testimonials_new"].append(item)
                record = Testimonial(name=item["name"], slug=item["slug"], role=item["role"], company=item["company"],
                                     programme=item["programme"], quote=stored[f"quote:{item['slug']}"] or "-",
                                     url=item["url"], wordpress_id=item["wordpress_id"])
                try:
                    record.full_clean(exclude=["photo", "programmes"])
                except ValidationError as exc:
                    plan["blockers"].append(f"{item['name']}: {'; '.join(f'{k}: {v[0]}' for k, v in exc.message_dict.items())}")

        needed = {(("testimonials", t["photo"])) for t in plan["testimonials_new"] if t.get("photo")}
        for key, page_plan in plan["pages"].items():
            if page_plan.page is None or page_plan.fields.get("sections") == EMPTY or page_plan.fields.get("form_image") == EMPTY:
                page = content[key]["page"]
                if key == "contact" and page.get("form_image"):
                    needed.add((key, page["form_image"]))
                for section in page["sections"]:
                    needed |= {(key, x["image"]) for x in section.get("logos", []) + section.get("cards", []) + section.get("offices", []) if x.get("image")}
        self._plan_media(plan, content, needed)
        plan["fingerprint"] = self._fingerprint(plan)
        return plan

    def _plan_page(self, plan, key, content, stored):
        model_name, slug, texts, rich, streams, images = PAGES[key]
        model = apps.get_model("cms", model_name)
        page_plan = PagePlan(key)
        existing = Page.objects.child_of(plan["root"]).filter(slug=slug).first()
        if existing is not None:
            specific = existing.specific
            if not isinstance(specific, model):
                raise CommandError(f"/{slug}/ is {type(specific).__name__} #{specific.pk}, not a {model_name}; nothing was changed.")
            page_plan.page, page_plan.current = specific, specific.get_latest_revision_as_object()
            proxy = _BlockerProxy(page_plan)
            self._page_blockers(proxy)
            page_plan.blockers = proxy.blockers
            approved = content[key]["page"]
            current = page_plan.current
            for name in texts:
                value = getattr(current, name) or ""
                page_plan.fields[name] = SAME if value == approved[name] else EMPTY if not value.strip() else KEPT
            for name, source in rich.items():
                value = getattr(current, name) or ""
                page_plan.fields[name] = SAME if value == stored[f"contact.{source}"] else EMPTY if rich_text_is_empty(value) else KEPT
            for name in streams:
                page_plan.fields[name] = EMPTY if len(getattr(current, name)) == 0 else KEPT
            for name in images:
                page_plan.fields[name] = EMPTY if getattr(current, f"{name}_id") is None else KEPT
            for name in ("seo_title", "search_description"):
                if not (getattr(current, name) or "").strip() and approved.get(name):
                    page_plan.seo[name] = approved[name]
        others = model.objects.exclude(pk=page_plan.page.pk if page_plan.page else None)
        for other in others:
            plan["blockers"].append(f"another {model_name} exists (#{other.pk} at {other.url_path}); only one is allowed")
        plan["blockers"] += [f"{model_name}: {b}" for b in page_plan.blockers]
        return page_plan

    def _plan_media(self, plan, content, needed):
        storage = storages["default"]
        image_model = get_image_model()
        for package, key in sorted(needed):
            item = next(m for m in content[package]["media"] if m["key"] == key)
            entry = MediaFile(sha256=item["sha256"], file=item["file"], keys=[key], width=item["width"], height=item["height"])
            name = f"{STORAGE_FOLDER}/{entry.file}"
            entry.storage_name = name
            original, entry.problem = self._stored_original(storage, name, entry)
            if original is not None:
                entry.sha1, entry.size = original["sha1"], original["size"]
                entry.image = (image_model.objects.filter(file_hash=entry.sha1).order_by("pk").first()
                               or image_model.objects.filter(file=name).order_by("pk").first())
                if entry.image is not None:
                    entry.storage_name = entry.image.file.name
                    entry.problem = self._existing_image_problem(storage, entry)
            if entry.problem:
                plan["blockers"].append(entry.problem)
            plan["media"][(package, key)] = (entry, item)

    @staticmethod
    def _fingerprint(plan):
        Programme, Testimonial = apps.get_model("cms", "Programme"), apps.get_model("cms", "Testimonial")
        state = {
            "pages": {k: None if p.page is None else [p.page.pk, p.page.live, p.page.live_revision_id, p.page.latest_revision_id, p.fields, p.seo]
                      for k, p in plan["pages"].items()},
            "programmes": list(Programme.objects.order_by("pk").values_list("pk", "slug", "code")),
            "testimonials": list(Testimonial.objects.order_by("pk").values_list("pk", "slug", "wordpress_id", "published_at")),
            "images": {f"{k[0]}:{k[1]}": [e.sha256, e.image.pk if e.image else None, e.storage_name] for k, (e, _i) in plan["media"].items()},
        }
        return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()

    @staticmethod
    def _token(plan, content, publish):
        db = connection.settings_dict
        parts = [db.get("NAME") or "", (db.get("HOST") or "").strip(), str(db.get("PORT") or ""), f"site{plan['site'].pk}",
                 content["testimonials"]["content_sha256"], content["contact"]["content_sha256"], plan["fingerprint"],
                 "publish" if publish else "draft"]
        return f"batch3-{hashlib.sha256('|'.join(parts).encode()).hexdigest()[:16]}"

    @staticmethod
    def _nothing_to_do(plan, publish):
        pages_done = all(p.page is not None and not any(s == EMPTY for s in p.fields.values()) and not p.seo
                         and (p.page.live or not publish) for p in plan["pages"].values())
        return pages_done and not plan["programmes_new"] and not plan["testimonials_new"] and not plan["testimonials_fill"]

    # -- writing ----------------------------------------------------------------------------

    def _apply(self, content, stored, planned, token, publish, backup):
        Programme, Testimonial = apps.get_model("cms", "Programme"), apps.get_model("cms", "Testimonial")
        image_model = get_image_model()
        with transaction.atomic():
            for page_plan in planned["pages"].values():
                Page.objects.select_for_update().get(pk=(page_plan.page or planned["root"]).pk)
            with connection.execute_wrapper(DryRunWriteGuard()):
                plan = self._plan(content, stored)
            if plan["blockers"]:
                raise CommandError(f"Refused, nothing was changed: {'; '.join(plan['blockers'])}.")
            if self._token(plan, content, publish) != token:
                raise CommandError("The content changed while this command was running; nothing was changed. Run the preview again.")

            images, created_images, collection = {}, 0, None
            for (package, key), (entry, item) in plan["media"].items():
                image = entry.image or next((i for i in images.values() if i.file.name == entry.storage_name), None)
                if image is None:
                    collection = collection or media_collection()
                    image = image_model(title=(item.get("alt") or entry.file.rsplit(".", 1)[0])[:255], collection=collection,
                                        width=entry.width, height=entry.height, file_size=entry.size, file_hash=entry.sha1)
                    image.file.name = entry.storage_name  # the stored original; nothing is uploaded
                    image.save()
                    created_images += 1
                images[(package, key)] = image

            programmes = {p.slug: p for p in Programme.objects.all()}
            for programme in plan["programmes_new"]:
                programmes[programme["slug"]] = Programme.objects.create(code=programme["code"], slug=programme["slug"], sort_order=programme["sort_order"])
            for item in plan["testimonials_new"]:
                record = Testimonial.objects.create(
                    name=item["name"], slug=item["slug"], role=item["role"], company=item["company"], programme=item["programme"],
                    quote=stored[f"quote:{item['slug']}"], photo=images.get(("testimonials", item["photo"])), url=item["url"],
                    wordpress_id=item["wordpress_id"], published_at=datetime.fromisoformat(item["published_at"]),
                    is_public=item.get("is_public", True),
                )
                record.programmes.set([programmes[s] for s in item["programmes"]])
            for item, existing, fill in plan["testimonials_fill"]:
                if "programmes" in fill:
                    existing.programmes.set([programmes[s] for s in item["programmes"]])
                if "published_at" in fill:
                    Testimonial.objects.filter(pk=existing.pk).update(published_at=datetime.fromisoformat(item["published_at"]))

            revisions = []
            for key, page_plan in plan["pages"].items():
                revisions.append(self._write_page(key, page_plan, content, stored, images, plan["root"], token, backup, publish))
        return (f"Created {created_images} image records (no files uploaded), {len(plan['programmes_new'])} programmes, "
                f"{len(plan['testimonials_new'])} testimonials; filled {len(plan['testimonials_fill'])} existing testimonials; "
                f"pages {', '.join(revisions)} {'published' if publish else 'saved as drafts'}.")

    def _write_page(self, key, page_plan, content, stored, images, root, token, backup, publish):
        model_name, slug, texts, rich, streams, image_fields = PAGES[key]
        model = apps.get_model("cms", model_name)
        approved = content[key]["page"]
        if page_plan.page is None:
            page = model(title=approved["title"], slug=slug, live=False)
            root.add_child(instance=page)
            fields = {name: EMPTY for name in texts + tuple(rich) + streams + tuple(image_fields)}
            seo = {"seo_title": approved.get("seo_title", ""), "search_description": approved.get("search_description", "")}
            draft = page
        else:
            fields, seo, draft = page_plan.fields, page_plan.seo, page_plan.page.get_latest_revision_as_object()
        for name in texts:
            if fields[name] == EMPTY:
                setattr(draft, name, approved[name])
        for name, source in rich.items():
            if fields[name] == EMPTY:
                setattr(draft, name, stored[f"contact.{source}"])
        for name, source in image_fields.items():
            if fields[name] == EMPTY and approved.get(source):
                setattr(draft, name, images[(key, approved[source])])
        if "stats" in streams and fields["stats"] == EMPTY:
            draft.stats = StreamValue(draft.stats.stream_block, stats_raw(approved), is_lazy=True)
        if fields["sections"] == EMPTY:
            raw = sections_raw({"sections": approved["sections"], "media": content[key]["media"]}, stored,
                               image_id=lambda k: images[(key, k)].pk if k else None, testimonial_id=lambda s: None)
            draft.sections = StreamValue(draft.sections.stream_block, raw, is_lazy=True)
        for name, value in seo.items():
            setattr(draft, name, value)
        revision = draft.save_revision(log_action=False)
        log(instance=draft, action="wagtail.edit", revision=revision, content_changed=True,
            data={"source": "import_batch3_content", "content_sha256": content[key]["content_sha256"], "confirmation": token, **backup})
        if publish:
            revision.publish(log_action=True)
            if not model.objects.get(pk=draft.pk).live:
                raise CommandError(f"/{slug}/ did not end up live; every change was rolled back.")
        return f"/{slug}/ (revision #{revision.pk})"

    # -- renditions -------------------------------------------------------------------------

    @staticmethod
    def _renditions_needed():
        from cms.about_page_api import SPEC_CARD, SPEC_INTRO, SPEC_LOGO, SPEC_OFFICE, SPEC_PHOTO

        Testimonial = apps.get_model("cms", "Testimonial")
        needed = [(t.photo, SPEC_PHOTO) for t in Testimonial.objects.filter(is_public=True).exclude(photo=None).select_related("photo")]
        for model_name, slug, *_rest in PAGES.values():
            page = apps.get_model("cms", model_name).objects.filter(slug=slug).first()
            if page is None:
                continue
            page = page.get_latest_revision_as_object()
            if getattr(page, "form_image", None):
                needed.append((page.form_image, SPEC_INTRO))
            for block in page.sections:
                specs = {"logo_strip": ("logos", SPEC_LOGO), "card_group": ("cards", SPEC_CARD), "offices": ("offices", SPEC_OFFICE)}
                if block.block_type in specs:
                    field, spec = specs[block.block_type]
                    needed += [(x["image"], spec) for x in block.value[field] if x.get("image")]
        unique = {}
        for image, spec in needed:
            unique.setdefault((image.pk, spec), (image, spec))
        return list(unique.values())

    def _prepare_renditions(self):
        needed = self._renditions_needed()
        if not needed:
            raise CommandError("Nothing to prepare: import the content first.")
        started, created, failed = time.monotonic(), 0, []
        for image, spec in needed:
            existed = image.renditions.filter(filter_spec=spec).exists()
            try:
                image.get_rendition(spec)
            except Exception as exc:
                failed.append(f"image #{image.pk} {image.file.name} {spec}: {type(exc).__name__}: {exc}")
                continue
            created += 0 if existed else 1
        self.stdout.write(f"Renditions: {len(needed)} used by the pages; {created} generated, {len(needed) - created - len(failed)} "
                          f"already existed, {len(failed)} failed ({time.monotonic() - started:.1f}s)")
        if failed:
            raise CommandError("Some renditions could not be generated (those images would be missing): " + "; ".join(failed[:5]))
        self.stdout.write(self.style.SUCCESS("All renditions the Testimonials and Contact pages use exist."))

    # -- output -----------------------------------------------------------------------------

    def _report(self, plan, token, publish):
        storage = storages["default"]
        self.stdout.write(f"Storage: {type(storage).__name__}{' bucket ' + storage.bucket_name if getattr(storage, 'bucket_name', None) else ''}"
                          f"{'' if isinstance(storage, LOCAL_STORAGE_CLASSES) else ' (read only: objects are checked, never written)'}")
        self.stdout.write(f"Site: #{plan['site'].pk} {plan['site'].hostname}; root page #{plan['root'].pk} '{plan['root'].title}'")
        for key, page_plan in plan["pages"].items():
            model_name, slug, *_rest = PAGES[key]
            if page_plan.page is None:
                self.stdout.write(f"Page /{slug}/: none -> a {model_name} will be created{' and published' if publish else ' as a draft'}")
            else:
                filled = [n for n, s in page_plan.fields.items() if s == EMPTY]
                self.stdout.write(f"Page /{slug}/: {model_name} #{page_plan.page.pk} ({'live' if page_plan.page.live else 'draft'}); "
                                  f"fields to fill: {', '.join(filled) or 'none'}; kept: {sum(1 for s in page_plan.fields.values() if s == KEPT)}")
        for reason in plan["blockers"]:
            self.stdout.write(self.style.ERROR(f"  blocked: {reason}"))
        self.stdout.write(f"Programmes: {len(plan['programmes_new'])} to create, {len(plan['programmes_kept'])} existing kept")
        new_public = sum(1 for t in plan["testimonials_new"] if t.get("is_public", True))
        self.stdout.write(f"Testimonials: {len(plan['testimonials_new'])} to create ({new_public} public, "
                          f"{len(plan['testimonials_new']) - new_public} hidden: no quote on WordPress), "
                          f"{len(plan['testimonials_fill'])} existing to complete (programmes/date only), "
                          f"{len(plan['testimonials_kept'])} existing kept unchanged")
        reuse = sum(1 for e, _i in plan["media"].values() if e.image is not None)
        problems = sum(1 for e, _i in plan["media"].values() if e.problem)
        self.stdout.write(f"Images: {len(plan['media'])} needed, verified in storage by SHA-256: {reuse} existing Wagtail images reused, "
                          f"{len(plan['media']) - reuse - problems} image records to create, {problems} problems; 0 uploads")
        self.stdout.write(f"Confirmation token: {token}")


class _BlockerProxy:
    """Adapter so import_team_page's page checks can be reused (they read .page/.current, append to .blockers)."""

    def __init__(self, page_plan):
        self.page, self.current, self.blockers = page_plan.page, page_plan.current, []
