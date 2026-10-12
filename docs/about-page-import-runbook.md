# About page import runbook (`import_about_page`)

Imports the approved WordPress About content (`cms/about_page_content/`) into the existing
AboutPage of an environment (staging, production) and publishes it. Read-only unless `--apply`.

## Why migrations do not import content

Migrations define the schema and run automatically on every environment (local, test, CI,
staging, production). Page content is data: each environment's AboutPage has its own ID, history
and edits, an import must be reviewed against that environment's current state, and it needs a
backup first. So the schema (AboutPage `intro_image`/`stats`/`sections` and the `Testimonial`
snippet) comes from the cms migration that adds them, and the content comes from this explicit,
reviewed command. Nothing runs it automatically (startup, image build or migrate).

The command checks the database tables and columns, not migration names: the same schema change
is recorded as `0016_aboutpage_intro_image_aboutpage_sections_and_more` on the server and as
`0016_about_page_sections_testimonial` locally. This change adds no migration.

## Prerequisites

1. The backend image contains the package and the command (deployed through the normal GitHub
   Actions workflow). Check on the server:
   ```bash
   docker exec ecp-backend ls cms/about_page_content/images | wc -l        # 41
   docker exec ecp-backend python manage.py help import_about_page | head -3
   ```
2. The AboutPage schema is migrated (the preview stops with "the database schema is not ready"
   otherwise).
3. The 40 original images are in the media bucket at `original_images/<file name>` (already
   uploaded). The command never uploads; it downloads each object and compares its SHA-256.
4. A fresh RDS snapshot of the database (see "Backup").

## 1. Backup

Take a manual snapshot and wait until it is available (operator machine with RDS permissions):

```bash
aws rds create-db-snapshot --db-instance-identifier <db-instance> \
    --db-snapshot-identifier ecp-pre-about-import-$(date +%Y%m%d-%H%M)
aws rds wait db-snapshot-available --db-snapshot-identifier <snapshot-id>
```

`--apply` verifies the snapshot through the RDS API: it must exist, be `available`, be at most
24 hours old (`--backup-max-age-hours`) and be a snapshot of the database the backend uses
(matched by its endpoint; behind RDS Proxy pass `--db-instance <identifier>`). The container's
role needs `rds:DescribeDBSnapshots` and `rds:DescribeDBInstances` (cluster equivalents for
Aurora). If it may not call the RDS API, verify the snapshot yourself and add
`--backup-verified-externally`; the snapshot ID and the verification method are recorded in the
page's history either way.

## 2. Preview (read-only)

```bash
docker exec ecp-backend python manage.py import_about_page --dry-run
```

Runs only SELECT statements and only reads from storage. Expected output on a page that still
holds the earlier IMAA Connect content:

```
Import About page /about/: PREVIEW (read-only, no changes)
  ok: approved content (sha256 fb3948be43f0, 41 media references verified against their SHA-256)
  ok: 30 rich-text values load in the Wagtail editor with their text intact
Storage: S3Storage bucket <bucket> (read only: objects are checked, never written)
Page: AboutPage #7 'About Us' at /…/about/ (live; live revision #…; … revisions)
Fields (page ID, title, slug and earlier revisions are kept):
    hero_title   empty    'About IMAA Connect' -> 'Setting and Advancing the Standards of M&A Globally'
    intro_html   replace  … characters: '<p>…'  REPLACE -> 1760 characters      (only if it holds text)
    stats        empty    0 blocks -> 3 statistics
    sections     empty    0 blocks -> 8 sections
    …
Images: 41 references, 40 distinct files, all verified in storage by SHA-256: … reused, … to create, 0 problems; 0 uploads
Testimonials: 10 approved: … existing reused unchanged, … to create
Confirmation token: about-7-<16 hex>
```

* `empty` fields (empty or the model default, e.g. "About IMAA Connect") are filled.
* `replace` fields hold other content (the earlier Connect texts). Read them; to replace them run
  the preview again with `--replace-existing-content` and use the token printed by that run.
* `blocked:` lines (unpublished changes, locks, workflows, schedules, restrictions, missing or
  different images in storage) stop the import; resolve them in Wagtail / storage, then preview
  again.

## 3. Apply

```bash
docker exec ecp-backend python manage.py import_about_page --apply \
    --page-id 7 --confirm about-7-<token from the preview> \
    [--replace-existing-content] --backup-snapshot <snapshot-id>
```

* `--page-id` and `--confirm` must come from the preview of the same database. The token binds
  the database, site, page, its live and latest revisions, the reviewed current content, the
  approved content and the options; if anything changed since the preview the run is refused.
* Within one transaction it locks the page, repeats every check, creates the missing Wagtail
  image records for the stored originals (no file is uploaded or overwritten) and the missing
  testimonials (existing ones are reused unchanged), saves a revision with the approved content,
  logs it (source, content hash, token, backup) and publishes it. Any error rolls all of it back.
* Kept: page ID, title, slug, position in the tree, earlier revisions, non-empty SEO fields.

Expected: `Created N image records (no files uploaded) and N testimonials; published revision #…
of AboutPage #7. /about/ is live with the approved content.`

## 4. Verify

```bash
docker exec ecp-backend python manage.py import_about_page --dry-run   # "Already imported …"
curl -s "https://<api-host>/api/cms/public/pages/by-path/?path=/about/" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['hero_title'], len(d['stats']), [s['type'] for s in d['sections']])"
```

Expect the WordPress hero title, 3 statistics and 8 sections (accordion, cta_band, card_group,
card_group, testimonials, contact_callout, logo_strip, offices). Then open `/about` on the
staging frontend (images, carousel, testimonials, offices) and the page's history in Wagtail.

The first API request creates the image renditions (new objects under `images/` in the bucket).
That is Wagtail's normal behaviour, not part of the import.

## Re-runs

Re-running is safe: when the page holds the approved content the preview and `--apply` report
"Already imported" and change nothing. Image records and testimonials are matched by content
hash / storage name and WordPress ID / slug, so they are never duplicated.

## Rollback and failure recovery

* A failed `--apply` changes nothing (single transaction). Fix the reported cause and preview
  again (the token changes).
* To undo a published import: Wagtail > Pages > About Us > History, pick the revision before the
  import ("Review this version") and publish it. The image records and testimonials stay; they
  are harmless when unused.
* Do not delete the imported image records in Wagtail: deleting an image deletes its original
  file in the bucket, which other environments' records may point to.
* Last resort: restore the RDS snapshot taken in step 1 (restores the whole database).
