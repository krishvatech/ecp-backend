# Our Team runbook: deploy, copy the originals, import (`team_media_transfer`, `import_team_page`)

Imports the approved WordPress Our Team content (`cms/team_page_content/team.json`: 63 faculty,
24 staff, 7 programmes, the page texts) into an environment and publishes `/our-team/`.
Same safety model as the About page (docs/about-page-import-runbook.md): read-only preview,
confirmation token, verified backup, one transaction, idempotent reruns.

## Order (avoids 404s and 500s)

1. **Backend** (ecp-backend): deploy the code with the Team models. The cms migration that creates
   `cms_programme`, `cms_teammember`, `cms_teammember_programmes` and `cms_teampage` runs in the
   normal deployment (it only creates tables). `/our-team/` on the API is a 404 until step 3.
2. **Originals** to the bucket: `team_media_transfer` (below), after approval.
3. **Import** on the server: `import_team_page --dry-run --publish`, review, `--apply`.
4. **Frontend** (Amplify): set `NEXT_PUBLIC_OUR_TEAM_ROUTE=enabled` for that environment and
   rebuild. Until then the header, mobile menu and footer "Our Team" links point to
   imaa-institute.org/our-team/ (src/lib/ourTeamRoute.js), so no build links to a 404. The
   `/our-team` route itself is a normal 404 until step 3.

Why migrations do not import content: migrations run automatically everywhere; content must be
reviewed against each environment's state, needs a backup, and the image originals live in the
bucket, not in Git.

## Image binaries are not in Git

`cms/team_page_content/images/` (98 files, ~9.6 MB) stays out of Git and out of the Docker
image. `import_team_page` never reads it: it downloads each original it needs from storage at
`original_images/<file name>`, checks SHA-256 and dimensions against team.json and takes the
Wagtail file hash and size from those bytes. Only `populate_team_page` (local databases only)
and `team_media_transfer` (run where the files are) use the local files.

## Step 2 — copy the missing originals (needs approval)

On a machine that has `cms/team_page_content/images/`, with the target environment's storage
settings (the media bucket):

```bash
python manage.py team_media_transfer --dry-run --manifest team-media.json
```

Inventory on 2026-10-12 against `events-agora-recordings`: 98 originals, **13 present**
(identical: the programme and office images shared with About), **85 missing** (8,991,697 bytes),
**0 conflicts**. A conflict (different content at a key) refuses the whole run; nothing is ever
overwritten. To upload, after review:

```bash
python manage.py team_media_transfer --apply --confirm <token from the dry run>
```

Every PutObject carries the HTTP condition `If-None-Match: *` (added to the signed request; the
pinned boto3 has no `IfNoneMatch` parameter), so S3 refuses to replace an object that appears
meanwhile (412) or is being written concurrently (409); either stops the run, nothing is
overwritten. Every upload is verified (size, MD5). Run the dry run again afterwards: "All originals are present".

## Step 3 — import on the server

Backup first (RDS snapshot, as for About), then:

```bash
docker exec ecp-backend python manage.py import_team_page --dry-run --publish
```

Expected on an empty environment:

```
Page: none at /our-team/ -> a TeamPage 'Our Team' will be created and published
Programmes: 7 to create, 0 existing kept unchanged
People: 87 to create (63 faculty, 24 staff), 0 existing kept unchanged
Images: 98 needed by this run, verified in storage by SHA-256: 13 existing Wagtail images reused,
        85 image records to create, 0 problems; 0 uploads
Confirmation token: team-new-<16 hex>
```

(13 reused: the About import created image records for the shared programme and office images.)

```bash
docker exec ecp-backend python manage.py import_team_page --apply --publish \
    --confirm team-new-<token> --backup-snapshot <rds-snapshot-id>
```

* The token binds the database, site, page, the existing programmes and people, the approved
  content and `--publish`; any change in between refuses the run (preview again).
* Refused before any write: identity conflicts (a slug and a WordPress ID that are different
  records, a programme code under another slug, a second TeamPage), unpublished changes on the
  live page, locks, workflows, schedules, restrictions, missing/different images, invalid links.
* Existing programmes and people are never changed; an existing page only gets its empty fields
  filled. Everything is one transaction.
* Without `--publish` the page is saved as a draft (publish it in Wagtail).

Then generate the image renditions the page uses (98: portraits fill-400x400, programme cards,
office badges), so the first visitor does not wait for ~100 to be created in one request
(~30–60 s on the server) and no photo is silently left out:

```bash
docker exec ecp-backend python manage.py import_team_page --prepare-renditions
```

It adds rendition rows and new S3 objects only (never overwrites), reports any failure, and is
safe to rerun ("0 generated, 98 already existed"). The preview shows how many are still missing.

## Step 4 — verify

```bash
docker exec ecp-backend python manage.py import_team_page --dry-run --publish   # "Already imported"
curl -s "https://<api-host>/api/cms/public/pages/by-path/?path=/our-team/" | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(len(d['faculty']), len(d['staff']), [p['code'] for p in d['programmes']])"
```

Expect `63 24 ['IM&A', 'CPMI', 'M&AP', 'LM&A', 'HRM&A', 'SCDE', 'VALUATION']`, then enable the
frontend route (step 4 of the order) and check /our-team: filters (All 63, IM&A 50, CPMI 6,
M&AP 3, LM&A 19, HRM&A 14, SCDE 4, VALUATION 1), photos, Bio and LinkedIn links.

## Editing in Wagtail

* /cms/ is limited to the `platform_admin` group (users.middleware). Editors there also need the
  "Team member" and "Programme" snippet permissions and page permissions for the Our Team page.
* People and programmes are snippets: **saving a person changes the public page immediately**
  (there is no draft step for people; "Public" unticked hides the person). Page texts, buttons,
  sections and SEO fields are on the page and follow the normal draft/publish workflow.
* LinkedIn must be an https:// address on linkedin.com; profile links must be safe URLs
  (validated on save; the public API also drops anything unsafe).

## Rollback

* A failed `--apply` changes nothing.
* Hide the page: unpublish /our-team/ in Wagtail (the API answers 404; set
  `NEXT_PUBLIC_OUR_TEAM_ROUTE=disabled` and rebuild the frontend so links go back to WordPress).
* Undo page text changes: page history in Wagtail.
* Remove imported people: delete the snippets in Wagtail. Do **not** delete the image records:
  deleting a Wagtail image deletes its original in the bucket.
* Last resort: restore the RDS snapshot.
