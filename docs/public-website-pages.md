# Public website pages: setup, default content and endpoint contract

Five public pages of the client's WordPress site now live in this platform. The Next.js
frontend server-renders each one from a Wagtail `StandardPage`, resolved by its complete path
within one configured Wagtail Site. While a page does not exist in Wagtail at all, the frontend
shows approved default content migrated from imaa-institute.org instead.

Pages are created only when someone runs `manage.py setup_public_pages --apply` (or creates
them by hand in Wagtail). Nothing is created or published on application startup, during a
deployment, by a migration, or by a frontend request.

This covers only the five pages below. Other WordPress pages are not migrated.

## Routes, slugs and default content

| Public URL (no trailing slash) | Wagtail slug | Default content while the page is absent |
|---|---|---|
| `/frequently-asked-questions` | `frequently-asked-questions` | Yes: the WordPress FAQ (19 questions) |
| `/references` | `references` | Yes: the WordPress logo wall (258 logos) and its Contact Us block |
| `/terms-and-conditions` | `terms-and-conditions` | Yes: the WordPress Terms and Conditions |
| `/privacy-policy` | `privacy-policy` | Yes: the WordPress Privacy Policy |
| `/imprint` | `imprint` | Yes: the WordPress Imprint |

Each page must be a **direct child of the Site's root HomePage** (its Wagtail path is
`/<slug>/` relative to the Site). A request with a trailing slash is redirected to the
slash-less URL.

The approved content, its WordPress sources and the wording flagged for review are in
`cms/public_page_content/` (see its README). References keeps its 258 logos as Wagtail images
in a rich-text image format called "Logo (logo wall)"; the website lays them out as a grid. No
schema change was needed.

Not migrated, by design: the FAQ page's "Contact Us" section (a Contact Form 7 form plus an
image and three counters). The client's migration plan schedules contact and enquiry forms as
a separate step, and this platform has no contact submission API yet, so a form would look
usable but could not send anything.

## 1. Check the Wagtail Site root (once per environment)

Wagtail admin → **Settings → Sites**. The public website uses one Site, chosen like this:

1. If `CMS_PUBLIC_SITE_HOSTNAME` is set, the Site with exactly that hostname.
2. Otherwise, if exactly one Site exists, that Site.
3. Otherwise, the single Site marked **Is default site**.

Any other configuration (no Site, several Sites and no default, a hostname that matches zero
or several Sites) makes the public endpoint answer **HTTP 503**, and the setup command stops
with the reason. The request's `Host` header is never used.

The Site's **Root page** must be the ECP **HomePage** ("IMAA Connect"). If it is still Wagtail's
"Welcome to your new Wagtail site!" page, change the Site's root page to the HomePage, or set
`CMS_PUBLIC_SITE_HOSTNAME` to a Site whose root is the HomePage. With any other root:

* `setup_public_pages` stops with an error that names the HomePages it found, and changes nothing;
* the public pages answer 404 and the frontend shows **no** default content, because pages
  published under the real HomePage would be out of reach and must not be hidden behind defaults.

## 2. Create the pages: `manage.py setup_public_pages`

Run from `ecp-backend` with the project's virtualenv active:

```bash
# 1. Preview. Read-only: it refuses any database write. Also the default without --apply.
python manage.py setup_public_pages --dry-run

# 2. Preview what --publish-new would publish.
python manage.py setup_public_pages --dry-run --publish-new

# 3a. Create the missing pages as DRAFTS. Editors review them and publish in Wagtail.
python manage.py setup_public_pages --apply

# 3b. Create the missing pages and PUBLISH those that have approved content.
python manage.py setup_public_pages --apply --publish-new
```

Example (`--dry-run --publish-new` on a database where Privacy Policy was published by hand and
Terms and Conditions is an empty draft):

```text
Public website pages: DRY RUN (no database changes)
--publish-new without --apply: showing what would be published.
Site: #1 localhost:80 (default site)
Root page: #5 HomePage 'IMAA Connect' (slug 'imaa-connect', live)
  /frequently-asked-questions   missing    would create and publish 'Frequently Asked Questions' (approved content, sha256 386e6d0eb743)
  /references                   missing    would create and publish 'References' (approved content, sha256 667eb2dbe539)
      258 bundled images: 0 already in the Wagtail image library, 258 to import into the 'Public website pages' collection
  /terms-and-conditions         exists     would keep
      StandardPage #8 'Terms and Conditions': draft, never published; not public (404); left unchanged
  /privacy-policy               exists     would keep
      StandardPage #7 'Privacy Policy': live; served publicly; left unchanged
  /imprint                      missing    would create and publish 'Imprint' (approved content, sha256 d46b4dc61b19)
Summary: 0 would be created as draft, 3 would be created and published, 2 kept unchanged, 0 skipped.
```

What the command guarantees:

* **Same Site as the public endpoint.** It uses the rules in section 1 and requires the root
  to be a non-archived HomePage. It never creates a HomePage and never changes a Site.
* **Only missing pages.** For each of the five slugs it creates a `StandardPage` as a direct
  child of the root, only where no page record of any kind exists at that path. The title,
  body and SEO fields come from `cms/public_page_content/<slug>.json`.
* **Existing pages are never touched.** A page that already has the slug keeps its title,
  slug, body, SEO fields, privacy settings, revisions and publication state, whatever that
  state is: live, draft, unpublished, scheduled, expired, archived or restricted. The command
  does not restore archived pages, remove restrictions or republish anything.
* **Problems are reported, not fixed.** A page of another type that owns the slug is reported
  as a `collision` and skipped. A Wagtail redirect at the path, or a restricted root, is
  reported and skipped too.
* **`--publish-new` is narrow.** It publishes only pages created in that run, and only when
  approved content exists (a title and a body). All five pages have approved content; a
  newly created References page also imports its 258 logos (see section 2a).
* **Safe to repeat.** Creation runs in one transaction with a row lock on the HomePage and
  re-checks every path under the lock. A second run reports "Nothing to create" and changes
  nothing; pages are never duplicated or overwritten.
* **Dry runs cannot write.** With `--dry-run` (or no `--apply`) every non-SELECT statement is
  refused before it reaches the database.

### Drafts and the frontend

**A draft is never bypassed.** The frontend shows default content only while no page record
exists at the path. A draft created by `--apply` is such a record: from that moment the page's
URL returns **404**, not the default content and not the draft, until an editor publishes it
in Wagtail. The same holds for a page that is unpublished, scheduled, expired, archived or
restricted.

So `--apply` without `--publish-new` takes FAQ, Terms and Conditions, Privacy Policy and
Imprint offline (404) wherever they were showing default content, until each draft is
published. Use `--apply --publish-new` when the approved content should stay visible; the
published pages show exactly the same HTML as the defaults, now as editable CMS pages. Run
plain `--apply` only when editors will review and publish the drafts straight away.

## 2a. Fill an existing empty draft: `manage.py populate_public_page_draft`

`setup_public_pages` never touches existing pages. For a Terms or References page that already
exists as an **empty, never-published draft** (for example created by hand, or by an earlier
version of the setup command), use:

```bash
python manage.py populate_public_page_draft terms-and-conditions            # preview (default, read-only)
python manage.py populate_public_page_draft terms-and-conditions --apply    # save a draft revision
python manage.py populate_public_page_draft terms-and-conditions --apply --publish
python manage.py populate_public_page_draft references --apply --publish    # also imports the 258 logos
```

* Only `terms-and-conditions` and `references`, one explicit slug per run; same Site and HomePage
  checks as `setup_public_pages`.
* Refused (nothing changed) when the page is live or was ever published, archived, an alias,
  locked, in a workflow or moderation, scheduled (go-live, expiry or a scheduled revision),
  view-restricted on itself or an ancestor, when its latest draft changes the slug, or when the
  body is not empty in the page record **or its latest revision** (an editor's draft is never
  overwritten).
* Sets only the body and EMPTY SEO fields on top of the latest draft revision; title, slug,
  privacy and non-empty SEO fields are kept. Saved as a new Wagtail revision and logged.
* `--publish` (with `--apply`) publishes only complete approved content, and not when a Wagtail
  redirect claims the path. Without it the page stays a draft (404 on the public site).
* Re-running is safe: a draft that already holds exactly the approved content is left alone
  (`--apply --publish` may then publish it); a live page is refused.
* With `--apply`, the page row is locked and every check repeated; if the page changed since the
  check in the same run, nothing is written. Logos are imported before the lock, reusing any
  identical image already in the library (no duplicates, existing files untouched).

## 3. What the public website shows

The frontend asks the backend for `/<slug>/` on every request (no caching) and decides:

| State of `/<slug>/` in the configured Site | Endpoint | Public website |
|---|---|---|
| Published, public StandardPage | 200 | **The CMS page**, as published, even if an editor left the body or SEO fields empty |
| No page record at the path, no redirect, nothing blocking it (section 1) | 404 `page_absent` | **Default content** (all five pages; References with its logo wall) |
| Draft never published, unpublished, scheduled, or past its expiry date | 404 `page_unavailable` | 404 |
| Archived (deleted in Wagtail), or below an archived page | 404 `page_unavailable` | 404 |
| Password, login or group restriction on the page, its root or an ancestor | 404 `page_unavailable` | 404 |
| A page of another type at the slug, or a Wagtail redirect at the path | 404 `page_unavailable` | 404 |
| Site root is not the HomePage, or is archived | 404 `page_unavailable` | 404 |
| Any other URL | n/a | 404 (the backend is not asked) |
| Backend unreachable, throttled (429), server error, malformed response | 5xx / none | Error page "This page can't be loaded right now" (HTTP 500). **Never** default content and never a 404 |

Absence is decided by the backend from every page record at the path, in any state. It is not
inferred from a search of published pages, and the 404 never reveals a page's title, ID,
content or restriction. The frontend never reads drafts.

Default and CMS content go through the same server renderer
(`src/components/public/StandardPageArticle.jsx`). Body, title, meta description, canonical URL
and Open Graph tags are in the initial server HTML. The rendered `<article>` carries
`data-public-content="cms"` or `"default"`; a default also carries `data-content-sha256`, which
matches the hash the setup command prints.

### Default content and its consistency

The approved content exists twice, with no runtime link between the repositories:

* `ecp-backend/cms/public_page_content/*.json`, used by the setup command for new pages;
* `Events-Community-Platform-Frontend/src/content/public-pages/*.json`, byte-identical copies
  bundled into the Next.js server build.

Each file carries `content_sha256`. Tests in both repositories recompute it, so a copy edited
without updating the hash fails, and the frontend tests compare the two copies byte for byte
when both checkouts sit side by side. Change the backend copy first, run
`python -m cms.public_page_content --update-hashes`, then copy the files to the frontend
(`cms/public_page_content/README.md` has the steps). Changing these files never changes pages
that already exist in Wagtail.

## 4. Editing and publishing later in Wagtail

Pages created by the command are ordinary Wagtail pages:

1. Wagtail admin → **Pages** → **IMAA Connect** → the page → **Edit**.
2. **Content** tab: *Title* (the page heading) and *Body*. **Promote** tab: *Slug* (do not
   change it), *Title tag* (`seo_title`) and *Meta description* (`search_description`).
   Leave privacy at **Public**.
3. **Publish**. The public URL shows the new version on the next request.

A draft created by the command is published the same way. To create a page by hand instead,
open the HomePage → **Add child page** → **Standard page**, use the exact slug from the table
above, then **Publish** (not just *Save draft*).

To take a page offline, **Unpublish** it; the URL then returns 404, without default content.
**Deleting** a page in Wagtail archives it (the record is kept): the URL returns 404, the page
disappears from the explorer (add `?show_deleted=1` to the explorer URL to see it) and it keeps
its slug, so the command will not recreate it.

## 5. Deploying

**Deploying code does not transfer database content.** Pages created or edited on one machine,
such as a locally created Privacy Policy, exist only in that database. In each environment:

1. Deploy the backend and the frontend together. The frontend relies on the endpoint's `code`;
   against an older backend it shows 404s instead of default content.
2. Check the Site root (section 1).
3. Run `python manage.py setup_public_pages --dry-run` there and read the plan.
4. Run `python manage.py setup_public_pages --apply --publish-new` (or `--apply`, see
   "Drafts and the frontend").

5. Where a Terms or References page already exists as an empty, never-published draft, fill it
   with `populate_public_page_draft` (section 2a); `setup_public_pages` never changes it.

Until step 4, that environment shows the default content for all five pages. The pages exist only in the Next.js build; the
Vite build has no such routes.

## 6. Limitations

* **Permanently deleted pages.** If a page is removed with no record left (for example from a
  Django shell, a script or a database restore; Wagtail's own delete archives instead), the path
  is absent again and the default content reappears. Unpublish or archive pages instead.
* **Renamed or moved pages.** Wagtail creates a redirect from the old path. The old path then
  counts as unavailable: a 404 without default content (the frontend does not follow CMS
  redirects), and the command skips it. Delete the redirect in **Settings → Redirects** if the
  path should be free again.
* **Archived pages** keep blocking the default content and the slug. There is no restore button;
  `restore()` from a Django shell clears the archive flag but does not republish.
* **References** is the plain WordPress logo wall. The mockup's References directory (filters,
  pagination, company pages, company consent) is new functionality and not part of this phase.
  25 WordPress logos had no alt text; their alt text uses the WordPress company name.
* **FAQ contact form** is not migrated: it needs a contact submission API, scheduled for a later
  step. The FAQ questions and answers are complete.
* **Media storage.** Importing the References logos uploads 258 small images to the configured
  media storage (S3 where configured) and pre-generates their renditions; it takes a few minutes.
* **Content currency.** The defaults are the WordPress pages as retrieved on 2026-10-08. The
  legal texts were written for imaa-institute.org, and several statements are flagged
  **FOR REVIEW** in the files' `migration_notes` (for example the EU-US Privacy Shield and
  differing addresses). Wording was not corrected; have it reviewed before relying on it.

## 7. Environment variables

Backend (`.env`):

- `CMS_PUBLIC_SITE_HOSTNAME`: see section 1. Empty is fine with a single or single-default Site.
- `DRF_THROTTLE_CMS_PUBLIC`: throttle for the public endpoint, default `300/min` per client
  address (the Next.js server is one client).

Frontend (Next.js runtime / Amplify environment):

- `NEXT_PUBLIC_SITE_URL`: public origin for canonical and Open Graph URLs, e.g.
  `https://connect.imaa-institute.org`, no trailing slash. When empty, canonical tags are
  omitted rather than emitted with a wrong host.
- `CMS_API_BASE_URL`: optional server-only backend base for the CMS fetches (for example an
  internal URL). Defaults to the public API base (`NEXT_PUBLIC_API_BASE_URL` /
  `VITE_API_BASE_URL`).

## 8. Endpoint contract

`GET /api/cms/public/pages/by-path/?path=/privacy-policy/` (public, no authentication)

- **200**: JSON with `id`, `title`, `slug`, `type` (page class, e.g. `StandardPage`), `path`,
  `body_html` (rich text, allowlist-sanitised, backend media/document URLs absolute),
  `seo_title`, `search_description`, `first_published_at`, `last_published_at`, plus the
  type-specific fields the slug endpoint already returns for HomePage/AboutPage/
  EventsLandingPage.
- **400**: the `path` is missing or not a valid relative slug path.
- **404**: no published, public page at that path (see the table in section 3).
  - For the five default-eligible paths (`/<slug>/` above) the body is
    `{"detail": "Not found", "code": "page_absent"}` when no page record exists at the path
    and nothing blocks it, otherwise `{"detail": "Not found", "code": "page_unavailable"}`.
  - For every other path the body stays `{"detail": "Not found"}`.
  - A 404 never includes a page's title, ID, content or restriction details.
- **429**: throttled (`DRF_THROTTLE_CMS_PUBLIC`).
- **503**: the public Site cannot be chosen unambiguously (section 1).

The existing `GET /api/cms/pages/<slug>/` endpoint is unchanged and still serves Home and About.
