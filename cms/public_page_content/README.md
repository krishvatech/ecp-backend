# Public page content

Approved initial content for the five public website StandardPages. One JSON file per page,
migrated from the client's WordPress site (imaa-institute.org).

| File | Status | WordPress source | WordPress page | Last modified (GMT) |
|---|---|---|---|---|
| `frequently-asked-questions.json` | migrated | https://imaa-institute.org/frequently-asked-questions/ | 887 "FAQ about IMAA" | 2025-03-26 |
| `references.json` | migrated (logo wall, 258 logos in `media/references/`) | https://imaa-institute.org/references/ | 3035 "References" | 2024-07-24 |
| `terms-and-conditions.json` | migrated | https://imaa-institute.org/terms-and-conditions/ | 50147 "Terms and Conditions" | 2024-08-14 |
| `privacy-policy.json` | migrated | https://imaa-institute.org/privacy-policy/ | 3 "Privacy Policy" | 2021-12-02 |
| `imprint.json` | migrated | https://imaa-institute.org/imprint/ | 50171 "Imprint" | 2026-10-01 |

Retrieved on 2026-10-08: FAQ, Terms, Privacy and Imprint from the WordPress REST API
(`https://imaa-institute.org/wp-json/wp/v2/pages?slug=<slug>`), References from the live page
and its logo files, with company names from the local WordPress export of 2026-07-02 (258
`company` records that match the live logos one to one). The text of all five was re-checked
word for word against the live pages on 2026-10-08. Each file's `migration_notes` lists what
was excluded, what was changed (formatting only), and wording flagged **FOR REVIEW**. Wording
has not been corrected; legal pages must be reviewed before they are relied on for IMAA Connect.

Not migrated, by design: the FAQ page's "Contact Us" section (a Contact Form 7 form with an
image and three counters). The client's plan schedules contact and enquiry forms as a separate
step, and the platform has no contact submission API yet.

## Who uses it

* `python manage.py setup_public_pages --apply` uses a file as the initial title, body and SEO
  fields of a page it **creates**. Existing pages are never updated from these files.
* `python manage.py populate_public_page_draft <slug> --apply` fills an **existing, empty,
  never-published** Terms or References draft from the same file (body and empty SEO fields only).
* The Next.js frontend keeps byte-identical copies in
  `Events-Community-Platform-Frontend/src/content/public-pages/` and renders them only while
  the page is genuinely absent from the configured Wagtail Site.

There is no runtime link between the two repositories. See `docs/public-website-pages.md`.

## Format (`format_version` 1)

| Field | Meaning |
|---|---|
| `slug`, `title` | Must match `PUBLIC_PAGES` in `__init__.py`. |
| `seo_title`, `search_description` | Wagtail's SEO fields. Empty when WordPress had none. |
| `migration_status` | `migrated` (has a body) or `not_migrated` (no body; no default is shown). |
| `body_html` | The body as a list of lines; the page body is the lines joined with `\n`. It is stored exactly as the public API returns rich text (already sanitised, Draftail-compatible tags only), so the CMS and default renderings are identical. |
| `content_sha256` | SHA-256 of slug, title, seo_title, search_description and the joined body, separated by `\x1f`; for a page with media, plus one `key\tsha256\twidth\theight` line per file. |
| `media` | Bundled files under `media/` (`key`, file `sha256`, `width`, `height`, and the `company`, `alt_source` and WordPress `source_url` for reference). Empty for pages without media. |
| `source`, `migration_notes` | Where the content came from and how it was migrated. Not rendered. |

A body line that shows a bundled file is exactly
`<img alt="…" class="richtext-image logo" height="…" src="media:<key>" width="…">`. The commands
import the file into the Wagtail image library (collection "Public website pages", identical
files reused) and store a rich-text image embed in the `logo` format (`cms/image_formats.py`);
the frontend serves its copy from `public/public-pages/<key>`.

## Changing the content

1. Edit the JSON file here, keeping the format above.
2. Recompute the hashes and validate every file:

   ```bash
   python -m cms.public_page_content --update-hashes
   python -m cms.public_page_content
   ```

3. Run `pytest cms/test_public_page_content.py`. It checks the hashes, the formatting and
   that the body survives Wagtail rich text and the public sanitiser unchanged.
4. Copy the changed files to `Events-Community-Platform-Frontend/src/content/public-pages/`
   (and changed media to its `public/public-pages/<key>`), then run the frontend tests
   (`publicSitePages.test.mjs`). They recompute the hashes and, when this repository is checked
   out next to the frontend, compare the JSON files and the media byte by byte.
5. Commit both repositories.

A changed file affects only pages created afterwards and the frontend default for pages that
do not exist yet. Pages that already exist in Wagtail are edited in Wagtail.
