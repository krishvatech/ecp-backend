"""Maintenance entry point for the public page content files (no database, no Django settings).

    python -m cms.public_page_content                  # check every file (default)
    python -m cms.public_page_content --update-hashes  # after an intentional edit

After updating, copy the JSON files to the frontend (src/content/public-pages/) and any
bundled media (media/<key>) to the frontend's public/public-pages/<key>, so both copies stay
byte-identical; the frontend tests verify the same hashes.
"""

import argparse
import json
import sys

from . import (
    MEDIA_DIR,
    PUBLIC_PAGE_SLUGS,
    PublicPageContentError,
    compute_content_hash,
    content_path,
    dump_content_file,
    file_sha256,
    load_public_page_content,
)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m cms.public_page_content")
    parser.add_argument("--update-hashes", action="store_true", help="Rewrite content_sha256 in every file.")
    args = parser.parse_args(argv)

    failures = 0
    for slug in PUBLIC_PAGE_SLUGS:
        path = content_path(slug)
        if args.update_hashes:
            data = json.loads(path.read_text(encoding="utf-8"))
            # Bundled files: refresh each recorded SHA-256 from the file on disk.
            for item in data.get("media", []):
                media_path = MEDIA_DIR / item["key"]
                if media_path.is_file():
                    item["sha256"] = file_sha256(media_path)
            data["content_sha256"] = compute_content_hash(
                data["slug"], data["title"], data["seo_title"], data["search_description"], data["body_html"],
                data.get("media", []),
            )
            path.write_text(dump_content_file(data), encoding="utf-8")
        try:
            content = load_public_page_content(slug)
        except PublicPageContentError as exc:
            failures += 1
            print(f"FAIL  {slug}: {exc}")
            continue
        print(
            f"ok    {slug:<28} {content.migration_status:<13} "
            f"sha256 {content.content_sha256[:12]}  {len(content.body_lines)} body lines"
            + (f", {len(content.media)} media files" if content.media else "")
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
