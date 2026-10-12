"""Test support for the Our Team content package (cms/test_team_page.py, cms/test_import_team_page.py).

The approved image binaries (cms/team_page_content/images/) are not in Git: production verifies
the originals in storage (import_team_page). Tests therefore use generated originals with the
approved file names and dimensions, the content's SHA-256 values mapped onto them, so they run in
a clean checkout. Tests that need the approved files themselves are skipped unless
``REAL_FILES_PRESENT``.
"""

import copy
import hashlib
import json

from cms.about_page_testing import generated_image
from cms.team_page_content import IMAGES_DIR, compute_content_hash, load_team_content

APPROVED = load_team_content(verify_files=False)  # team.json only: no image binaries needed
REAL_FILES_PRESENT = all((IMAGES_DIR / m["file"]).is_file() for m in APPROVED["media"])


def generated_originals():
    """(content, {file name: bytes}): the approved content with generated originals of the same names
    and dimensions; each media item's ``sha256`` is that of its generated file."""
    content, data = copy.deepcopy(APPROVED), {}
    for index, item in enumerate(content["media"]):
        data[item["file"]] = generated_image(item["width"], item["height"], item["file"], seed=200 + index)
        item["sha256"] = hashlib.sha256(data[item["file"]]).hexdigest()
    return content, data


def write_generated_package(directory):
    """A complete stand-in package in ``directory``: team.json (generated media hashes, its
    content_sha256 recomputed) and images/. Returns (content file, images dir, content, originals);
    patch ``cms.team_page_content.CONTENT_FILE``/``IMAGES_DIR`` with the paths to load it with every
    check, file hashes included."""
    content, originals = generated_originals()
    content["content_sha256"] = compute_content_hash(content)
    images = directory / "images"
    images.mkdir()
    for name, data in originals.items():
        (images / name).write_bytes(data)
    content_file = directory / "team.json"
    content_file.write_text(json.dumps(content, ensure_ascii=False))
    return content_file, images, content, originals
