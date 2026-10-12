"""Test support for the About content package (used by cms/test_about_page.py and
cms/test_import_about_page.py).

The approved image binaries (cms/about_page_content/images/) are not in Git: production verifies
the originals in storage. Tests therefore use generated originals with the approved file names
and dimensions and map the content's SHA-256 values onto them, so they run in a clean checkout.
Tests that need the approved files themselves are skipped unless ``REAL_FILES_PRESENT``.
"""

import copy
import hashlib
import json
from io import BytesIO

from PIL import Image as PILImage

from cms.about_page_content import IMAGES_DIR, compute_content_hash, load_about_content

APPROVED = load_about_content(verify_files=False)  # about.json only: no image binaries needed
REAL_FILES_PRESENT = all((IMAGES_DIR / m["file"]).is_file() for m in APPROVED["media"])
_FORMATS = {"webp": "WEBP", "png": "PNG", "jpg": "JPEG", "jpeg": "JPEG"}


def first_per_file(content):
    """{sha256: first media item}: two references share one file; the first name is the stored one."""
    first = {}
    for m in content["media"]:
        first.setdefault(m["sha256"], m)
    return first


def generated_image(width, height, file_name, seed=0):
    """Deterministic image bytes of the given size, in the format of ``file_name``'s extension."""
    image = PILImage.new("RGB", (width, height), ((seed * 37) % 256, (seed * 91) % 256, 120))
    image.putpixel((0, 0), (seed % 256, 255 - seed % 256, 7))
    buffer = BytesIO()
    image.save(buffer, _FORMATS[file_name.rsplit(".", 1)[-1].lower()])
    return buffer.getvalue()


def generated_originals():
    """(content, {file name: bytes}): the approved content with generated originals of the same names
    and dimensions; each media item's ``sha256`` is that of its generated file."""
    content, data, new_hash = copy.deepcopy(APPROVED), {}, {}
    for index, (sha256, item) in enumerate(first_per_file(APPROVED).items()):
        data[item["file"]] = generated_image(item["width"], item["height"], item["file"], seed=index)
        new_hash[sha256] = hashlib.sha256(data[item["file"]]).hexdigest()
    for m in content["media"]:
        m["sha256"] = new_hash[m["sha256"]]
    return content, data


def write_package_images(directory, content, originals):
    """Write a stand-in for the package's images/: one file per media reference (41 names; the two
    references that share a file get identical bytes, as in the approved package)."""
    by_hash = {hashlib.sha256(data).hexdigest(): data for data in originals.values()}
    for m in content["media"]:
        (directory / m["file"]).write_bytes(by_hash[m["sha256"]])


def write_generated_package(directory):
    """A complete stand-in package in ``directory``: about.json (generated media hashes, its
    content_sha256 recomputed) and images/. Returns (content file, images dir, content, originals);
    patch ``cms.about_page_content.CONTENT_FILE``/``IMAGES_DIR`` with the paths to load it with every
    check, file hashes included."""
    content, originals = generated_originals()
    content["content_sha256"] = compute_content_hash(content)
    images = directory / "images"
    images.mkdir()
    write_package_images(images, content, originals)
    content_file = directory / "about.json"
    content_file.write_text(json.dumps(content, ensure_ascii=False))
    return content_file, images, content, originals
