"""Test support for the Testimonials and Contact Us packages (cms/test_batch3.py).

The image binaries are not in Git, so tests use generated originals with the approved file names and
dimensions; each package's media ``sha256`` values are mapped onto them (as cms/team_page_testing.py).
"""

import copy
import hashlib

from cms.about_page_testing import generated_image
from cms.contact_page_content import load_contact_content
from cms.testimonials_content import load_testimonials_content

TESTIMONIALS = load_testimonials_content()
CONTACT = load_contact_content()


def generated_packages():
    """(testimonials content, contact content, {file name: bytes}) with generated originals; a file
    shared by both packages gets one generated original (same SHA-256 in both)."""
    testimonials, contact, data, new_hash = copy.deepcopy(TESTIMONIALS), copy.deepcopy(CONTACT), {}, {}
    for index, item in enumerate(m for package in (testimonials, contact) for m in package["media"]):
        if item["sha256"] not in new_hash:
            data[item["file"]] = generated_image(item["width"], item["height"], item["file"], seed=400 + index)
            new_hash[item["sha256"]] = hashlib.sha256(data[item["file"]]).hexdigest()
    for package in (testimonials, contact):
        for item in package["media"]:
            item["sha256"] = new_hash[item["sha256"]]
    return testimonials, contact, data
