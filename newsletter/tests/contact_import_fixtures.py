"""Synthetic CSV fixtures for contact import tests.

Every record is artificial: reserved ``example.test`` addresses and made-up
names and organisations. Never replace these with real contact data.
Opt-in columns here are test values only and never authorise sending email.
"""

from __future__ import annotations

import csv
import io

HEADERS = [
    "Email",
    "First Name",
    "Last Name",
    "Organization",
    "Country",
    "City",
    "Phone Number",
    "Tags",
    "Newsletter Opt-In",
    "Promotional Mailing",
    "Do Not Contact",
]

ORGANISATIONS = ["Example Company", "Demo Organization", "Sample Company", "Placeholder Ltd"]
PLACES = [("India", "Surat"), ("Singapore", "Singapore"), ("India", "Mumbai"), ("United Kingdom", "London")]
TAGS = ["Conference", "Newsletter", "Events", "Conference|Events"]


def contact_row(index: int, **overrides) -> dict[str, str]:
    country, city = PLACES[index % len(PLACES)]
    row = {
        "Email": f"user{index:05d}@example.test",
        "First Name": "Test",
        "Last Name": f"Contact{index:05d}",
        "Organization": ORGANISATIONS[index % len(ORGANISATIONS)],
        "Country": country,
        "City": city,
        "Phone Number": "",
        "Tags": TAGS[index % len(TAGS)],
        "Newsletter Opt-In": "true" if index % 2 else "false",
        "Promotional Mailing": "false",
        "Do Not Contact": "true" if index % 7 == 0 else "false",
    }
    row.update(overrides)
    return row


def to_csv(rows, headers=None, *, delimiter=",", bom=False, newline="\n") -> bytes:
    headers = headers or HEADERS
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=headers, delimiter=delimiter, lineterminator=newline, extrasaction="ignore"
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    data = buffer.getvalue().encode("utf-8")
    return (b"\xef\xbb\xbf" + data) if bom else data


def contacts_csv(count: int, *, start: int = 1, **kwargs) -> bytes:
    return to_csv([contact_row(i) for i in range(start, start + count)], **kwargs)


def edge_case_rows() -> list[dict[str, str]]:
    """One row per validation scenario, in a fixed order (rows 2..)."""
    return [
        contact_row(1),                                                   # 2 valid
        contact_row(2, Email=""),                                         # 3 missing email
        contact_row(3, Email="not-an-email"),                             # 4 invalid email
        contact_row(4, Email="USER00001@EXAMPLE.TEST"),                   # 5 duplicate of row 2
        contact_row(5, **{"First Name": "", "Last Name": ""}),            # 6 missing names (valid)
        contact_row(6, Organization="", City="", Country=""),             # 7 empty optionals (valid)
        contact_row(7, **{"First Name": "Zoë", "Last Name": "Ñúñez-Öğüt", "City": "São Paulo"}),  # 8 UTF-8
        contact_row(8, Organization='Acme, "Quoted" Inc'),                # 9 quoted comma
        contact_row(9, Tags="Conference|Events|conference"),              # 10 multi tags + dup
        contact_row(10, **{"Do Not Contact": "maybe"}),                   # 11 invalid DNC
        contact_row(11, **{"Newsletter Opt-In": "perhaps"}),              # 12 invalid boolean
        contact_row(12, Tags="-Conference"),                              # 13 tag removal
        contact_row(13, City="NULL"),                                     # 14 NULL literal
        contact_row(14, Organization="Line\nBreak Org"),                  # 15 embedded newline
    ]
