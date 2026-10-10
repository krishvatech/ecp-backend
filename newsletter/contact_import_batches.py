"""Split a contact CSV that exceeds the import limits into importable batches.

The wizard refuses files over the row/byte limits rather than raising them.
This splits such a file into batch files that each fit. Record boundaries come
from the same csv parser, delimiter detection and strictness the wizard uses
(``parse_csv``), so a file the wizard can read is split exactly as the wizard
would read it: quoted multi-line values stay whole, a stray quote inside an
unquoted value stays a literal character, and a record of quoted empty values
(``"",""``) is blank, as it is for the importer.

Each record is copied with the exact text it occupied in the source, so field
values, quoting and order are unchanged. The only byte-level normalisations:

* a UTF-8 BOM is not repeated in the batches;
* a header or final record without a line break gets ``\\n`` appended;
* blank records travel with the next data record; blank records after the last
  data record are kept when they fit and otherwise dropped and counted
  (``blank_records_dropped``). Blank records carry no contact data.

Every batch is re-parsed and compared with the source's records, and checked
against the row and byte limits, so a batch set that does not add up exactly
is never written. Nothing is de-duplicated or imported here.
"""

from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass, field

from .contact_import_services import ContactImportError, _detect_delimiter, max_bytes, max_rows


@dataclass
class Batch:
    content: bytes
    rows: int
    # Spreadsheet row numbers in the source file (its header is row 1).
    first_source_row: int
    last_source_row: int


@dataclass
class SplitResult:
    header: str
    total_rows: int
    batches: list[Batch] = field(default_factory=list)
    source_sha256: str = ""
    blank_records_dropped: int = 0


class _LineRecorder:
    """Feeds lines to csv.reader and keeps the raw text it consumed, so each
    parsed record can be copied byte for byte. csv.reader pulls lines only
    until the current record is complete; it never reads ahead."""

    def __init__(self, text: str):
        self._lines = iter(io.StringIO(text, newline=""))
        self.consumed: list[str] = []

    def __iter__(self):
        return self

    def __next__(self) -> str:
        line = next(self._lines)
        self.consumed.append(line)
        return line

    def take(self) -> str:
        raw, self.consumed = "".join(self.consumed), []
        return raw


def _records(text: str, delimiter: str):
    """Yield (raw text, cells) per record, parsed exactly like parse_csv."""
    recorder = _LineRecorder(text)
    reader = csv.reader(recorder, delimiter=delimiter, strict=True)
    row_number = 0
    while True:
        try:
            cells = next(reader)
        except StopIteration:
            return
        except csv.Error:
            raise ContactImportError(
                f"Row {row_number + 1} is not valid CSV (check for an unclosed quote).",
                code="malformed_csv",
            ) from None
        row_number += 1
        yield recorder.take(), cells


def _terminated(raw: str) -> str:
    return raw if raw.endswith(("\n", "\r")) else raw + "\n"


def _is_blank(cells: list[str]) -> bool:
    # Same rule as parse_csv: a record whose cells are all empty or whitespace.
    return not any(str(cell).strip() for cell in cells)


def _size(text: str) -> int:
    return len(text.encode("utf-8"))


def split_csv(raw: bytes, *, batch_rows: int | None = None, batch_bytes: int | None = None) -> SplitResult:
    batch_rows = max_rows() if batch_rows is None else batch_rows
    batch_bytes = max_bytes() if batch_bytes is None else batch_bytes
    if batch_rows <= 0 or batch_bytes <= 0:
        raise ContactImportError("Batch rows and bytes must be greater than zero.", code="invalid_batch_size")
    if batch_rows > max_rows() or batch_bytes > max_bytes():
        raise ContactImportError("Batches may not exceed the import limits.", code="invalid_batch_size")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ContactImportError("The file is not valid UTF-8.", code="encoding") from None
    if not text.strip():
        raise ContactImportError("The file is empty.", code="empty_file")

    delimiter = _detect_delimiter(text.split("\n", 1)[0].rstrip("\r"))
    records = _records(text, delimiter)
    header_raw, header_cells = next(records)
    header = _terminated(header_raw)
    header_bytes = _size(header)

    result = SplitResult(header=header, total_rows=0, source_sha256=hashlib.sha256(raw).hexdigest())
    source_rows: list[list[str]] = []
    current: list[str] = []
    current_rows = current_bytes = 0
    first_row = last_row = None
    pending: list[str] = []  # blank records waiting for the next data record

    def close():
        nonlocal current, current_rows, current_bytes, first_row
        if current_rows:
            result.batches.append(
                Batch(
                    content=(header + "".join(current)).encode("utf-8"),
                    rows=current_rows,
                    first_source_row=first_row,
                    last_source_row=last_row,
                )
            )
        current, current_rows, current_bytes, first_row = [], 0, 0, None

    source_row = 1
    for record_raw, cells in records:
        source_row += 1
        if _is_blank(cells):
            pending.append(record_raw)
            continue
        record = _terminated(record_raw)
        chunk = "".join(pending) + record
        size = _size(chunk)
        if header_bytes + size > batch_bytes:
            raise ContactImportError(
                f"Row {source_row} (with any blank lines before it) is larger than the batch size limit.",
                code="file_too_large",
            )
        if current_rows >= batch_rows or header_bytes + current_bytes + size > batch_bytes:
            close()
        pending = []
        if first_row is None:
            first_row = source_row
        current.append(chunk)
        current_rows += 1
        current_bytes += size
        last_row = source_row
        result.total_rows += 1
        source_rows.append(cells)

    if pending:
        trailing = "".join(pending)
        if current_rows and header_bytes + current_bytes + _size(trailing) <= batch_bytes:
            current.append(trailing)
            current_bytes += _size(trailing)
        else:
            result.blank_records_dropped = len(pending)
    close()

    if not result.total_rows:
        raise ContactImportError("The file has a header row but no contacts.", code="no_rows")
    _verify(header_cells, source_rows, delimiter, result, batch_rows, batch_bytes)
    return result


def _verify(header_cells, source_rows, delimiter, result: SplitResult, batch_rows: int, batch_bytes: int) -> None:
    """Every batch must fit the limits, re-parse to the source header, and
    together hold exactly the source's non-blank records in order."""
    combined = []
    for batch in result.batches:
        if len(batch.content) > batch_bytes or batch.rows > batch_rows:
            raise ContactImportError("A batch exceeds the size limits.", code="split_failed")
        parsed = list(csv.reader(io.StringIO(batch.content.decode("utf-8"), newline=""), delimiter=delimiter, strict=True))
        if parsed[0] != header_cells:
            raise ContactImportError("A batch header does not match the source.", code="split_failed")
        rows = [cells for cells in parsed[1:] if not _is_blank(cells)]
        if len(rows) != batch.rows:
            raise ContactImportError("A batch row count does not match.", code="split_failed")
        combined.extend(rows)
    if combined != source_rows or len(combined) != result.total_rows:
        raise ContactImportError("The batches do not add up to the source file.", code="split_failed")


def manifest(result: SplitResult, names: list[str], source_name: str) -> dict:
    return {
        "source": source_name,
        "source_sha256": result.source_sha256,
        "total_rows": result.total_rows,
        "blank_records_dropped": result.blank_records_dropped,
        "batches": [
            {
                "file": name,
                "rows": batch.rows,
                "source_rows": [batch.first_source_row, batch.last_source_row],
                "bytes": len(batch.content),
                "sha256": hashlib.sha256(batch.content).hexdigest(),
            }
            for name, batch in zip(names, result.batches)
        ],
    }
