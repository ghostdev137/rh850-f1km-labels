#!/usr/bin/env python3
"""Extract the Peripheral I/O Address Map tables from the Renesas
RH850/F1KH, RH850/F1KM hardware user's manual (R01UH0684EJ) and emit
one CSV per variant (F1KH-D8, F1KM-S4, F1KM-S2, F1KM-S1).

The PDF prints each variant's map under Section 4A.3 / 4B.3 / 4C.3.
We run pdftotext -layout to preserve columns, then parse each row:

    FFA0 0000H to FFA0 001FH         1                  FLMD

producing (start, end, group, peripheral) tuples. "Access prohibited"
holes are dropped — they inflate the CSV without carrying info.

Usage:
    python3 extract_mmio.py <hardware_manual.pdf> <out_dir>
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import csv

VARIANTS = [
    # (section header key, output filename, friendly label)
    ("4A.3",       "f1kh-d8.csv",  "RH850/F1KH-D8"),
    ("4B.3",       "f1km-s4-s2.csv", "RH850/F1KM-S4, RH850/F1KM-S2"),
    ("4C.3",       "f1km-s1.csv",  "RH850/F1KM-S1"),
]

ROW = re.compile(
    r"^\s*"
    r"([0-9A-F]{4})\s*([0-9A-F]{4})H"       # start: FFxx xxxxH
    r"\s+to\s+"
    r"([0-9A-F]{4})\s*([0-9A-F]{4})H"       # end
    r"\s+(\S+)"                              # group (number or "—")
    r"\s+(.+?)\s*$"                          # peripheral name
)


def pdftotext(pdf: pathlib.Path) -> list[str]:
    out = subprocess.check_output(["pdftotext", "-layout", str(pdf), "-"],
                                  stderr=subprocess.DEVNULL)
    return out.decode("utf-8", "replace").splitlines()


def slice_variant(lines: list[str], header_key: str) -> list[str]:
    """Return the run of lines starting at the given section header and
    ending when the next section ("<n>.1") or "Section <digit>" appears."""
    # Match e.g. "4A.3       Peripheral I/O Address Map" (body text, not
    # the TOC line which has "...717" trailing page number).
    header_re = re.compile(rf"^{re.escape(header_key)}\s+Peripheral I/O "
                           r"Address Map\s*$")
    start = None
    for i, line in enumerate(lines):
        if header_re.match(line.lstrip()):
            start = i
            break
    if start is None:
        raise ValueError(f"section {header_key} not found")
    end_re = re.compile(r"^(?:[0-9A-F]+[A-C]?\.[1-9]|Section\s+\d)")
    for j in range(start + 1, len(lines)):
        stripped = lines[j].lstrip()
        if stripped.startswith(header_key):
            continue
        if end_re.match(stripped):
            return lines[start:j]
    return lines[start:]


def parse_rows(region: list[str]):
    for line in region:
        m = ROW.match(line)
        if not m:
            continue
        s_hi, s_lo, e_hi, e_lo, group, periph = m.groups()
        periph = periph.strip()
        if "prohibited" in periph.lower() or periph == "—":
            continue
        start = int(s_hi + s_lo, 16)
        end = int(e_hi + e_lo, 16)
        yield start, end, group if group != "—" else "", periph


def main(pdf_path: str, out_dir: str) -> None:
    pdf = pathlib.Path(pdf_path)
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    lines = pdftotext(pdf)
    for key, fname, label in VARIANTS:
        region = slice_variant(lines, key)
        rows = list(parse_rows(region))
        path = out / fname
        with path.open("w", newline="") as fp:
            w = csv.writer(fp)
            w.writerow(["start", "end", "group", "peripheral"])
            for start, end, group, periph in rows:
                w.writerow([f"0x{start:08x}", f"0x{end:08x}", group, periph])
        print(f"{label}: {len(rows):4d} regions -> {path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
