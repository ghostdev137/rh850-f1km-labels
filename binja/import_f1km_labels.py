"""Binary Ninja label importer for RH850/F1KH/F1KM peripheral regions.

Run from the BN Python console, or wire in as a plugin command:

    import sys; sys.path.insert(0, "/path/to/rh850-f1km-labels/binja")
    import import_f1km_labels as f
    f.apply(bv, variant="f1km-s4-s2")

For each peripheral region in the CSV this creates a section + a
data-variable symbol (`v<name>`), so hovering / XRef'ing any MMIO
access lights up the peripheral name. Segments that overlap existing
BN segments are skipped silently.
"""
from __future__ import annotations

import csv
import pathlib
import re

import binaryninja as bn

_HERE = pathlib.Path(__file__).resolve().parent
_MMIO = _HERE.parent / "mmio"

_SANITIZE = re.compile(r"[^0-9A-Za-z_]+")


def _sym(name: str) -> str:
    """Make a C-ish identifier out of an arbitrary peripheral label."""
    cleaned = _SANITIZE.sub("_", name).strip("_")
    return cleaned or "periph"


def apply(bv: "bn.BinaryView", variant: str = "f1km-s4-s2",
          prefix: str = "sfr_") -> int:
    """Annotate `bv` with peripheral-region symbols for `variant`.

    Returns the number of regions applied.
    """
    csv_path = _MMIO / f"{variant}.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"unknown variant '{variant}': {csv_path}")

    applied = 0
    with csv_path.open() as fp:
        for row in csv.DictReader(fp):
            start = int(row["start"], 16)
            end = int(row["end"], 16)
            name = row["peripheral"]
            size = end - start + 1

            # Create a read/write segment so BN can name the bytes even
            # when the MMIO region isn't backed by the binary's raw data.
            try:
                bv.add_auto_segment(
                    start, size, 0, 0,
                    bn.SegmentFlag.SegmentReadable
                    | bn.SegmentFlag.SegmentWritable)
            except Exception:
                pass  # overlaps existing are expected and safe to ignore

            try:
                bv.add_auto_section(
                    f"{prefix}{variant}_{start:08x}", start, size,
                    bn.SectionSemantics.ReadWriteDataSectionSemantics)
            except Exception:
                pass

            sym_name = f"{prefix}{_sym(name)}_{start:08x}"
            bv.define_auto_symbol(
                bn.Symbol(bn.SymbolType.DataSymbol, start, sym_name))
            applied += 1

    bv.update_analysis()
    return applied


if __name__ == "__main__":
    import sys
    print("Run inside Binary Ninja: import this module and call apply(bv).",
          file=sys.stderr)
    sys.exit(2)
