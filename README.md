# rh850-f1km-labels

Peripheral-region labels for the **Renesas RH850/F1KH, RH850/F1KM** family
(G3K / G3KH / G3MH cores), machine-extracted from the Renesas hardware
user's manual and packaged for import into **Binary Ninja** and **Ghidra**.

The primary target is Ford PSCM / APIM / BCM / ABS firmwares, which almost
universally use F1KM-S1/S2/S4 parts, but the CSVs work for any firmware
that hits the same Renesas I/O space.

## What's here

```
mmio/
  f1kh-d8.csv      — RH850/F1KH-D8          (Section 4A.3)
  f1km-s4-s2.csv   — RH850/F1KM-S4 / S2     (Section 4B.3)
  f1km-s1.csv      — RH850/F1KM-S1          (Section 4C.3)
binja/
  import_f1km_labels.py   — Binary Ninja Python API importer
ghidra/
  ImportF1kmLabels.py     — Ghidra script
tools/
  extract_mmio.py   — rebuilds the CSVs from the Renesas PDF
```

Each CSV row is a single peripheral region:

```
start,end,group,peripheral
0xffc00000,0xffc0000f,1,FENMI (ECON_NMI)
0xffc01000,0xffc01003,1,SELB_INTC (SL_INTC)
```

`group` is the Renesas bus-master permission group (1–5 plus "CPU" for
local-peripheral areas); firmwares don't need it but it's handy when
mapping IPG / PBG / HBG guard tables.

Access-prohibited filler rows are dropped.

## Binary Ninja

```python
import sys
sys.path.insert(0, "/path/to/rh850-f1km-labels/binja")
import import_f1km_labels as f
f.apply(bv, variant="f1km-s4-s2")   # or "f1km-s1", "f1kh-d8"
```

For each region the script adds a read/write segment, a data section,
and a primary symbol at the base address:

```
sfr_RSCAN0_ffd00000:
sfr_ADCA0_ff9c0000:
```

Overlapping existing segments is a no-op, so it's safe to re-run.

## Ghidra

Copy `ghidra/ImportF1kmLabels.py` into any directory on your Ghidra
script path (typically `~/ghidra_scripts/`), open the firmware, then
run **Tools → RH850 → Import F1KM Labels** from the Script Manager and
point it at the CSV for your variant. It creates uninitialized RAM
blocks + primary labels the same way the BN importer does.

## Rebuilding the CSVs

```
pip install --user  # nothing — only uses stdlib + pdftotext
python3 tools/extract_mmio.py \
    /path/to/RH850_F1KH_F1KM_hardware_R01UH0684EJ.pdf \
    mmio/
```

`pdftotext -layout` (from `poppler`) is the only external dep.
The extractor parses every row of the **Peripheral I/O Address Map**
tables in sections 4A.3, 4B.3, and 4C.3.

## Source

Derived from **RH850/F1KH, RH850/F1KM Hardware User's Manual**,
document `R01UH0684EJ0130 Rev.1.30` (Renesas, 30 Sep 2021), §4A.3 /
§4B.3 / §4C.3. Renesas retains copyright on the original tables; the
CSVs in this repo are reproduced for interoperability with disassembly
tools, and the extraction script is provided so anyone can re-derive
them from their own copy of the manual.

## License

[Apache License 2.0](LICENSE) for the code (extraction script +
importers). The extracted CSV data is a factual restatement of Renesas
documentation and is distributed with the same intent as an SVD file.
See `NOTICE` for details.
