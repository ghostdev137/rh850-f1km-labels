# Ghidra script — imports RH850/F1KH/F1KM peripheral region labels.
# @category RH850
# @menupath Tools.RH850.Import F1KM Labels
#
# Usage: copy this file into your ghidra_scripts/ directory, open the
# target firmware, and run from the Script Manager. Pick the variant
# CSV when prompted. Each peripheral region becomes an uninitialized
# memory block + a primary label at its base address.

import csv
import os
import re

from ghidra.program.model.address import AddressOverflowException
from ghidra.program.model.mem import MemoryConflictException
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException

SANITIZE = re.compile(r"[^0-9A-Za-z_]+")


def sym(name):
    s = SANITIZE.sub("_", name).strip("_")
    return s or "periph"


def run():
    csv_path = askFile("Peripheral-region CSV", "Import").toString()
    variant = os.path.splitext(os.path.basename(csv_path))[0]
    mem = currentProgram.getMemory()
    st = currentProgram.getSymbolTable()

    count = 0
    with open(csv_path) as fp:
        for row in csv.DictReader(fp):
            start = int(row["start"], 16)
            end = int(row["end"], 16)
            size = end - start + 1
            name = "sfr_%s_%08x" % (sym(row["peripheral"]), start)
            addr = toAddr(start)

            # Create an uninitialized RAM block so address -> symbol
            # resolution works even for firmwares that don't map MMIO.
            try:
                mem.createUninitializedBlock(
                    "periph_%s_%08x" % (variant, start), addr, size, False)
            except MemoryConflictException:
                pass  # region already covered by firmware or prior run
            except AddressOverflowException:
                continue

            try:
                st.createLabel(addr, name, SourceType.USER_DEFINED)
                count += 1
            except DuplicateNameException:
                pass

    println("Applied %d peripheral labels from %s" % (count, csv_path))


run()
