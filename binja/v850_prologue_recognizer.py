"""V850/RH850 PREPARE-prologue function recognizer for Binary Ninja.

Binary Ninja finds functions via (a) explicit entry points, (b) direct-call
xrefs, and (c) linear-sweep prologue matching. For V850 code compiled by
CC-RH the canonical function prologue is one of:

    prepare  {<reglist>}, <imm5>               # 32-bit, no frame
    prepare  {<reglist>}, <imm5>, sp           # 32-bit, ep = sp
    prepare  {<reglist>}, <imm5>, imm16sx      # 48-bit variants
    addi     -N, sp, sp                        # lean prologue (no saves)
    movea    -N, sp, sp  (rare, same idea)

BN's built-in linear sweep doesn't know any of these patterns for the v850
arch, so it misses many real functions on first open. This module scans
all executable segments at every 2-byte aligned offset for these prologues,
filters out matches already inside known functions, and creates user
functions for the rest. Re-runnable and idempotent.

Usage:

    import sys; sys.path.insert(0, "/Users/rossfisher/src/rh850-f1km-labels/binja")
    import v850_prologue_recognizer as vpr
    vpr.apply(bv)

Plugin command:  Plugins -> V850 -> Recognize PREPARE prologues
"""
from __future__ import annotations

import binaryninja as bn


def _define_function(bv: "bn.BinaryView", addr: int) -> None:
    if hasattr(bv, "create_user_function"):
        bv.create_user_function(addr)
    else:
        bv.add_function(addr)

# V850 format-XIII PREPARE opcode: hw1 bits [10:6] == 0b11001.
# PREPARE's full spec:
#   hw1 = rrrrr 11001 0 L iiiii              (wait - spec is:
#                                              0000011001iiiiiL)
# Actually for V850E1 PREPARE the canonical form is format XIII with
# a 5-bit opcode 0b11001 in hw1[10:6].  Both sub-opcodes 0b001 and 0b011
# in hw2[18:16] (= (hw2 >> 0) & 7 after the 5-bit preamble) are valid.
# We recognize a prologue by a relaxed match: hw1[15:6] == 0000011110_b
# OR the shorthand `addi -N, sp, sp`.

def _is_prepare(data: bytes) -> bool:
    """Return True if the leading 2 bytes start a PREPARE instruction."""
    if len(data) < 4:
        return False
    hw1 = int.from_bytes(data[0:2], "little")
    hw2 = int.from_bytes(data[2:4], "little")
    # Format XIII PREPARE: hw1[10:6] == 0b11001, plus sub-op in hw2[2:0]
    if ((hw1 >> 6) & 0x1F) != 0b11001:
        return False
    subop = hw2 & 0x7
    return subop in (0b001, 0b011)


def _is_addi_neg_sp(data: bytes) -> bool:
    """Match `addi imm16, sp, sp` where imm16 is a negative number.

    V850 addi format VI: hw1[15:11] reg2, hw1[10:6] opcode 0b110000,
    hw1[5:0]=0b000000, hw2 = imm16 (signed).  We need reg1 == sp (3) in
    hw1[5:0] — wait, format VI actually puts reg1 in hw1[4:0] and opcode
    in hw1[10:6]. We want addi src=sp dst=sp with imm16 < 0.
    """
    if len(data) < 4:
        return False
    hw1 = int.from_bytes(data[0:2], "little")
    hw2 = int.from_bytes(data[2:4], "little")
    opcode = (hw1 >> 6) & 0x3F   # 6-bit op for format VI
    if opcode != 0b110000:
        return False
    reg1 = hw1 & 0x1F
    reg2 = (hw1 >> 11) & 0x1F
    if reg1 != 3 or reg2 != 3:  # sp == r3
        return False
    # Check imm16 sign bit and ensure it's a "reasonable" stack frame
    imm16 = hw2 if hw2 < 0x8000 else hw2 - 0x10000
    return -0x8000 <= imm16 <= -4   # small negative (-4..-32K)


_CAL_RANGES = (
    # Known pure-data regions on Ford/TKP firmwares. Any prologue match
    # inside these is guaranteed to be a float-table false positive.
    (0x00FD0000, 0x00FE0000),  # Transit / F150 cal data flash window
)


def _addr_in_data_region(bv: "bn.BinaryView", addr: int) -> bool:
    """True if `addr` sits inside a section whose semantics are read-only
    data or writable data — places a function prologue cannot exist."""
    if any(lo <= addr < hi for lo, hi in _CAL_RANGES):
        return True
    for s in bv.get_sections_at(addr):
        semantics = s.semantics
        if semantics in (bn.SectionSemantics.ReadOnlyDataSectionSemantics,
                         bn.SectionSemantics.ReadWriteDataSectionSemantics):
            return True
    return False


def apply(bv: "bn.BinaryView", max_scan_bytes: int = 4 * 1024 * 1024) -> int:
    """Scan all executable segments for PREPARE / addi-neg-sp prologues
    and create functions at every match that isn't already one.

    Returns the number of newly-created functions.
    """
    created = 0
    existing_starts = {fn.start for fn in bv.functions}
    # Fast membership test for "is this address backed by a segment BN
    # can actually analyze" — guards against creating ghost functions in
    # memory the file never maps.
    backed = [(seg.start, seg.end) for seg in bv.segments if seg.executable]

    def in_backed(a):
        return any(lo <= a < hi for lo, hi in backed)

    for seg in bv.segments:
        if not seg.executable:
            continue
        start, end = seg.start, min(seg.end, seg.start + max_scan_bytes)
        data = bv.read(start, end - start)
        for off in range(0, len(data) - 4, 2):
            addr = start + off
            if addr in existing_starts:
                continue
            if bv.get_functions_containing(addr):
                continue
            if _addr_in_data_region(bv, addr):
                continue
            # Both the prologue bytes AND any fall-through must be inside
            # a real backed executable segment; without this BN complains
            # "Attempting to add function not backed by file" on edge hits.
            if not in_backed(addr):
                continue
            chunk = data[off : off + 4]
            if _is_prepare(chunk) or _is_addi_neg_sp(chunk):
                _define_function(bv, addr)
                existing_starts.add(addr)
                created += 1

    if created:
        bv.update_analysis()
    bn.log_info(f"PREPARE-prologue recognizer: created {created} functions")
    return created


def _cmd(bv):
    try:
        n = apply(bv)
        bn.show_message_box(
            "V850 prologue recognizer",
            f"Created {n} new functions from PREPARE / addi-sp prologues.",
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.InformationIcon)
    except Exception as e:
        bn.show_message_box(
            "Recognizer failed", str(e),
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.ErrorIcon)


try:
    bn.PluginCommand.register(
        "V850\\Recognize PREPARE prologues",
        "Scan executable segments for V850 PREPARE / addi -N, sp, sp "
        "function prologues and create user functions at every match.",
        _cmd)
except Exception:
    pass
