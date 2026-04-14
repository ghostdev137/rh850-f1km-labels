"""CALLT table analysis for V850/RH850 Ford PSCM firmwares.

V850's `callt imm6` instruction is a compact indirect call: the CPU reads a
16-bit entry from the table at system register CTBP + (imm6 << 1), adds
CTBP to the loaded value, and jumps there. BN's v850 lifter models this
correctly at the LLIL level, but has no way to know what CTBP is set to at
runtime, so every CALLT is an xref dead-end.

This module:

  1. Scans code for the common initialisation pattern
         movhi <hi>, r0, <rX>
         movea <lo>, <rX>, <rX>
         ldsr <rX>, ctbp
     and recovers the CTBP base address.
  2. Walks the 64 CALLT table entries (halfword each) starting there.
  3. Creates a function at every resolved target and a code xref from each
     CALLT site to the target.

Invoke from the BN Python console:

    import sys; sys.path.insert(0, "/Users/rossfisher/src/rh850-f1km-labels/binja")
    import callt_analysis as c
    c.apply(bv)                   # auto-detect CTBP
    c.apply(bv, ctbp=0x01003000)  # or specify manually

It also registers as a plugin command so it shows up in
Plugins -> V850 -> Annotate CALLT table.
"""
from __future__ import annotations

import struct
from typing import Iterable, Optional

import binaryninja as bn


# ---------- CTBP recovery -----------------------------------------------

def _iter_v850_insns(bv: "bn.BinaryView") -> Iterable:
    for fn in bv.functions:
        for bb in fn.basic_blocks:
            addr = bb.start
            while addr < bb.end:
                info = bv.arch.get_instruction_info(
                    bv.read(addr, 8), addr)
                if info is None or info.length == 0:
                    break
                yield addr, bv.get_disassembly(addr) or ""
                addr += info.length


def _parse_imm(tok: str) -> Optional[int]:
    tok = tok.strip().rstrip(",")
    try:
        return int(tok, 0)
    except ValueError:
        return None


def detect_ctbp(bv: "bn.BinaryView") -> Optional[int]:
    """Scan lifted code for the standard CTBP initialiser.

    Common Ford / TKP pattern (CC-RH startup):
        movhi 0xHHHH, r0, rN
        movea 0xLLLL, rN, rN
        ldsr  rN, ctbp         (or "ldsr rN, 20")

    Returns the 32-bit CTBP base or None if nothing matches.
    """
    insns = list(_iter_v850_insns(bv))
    for i, (addr, txt) in enumerate(insns):
        if not txt.lower().startswith("ldsr "):
            continue
        if "ctbp" not in txt.lower() and ", 20" not in txt.lower():
            continue
        # Walk the preceding ~6 insns for movhi/movea feeding the src reg.
        parts = txt.split()
        src_reg = parts[1].rstrip(",") if len(parts) > 1 else None
        if not src_reg:
            continue
        hi = lo = None
        for j in range(i - 1, max(-1, i - 8), -1):
            _, t = insns[j]
            tlow = t.lower()
            if tlow.startswith(f"movhi ") and f", {src_reg}" in tlow:
                # "movhi 0xHHHH, r0, rN"
                fields = [f.strip().rstrip(",") for f in t.split()]
                v = _parse_imm(fields[1]) if len(fields) > 1 else None
                if v is not None:
                    hi = v
            elif tlow.startswith("movea ") and f", {src_reg}" in tlow:
                fields = [f.strip().rstrip(",") for f in t.split()]
                v = _parse_imm(fields[1]) if len(fields) > 1 else None
                if v is not None:
                    lo = v
            elif tlow.startswith(("mov ", "movhi ", "movea ")) and \
                    tlow.endswith(f", {src_reg}"):
                pass
            if hi is not None and lo is not None:
                break
        if hi is not None and lo is not None:
            return ((hi & 0xFFFF) << 16) + (lo & 0xFFFF)
    return None


# ---------- table walk + annotation -------------------------------------

def apply(bv: "bn.BinaryView", ctbp: Optional[int] = None,
          entries: int = 64) -> int:
    """Annotate all CALLT sites with xrefs to the resolved target.

    Returns the number of CALLT sites successfully annotated. `entries` is
    the table size (V850 supports 64 but some firmwares use fewer).
    """
    if ctbp is None:
        ctbp = detect_ctbp(bv)
    if ctbp is None:
        raise RuntimeError("CTBP base not detected — pass ctbp= explicitly")

    # Read the 64 halfwords (little-endian) and compute resolved targets.
    raw = bv.read(ctbp, entries * 2)
    if len(raw) != entries * 2:
        raise RuntimeError(f"CALLT table at {ctbp:#010x} out of range")

    # Label the table itself.
    try:
        bv.define_user_symbol(bn.Symbol(
            bn.SymbolType.DataSymbol, ctbp, f"callt_table_{ctbp:08x}"))
        bv.define_user_data_var(
            ctbp, bn.Type.array(bn.Type.int(2, False), entries))
    except Exception:
        pass

    targets = []
    for i in range(entries):
        off = struct.unpack_from("<H", raw, i * 2)[0]
        if off == 0 or off == 0xFFFF:
            continue
        target = ctbp + off
        targets.append((i, target))
        if bv.get_function_at(target) is None:
            bv.add_function(target)
        try:
            bv.define_user_symbol(bn.Symbol(
                bn.SymbolType.FunctionSymbol, target,
                f"callt_{i:02x}"))
        except Exception:
            pass

    # Every CALLT imm6 instruction gets a user code xref to its target.
    annotated = 0
    for fn in bv.functions:
        for bb in fn.basic_blocks:
            addr = bb.start
            while addr < bb.end:
                info = bv.arch.get_instruction_info(
                    bv.read(addr, 8), addr)
                if info is None or info.length == 0:
                    break
                txt = (bv.get_disassembly(addr) or "").lower()
                if txt.startswith("callt"):
                    # callt 0x<imm6>
                    fields = txt.split()
                    if len(fields) >= 2:
                        imm = _parse_imm(fields[1])
                        if imm is not None and 0 <= imm < entries:
                            off = struct.unpack_from("<H", raw, imm * 2)[0]
                            if off != 0 and off != 0xFFFF:
                                target = ctbp + off
                                bv.add_user_code_ref(addr, target)
                                annotated += 1
                addr += info.length

    bv.update_analysis()
    bn.log_info(f"CALLT: base={ctbp:#010x}  resolved={len(targets)}  "
                f"xrefs={annotated}")
    return annotated


# ---------- plugin command registration ---------------------------------

def _command_entry(bv):
    try:
        n = apply(bv)
        bn.show_message_box(
            "CALLT analysis",
            f"Annotated {n} CALLT sites.",
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.InformationIcon)
    except Exception as e:
        bn.show_message_box(
            "CALLT analysis failed",
            f"{e}\n\nTry providing CTBP manually via:\n"
            "  callt_analysis.apply(bv, ctbp=0xADDR)",
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.ErrorIcon)


try:
    bn.PluginCommand.register(
        "V850\\Annotate CALLT table",
        "Detect CTBP, walk the CALLT table, and add xrefs to every "
        "callt imm6 site.",
        _command_entry)
except Exception:
    # Safe to fail if imported twice.
    pass
