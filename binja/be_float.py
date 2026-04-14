"""Big-endian float utilities for V850/RH850 Ford/TKP cal regions.

Ford PSCM and related TKP / Thyssenkrupp firmwares ship calibration blocks
as big-endian IEEE-754 floats, even though the V850 / RH850 host is
little-endian. BN's native `float` type decodes with the host endianness,
so cal regions render as tiny denormals (garbage). These helpers wrap each
4-byte word as `uint32_t` + an inline `// be_f32 = <value>` comment, which
gives you a readable linear view without waiting for BN to grow a native
float-endianness override.

Usage (BN Python console):

    import sys; sys.path.insert(0, "/Users/rossfisher/src/rh850-f1km-labels/binja")
    import be_float as bf
    bf.apply_region(bv, 0x00FD0000, 0xFFF0)          # whole cal
    bf.apply_array(bv, 0x00FD0038, 10, "speed_bp")   # one table
    bf.read_array(bv, 0x00FD0038, 10)                # returns [5.0, 10.0, ...]

It also registers a plugin command under
Plugins -> V850 -> Decode region as big-endian floats.
"""
from __future__ import annotations

import math
import struct
from typing import List, Optional

import binaryninja as bn


def _plausible(bytes4: bytes) -> Optional[float]:
    if bytes4 == b"\xff\xff\xff\xff" or bytes4 == b"\x00\x00\x00\x00":
        return None
    f = struct.unpack(">f", bytes4)[0]
    if not math.isfinite(f):
        return None
    af = abs(f)
    if af == 0 or (1e-6 < af < 1e8):
        return f
    return None


def read_array(bv: "bn.BinaryView", addr: int, count: int) -> List[float]:
    raw = bv.read(addr, count * 4)
    return [struct.unpack(">f", raw[i * 4 : i * 4 + 4])[0]
            for i in range(count)]


def apply_array(bv: "bn.BinaryView", addr: int, count: int,
                name: str) -> int:
    """Type `count` big-endian floats as a named `uint32_t` array with
    per-element inline comments.
    """
    u32 = bn.Type.int(4, False)
    try:
        bv.define_user_data_var(
            addr, bn.Type.array(u32, count))
        bv.define_user_symbol(bn.Symbol(
            bn.SymbolType.DataSymbol, addr, name))
    except Exception:
        pass

    raw = bv.read(addr, count * 4)
    for i in range(count):
        b = raw[i * 4 : i * 4 + 4]
        f = _plausible(b)
        if f is not None:
            bv.set_comment_at(addr + i * 4, f"be_f32 = {f:.6g}")
    return count


def apply_region(bv: "bn.BinaryView", start: int, size: int,
                 skip_ff: bool = True) -> int:
    """Walk a region 4 bytes at a time; type each word as uint32_t and
    annotate BE-float-plausible words with an inline comment.

    Returns the number of words annotated (not merely typed).
    """
    u32 = bn.Type.int(4, False)
    annotated = 0
    data = bv.read(start, size)
    for off in range(0, size - 3, 4):
        b = data[off : off + 4]
        if skip_ff and b == b"\xff\xff\xff\xff":
            continue
        addr = start + off
        if bv.get_data_var_at(addr) is None:
            try:
                bv.define_user_data_var(addr, u32)
            except Exception:
                pass
        f = _plausible(b)
        if f is not None:
            bv.set_comment_at(addr, f"be_f32 = {f:.6g}")
            annotated += 1
    return annotated


# ---------- plugin command -----------------------------------------------

def _cmd(bv, start, size):
    try:
        n = apply_region(bv, int(start), int(size))
        bn.show_message_box(
            "be_float", f"Annotated {n} BE-float words.",
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.InformationIcon)
    except Exception as e:
        bn.show_message_box(
            "be_float failed", str(e),
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.ErrorIcon)


try:
    bn.PluginCommand.register_for_range(
        "V850\\Decode selection as big-endian floats",
        "Treat each 4-byte word in the selection as a big-endian IEEE-754 "
        "float; type as uint32_t and annotate with a `// be_f32 = val` "
        "comment.",
        _cmd)
except Exception:
    pass
