"""Small backward value tracker for V850/RH850 Binary Ninja analyses.

This is intentionally narrow: it resolves constant register values through
the handful of arithmetic/data-movement instructions that appear in switch
setup code and CALLT / CTBP initialisers.

It is not a full emulator. The goal is to recover enough values to annotate
indirect control flow and table bases in Ford PSCM firmwares.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Optional


_REG = re.compile(r"^r([0-9]+|gp|sp|tp|ep|lp)$", re.IGNORECASE)

_ALIASES = {
    "sp": "r3",
    "gp": "r4",
    "tp": "r5",
    "ep": "r30",
    "lp": "r31",
}


def normalize_reg(reg: str) -> str:
    reg = reg.strip().lower()
    return _ALIASES.get(reg, reg)


def is_reg(token: str) -> bool:
    return bool(_REG.match(normalize_reg(token)))


def parse_imm(token: str) -> Optional[int]:
    token = token.strip().rstrip(",")
    try:
        return int(token, 0)
    except ValueError:
        return None


@dataclass(frozen=True)
class Insn:
    addr: int
    mnemonic: str
    operands: tuple[str, ...]
    size: int


def resolve_reg(insns: list[Insn], idx: int, reg: str, depth: int = 0) -> Optional[int]:
    """Resolve `reg` before insns[idx].

    Walks backwards through `insns` and follows a limited set of producers:
    `mov`, `movhi`, `movea`, `addi`, `add`, `sub`, `shl`.
    """
    reg = normalize_reg(reg)
    if reg == "r0":
        return 0
    if depth > 8:
        return None

    for j in range(idx - 1, -1, -1):
        insn = insns[j]
        ops = insn.operands
        m = insn.mnemonic

        # mov src, dst
        if m == "mov" and len(ops) == 2 and normalize_reg(ops[1]) == reg:
            src = normalize_reg(ops[0])
            if is_reg(src):
                return resolve_reg(insns, j, src, depth + 1)
            return parse_imm(ops[0])

        # jarl target, dst_reg  => dst_reg receives return address
        if m == "jarl" and len(ops) == 2 and normalize_reg(ops[1]) == reg:
            return (insn.addr + insn.size) & 0xFFFFFFFF

        # movhi imm, base, dst
        if m == "movhi" and len(ops) == 3 and normalize_reg(ops[2]) == reg:
            imm = parse_imm(ops[0])
            if imm is None:
                return None
            base = ops[1]
            base_val = resolve_reg(insns, j, base, depth + 1) if is_reg(base) else parse_imm(base)
            if base_val is None:
                return None
            return ((imm & 0xFFFF) << 16) + base_val

        # movea/addi imm, base, dst
        if m in {"movea", "addi"} and len(ops) == 3 and normalize_reg(ops[2]) == reg:
            imm = parse_imm(ops[0])
            if imm is None:
                return None
            base = ops[1]
            base_val = resolve_reg(insns, j, base, depth + 1) if is_reg(base) else parse_imm(base)
            if base_val is None:
                return None
            return (base_val + imm) & 0xFFFFFFFF

        # add/sub imm|reg, dst   (two-operand form)
        if m in {"add", "sub", "shl"} and len(ops) == 2 and normalize_reg(ops[1]) == reg:
            lhs = ops[0]
            rhs_val = resolve_reg(insns, j, reg, depth + 1)
            if rhs_val is None:
                return None
            lhs_val = resolve_reg(insns, j, lhs, depth + 1) if is_reg(lhs) else parse_imm(lhs)
            if lhs_val is None:
                return None
            if m == "add":
                return (rhs_val + lhs_val) & 0xFFFFFFFF
            if m == "sub":
                return (rhs_val - lhs_val) & 0xFFFFFFFF
            if m == "shl":
                return (rhs_val << lhs_val) & 0xFFFFFFFF

        # shl imm, src, dst   (three-operand form used in some renderings)
        if m == "shl" and len(ops) == 3 and normalize_reg(ops[2]) == reg:
            imm = parse_imm(ops[0])
            src = normalize_reg(ops[1])
            if imm is None:
                return None
            src_val = resolve_reg(insns, j, src, depth + 1)
            if src_val is None:
                return None
            return (src_val << imm) & 0xFFFFFFFF

    return None
