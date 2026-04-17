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


@dataclass(frozen=True)
class Expr:
    const: int = 0
    reg: Optional[str] = None
    scale: int = 1

    def is_const(self) -> bool:
        return self.reg is None


def _add_expr(a: Expr, b: Expr) -> Optional[Expr]:
    if a.reg is None:
        return Expr(const=(a.const + b.const) & 0xFFFFFFFF, reg=b.reg, scale=b.scale)
    if b.reg is None:
        return Expr(const=(a.const + b.const) & 0xFFFFFFFF, reg=a.reg, scale=a.scale)
    if a.reg == b.reg and a.scale == b.scale:
        return Expr(const=(a.const + b.const) & 0xFFFFFFFF, reg=a.reg, scale=a.scale * 2)
    return None


def _sub_expr(a: Expr, b: Expr) -> Optional[Expr]:
    if b.reg is None:
        return Expr(const=(a.const - b.const) & 0xFFFFFFFF, reg=a.reg, scale=a.scale)
    if a.reg == b.reg and a.scale == b.scale:
        return Expr(const=(a.const - b.const) & 0xFFFFFFFF)
    return None


def _shl_expr(expr: Expr, imm: int) -> Expr:
    return Expr(const=(expr.const << imm) & 0xFFFFFFFF, reg=expr.reg, scale=expr.scale << imm)


def resolve_expr(insns: list[Insn], idx: int, reg: str, depth: int = 0) -> Optional[Expr]:
    """Resolve a narrow symbolic expression for `reg` before insns[idx].

    Expressions are limited to the form:
      const
      const + scale * reg

    That is enough for RH850 jump-table address setup such as:
      shl 2, r6, r6
      movea table, r6, r7
      ld.w 0[r7], r8
      jmp [r8]
    """
    reg = normalize_reg(reg)
    if reg == "r0":
        return Expr(const=0)
    if depth > 8:
        return None

    for j in range(idx - 1, -1, -1):
        insn = insns[j]
        ops = insn.operands
        m = insn.mnemonic

        if m == "mov" and len(ops) == 2 and normalize_reg(ops[1]) == reg:
            src = normalize_reg(ops[0])
            if is_reg(src):
                inner = resolve_expr(insns, j, src, depth + 1)
                if inner is not None:
                    return inner
                return Expr(const=0, reg=src, scale=1)
            imm = parse_imm(ops[0])
            if imm is not None:
                return Expr(const=imm & 0xFFFFFFFF)
            return None

        if m == "jarl" and len(ops) == 2 and normalize_reg(ops[1]) == reg:
            return Expr(const=(insn.addr + insn.size) & 0xFFFFFFFF)

        if m == "movhi" and len(ops) == 3 and normalize_reg(ops[2]) == reg:
            imm = parse_imm(ops[0])
            if imm is None:
                return None
            base = ops[1]
            if is_reg(base):
                base_expr = resolve_expr(insns, j, base, depth + 1)
                if base_expr is None:
                    base_expr = Expr(const=0, reg=normalize_reg(base), scale=1)
            else:
                base_val = parse_imm(base)
                if base_val is None:
                    return None
                base_expr = Expr(const=base_val & 0xFFFFFFFF)
            return Expr(
                const=(((imm & 0xFFFF) << 16) + base_expr.const) & 0xFFFFFFFF,
                reg=base_expr.reg,
                scale=base_expr.scale,
            )

        if m in {"movea", "addi"} and len(ops) == 3 and normalize_reg(ops[2]) == reg:
            imm = parse_imm(ops[0])
            if imm is None:
                return None
            base = ops[1]
            if is_reg(base):
                base_expr = resolve_expr(insns, j, base, depth + 1)
                if base_expr is None:
                    base_expr = Expr(const=0, reg=normalize_reg(base), scale=1)
            else:
                base_val = parse_imm(base)
                if base_val is None:
                    return None
                base_expr = Expr(const=base_val & 0xFFFFFFFF)
            return Expr(
                const=(base_expr.const + imm) & 0xFFFFFFFF,
                reg=base_expr.reg,
                scale=base_expr.scale,
            )

        if m in {"add", "sub", "shl"} and len(ops) == 2 and normalize_reg(ops[1]) == reg:
            lhs = ops[0]
            rhs_expr = resolve_expr(insns, j, reg, depth + 1)
            if rhs_expr is None:
                return None
            if is_reg(lhs):
                lhs_expr = resolve_expr(insns, j, lhs, depth + 1)
                if lhs_expr is None:
                    lhs_expr = Expr(const=0, reg=normalize_reg(lhs), scale=1)
            else:
                lhs_val = parse_imm(lhs)
                if lhs_val is None:
                    return None
                lhs_expr = Expr(const=lhs_val & 0xFFFFFFFF)

            if m == "add":
                return _add_expr(rhs_expr, lhs_expr)
            if m == "sub":
                return _sub_expr(rhs_expr, lhs_expr)
            if lhs_expr.reg is None:
                return _shl_expr(rhs_expr, lhs_expr.const)
            return None

        if m == "shl" and len(ops) == 3 and normalize_reg(ops[2]) == reg:
            imm = parse_imm(ops[0])
            src = normalize_reg(ops[1])
            if imm is None:
                return None
            src_expr = resolve_expr(insns, j, src, depth + 1)
            if src_expr is None:
                src_expr = Expr(const=0, reg=src, scale=1)
            return _shl_expr(src_expr, imm)

    return None


def resolve_reg(insns: list[Insn], idx: int, reg: str, depth: int = 0) -> Optional[int]:
    """Resolve `reg` before insns[idx].

    Walks backwards through `insns` and follows a limited set of producers:
    `mov`, `movhi`, `movea`, `addi`, `add`, `sub`, `shl`.
    """
    expr = resolve_expr(insns, idx, reg, depth=depth)
    if expr is None or not expr.is_const():
        return None
    return expr.const
