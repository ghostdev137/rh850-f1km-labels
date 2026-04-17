"""Recover V850/RH850 switch tables in Binary Ninja.

This reimplements the useful parts of IDA's NEC850 switch recogniser in a
Binary Ninja-friendly way:

1. Detect `switch rA`-style table jumps.
2. Recover nearby `cmp/addi + conditional branch` bounds/default metadata.
3. Recover optional lowcase adjustments via `movea/add`.
4. Detect the common `shl + jmp table[rA]` variant and walk JR tables.
5. Add user code xrefs from the indirect branch site to every recovered case.

The focus is Ford/TKP RH850 PSCM firmwares, where unresolved indirect control
flow is dominated by switch tables and CALLT sites.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable, Optional

import binaryninja as bn

from v850_value_tracker import Expr, Insn, normalize_reg, parse_imm, resolve_expr, resolve_reg


def _define_function(bv: "bn.BinaryView", addr: int) -> None:
    if hasattr(bv, "create_user_function"):
        bv.create_user_function(addr)
    else:
        bv.add_function(addr)


@dataclass(frozen=True)
class Recovery:
    site: int
    kind: str
    index_reg: str
    table_base: int
    ncases: int
    lowcase: int
    default: Optional[int]
    targets: tuple[int, ...]


def _iter_fn_insns(bv: "bn.BinaryView", fn) -> list[Insn]:
    insns: list[Insn] = []
    seen: set[int] = set()
    for bb in fn.basic_blocks:
        addr = bb.start
        while addr < bb.end:
            if addr in seen:
                break
            seen.add(addr)
            info = bv.arch.get_instruction_info(bv.read(addr, 8), addr)
            if info is None or info.length == 0:
                break
            text = (bv.get_disassembly(addr) or "").strip()
            if " " in text:
                mnemonic, rest = text.split(None, 1)
                operands = tuple(op.strip() for op in rest.split(","))
            else:
                mnemonic, operands = text, ()
            insns.append(Insn(addr=addr, mnemonic=mnemonic.lower(), operands=operands, size=info.length))
            addr += info.length
    insns.sort(key=lambda x: x.addr)
    return insns


def _info_for(bv: "bn.BinaryView", addr: int):
    return bv.arch.get_instruction_info(bv.read(addr, 8), addr)


def _branch_target(bv: "bn.BinaryView", addr: int) -> Optional[int]:
    info = _info_for(bv, addr)
    if info is None:
        return None
    for br in info.branches:
        target = getattr(br, "target", None)
        if target is not None:
            return target
    return None


def _next_insn(insns: list[Insn], idx: int) -> Optional[Insn]:
    return insns[idx + 1] if idx + 1 < len(insns) else None


def _find_lowcase(insns: list[Insn], idx: int, reg: str) -> int:
    reg = normalize_reg(reg)
    for j in range(max(0, idx - 3), idx):
        insn = insns[j]
        ops = insn.operands
        if insn.mnemonic in {"movea", "addi"} and len(ops) == 3 and normalize_reg(ops[2]) == reg and normalize_reg(ops[1]) == reg:
            imm = parse_imm(ops[0])
            if imm is not None and imm < 0:
                return -imm
        if insn.mnemonic == "add" and len(ops) == 2 and normalize_reg(ops[1]) == reg:
            imm = parse_imm(ops[0])
            if imm is not None and imm < 0:
                return -imm
    return 0


def _default_for_branch(bv: "bn.BinaryView", insns: list[Insn], branch_idx: int) -> tuple[Optional[int], bool]:
    """Return (default_target, inc_ncases)."""
    insn = insns[branch_idx]
    m = insn.mnemonic
    target = _branch_target(bv, insn.addr)
    next_insn = _next_insn(insns, branch_idx)

    # Mirrors the V850 patterns used by IDA:
    #   bh / bnc : branch goes to default, case count is exact
    #   bl / bnh : branch goes into switch body, default is fallthrough/jr
    if m in {"bh", "bnc"}:
        return target, m == "bh"
    if m in {"bl", "bnh"}:
        default = next_insn.addr if next_insn else None
        if next_insn and next_insn.mnemonic == "jr":
            default = _branch_target(bv, next_insn.addr)
        return default, m == "bnh"
    return None, False


def _ncases_from_cmp(insns: list[Insn], cmp_idx: int, reg: str, inc: bool) -> Optional[int]:
    insn = insns[cmp_idx]
    ops = insn.operands
    reg = normalize_reg(reg)

    if insn.mnemonic == "cmp" and len(ops) == 2 and normalize_reg(ops[1]) == reg:
        val = resolve_reg(insns, cmp_idx, ops[0]) if normalize_reg(ops[0]).startswith("r") else parse_imm(ops[0])
        if val is None:
            return None
        return int(val) + (1 if inc else 0)

    if insn.mnemonic == "addi" and len(ops) == 3 and normalize_reg(ops[1]) == reg and normalize_reg(ops[2]) == "r0":
        imm = parse_imm(ops[0])
        if imm is None or imm >= 0:
            return None
        return -imm + (1 if inc else 0)

    return None


def _find_bounds(insns: list[Insn], idx: int, reg: str, bv: "bn.BinaryView") -> tuple[Optional[int], Optional[int], int]:
    """Return (ncases, default, lowcase)."""
    reg = normalize_reg(reg)
    branch_idx = cmp_idx = None
    for j in range(idx - 1, max(-1, idx - 7), -1):
        if j < 0:
            break
        m = insns[j].mnemonic
        if branch_idx is None and m in {"bh", "bnc", "bl", "bnh"}:
            branch_idx = j
            continue
        if branch_idx is not None and m in {"cmp", "addi"}:
            cmp_idx = j
            break
    if branch_idx is None or cmp_idx is None:
        return None, None, 0

    default, inc_ncases = _default_for_branch(bv, insns, branch_idx)
    ncases = _ncases_from_cmp(insns, cmp_idx, reg, inc_ncases)
    lowcase = _find_lowcase(insns, cmp_idx, reg)
    return ncases, default, lowcase


def _in_exec(bv: "bn.BinaryView", addr: int) -> bool:
    seg = bv.get_segment_at(addr)
    return seg is not None and seg.executable


def _recover_switch_table(bv: "bn.BinaryView", insns: list[Insn], idx: int) -> Optional[Recovery]:
    insn = insns[idx]
    if insn.mnemonic != "switch" or len(insn.operands) != 1:
        return None

    reg = normalize_reg(insn.operands[0])
    ncases, default, lowcase = _find_bounds(insns, idx, reg, bv)
    if ncases is None or ncases <= 0 or ncases > 0x2000:
        return None

    table_base = insn.addr + insn.size
    raw = bv.read(table_base, ncases * 2)
    if len(raw) != ncases * 2:
        return None

    targets: list[int] = []
    for i in range(ncases):
        off = struct.unpack_from("<h", raw, i * 2)[0]
        target = (table_base + (off << 1)) & 0xFFFFFFFF
        if _in_exec(bv, target):
            targets.append(target)
    if not targets:
        return None

    return Recovery(
        site=insn.addr,
        kind="switch",
        index_reg=reg,
        table_base=table_base,
        ncases=ncases,
        lowcase=lowcase,
        default=default,
        targets=tuple(targets),
    )


def _parse_jmp_table_operand(op: str) -> tuple[Optional[int], Optional[str]]:
    # Matches "0x200[r6]" or "-0x20[r10]"
    if "[" not in op or "]" not in op:
        return None, None
    disp_s, reg_s = op.split("[", 1)
    reg = reg_s.rstrip("]").strip()
    disp = parse_imm(disp_s.strip()) if disp_s.strip() else 0
    if disp is None:
        return None, None
    return disp, normalize_reg(reg)


def _recover_jmp_table(bv: "bn.BinaryView", insns: list[Insn], idx: int) -> Optional[Recovery]:
    insn = insns[idx]
    if insn.mnemonic != "jmp" or len(insn.operands) != 1:
        return None
    disp, reg = _parse_jmp_table_operand(insn.operands[0])
    if reg is None:
        return None

    shl_idx = None
    elsize = None
    for j in range(idx - 1, max(-1, idx - 6), -1):
        if j < 0:
            break
        prev = insns[j]
        if prev.mnemonic == "shl" and len(prev.operands) >= 2 and normalize_reg(prev.operands[-1]) == reg:
            imm = parse_imm(prev.operands[0])
            if imm == 1:
                shl_idx, elsize = j, 2
                break
            if imm == 2:
                shl_idx, elsize = j, 4
                break
    if shl_idx is None or elsize is None:
        return None

    ncases, default, lowcase = _find_bounds(insns, shl_idx, reg, bv)
    if ncases is None or ncases <= 0 or ncases > 0x2000:
        return None

    table_base = disp
    targets: list[int] = []
    for i in range(ncases):
        entry_addr = table_base + i * elsize
        info = _info_for(bv, entry_addr)
        if info is None:
            continue
        for br in info.branches:
            target = getattr(br, "target", None)
            if target is not None and _in_exec(bv, target):
                targets.append(target)
                break
    if not targets:
        return None

    return Recovery(
        site=insn.addr,
        kind="jmp-table",
        index_reg=reg,
        table_base=table_base,
        ncases=ncases,
        lowcase=lowcase,
        default=default,
        targets=tuple(targets),
    )


def _parse_mem_operand(op: str) -> tuple[Optional[int], Optional[str]]:
    if "[" not in op or "]" not in op:
        return None, None
    disp_s, reg_s = op.split("[", 1)
    reg = normalize_reg(reg_s.rstrip("]").strip())
    disp = parse_imm(disp_s.strip()) if disp_s.strip() else 0
    if disp is None:
        return None, None
    return disp, reg


def _extract_table_base(expr: Expr, disp: int) -> Optional[tuple[int, str, int]]:
    if expr.reg is None:
        return None
    scale = expr.scale
    if scale not in {1, 2, 4, 8}:
        return None
    return ((expr.const + disp) & 0xFFFFFFFF, expr.reg, scale)


def _recover_ldw_jmp_table(bv: "bn.BinaryView", insns: list[Insn], idx: int) -> Optional[Recovery]:
    insn = insns[idx]
    if insn.mnemonic != "jmp" or len(insn.operands) != 1:
        return None

    target_reg = _indirect_target_reg(insn.operands[0])
    if target_reg is None:
        return None

    ld_idx = None
    ld_insn = None
    for j in range(idx - 1, max(-1, idx - 4), -1):
        if j < 0:
            break
        cand = insns[j]
        if cand.mnemonic not in {"ld.w", "ldw"} or len(cand.operands) != 2:
            continue
        if normalize_reg(cand.operands[1]) != target_reg:
            continue
        ld_idx = j
        ld_insn = cand
        break
    if ld_idx is None or ld_insn is None:
        return None

    disp, addr_reg = _parse_mem_operand(ld_insn.operands[0])
    if addr_reg is None:
        return None
    addr_expr = resolve_expr(insns, ld_idx, addr_reg)
    if addr_expr is None:
        return None
    table_info = _extract_table_base(addr_expr, disp)
    if table_info is None:
        return None
    table_base, index_reg, elsize = table_info

    ncases, default, lowcase = _find_bounds(insns, ld_idx, index_reg, bv)
    if ncases is None or ncases <= 0 or ncases > 0x2000:
        return None

    targets: list[int] = []
    for i in range(ncases):
        entry_addr = table_base + i * elsize
        raw = bv.read(entry_addr, 4)
        if len(raw) != 4:
            continue
        direct = struct.unpack_from("<I", raw, 0)[0]
        if _in_exec(bv, direct):
            targets.append(direct)
            continue
        rel = (table_base + i * elsize + struct.unpack_from("<i", raw, 0)[0]) & 0xFFFFFFFF
        if _in_exec(bv, rel):
            targets.append(rel)
    if not targets:
        return None

    return Recovery(
        site=insn.addr,
        kind="ldw-jmp-table",
        index_reg=index_reg,
        table_base=table_base,
        ncases=ncases,
        lowcase=lowcase,
        default=default,
        targets=tuple(targets),
    )


def _indirect_target_reg(op: str) -> Optional[str]:
    op = op.strip()
    if not (op.startswith("[") and op.endswith("]")):
        return None
    return normalize_reg(op[1:-1])


def apply(bv: "bn.BinaryView") -> int:
    """Recover switch tables and annotate them with user code xrefs."""
    recovered = 0
    seen_sites: set[int] = set()

    for fn in bv.functions:
        insns = _iter_fn_insns(bv, fn)
        for idx, insn in enumerate(insns):
            rec = None
            if insn.mnemonic == "switch":
                rec = _recover_switch_table(bv, insns, idx)
            elif insn.mnemonic == "jmp":
                rec = _recover_jmp_table(bv, insns, idx) or _recover_ldw_jmp_table(bv, insns, idx)
            if rec is None or rec.site in seen_sites:
                continue

            seen_sites.add(rec.site)
            for target in rec.targets:
                if bv.get_function_at(target) is None:
                    _define_function(bv, target)
                bv.add_user_code_ref(rec.site, target)
            if rec.default is not None and _in_exec(bv, rec.default):
                bv.add_user_code_ref(rec.site, rec.default)

            try:
                case_count = len(rec.targets)
                comment = (
                    f"{rec.kind} table @ {rec.table_base:#010x}, "
                    f"index={rec.index_reg}, lowcase={rec.lowcase}, "
                    f"cases={case_count}"
                )
                if rec.default is not None:
                    comment += f", default={rec.default:#010x}"
                bv.set_comment_at(rec.site, comment)
            except Exception:
                pass

            recovered += 1

    if recovered:
        bv.update_analysis()
    bn.log_info(f"V850 switch analysis: recovered {recovered} switch/jump-table sites")
    return recovered


def _cmd(bv):
    try:
        n = apply(bv)
        bn.show_message_box(
            "V850 switch analysis",
            f"Recovered {n} switch / jump-table sites.",
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.InformationIcon)
    except Exception as e:
        bn.show_message_box(
            "V850 switch analysis failed",
            str(e),
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.ErrorIcon)


try:
    bn.PluginCommand.register(
        "V850\\Recover switch tables",
        "Detect V850 switch/jump-table patterns, add user code refs to case "
        "targets, and create functions at recovered destinations.",
        _cmd)
except Exception:
    pass
