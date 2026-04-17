"""Recover constant indirect control flow in V850/RH850 Binary Ninja analyses.

The v850 BN architecture plugin decodes and lifts indirect branches, but many
sites remain tagged as unresolved because the target register value is not
propagated far enough during analysis.

This helper does a narrow, practical recovery pass:

- `jmp [reg]` with a constant-resolvable target
- `jarl reg, dst` with a constant-resolvable target
- `jmp [reg]` sites whose `lp` appears to hold the fallthrough address, which
  is a strong hint the jump is acting as an indirect call

For recovered sites it adds user code refs, creates target functions, and
attaches comments so the analyst can distinguish ordinary indirect jumps from
likely call-like dispatch.
"""
from __future__ import annotations

import re
from typing import Optional

import binaryninja as bn

from v850_value_tracker import Insn, normalize_reg, resolve_reg
from switch_analysis import _iter_fn_insns, _in_exec


_BRACKET_REG = re.compile(r"^\[([^\]]+)\]$")


def _indirect_reg(op: str) -> Optional[str]:
    op = op.strip()
    m = _BRACKET_REG.match(op)
    if not m:
        return None
    return normalize_reg(m.group(1))


def _recover_site(bv: "bn.BinaryView", insns: list[Insn], idx: int) -> bool:
    insn = insns[idx]
    m = insn.mnemonic
    ops = insn.operands

    target = None
    note = None

    if m == "jmp" and len(ops) == 1:
        reg = _indirect_reg(ops[0])
        if reg is None:
            return False
        target = resolve_reg(insns, idx, reg)
        lp_val = resolve_reg(insns, idx, "lp")
        if lp_val == (insn.addr + insn.size):
            note = f"likely indirect call via jmp [{reg}]"
        else:
            note = f"indirect jump via [{reg}]"

    elif m == "jarl" and len(ops) == 2:
        reg = normalize_reg(ops[0])
        if reg.startswith("r"):
            target = resolve_reg(insns, idx, reg)
            note = f"indirect call via {reg}"

    if target is None or not _in_exec(bv, target):
        return False

    if bv.get_function_at(target) is None:
        bv.add_function(target)
    bv.add_user_code_ref(insn.addr, target)

    try:
        bv.set_comment_at(insn.addr, f"{note}, resolved_target={target:#010x}")
    except Exception:
        pass

    return True


def apply(bv: "bn.BinaryView") -> int:
    recovered = 0
    for fn in bv.functions:
        insns = _iter_fn_insns(bv, fn)
        for idx, insn in enumerate(insns):
            if insn.mnemonic not in {"jmp", "jarl"}:
                continue
            if _recover_site(bv, insns, idx):
                recovered += 1
    if recovered:
        bv.update_analysis()
    bn.log_info(f"V850 control-flow recovery: recovered {recovered} indirect branch/call sites")
    return recovered


def _cmd(bv):
    try:
        n = apply(bv)
        bn.show_message_box(
            "V850 control-flow recovery",
            f"Recovered {n} constant indirect branch/call sites.",
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.InformationIcon)
    except Exception as e:
        bn.show_message_box(
            "V850 control-flow recovery failed",
            str(e),
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.ErrorIcon)


try:
    bn.PluginCommand.register(
        "V850\\Recover indirect control flow",
        "Resolve constant V850 indirect jmp/jarl targets and annotate likely "
        "call-like dispatch sites.",
        _cmd)
except Exception:
    pass
