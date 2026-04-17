"""Run the full RH850/V850 recovery stack for Ford PSCM firmwares.

This is the convenience entry point:

1. recognize missing PREPARE/addi-sp functions
2. resolve CALLT xrefs via CTBP recovery
3. recover switch/jump tables
4. recover constant indirect jmp/jarl control flow
"""
from __future__ import annotations

import binaryninja as bn

import v850_prologue_recognizer as vpr
import callt_analysis as callt
import switch_analysis as switches
import control_flow_analysis as cflow


def apply(bv: "bn.BinaryView", wait_for_analysis: bool = False) -> dict[str, int]:
    before = len(list(bv.functions))
    out: dict[str, int] = {"before": before}
    out["prologues"] = vpr.apply(bv)
    try:
        out["callt"] = callt.apply(bv)
    except Exception:
        out["callt"] = 0
    out["switches"] = switches.apply(bv)
    out["indirect_cf"] = cflow.apply(bv)
    if wait_for_analysis:
        bv.update_analysis_and_wait()
    out["after"] = len(list(bv.functions))
    out["delta"] = out["after"] - out["before"]
    return out


def _cmd(bv):
    try:
        out = apply(bv)
        body = "\n".join(f"{k}: {v}" for k, v in out.items())
        bn.show_message_box(
            "V850 full recovery",
            body,
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.InformationIcon)
    except Exception as e:
        bn.show_message_box(
            "V850 full recovery failed",
            str(e),
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.ErrorIcon)


try:
    bn.PluginCommand.register(
        "V850\\Run full recovery pass",
        "Run PREPARE, CALLT, switch-table, and indirect-control-flow recovery "
        "passes for V850/RH850 firmware.",
        _cmd)
except Exception:
    pass
