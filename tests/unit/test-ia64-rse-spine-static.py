#!/usr/bin/env python3
"""Structural contract checks for the typed IA-64 RSE spine."""

from __future__ import annotations

import argparse
from pathlib import Path


def region(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def ordered(text: str, *needles: str) -> None:
    offsets = [text.index(needle) for needle in needles]
    assert offsets == sorted(offsets), f"out-of-order contract: {needles!r}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root
    translate = (root / "target/ia64/translate.c").read_text(encoding="utf-8")
    arch_helpers = (root / "target/ia64/arch-helpers.c").read_text(
        encoding="utf-8"
    )
    insn = (root / "target/ia64/insn.c").read_text(encoding="utf-8")
    rse = (root / "target/ia64/rse.c").read_text(encoding="utf-8")

    admission = region(
        translate,
        "static bool ia64_tr_decoded_opcode_supported",
        "static unsigned ia64_tr_decoded_sources",
    )
    assert "ia64_opcode_traits_for" in admission
    assert "IA64_OPCODE_OWNER_FOCUSED_HELPER" in admission

    emitter = region(
        translate,
        "static bool ia64_tr_emit_decoded_rse_spine",
        "static bool ia64_tr_try_decoded_bundle",
    )
    for helper in (
        "gen_helper_rse_alloc",
        "gen_helper_rse_cover",
        "gen_helper_rse_flushrs",
        "gen_helper_rse_loadrs",
        "gen_helper_rse_clrrrb",
    ):
        assert helper in emitter
    assert "gen_helper_exec_bundle" not in emitter
    assert "gen_helper_exec_slot" not in emitter
    static_noreturn = region(
        translate,
        "static bool ia64_tr_rse_spine_is_static_noreturn",
        "static void ia64_tr_rewrite_plan_reset",
    )
    for legality in (
        "insn->r1 == 0",
        "insn->r1 >= IA64_STATIC_GR_COUNT + sof",
        "insn->qp != 0",
        "sof > IA64_RSE_PHYS_STACKED_REGS",
        "sol > sof",
        "sor * 8 > sof",
    ):
        assert legality in static_noreturn
    preflight_terminal = region(
        translate,
        "static bool ia64_tr_first_rse_static_noreturn",
        "static bool ia64_tr_decoded_bundle_has_system",
    )
    assert "ia64_tr_rse_spine_is_static_noreturn(insn)" in preflight_terminal
    ordered(emitter, "ia64_tr_rse_spine_is_static_noreturn(insn)",
            "ia64_tr_publish_fault_state")
    ordered(emitter, "ia64_tr_publish_fault_state", "gen_helper_rse_alloc")
    ordered(emitter, "gen_helper_rse_alloc", "ia64_tr_finish_faulting_slot")

    dispatch = region(
        translate,
        "static bool ia64_tr_try_decoded_bundle",
        "static bool ia64_tr_emit_decoded_return_split",
    )
    ordered(dispatch,
            "ia64_tr_split_state_cache_at_typed_branch(ctx)",
            "ia64_tr_group_begin_instruction(ctx, insn)",
            "ia64_tr_emit_decoded_rse_spine(ctx, insn)",
            "ia64_tr_group_finish_instruction_success(ctx, insn)")

    helper = region(arch_helpers, "uint64_t HELPER(rse_alloc)",
                    "void HELPER(rse_cover)")
    ordered(helper, "ia64_rse_validate_alloc", "ia64_rse_spill_for_alloc",
            "ia64_rse_commit_alloc")

    spill = region(
        insn,
        "IA64RSEStepResult ia64_rse_spill_excess_dirty_interruptible",
        "uint32_t ia64_rse_spill_excess_dirty",
    )
    spill_poll_before = spill.index("interruption_pending(env, opaque)")
    spill_step = spill.index("ia64_rse_mandatory_store_step",
                             spill_poll_before)
    spill_poll_after = spill.index("interruption_pending(env, opaque)",
                                   spill_step)
    assert spill_poll_before < spill_step < spill_poll_after
    assert "*spilled_registers = spilled" in spill

    flush = region(
        insn,
        "IA64RSEStepResult ia64_rse_flush_dirty_interruptible",
        "IA64RSEStepResult ia64_rse_mandatory_load_step",
    )
    flush_poll_before = flush.index("interruption_pending(env, opaque)")
    flush_step = flush.index("ia64_rse_mandatory_store_step",
                             flush_poll_before)
    flush_poll_after = flush.index("interruption_pending(env, opaque)",
                                   flush_step)
    assert flush_poll_before < flush_step < flush_poll_after

    legality = region(
        insn,
        "bool ia64_rse_loadrs_is_legal",
        "static IA64RSEStepResult ia64_rse_loadrs_word_step",
    )
    ordered(legality, "requested_registers++",
            "requested_registers <= IA64_RSE_PHYS_STACKED_REGS")

    loadrs = region(
        insn,
        "IA64RSEStepResult ia64_rse_execute_loadrs_interruptible",
        "uint64_t ia64_read_application_register",
    )
    loadrs_preflight = loadrs.index("!ia64_rse_loadrs_is_legal(env)")
    loadrs_sync = loadrs.index("ia64_rse_sync_logical_out(env)",
                               loadrs_preflight)
    loadrs_poll_before = loadrs.index("interruption_pending(env, opaque)",
                                      loadrs_sync)
    loadrs_step = loadrs.index("ia64_rse_loadrs_word_step",
                               loadrs_poll_before)
    loadrs_poll_after = loadrs.index("interruption_pending(env, opaque)",
                                     loadrs_step)
    loadrs_finish = loadrs.index("ia64_rse_clear_rnat(env)",
                                 loadrs_poll_after)
    assert (loadrs_preflight < loadrs_sync < loadrs_poll_before <
            loadrs_step < loadrs_poll_after < loadrs_finish)
    assert "ia64_raise_illegal_operation" not in loadrs

    runtime_flush = region(rse, "void ia64_exec_flushrs",
                           "static uint64_t ia64_rse_read_backing_store")
    runtime_alloc = region(rse, "void ia64_rse_spill_for_alloc",
                           "static bool ia64_rse_read_mandatory_word")
    runtime_loadrs = rse[rse.index("void ia64_exec_loadrs"):]
    for runtime in (runtime_flush, runtime_alloc, runtime_loadrs):
        assert "ia64_rse_mandatory_word_interruption_pending" in runtime
        assert "ia64_rse_finish_mandatory_sequence" in runtime

    loadrs_helper = region(arch_helpers, "void HELPER(rse_loadrs)",
                           "void HELPER(rse_clrrrb)")
    ordered(loadrs_helper, "ia64_rse_loadrs_is_legal",
            "ia64_arch_raise_illegal", "ia64_exec_loadrs")


if __name__ == "__main__":
    main()
