#!/usr/bin/env python3
"""Structural guardrails for the IA-64 full-TCG rewrite path."""

from __future__ import annotations

import pathlib
import re
import sys


def section(source: str, start: str, end: str) -> str:
    begin = source.find(start)
    finish = source.find(end, begin + len(start))
    if begin < 0 or finish < 0:
        raise AssertionError(f"missing section markers: {start!r}, {end!r}")
    return source[begin:finish]


def require(source: str, tokens: tuple[str, ...], label: str) -> None:
    missing = [token for token in tokens if token not in source]
    if missing:
        raise AssertionError(f"{label} is missing: {', '.join(missing)}")


def forbid(source: str, tokens: tuple[str, ...], label: str) -> None:
    present = [token for token in tokens if token in source]
    if present:
        raise AssertionError(f"{label} contains forbidden seams: "
                             f"{', '.join(present)}")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} TRANSLATE_C")

    path = pathlib.Path(sys.argv[1])
    source = path.read_text(encoding="utf-8")
    interp_source = path.with_name("interp.c").read_text(encoding="utf-8")
    insn_source = path.with_name("insn.c").read_text(encoding="utf-8")
    insn_header = path.with_name("insn.h").read_text(encoding="utf-8")
    rse_source = path.with_name("rse.c").read_text(encoding="utf-8")
    helper_source = path.with_name("helper.h").read_text(encoding="utf-8")
    exception_source = path.with_name("exception.c").read_text(
        encoding="utf-8"
    )
    cpu_source = path.with_name("cpu.c").read_text(encoding="utf-8")
    cpu_header = path.with_name("cpu.h").read_text(encoding="utf-8")
    machine_source = path.with_name("machine.c").read_text(encoding="utf-8")
    classifier_source = path.with_name("tcg-classify.c").read_text(
        encoding="utf-8"
    )
    rewrite = section(source,
                      "static bool ia64_tr_decoded_is_noop",
                      "static bool ia64_tr_translate_fast_bundle")
    supported = section(source,
                        "static bool ia64_tr_decoded_opcode_supported",
                        "static unsigned ia64_tr_decoded_sources")
    lower = section(source,
                    "static void ia64_tr_emit_decoded_instruction",
                    "static void ia64_tr_clear_restart_ri")
    predicate_lower = section(
        source,
        "static void ia64_tr_emit_decoded_integer_compare",
        "static void ia64_tr_emit_decoded_instruction",
    )
    compare_admission = section(
        source,
        "typedef enum IA64TrDecodedCompareSource",
        "static bool ia64_tr_decoded_opcode_supported",
    )
    predicate_test_admission = section(
        source,
        "typedef enum IA64TrDecodedPredicateTestKind",
        "static bool ia64_tr_decoded_is_supported_integer_compare",
    )
    predicate_test_lower = section(
        source,
        "static void ia64_tr_emit_decoded_predicate_test",
        "static void ia64_tr_emit_decoded_instruction",
    )
    illegal_lower = section(
        source,
        "static void ia64_tr_emit_decoded_illegal_operation",
        "static bool ia64_tr_decoded_is_noop",
    )
    pr_move_lower = section(
        source,
        "static void ia64_tr_emit_decoded_register_nat_consumption",
        "static unsigned ia64_tr_decoded_bitfield_pos",
    )
    pr_image_load = section(
        source,
        "static void ia64_tr_group_load_ordinary_pr_image",
        "static void ia64_tr_group_load_ordinary_predicate",
    )
    br_ordinary_load = section(
        source,
        "static void ia64_tr_group_load_ordinary_br",
        "static void ia64_tr_group_load_ordinary_pr_image",
    )
    branch_forward = section(
        source,
        "static void ia64_tr_group_update_branch_forward_predicate",
        "static void ia64_tr_group_preserve_ordinary_gr_source",
    )
    br_forward = section(
        source,
        "static void ia64_tr_group_update_branch_forward_br",
        "static void ia64_tr_group_load_branch_predicate",
    )
    br_preserve = section(
        source,
        "static void ia64_tr_group_preserve_ordinary_br_source",
        "static void ia64_tr_group_preserve_ordinary_pr_source",
    )
    branch_br_load = section(
        source,
        "static void ia64_tr_group_load_branch_br",
        "static void ia64_tr_group_preserve_ordinary_gr_source",
    )
    typed_taken_visibility = section(
        source,
        "static void ia64_tr_store_typed_taken_visibility_state",
        "static void ia64_tr_emit_typed_direct_branch_exit",
    )
    typed_direct_branch_exit = section(
        source,
        "static void ia64_tr_emit_typed_direct_branch_exit",
        "static void ia64_tr_emit_typed_indirect_branch_exit",
    )
    typed_indirect_branch_exit = section(
        source,
        "static void ia64_tr_emit_typed_indirect_branch_exit",
        "static void ia64_tr_emit_typed_return_exit",
    )
    typed_return_exit = section(
        source,
        "static void ia64_tr_emit_typed_return_exit",
        "static void ia64_tr_split_state_cache_at_typed_branch",
    )
    deferred_return_retire = section(
        source,
        "static void ia64_tr_retire_fast_bundle_ticks_deferred_interrupt",
        "static void ia64_tr_commit_ip",
    )
    loop_classifier = section(
        source,
        "static bool ia64_tr_decoded_is_loop_branch",
        "static bool ia64_tr_decoded_is_conditional_branch",
    )
    call_classifier = section(
        source,
        "static bool ia64_tr_decoded_is_call_branch",
        "static bool ia64_tr_decoded_is_return_branch",
    )
    return_classifier = section(
        source,
        "static bool ia64_tr_decoded_is_return_branch",
        "static bool ia64_tr_decoded_is_conditional_branch",
    )
    call_admission = section(
        source,
        "static bool ia64_tr_decoded_instruction_supported",
        "static void ia64_tr_rewrite_plan_reset",
    )
    call_transition = section(
        source,
        "static void ia64_tr_emit_call_frame_transition",
        "static void ia64_tr_assert_loop_branch_resources",
    )
    loop_resource_assert = section(
        source,
        "static void ia64_tr_assert_loop_branch_resources",
        "static void ia64_tr_emit_decoded_loop_branch_split",
    )
    loop_lower = section(
        source,
        "static void ia64_tr_emit_decoded_loop_branch_split(\n"
        "    DisasContext *ctx, const IA64Instruction *insn,\n"
        "    IA64TrDecodedBranchArm *arm)\n{",
        "static bool ia64_tr_emit_decoded_branch_split",
    )
    call_resource_assert = section(
        source,
        "static void ia64_tr_assert_call_branch_resources",
        "static bool ia64_tr_emit_decoded_call_split",
    )
    return_resource_assert = section(
        source,
        "static void ia64_tr_assert_return_branch_resources",
        "static bool ia64_tr_emit_decoded_return_split",
    )
    return_lower = section(
        source,
        "static bool ia64_tr_emit_decoded_return_split(\n"
        "    DisasContext *ctx, const IA64Instruction *insn,\n"
        "    IA64TrDecodedBranchArm *arm)\n{",
        "static void ia64_tr_assert_call_branch_resources",
    )
    call_lower = section(
        source,
        "static bool ia64_tr_emit_decoded_call_split(\n"
        "    DisasContext *ctx, const IA64Instruction *insn,\n"
        "    IA64TrDecodedBranchArm *arm)\n{",
        "static bool ia64_tr_emit_decoded_branch_split",
    )
    typed_branch_split = section(
        source,
        "static bool ia64_tr_emit_decoded_branch_split(\n"
        "    DisasContext *ctx, const IA64Instruction *insn,\n"
        "    IA64TrDecodedBranchArm *arm)\n{",
        "static void ia64_tr_emit_decoded_branch_cfg_exits(\n"
        "    DisasContext *ctx, IA64TrDecodedBranchArm",
    )
    typed_branch_cfg_exits = section(
        source,
        "static void ia64_tr_emit_decoded_branch_cfg_exits(\n"
        "    DisasContext *ctx, IA64TrDecodedBranchArm arms[IA64_SLOT_COUNT],\n"
        "    unsigned arm_count, bool has_fallthrough, uint64_t fallthrough_target,\n"
        "    bool fallthrough_group_start, bool fallthrough_typed_active)\n{",
        "static void ia64_tr_emit_inline_indirect_branch_exit",
    )
    branch_cfg_preflight = section(
        source,
        "static bool ia64_tr_preflight_branch_cfg",
        "static bool ia64_tr_preflight_to_first_stop",
    )
    rewrite_plan = section(
        source,
        "static void ia64_tr_rewrite_plan_append(",
        "static void ia64_tr_rewrite_plan_append_bundle",
    )
    rewrite_liveness = section(
        source,
        "static void ia64_tr_rewrite_plan_finalize",
        "static bool ia64_tr_preflight_decoded_bundle_through",
    )
    nat_helper = section(
        interp_source,
        "G_NORETURN void HELPER(raise_register_nat_consumption)",
        "void HELPER(perf_tb_exec)",
    )
    rotation_helper = section(
        interp_source,
        "void HELPER(rotate_modulo_registers)",
        "typedef enum IA64PlannedSlotResult",
    )
    rotation_core = section(
        insn_source,
        "void ia64_rotate_modulo_scheduled_registers",
        "static void ia64_cover_stack_frame",
    )
    call_frame_core = section(
        insn_source,
        "void ia64_enter_call_frame(CPUIA64State *env)\n{",
        "bool ia64_rse_return_frame_from_pfs",
    )
    call_frame_helper = section(
        interp_source,
        "void HELPER(enter_call_frame)(CPUIA64State *env)\n{",
        "typedef enum IA64PlannedSlotResult",
    )
    return_frame_core = section(
        insn_source,
        "bool ia64_rse_return_frame_from_pfs(CPUIA64State *env, uint64_t pfs)\n{",
        "bool ia64_return_from_call_frame",
    )
    return_partition_core = section(
        insn_source,
        "static bool ia64_rse_return_to_frame(CPUIA64State *env, uint64_t pfm,",
        "static uint32_t ia64_stacked_gr_slot",
    )
    return_partition_adjust = section(
        insn_source,
        "static bool ia64_rse_restore_frame_partitions",
        "static bool ia64_rse_return_to_frame",
    )
    return_frame_helper = section(
        interp_source,
        "uint32_t HELPER(return_frame_from_pfs)(CPUIA64State *env, uint64_t pfs)\n{",
        "void HELPER(complete_rse_frame_loads)",
    )
    return_fill_helper = section(
        interp_source,
        "void HELPER(complete_rse_frame_loads)(CPUIA64State *env)\n{",
        "uint32_t HELPER(return_chain_ok)",
    )
    return_chain_helper = section(
        interp_source,
        "uint32_t HELPER(return_chain_ok)(CPUIA64State *env)\n{",
        "static G_NORETURN void ia64_raise_branch_trap",
    )
    return_trap_helpers = section(
        interp_source,
        "static G_NORETURN void ia64_raise_branch_trap",
        "typedef enum IA64PlannedSlotResult",
    )
    interruption_isr = section(
        exception_source,
        "static uint64_t ia64_interruption_isr",
        "const char *ia64_exception_name",
    )
    interruption_delivery = section(
        exception_source,
        "static void ia64_deliver_exception_common",
        "void ia64_deliver_exception(CPUIA64State *env",
    )
    cpu_exec_interrupt = section(
        cpu_source,
        "static bool ia64_cpu_exec_interrupt",
        "void ia64_cpu_dump_state",
    )
    mandatory_load_completion = section(
        insn_source,
        "IA64RSEStepResult ia64_rse_complete_mandatory_loads_interruptible",
        "typedef struct IA64RSELegacyReadBridge",
    )
    runtime_frame_load = section(
        rse_source,
        "static bool ia64_rse_mandatory_load_interruption_pending",
        "static void ia64_rse_schedule_pending_fill",
    )
    transaction = section(source,
                          "static void ia64_tr_group_reserve",
                          "static bool ia64_tr_decoded_is_noop")
    transaction_retire = section(
        source,
        "static void ia64_tr_group_retire_instruction",
        "static void ia64_tr_group_finish_instruction_success",
    )
    transaction_begin = section(
        source,
        "static void ia64_tr_group_begin_instruction",
        "static IA64TrGrWrite *ia64_tr_group_prepare_gr",
    )
    optional_gr_prepare = section(
        source,
        "static IA64TrGrWrite *ia64_tr_group_prepare_gr",
        "static void ia64_tr_group_stage_gr",
    )
    optional_br_prepare = section(
        source,
        "static IA64TrBrWrite *ia64_tr_group_prepare_br",
        "static void ia64_tr_group_stage_br",
    )
    optional_pr_prepare = section(
        source,
        "static IA64TrPrWrite *ia64_tr_group_prepare_pr",
        "static void ia64_tr_group_stage_pr_bool",
    )
    optional_pr_image_prepare = section(
        source,
        "ia64_tr_group_prepare_pr_image",
        "static void ia64_tr_group_stage_pr_image",
    )
    br_move_lower = section(
        source,
        "static void ia64_tr_emit_decoded_br_move",
        "static unsigned ia64_tr_decoded_bitfield_pos",
    )
    pfs_ordinary_load = section(
        source,
        "static void ia64_tr_group_load_ordinary_pfs",
        "static void ia64_tr_group_load_branch_pfs",
    )
    pfs_branch_load = section(
        source,
        "static void ia64_tr_group_load_branch_pfs",
        "static void ia64_tr_group_write_pfs",
    )
    pfs_write = section(
        source,
        "static void ia64_tr_group_write_pfs",
        "static void ia64_tr_group_preserve_ordinary_gr_source",
    )
    source_overlay_clear = section(
        source,
        "static void ia64_tr_group_clear_ordinary_source_overlay",
        "static void ia64_tr_group_begin_instruction",
    )
    pfs_move_lower = section(
        source,
        "static void ia64_tr_emit_decoded_pfs_move",
        "static unsigned ia64_tr_decoded_bitfield_pos",
    )
    typed_bundle = section(
        source,
        "static bool ia64_tr_try_decoded_bundle",
        "static bool ia64_tr_translate_fast_bundle",
    )
    group_preflight = section(source,
                              "static bool ia64_tr_preflight_rewrite_region",
                              "static void ia64_tr_prime_decoded_instruction_state")
    logical_globals = section(
        source,
        "static TCGv_i64 cpu_logical_gr",
        "static bool ia64_tr_use_zero_helper_path",
    )
    logical_init = section(
        source,
        "void ia64_translate_init(void)",
        "static void ia64_tr_init_disas_context",
    )
    logical_access = section(
        source,
        "static unsigned ia64_tr_logical_gr_index",
        "static TCGCond ia64_tr_compare_cond",
    )
    logical_pair = section(
        source,
        "static void ia64_tr_read_static_gr_nat",
        "static void ia64_tr_emit_fill_nat",
    )
    logical_nat_guards = section(
        source,
        "static void ia64_tr_emit_fast_nat_guards",
        "static void ia64_tr_emit_gr_alat_invalidate",
    )
    focused_alloc = section(
        source,
        "static void ia64_tr_emit_fast_alloc",
        "static void ia64_tr_emit_fast_slot",
    )
    decoded_prime = section(
        source,
        "static void ia64_tr_prime_decoded_instruction_state",
        "static TCGLabel *ia64_tr_emit_decoded_predicate_guard",
    )
    legacy_branch = section(
        source,
        "static IA64TrBranchResult ia64_tr_translate_direct_branch",
        "static void ia64_tr_translate_insn",
    )
    helper_frontier = section(
        source,
        "static void ia64_tr_prepare_helper_ip",
        "static void ia64_tr_emit_can_do_io",
    )
    partial_helper = section(
        source,
        "static void ia64_tr_emit_exec_slot",
        "static bool ia64_tr_partial_slot_needs_guard",
    )
    execution_epoch = section(
        source,
        "static bool ia64_tr_slot_ends_execution_epoch",
        "static bool ia64_tr_partial_slot_needs_guard",
    )
    legacy_impl = section(
        interp_source,
        "static bool ia64_exec_bundle_impl",
        "void HELPER(exec_bundle)",
    )
    legacy_wrappers = interp_source[interp_source.find(
        "void HELPER(exec_bundle)"
    ):]
    restore_opc = section(
        cpu_source,
        "static void ia64_restore_state_to_opc",
        "static TCGTBCPUState ia64_get_tb_cpu_state",
    )
    restore_visibility = section(
        cpu_header,
        "static inline void ia64_env_restore_source_visibility",
        "#define CPU_RESOLVING_TYPE",
    )
    fresh_visibility = section(
        cpu_header,
        "static inline void ia64_env_clear_ordinary_source_overlay",
        "static inline void ia64_env_set_psr",
    )

    compare_opcodes = (
        # A6 ordinary register forms.
        "IA64_OP_CMP_LT", "IA64_OP_CMP_LTU", "IA64_OP_CMP_EQ",
        "IA64_OP_CMP4_LT", "IA64_OP_CMP4_LTU", "IA64_OP_CMP4_EQ",
        # A6 parallel register forms.
        "IA64_OP_CMP_EQ_AND", "IA64_OP_CMP_NE_AND",
        "IA64_OP_CMP_EQ_OR", "IA64_OP_CMP_NE_OR",
        "IA64_OP_CMP_EQ_OR_ANDCM", "IA64_OP_CMP_NE_OR_ANDCM",
        "IA64_OP_CMP4_EQ_AND", "IA64_OP_CMP4_NE_AND",
        "IA64_OP_CMP4_EQ_OR", "IA64_OP_CMP4_NE_OR",
        "IA64_OP_CMP4_EQ_OR_ANDCM", "IA64_OP_CMP4_NE_OR_ANDCM",
        # A7 parallel comparisons of zero against r3.
        "IA64_OP_CMP_GT_AND", "IA64_OP_CMP_LE_AND",
        "IA64_OP_CMP_GE_AND", "IA64_OP_CMP_LT_AND",
        "IA64_OP_CMP_GT_OR", "IA64_OP_CMP_LE_OR",
        "IA64_OP_CMP_GE_OR", "IA64_OP_CMP_LT_OR",
        "IA64_OP_CMP_GT_OR_ANDCM", "IA64_OP_CMP_LE_OR_ANDCM",
        "IA64_OP_CMP_GE_OR_ANDCM", "IA64_OP_CMP_LT_OR_ANDCM",
        "IA64_OP_CMP4_GT_AND", "IA64_OP_CMP4_LE_AND",
        "IA64_OP_CMP4_GE_AND", "IA64_OP_CMP4_LT_AND",
        "IA64_OP_CMP4_GT_OR", "IA64_OP_CMP4_LE_OR",
        "IA64_OP_CMP4_GE_OR", "IA64_OP_CMP4_LT_OR",
        "IA64_OP_CMP4_GT_OR_ANDCM", "IA64_OP_CMP4_LE_OR_ANDCM",
        "IA64_OP_CMP4_GE_OR_ANDCM", "IA64_OP_CMP4_LT_OR_ANDCM",
        # A8 ordinary and parallel signed-imm8 forms.
        "IA64_OP_CMP_LT_IMM", "IA64_OP_CMP_LTU_IMM",
        "IA64_OP_CMP_EQ_IMM", "IA64_OP_CMP4_LT_IMM",
        "IA64_OP_CMP4_LTU_IMM", "IA64_OP_CMP4_EQ_IMM",
        "IA64_OP_CMP_EQ_AND_IMM", "IA64_OP_CMP_NE_AND_IMM",
        "IA64_OP_CMP_EQ_OR_IMM", "IA64_OP_CMP_NE_OR_IMM",
        "IA64_OP_CMP_EQ_OR_ANDCM_IMM",
        "IA64_OP_CMP_NE_OR_ANDCM_IMM",
        "IA64_OP_CMP4_EQ_AND_IMM", "IA64_OP_CMP4_NE_AND_IMM",
        "IA64_OP_CMP4_EQ_OR_IMM", "IA64_OP_CMP4_NE_OR_IMM",
        "IA64_OP_CMP4_EQ_OR_ANDCM_IMM",
        "IA64_OP_CMP4_NE_OR_ANDCM_IMM",
    )
    table_opcodes = set(re.findall(
        r"\[(IA64_OP_CMP[A-Z0-9_]*)\]\s*=\s*"
        r"IA64_TR_COMPARE\(",
        compare_admission,
    ))
    if table_opcodes != set(compare_opcodes):
        missing = sorted(set(compare_opcodes) - table_opcodes)
        extra = sorted(table_opcodes - set(compare_opcodes))
        raise AssertionError("typed integer-compare table is not the exact "
                             f"60-opcode A6/A7/A8 family; missing={missing}, "
                             f"extra={extra}")

    predicate_test_opcodes = {
        "IA64_OP_TBIT_Z", "IA64_OP_TBIT_NZ",
        "IA64_OP_TNAT_Z", "IA64_OP_TNAT_NZ",
        "IA64_OP_TF_Z", "IA64_OP_TF_NZ",
    }
    predicate_table_opcodes = set(re.findall(
        r"\[(IA64_OP_(?:TBIT|TNAT|TF)_[A-Z0-9_]+)\]\s*=\s*\{",
        predicate_test_admission,
    ))
    if predicate_table_opcodes != predicate_test_opcodes:
        raise AssertionError(
            "typed predicate-test table is not the exact six canonical "
            f"opcodes: got={sorted(predicate_table_opcodes)}"
        )

    require(rewrite, (
        "ia64_tr_preflight_decoded_bundle",
        "ia64_tr_emit_decoded_instruction",
        "ia64_tr_group_begin_instruction",
        "ia64_tr_group_stage_gr",
        "ia64_tr_group_stage_pr_bool",
        "ia64_tr_group_finish_instruction_success",
        "ia64_tr_group_close",
        "IA64_OP_MOVL",
        "IA64_OP_ADDS",
        "IA64_OP_ADDL",
        "IA64_OP_ADD",
        "IA64_OP_SUB",
        "IA64_OP_ANDCM",
        "IA64_OP_SHLADD",
        "IA64_OP_SHL",
        "IA64_OP_SHRP_IMM",
        "IA64_OP_DEPZ_IMM",
        "IA64_OP_DEP_IMM",
        "IA64_OP_EXTRU",
        "IA64_OP_SXT4",
        "IA64_OP_ZXT4",
        "IA64_OP_SHLADDP4",
        "IA64_OP_MPYSHL4",
        "IA64_OP_POPCNT",
        "IA64_OP_CLZ",
        "IA64_OP_ADDP4_IMM",
        "IA64_OP_CMP_LT",
        "IA64_OP_CMP_LTU",
        "IA64_OP_CMP_EQ",
        "IA64_OP_CMP4_LT",
        "IA64_OP_CMP4_LTU",
        "IA64_OP_CMP4_EQ",
        "IA64_OP_MOV_PRGR",
        "IA64_OP_MOV_GRPR",
        "IA64_OP_MOV_PR_ROT_IMM",
        "IA64_OP_MOV_BRGR",
        "IA64_OP_MOV_GRBR",
        "IA64_OP_MOV_ARGR",
        "IA64_OP_MOV_GRAR",
        "IA64_OP_TBIT_Z",
        "IA64_OP_TBIT_NZ",
        "IA64_OP_TNAT_Z",
        "IA64_OP_TNAT_NZ",
        "IA64_OP_TF_Z",
        "IA64_OP_TF_NZ",
        "IA64_OP_BR_COND",
        "IA64_OP_BRL_COND",
        "IA64_OP_BR_INDIRECT",
        "IA64_OP_BR_CLOOP",
        "IA64_OP_BR_CTOP",
        "IA64_OP_BR_CEXIT",
        "IA64_OP_BR_WTOP",
        "IA64_OP_BR_WEXIT",
    ), "typed rewrite")
    forbid(rewrite, (
        "IA64TcgFastSlot",
        "ia64_tcg_build_fast_bundle",
        "ia64_tr_emit_fast_slot",
        "ia64_tr_emit_fast_nat_guards",
        "gen_helper_exec_bundle",
        "gen_helper_exec_slot",
        "gen_helper_finish_fast_bundle",
        "gen_helper_fast_gr_nat_any",
    ), "typed rewrite")
    require(lower, ("ia64_tr_group_prepare_gr",
                    "ia64_tr_group_stage_gr",
                    "ia64_tr_decoded_is_integer_compare_opcode",
                    "ia64_tr_emit_decoded_integer_compare(ctx, insn)"),
            "typed instruction lowering")
    forbid(lower, ("gen_helper_", "fallback", "IA64TcgFast",
                   "ia64_tr_store_static_gr", "ia64_tr_write_gr_nat"),
           "typed instruction lowering")
    require(predicate_lower, (
        "ia64_tr_decoded_compare(insn->opcode)",
        "ia64_tr_group_prepare_pr",
        "ia64_tr_group_stage_pr_bool",
        "ia64_tr_group_stage_pr_const",
        "ia64_tr_group_load_ordinary_gr_pair",
        "insn->compare_immediate",
        "insn->compare_width == 4",
        "A7 encodes 0 relation r3",
        "tcg_gen_ext32s_i64",
        "tcg_gen_ext32u_i64",
        "tcg_gen_setcond_i64",
        "tcg_gen_or_i64(source_nat",
        "case IA64_PRED_UPDATE_NORMAL:",
        "case IA64_PRED_UPDATE_AND:",
        "case IA64_PRED_UPDATE_OR:",
        "case IA64_PRED_UPDATE_OR_ANDCM:",
        "!p1_write->must_write",
        "!p2_write->must_write",
        "if (insn->p1 == insn->p2)",
        "insn->compare_unc ? NULL",
        "ia64_tr_emit_decoded_illegal_operation",
    ), "complete typed integer-compare lowering")
    forbid(predicate_lower, (
        "gen_helper_",
        "ia64_exec_compare",
        "insn->raw >>",
        "ia64_tr_write_pr_bool",
        "ia64_tr_write_pr_const",
        "tcg_gen_st_i64(group->pr_value",
    ), "complete typed integer-compare lowering")
    require(compare_admission, (
        "insn->compare_width == compare->width",
        "insn->compare_immediate ==",
        "insn->pred_update == compare->pred_update",
        "IA64_TR_COMPARE_SOURCE_REGISTER",
        "IA64_TR_COMPARE_SOURCE_ZERO",
        "IA64_TR_COMPARE_SOURCE_IMMEDIATE",
        "ia64_tr_decoded_is_supported_integer_compare",
    ), "typed integer-compare normalization")
    forbid(compare_admission, (
        "insn->p1 == insn->p2",
        "insn->p1 != insn->p2",
        "insn->raw >>",
        "ia64_bits(",
        "ia64_decode_compare",
    ), "typed integer-compare admission")
    require(illegal_lower, (
        "ia64_tr_group_publish_prefix_for_noreturn_fault",
        "ia64_tr_publish_fault_state",
        "gen_helper_raise_illegal_operation",
    ), "typed Illegal Operation lowering")
    equal_target = predicate_lower.find("if (insn->p1 == insn->p2)")
    equal_guard = predicate_lower.find(
        "ia64_tr_emit_decoded_predicate_guard", equal_target
    )
    equal_fault = predicate_lower.find(
        "ia64_tr_emit_decoded_illegal_operation", equal_guard
    )
    source_prime = predicate_lower.find(
        "ia64_tr_prime_decoded_instruction_state", equal_fault
    )
    if not (0 <= equal_target < equal_guard < equal_fault < source_prime):
        raise AssertionError("equal-target integer compares must guard "
                             "normal/parallel forms and fault before source "
                             "preparation")
    unc_init = predicate_lower.find("if (insn->compare_unc)", source_prime)
    unc_stage = predicate_lower.find(
        "ia64_tr_group_stage_pr_const(p1_write, false)", unc_init
    )
    qualified_guard = predicate_lower.find(
        "ia64_tr_emit_decoded_predicate_guard(ctx, insn)", unc_stage
    )
    operand_read = predicate_lower.find(
        "if (insn->compare_immediate)", qualified_guard
    )
    if not (0 <= unc_init < unc_stage < qualified_guard < operand_read):
        raise AssertionError("cmp.unc must clear unequal targets before the "
                             "qualifier guard and every compare must qualify "
                             "before reading operands")

    and_case = predicate_lower.find("case IA64_PRED_UPDATE_AND:")
    and_nat = predicate_lower.find(
        "TCG_COND_NE, source_nat, 0, clear", and_case
    )
    and_result = predicate_lower.find(
        "TCG_COND_NE, result, 0, done", and_nat
    )
    and_stage = predicate_lower.find(
        "ia64_tr_group_stage_pr_const(p1_write, false)", and_result
    )
    or_case = predicate_lower.find("case IA64_PRED_UPDATE_OR:", and_stage)
    or_nat = predicate_lower.find(
        "TCG_COND_NE, source_nat, 0, done", or_case
    )
    or_result = predicate_lower.find(
        "TCG_COND_EQ, result, 0, done", or_nat
    )
    or_stage = predicate_lower.find(
        "ia64_tr_group_stage_pr_const(p1_write, true)", or_result
    )
    or_andcm_case = predicate_lower.find(
        "case IA64_PRED_UPDATE_OR_ANDCM:", or_stage
    )
    or_andcm_nat = predicate_lower.find(
        "TCG_COND_NE, source_nat, 0, done", or_andcm_case
    )
    or_andcm_result = predicate_lower.find(
        "TCG_COND_EQ, result, 0, done", or_andcm_nat
    )
    or_andcm_stage = predicate_lower.find(
        "ia64_tr_group_stage_pr_const(p2_write, false)",
        or_andcm_result,
    )
    if not (0 <= and_case < and_nat < and_result < and_stage < or_case <
            or_nat < or_result < or_stage < or_andcm_case < or_andcm_nat <
            or_andcm_result < or_andcm_stage):
        raise AssertionError("parallel compare updates must branch around "
                             "their conditional staging on the architectural "
                             "NaT/result no-write arms")

    require(predicate_test_admission, (
        "IA64_TR_PREDICATE_TEST_BIT",
        "IA64_TR_PREDICATE_TEST_NAT",
        "IA64_TR_PREDICATE_TEST_FEATURE",
        "insn->unit != IA64_INSN_UNIT_I",
        "insn->pred_update > IA64_PRED_UPDATE_OR_ANDCM",
        "insn->pred_update == IA64_PRED_UPDATE_NORMAL && test->nonzero",
        "insn->imm >= 32 && insn->imm < 64",
        "insn->r3 == 0",
    ), "typed predicate-test normalization")
    forbid(predicate_test_admission, (
        "insn->raw >>",
        "ia64_bits(",
        "ia64_decode_predicate_test",
        "IA64_OP_TBIT_Z_OR_ANDCM",
        "IA64_OP_TBIT_NZ_OR_ANDCM",
        "IA64_OP_TNAT_NZ_AND",
    ), "typed predicate-test admission")
    require(predicate_test_lower, (
        "ia64_tr_decoded_predicate_test(insn->opcode)",
        "ia64_tr_group_prepare_pr",
        "ia64_tr_group_load_ordinary_gr_pair",
        "offsetof(CPUIA64State, cpuid)",
        "4 * sizeof(uint64_t)",
        "source_unavailable",
        "case IA64_TR_PREDICATE_TEST_BIT:",
        "case IA64_TR_PREDICATE_TEST_NAT:",
        "case IA64_TR_PREDICATE_TEST_FEATURE:",
        "case IA64_PRED_UPDATE_NORMAL:",
        "case IA64_PRED_UPDATE_AND:",
        "case IA64_PRED_UPDATE_OR:",
        "case IA64_PRED_UPDATE_OR_ANDCM:",
        "if (insn->p1 == insn->p2)",
        "ia64_tr_emit_decoded_illegal_operation",
    ), "complete typed predicate-test lowering")
    forbid(predicate_test_lower, (
        "gen_helper_",
        "ia64_exec_predicate_test",
        "ia64_decode_predicate_test",
        "insn->raw >>",
        "ia64_tr_write_pr_bool",
        "ia64_tr_write_pr_const",
    ), "complete typed predicate-test lowering")
    pred_equal = predicate_test_lower.find("if (insn->p1 == insn->p2)")
    pred_equal_guard = predicate_test_lower.find(
        "ia64_tr_emit_decoded_predicate_guard", pred_equal
    )
    pred_equal_fault = predicate_test_lower.find(
        "ia64_tr_emit_decoded_illegal_operation", pred_equal_guard
    )
    pred_source_prime = predicate_test_lower.find(
        "ia64_tr_prime_decoded_instruction_state", pred_equal_fault
    )
    if not (0 <= pred_equal < pred_equal_guard < pred_equal_fault <
            pred_source_prime):
        raise AssertionError("equal-target predicate tests must fault before "
                             "reading GR/NaT or CPUID state")

    require(branch_forward, (
        "issue_group.branch_pr_forward_mask",
        "ia64_tr_predicate_bit(ctx, bit, predicate)",
        "ia64_tr_group_load_branch_predicate",
        "ia64_tr_group_load_ordinary_pr_image",
        "tcg_gen_movcond_i64",
        "live, ordinary",
    ), "explicit predicate-to-branch forwarding")
    forbid(branch_forward, (
        "gen_helper_",
        "IA64TcgDirectBranch",
        "ia64_tcg_build_direct_branch",
        "insn->raw >>",
    ), "explicit predicate-to-branch forwarding")

    require(br_ordinary_load, (
        "group->br_may_written",
        "group->br_must_saved",
        "issue_group.saved_br",
        "issue_group.saved_br_mask",
        "ia64_tr_load_br",
        "tcg_gen_movcond_i64",
        "saved, live",
    ), "ordinary BR overlay selection")
    forbid(br_ordinary_load, (
        "gen_helper_",
        "gen_helper_exec_bundle",
        "gen_helper_exec_slot",
        "fallback",
    ), "ordinary BR overlay selection")
    require(br_forward, (
        "issue_group.branch_br_forward_mask",
        "tcg_gen_ld8u_i64",
        "tcg_gen_andi_i64(mask, mask, (uint8_t)~bit)",
        "tcg_gen_st8_i64",
        "group->branch_br_forward_may_nonzero = true",
    ), "explicit BR-to-branch forwarding provenance")
    forbid(br_forward, (
        "gen_helper_exec_bundle",
        "gen_helper_exec_slot",
        "IA64TcgFastSlot",
        "fallback",
    ), "explicit BR-to-branch forwarding provenance")
    require(br_preserve, (
        "write->preserve_source",
        "group->br_must_saved",
        "issue_group.saved_br_mask",
        "ia64_tr_load_br",
        "issue_group.saved_br",
        "group->br_may_saved",
    ), "first-write BR preservation")
    forbid(br_preserve, (
        "gen_helper_",
        "fallback",
    ), "first-write BR preservation")

    call_opcodes = {
        "IA64_OP_BR_CALL",
        "IA64_OP_BRL_CALL",
        "IA64_OP_BR_CALL_INDIRECT",
    }
    classified_call_opcodes = set(re.findall(
        r"IA64_OP_[A-Z0-9_]+", call_classifier
    ))
    if classified_call_opcodes != call_opcodes:
        raise AssertionError(
            "typed call classifier is not exactly B3/X4/B5: "
            f"got={sorted(classified_call_opcodes)}"
        )
    require(call_admission, (
        "insn->opcode == IA64_OP_BR_CALL",
        "insn->unit == IA64_INSN_UNIT_B",
        "insn->slot_span == 1",
        "insn->b1 < IA64_BR_COUNT",
        "(insn->imm & 0xf) == 0",
        "insn->opcode == IA64_OP_BRL_CALL",
        "insn->unit == IA64_INSN_UNIT_X",
        "insn->slot == 1 && insn->slot_span == 2",
        "insn->opcode == IA64_OP_BR_CALL_INDIRECT",
        "insn->b2 < IA64_BR_COUNT",
    ), "typed B3/X4/B5 shape admission")
    require(rewrite_plan, (
        "ia64_tr_decoded_is_call_branch(insn->opcode)",
        "plan->dest_br = link",
        "insn->opcode == IA64_OP_BR_CALL_INDIRECT",
        "plan->branch_source_br = 1u << insn->b2",
        "plan->branch_source_pr = UINT64_C(1) << insn->qp",
        "plan->must_br = link",
        "plan->unconditional_noreturn = true",
        "ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_EC)",
        "ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_PFS)",
        "plan->source_cfm = true",
        "plan->dest_cfm = true",
        "g_assert(plan->source_br == 0 && plan->forward_br == 0)",
    ), "typed call ordered-resource planning")
    require(call_resource_assert, (
        "ia64_tr_decoded_is_call_branch(insn->opcode)",
        "instruction->source_ar[0] == 0",
        "instruction->source_ar[1] == ec",
        "instruction->dest_ar[0] == 0",
        "instruction->dest_ar[1] == pfs",
        "instruction->dest_pr == 0",
        "instruction->must_pr == 0",
        "instruction->forward_pr == 0",
        "instruction->branch_source_pr == expected_branch_pr",
        "instruction->source_br == 0",
        "instruction->dest_br == link",
        "instruction->must_br == (insn->qp == 0 ? link : 0)",
        "instruction->forward_br == 0",
        "instruction->branch_source_br == expected_target",
        "instruction->source_cfm && instruction->dest_cfm",
    ), "typed call transaction-resource audit")
    require(call_lower, (
        "ia64_tr_assert_call_branch_resources(instruction, insn)",
        "arm->call = true",
        "arm->indirect = indirect",
        "arm->indirect_target = tcg_temp_new_i64()",
        "arm->direct_target = bundle_ip + (uint64_t)insn->imm",
        "ia64_tr_group_prepare_br(ctx, insn->b1)",
        "!link_write->forward_to_branch",
        "ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp)",
        "tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, skip_call)",
        "ia64_tr_group_load_branch_br(\n"
        "            ctx, arm->indirect_target, insn->b2)",
        "tcg_gen_andi_i64(arm->indirect_target, arm->indirect_target",
        "~UINT64_C(0xf)",
        "tcg_constant_i64(bundle_ip + IA64_BUNDLE_SIZE)",
        "ia64_tr_group_finish_instruction_success(ctx, insn)",
        "if (insn->stop_after || unconditional)",
        "ia64_tr_group_close(ctx)",
        "ia64_tr_split_state_cache_at_typed_branch(ctx)",
        "tcg_gen_br(arm->taken)",
        "tcg_gen_brcondi_i64(TCG_COND_NE, predicate, 0, arm->taken)",
    ), "direct-TCG call predicate/BR/link split")
    forbid(call_lower, (
        "gen_helper_",
        "ia64_tr_emit_call_frame_transition",
        "gen_helper_exec_bundle",
        "gen_helper_exec_bundle_lookup_ptr",
        "gen_helper_exec_slot",
        "gen_helper_finish_direct_branch_bundle",
        "gen_helper_finish_indirect_branch_bundle",
        "ia64_branch_call_effects",
        "ia64_rse_sync_logical_in",
        "ia64_rse_sync_logical_out",
        "insn->raw >>",
    ), "direct-TCG call predicate/BR/link split")
    call_predicate = call_lower.find(
        "ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp)"
    )
    call_guard = call_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, skip_call)",
        call_predicate,
    )
    call_target_load = call_lower.find(
        "ia64_tr_group_load_branch_br(", call_guard
    )
    call_target_align = call_lower.find(
        "tcg_gen_andi_i64(arm->indirect_target", call_target_load
    )
    call_link_stage = call_lower.find(
        "ia64_tr_group_stage_br(", call_target_align
    )
    call_finish = call_lower.find(
        "ia64_tr_group_finish_instruction_success", call_link_stage
    )
    call_close = call_lower.find("ia64_tr_group_close(ctx)", call_finish)
    call_cache_split = call_lower.find(
        "ia64_tr_split_state_cache_at_typed_branch(ctx)", call_close
    )
    call_taken_split = call_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_NE, predicate, 0, arm->taken)",
        call_cache_split,
    )
    if not (0 <= call_predicate < call_guard < call_target_load <
            call_target_align < call_link_stage < call_finish < call_close <
            call_cache_split < call_taken_split):
        raise AssertionError(
            "typed call must guard, latch/align B5 target before b1 link, "
            "retire/close, split the cache, then select the taken arm"
        )
    if call_lower.count("ia64_tr_group_load_branch_predicate") != 1 or \
            call_lower.count("ia64_tr_group_stage_br") != 1:
        raise AssertionError("typed call must have one predicate read and one "
                             "ordinary transaction link stage")

    require(call_transition, (
        "g_assert(!ctx->state_cache_active)",
        "gen_helper_enter_call_frame(tcg_env)",
    ), "focused typed call-frame transition")
    forbid(call_transition, (
        "exec_bundle", "exec_slot", "finish_direct_branch_bundle",
        "finish_indirect_branch_bundle", "ia64_branch_call_effects",
        "ia64_rse_sync_logical_in", "ia64_rse_sync_logical_out",
    ), "focused typed call-frame transition")
    if source.count("gen_helper_enter_call_frame(tcg_env)") != 1:
        raise AssertionError("translator must have exactly one focused call-"
                             "frame helper site")
    if source.count("ia64_tr_emit_call_frame_transition(ctx)") != 1:
        raise AssertionError("focused call-frame transition must be invoked "
                             "from exactly one translated CFG seam")

    require(typed_bundle, (
        "ia64_tr_decoded_is_call_branch(insn->opcode)",
        "ia64_tr_emit_decoded_call_split(\n"
        "                    ctx, insn, &branch_arm[branch_count++])",
    ), "typed bundle call dispatch")
    require(typed_branch_cfg_exits, (
        "gen_set_label(arms[i].taken)",
        "if (arms[i].call)",
        "ia64_tr_emit_call_frame_transition(ctx)",
        "ia64_tr_emit_typed_indirect_branch_exit",
        "ia64_tr_emit_typed_direct_branch_exit",
    ), "taken-only call-frame CFG transition")
    taken_label = typed_branch_cfg_exits.find(
        "gen_set_label(arms[i].taken)"
    )
    call_arm_gate = typed_branch_cfg_exits.find(
        "if (arms[i].call)", taken_label
    )
    frame_transition = typed_branch_cfg_exits.find(
        "ia64_tr_emit_call_frame_transition(ctx)", call_arm_gate
    )
    indirect_taken_exit = typed_branch_cfg_exits.find(
        "ia64_tr_emit_typed_indirect_branch_exit", frame_transition
    )
    direct_taken_exit = typed_branch_cfg_exits.find(
        "ia64_tr_emit_typed_direct_branch_exit", frame_transition
    )
    if not (0 <= taken_label < call_arm_gate < frame_transition <
            indirect_taken_exit and frame_transition < direct_taken_exit):
        raise AssertionError("call-frame helper must remain inside the labeled "
                             "taken arm and precede either exact exit")

    require(insn_source, (
        "#define IA64_PFS_CFM_MASK UINT64_C(0x0000003fffffffff)",
        "#define IA64_PFS_PEC_SHIFT 52",
        "#define IA64_PFS_PEC_MASK UINT64_C(0x03f0000000000000)",
        "#define IA64_PFS_PPL_SHIFT 62",
        "#define IA64_PFS_PPL_MASK UINT64_C(0xc000000000000000)",
    ), "architectural PFS field layout")
    require(call_frame_core, (
        "caller_cfm = env->cfm",
        "caller_ec = ia64_read_ar(env, IA64_AR_EC) & 0x3f",
        "(ia64_env_psr(env) & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT",
        "caller_sof = ia64_cfm_sof(caller_cfm)",
        "caller_sol = ia64_cfm_sol(caller_cfm)",
        "g_assert(caller_sol <= caller_sof)",
        "output_count = caller_sof - caller_sol",
        "ia64_rse_sync_logical_out(env)",
        "env->ar[IA64_AR_PFS] = (caller_cfm & IA64_PFS_CFM_MASK)",
        "(caller_ec << IA64_PFS_PEC_SHIFT)",
        "(caller_cpl << IA64_PFS_PPL_SHIFT)",
        "ia64_alat_invalidate_stacked_gr_range(\n"
        "        env, IA64_GR_COUNT - IA64_STATIC_GR_COUNT)",
        "ia64_rse_preserve_frame(env, caller_sol)",
        "ia64_set_cfm(env, ia64_make_cfm(output_count, 0, 0))",
        "ia64_rse_sync_logical_in(env)",
    ), "complete architectural call-frame semantic core")
    call_sync_out = call_frame_core.find("ia64_rse_sync_logical_out(env)")
    call_pfs = call_frame_core.find("env->ar[IA64_AR_PFS]", call_sync_out)
    call_alat = call_frame_core.find(
        "ia64_alat_invalidate_stacked_gr_range", call_pfs
    )
    call_preserve = call_frame_core.find(
        "ia64_rse_preserve_frame(env, caller_sol)", call_alat
    )
    call_cfm = call_frame_core.find(
        "ia64_set_cfm(env, ia64_make_cfm(output_count, 0, 0))",
        call_preserve,
    )
    call_sync_in = call_frame_core.find(
        "ia64_rse_sync_logical_in(env)", call_cfm
    )
    if not (0 <= call_sync_out < call_pfs < call_alat < call_preserve <
            call_cfm < call_sync_in):
        raise AssertionError("call semantic core must flush dirty outputs, "
                             "pack PFS, invalidate ALAT, remap/preserve the "
                             "frame, install output CFM, then sync in")
    if call_frame_core.count("ia64_rse_sync_logical_out(env)") != 1 or \
            call_frame_core.count("ia64_rse_sync_logical_in(env)") != 1:
        raise AssertionError("focused call semantic core must use exactly one "
                             "logical sync-out and one sync-in")
    require(helper_source, (
        "DEF_HELPER_1(enter_call_frame, void, env)",
    ), "focused call-frame helper declaration")
    require(call_frame_helper, (
        "IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE)",
        "ia64_enter_call_frame(env)",
    ), "focused call-frame helper wrapper")
    forbid(call_frame_helper, (
        "exec_bundle", "exec_slot", "finish_direct_branch_bundle",
        "finish_indirect_branch_bundle", "ia64_branch_call_effects",
        "ia64_rse_sync_logical_in", "ia64_rse_sync_logical_out",
    ), "focused call-frame helper wrapper")

    return_opcodes = {"IA64_OP_BR_RET"}
    classified_return_opcodes = set(re.findall(
        r"IA64_OP_[A-Z0-9_]+", return_classifier
    ))
    if classified_return_opcodes != return_opcodes:
        raise AssertionError(
            "typed return classifier is not exactly B4 br.ret: "
            f"got={sorted(classified_return_opcodes)}"
        )
    require(call_admission, (
        "insn->opcode == IA64_OP_BR_RET",
        "insn->unit == IA64_INSN_UNIT_B",
        "insn->slot_span == 1",
        "insn->b2 < IA64_BR_COUNT",
    ), "typed B4 return shape admission")
    require(rewrite_plan, (
        "ia64_tr_decoded_is_return_branch(insn->opcode)",
        "plan->branch_source_br = 1u << insn->b2",
        "plan->branch_source_pfs = true",
        "ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_PFS)",
        "ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_EC)",
        "plan->source_cfm = true",
        "plan->dest_cfm = true",
        "plan->branch_source_pr = UINT64_C(1) << insn->qp",
        "plan->unconditional_noreturn = true",
    ), "typed return ordered-resource planning")
    require(return_resource_assert, (
        "ia64_tr_decoded_is_return_branch(insn->opcode)",
        "instruction->source_ar[0] == 0",
        "instruction->source_ar[1] == pfs",
        "instruction->dest_ar[0] == 0",
        "instruction->dest_ar[1] == ec",
        "instruction->dest_pr == 0",
        "instruction->must_pr == 0",
        "instruction->forward_pr == 0",
        "instruction->branch_source_pr == expected_branch_pr",
        "instruction->source_br == 0",
        "instruction->dest_br == 0",
        "instruction->must_br == 0",
        "instruction->forward_br == 0",
        "instruction->branch_source_br == (1u << insn->b2)",
        "instruction->source_cfm && instruction->dest_cfm",
        "!instruction->forward_pfs",
        "instruction->branch_source_pfs",
        "!instruction->must_pfs",
    ), "typed return transaction-resource audit")
    require(return_lower, (
        "ia64_tr_assert_return_branch_resources(instruction, insn)",
        "arm->indirect = true",
        "arm->ret = true",
        "arm->indirect_target = tcg_temp_new_i64()",
        "arm->return_pfs = tcg_temp_new_i64()",
        "ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp)",
        "tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, skip_return)",
        "ia64_tr_group_load_branch_br(ctx, arm->indirect_target, insn->b2)",
        "tcg_gen_andi_i64(arm->indirect_target, arm->indirect_target",
        "~UINT64_C(0xf)",
        "ia64_tr_group_load_branch_pfs(ctx, arm->return_pfs)",
        "ia64_tr_publish_fault_state(insn->address, insn->slot",
        "ia64_tr_group_finish_instruction_success(ctx, insn)",
        "if (insn->stop_after || unconditional)",
        "ia64_tr_group_close(ctx)",
        "ia64_tr_split_state_cache_at_typed_branch(ctx)",
        "tcg_gen_br(arm->taken)",
        "tcg_gen_brcondi_i64(TCG_COND_NE, predicate, 0, arm->taken)",
    ), "direct-TCG return predicate/BR/PFS split")
    forbid(return_lower, (
        "gen_helper_", "gen_helper_exec_bundle", "gen_helper_exec_slot",
        "gen_helper_finish_direct_branch_bundle",
        "gen_helper_finish_indirect_branch_bundle",
        "ia64_rse_return_frame_from_pfs", "ia64_return_from_call_frame",
        "insn->raw >>", "fallback",
    ), "direct-TCG return predicate/BR/PFS split")
    return_predicate = return_lower.find(
        "ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp)"
    )
    return_guard = return_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, skip_return)",
        return_predicate,
    )
    return_target_load = return_lower.find(
        "ia64_tr_group_load_branch_br(", return_guard
    )
    return_target_align = return_lower.find(
        "tcg_gen_andi_i64(arm->indirect_target", return_target_load
    )
    return_pfs_load = return_lower.find(
        "ia64_tr_group_load_branch_pfs(ctx, arm->return_pfs)",
        return_target_align,
    )
    return_fault_state = return_lower.find(
        "ia64_tr_publish_fault_state", return_pfs_load
    )
    return_skip = return_lower.find(
        "gen_set_label(skip_return)", return_fault_state
    )
    return_finish = return_lower.find(
        "ia64_tr_group_finish_instruction_success", return_skip
    )
    return_close = return_lower.find("ia64_tr_group_close(ctx)", return_finish)
    return_cache_split = return_lower.find(
        "ia64_tr_split_state_cache_at_typed_branch(ctx)", return_close
    )
    return_taken_split = return_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_NE, predicate, 0, arm->taken)",
        return_cache_split,
    )
    if not (0 <= return_predicate < return_guard < return_target_load <
            return_target_align < return_pfs_load < return_fault_state <
            return_skip < return_finish < return_close < return_cache_split <
            return_taken_split):
        raise AssertionError(
            "typed return must guard, capture/align B4 target and branch-visible "
            "PFS, publish the fault slot, retire/close, split the cache, then "
            "select the taken arm"
        )
    if return_lower.count("ia64_tr_group_load_branch_predicate") != 1 or \
            return_lower.count("ia64_tr_group_load_branch_br") != 1 or \
            return_lower.count("ia64_tr_group_load_branch_pfs") != 1:
        raise AssertionError("typed return must capture each branch-visible "
                             "input exactly once")

    require(deferred_return_retire, (
        "ctx->fast_bundle_ticks_used",
        "ctx->base.tb->flags & IA64_TB_FLAG_BENCHMARK",
        "ia64_tr_emit_benchmark_retire(ctx->fast_bundle_ticks)",
        "tcg_gen_movi_i32(ctx->fast_bundle_ticks, 0)",
    ), "return retirement with deferred interrupt observation")
    forbid(deferred_return_retire, (
        "gen_helper_finish_fast_tb", "ia64_tr_flush_fast_bundle_ticks",
        "ia64_tr_emit_exit_request_guard", "cpu_loop_exit",
    ), "return retirement with deferred interrupt observation")
    require(typed_return_exit, (
        "ia64_tr_store_typed_taken_visibility_state()",
        "ia64_tr_clear_restart_ri()",
        "ia64_tr_commit_ip_value(target)",
        "ia64_tr_retire_fast_bundle_ticks_deferred_interrupt(ctx)",
        "gen_helper_return_frame_from_pfs(lower_privilege, tcg_env, pfs)",
        "tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr))",
        "IA64_PSR_LP_BIT",
        "gen_helper_raise_lower_privilege_transfer_trap(tcg_env)",
        "IA64_PSR_TB_BIT",
        "gen_helper_raise_taken_branch_trap(tcg_env)",
        "gen_helper_complete_rse_frame_loads(tcg_env)",
        "gen_helper_return_chain_ok(chain_ok, tcg_env)",
        "tcg_gen_brcondi_i32(TCG_COND_EQ, chain_ok, 0, main_loop_exit)",
        "ia64_tr_emit_exit_request_guard(main_loop_exit)",
        "tcg_gen_lookup_and_goto_ptr()",
    ), "architecturally ordered typed return taken exit")
    forbid(typed_return_exit, (
        "gen_helper_exec_bundle", "gen_helper_exec_slot",
        "gen_helper_finish_fast_tb", "ia64_tr_flush_fast_bundle_ticks",
        "finish_direct_branch_bundle", "finish_indirect_branch_bundle",
        "ia64_return_from_call_frame", "tcg_gen_goto_tb",
        "insn->raw", "fallback",
    ), "architecturally ordered typed return taken exit")
    return_visibility = typed_return_exit.find(
        "ia64_tr_store_typed_taken_visibility_state()"
    )
    return_ri = typed_return_exit.find(
        "ia64_tr_clear_restart_ri()", return_visibility
    )
    return_ip = typed_return_exit.find(
        "ia64_tr_commit_ip_value(target)", return_ri
    )
    return_retire = typed_return_exit.find(
        "ia64_tr_retire_fast_bundle_ticks_deferred_interrupt(ctx)", return_ip
    )
    return_frame = typed_return_exit.find(
        "gen_helper_return_frame_from_pfs", return_retire
    )
    return_psr = typed_return_exit.find("tcg_gen_ld_i64(psr", return_frame)
    return_demotion = typed_return_exit.find(
        "TCG_COND_EQ, lower_privilege, 0", return_psr
    )
    return_lp = typed_return_exit.find("IA64_PSR_LP_BIT", return_demotion)
    return_lp_trap = typed_return_exit.find(
        "gen_helper_raise_lower_privilege_transfer_trap", return_lp
    )
    return_lp_done = typed_return_exit.find(
        "gen_set_label(not_lower_privilege)", return_lp_trap
    )
    return_tb = typed_return_exit.find("IA64_PSR_TB_BIT", return_lp_done)
    return_tb_trap = typed_return_exit.find(
        "gen_helper_raise_taken_branch_trap", return_tb
    )
    return_traps_done = typed_return_exit.find(
        "gen_set_label(not_taken_trap)", return_tb_trap
    )
    return_fill = typed_return_exit.find(
        "gen_helper_complete_rse_frame_loads", return_traps_done
    )
    return_chain_poll = typed_return_exit.find(
        "gen_helper_return_chain_ok", return_fill
    )
    return_chain_guard = typed_return_exit.find(
        "TCG_COND_EQ, chain_ok, 0, main_loop_exit", return_chain_poll
    )
    return_exit_guard = typed_return_exit.find(
        "ia64_tr_emit_exit_request_guard", return_chain_guard
    )
    return_lookup = typed_return_exit.find(
        "tcg_gen_lookup_and_goto_ptr", return_exit_guard
    )
    if not (0 <= return_visibility < return_ri < return_ip < return_retire <
            return_frame < return_psr < return_demotion < return_lp <
            return_lp_trap < return_lp_done < return_tb < return_tb_trap <
            return_traps_done < return_fill < return_chain_poll <
            return_chain_guard < return_exit_guard < return_lookup):
        raise AssertionError(
            "typed return taken edge must commit fresh target state, retire "
            "without asynchronous exit, restore its frame, arbitrate LP before "
            "TB, complete mandatory fills, then expose exits/lookup"
        )
    for helper_call in (
            "gen_helper_return_frame_from_pfs(",
            "gen_helper_complete_rse_frame_loads(",
            "gen_helper_return_chain_ok(",
            "gen_helper_raise_lower_privilege_transfer_trap(",
            "gen_helper_raise_taken_branch_trap("):
        if source.count(helper_call) != 1:
            raise AssertionError(f"focused return helper must have one taken-"
                                 f"edge call site: {helper_call}")

    require(typed_branch_cfg_exits, (
        "gen_set_label(arms[i].taken)",
        "if (arms[i].ret)",
        "arms[i].indirect_target != NULL",
        "arms[i].return_pfs != NULL",
        "ia64_tr_emit_typed_return_exit(",
        "continue;",
    ), "taken-only typed return CFG transition")
    return_taken_label = typed_branch_cfg_exits.find(
        "gen_set_label(arms[i].taken)"
    )
    return_arm_gate = typed_branch_cfg_exits.find(
        "if (arms[i].ret)", return_taken_label
    )
    return_exit = typed_branch_cfg_exits.find(
        "ia64_tr_emit_typed_return_exit(", return_arm_gate
    )
    return_continue = typed_branch_cfg_exits.find("continue;", return_exit)
    return_call_gate = typed_branch_cfg_exits.find(
        "if (arms[i].call)", return_continue
    )
    if not (0 <= return_taken_label < return_arm_gate < return_exit <
            return_continue < return_call_gate):
        raise AssertionError("return frame/trap/fill work must remain inside "
                             "the labeled taken arm and bypass ordinary exits")

    require(helper_source, (
        "DEF_HELPER_2(return_frame_from_pfs, i32, env, i64)",
        "DEF_HELPER_1(complete_rse_frame_loads, void, env)",
        "DEF_HELPER_1(return_chain_ok, i32, env)",
        "DEF_HELPER_FLAGS_1(raise_lower_privilege_transfer_trap, "
        "TCG_CALL_NO_RETURN",
        "DEF_HELPER_FLAGS_1(raise_taken_branch_trap, TCG_CALL_NO_RETURN",
    ), "focused return helper declarations")
    require(return_frame_helper, (
        "IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE)",
        "ia64_rse_return_frame_from_pfs(env, pfs)",
        "new_cpl > old_cpl",
    ), "focused return-frame helper wrapper")
    require(return_fill_helper, (
        "IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE)",
        "ia64_rse_complete_frame_loads(env)",
    ), "focused mandatory-fill helper wrapper")
    require(return_chain_helper, (
        "return ia64_lookup_ptr_chain_ok(env)",
    ), "post-return interrupt/chain eligibility helper")
    require(return_trap_helpers, (
        "ia64_deliver_branch_trap(env, kind)",
        "fault_exit_pending_tb_translate = true",
        "cpu_loop_exit(cpu)",
        "IA64_EXCEPTION_LOWER_PRIVILEGE_TRANSFER",
        "IA64_EXCEPTION_TAKEN_BRANCH_TRAP",
    ), "focused non-returning branch-trap helpers")
    require(interruption_isr, (
        "if (env->rse.cfle)",
        "isr |= UINT64_C(1) << IA64_ISR_IR_BIT",
        "env->rse.reference && ia64_exception_is_data_memory_fault(kind)",
        "isr |= UINT64_C(1) << IA64_ISR_RS_BIT",
    ), "independent ISR.ir/ISR.rs collection for incomplete returns")
    forbid(interruption_isr, (
        "env->rse.dirty < 0", "env->rse.dirty_nat < 0",
    ), "independent ISR.ir/ISR.rs collection for incomplete returns")
    isr_ir_gate = interruption_isr.find("if (env->rse.cfle)")
    isr_ir_set = interruption_isr.find("IA64_ISR_IR_BIT", isr_ir_gate)
    isr_rs_gate = interruption_isr.find(
        "env->rse.reference && ia64_exception_is_data_memory_fault(kind)",
        isr_ir_set,
    )
    isr_rs_set = interruption_isr.find("IA64_ISR_RS_BIT", isr_rs_gate)
    if not (0 <= isr_ir_gate < isr_ir_set < isr_rs_gate < isr_rs_set):
        raise AssertionError("ISR.ir must snapshot CFLE independently before "
                             "RSE-reference-only ISR.rs attribution")
    require(insn_header, (
        "typedef bool (*IA64RSEInterruptionPendingFn)",
        "IA64_RSE_STEP_INTERRUPTION",
        "ia64_rse_complete_mandatory_loads_interruptible",
    ), "interruptible mandatory-load interface")
    require(mandatory_load_completion, (
        "env->rse.cfle = true",
        "interruption_pending && interruption_pending(env, opaque)",
        "return IA64_RSE_STEP_INTERRUPTION",
        "ia64_rse_mandatory_load_step(env, read_word, opaque)",
        "env->rse.cfle = false",
        "env, read_word, NULL, opaque",
    ), "prefix-committing interruptible mandatory loads")
    first_boundary = mandatory_load_completion.find(
        "interruption_pending && interruption_pending(env, opaque)"
    )
    load_step = mandatory_load_completion.find(
        "ia64_rse_mandatory_load_step", first_boundary
    )
    final_boundary = mandatory_load_completion.find(
        "interruption_pending && interruption_pending(env, opaque)",
        load_step,
    )
    clear_cfle = mandatory_load_completion.find(
        "env->rse.cfle = false", final_boundary
    )
    if not (0 <= first_boundary < load_step < final_boundary < clear_cfle):
        raise AssertionError("mandatory return loads must poll before the "
                             "first/each load and after the final load while "
                             "CFLE remains set")
    if mandatory_load_completion.count(
            "return IA64_RSE_STEP_INTERRUPTION") != 2:
        raise AssertionError("both pre-load and post-final interruption "
                             "boundaries must retain incomplete state")
    require(runtime_frame_load, (
        "return ia64_external_interrupt_enabled(env)",
        "ia64_rse_complete_mandatory_loads_interruptible",
        "result == IA64_RSE_STEP_INTERRUPTION",
        "cpu_loop_exit(env_cpu(env))",
        "g_assert(result == IA64_RSE_STEP_DONE)",
    ), "runtime mandatory-load interruption handoff")
    require(cpu_exec_interrupt, (
        "if (env->rse.reference ||",
        "!env->rse.cfle &&",
        "env->rse.dirty < 0 || env->rse.dirty_nat < 0",
        "ia64_deliver_exception(env, IA64_EXCEPTION_EXTERNAL_INTERRUPT",
    ), "safe-boundary external-interruption delivery")
    forbid(cpu_exec_interrupt, (
        "env->rse.cfle ||",
    ), "safe-boundary external-interruption delivery")
    require(interruption_delivery, (
        "ia64_interruption_isr(",
        "env->rse.cfle = false",
        "env->rse.reference = false",
        "env->rse.pending_fill_count = 0",
        "env->rse.pending_fill_ip = 0",
    ), "interruption exposure of canonical incomplete-frame state")
    collect_isr = interruption_delivery.find("ia64_interruption_isr(")
    clear_cfle = interruption_delivery.find(
        "env->rse.cfle = false", collect_isr
    )
    clear_pending = interruption_delivery.find(
        "env->rse.pending_fill_count = 0", clear_cfle
    )
    if not (0 <= collect_isr < clear_cfle < clear_pending):
        raise AssertionError("interruption delivery must sample ISR.ir/rs "
                             "before clearing CFLE and legacy fill markers")
    forbid(return_frame_helper + return_fill_helper + return_chain_helper +
           return_trap_helpers, (
        "exec_bundle", "exec_slot", "finish_direct_branch_bundle",
        "finish_indirect_branch_bundle", "ia64_exec_b_indirect_branch",
        "ia64_return_from_call_frame",
    ), "focused return helper wrappers")
    require(return_frame_core, (
        "restored_cfm = pfs & IA64_PFS_CFM_MASK",
        "restored_ec =",
        "restored_cpl =",
        "restored_sol = ia64_cfm_sol(restored_cfm)",
        "bad_pfs = ia64_rse_return_to_frame(env, restored_cfm, restored_sol)",
        "ia64_write_ar(env, IA64_AR_EC, restored_ec)",
        "if (current_cpl < restored_cpl)",
        "restored_cpl << IA64_PSR_CPL_SHIFT",
        "return bad_pfs",
    ), "architectural PFS/CFM/EC/CPL return core")
    return_core_frame = return_frame_core.find("ia64_rse_return_to_frame")
    return_core_ec = return_frame_core.find("ia64_write_ar", return_core_frame)
    return_core_cpl = return_frame_core.find(
        "if (current_cpl < restored_cpl)", return_core_ec
    )
    if not (0 <= return_core_frame < return_core_ec < return_core_cpl):
        raise AssertionError("return core must restore the RSE/CFM frame, EC, "
                             "then demote CPL only when PPL is less privileged")
    require(return_partition_core, (
        "old_sof = env->rse.sof",
        "growth = (int32_t)new_sof - (int32_t)preserved -",
        "ia64_rse_sync_logical_out(env)",
        "ia64_assign_cfm(env, pfm & IA64_PFS_CFM_MASK)",
        "ia64_rse_set_bol(env, (int32_t)env->rse.bol - preserved)",
        "ia64_rse_restore_frame_partitions(",
        "env->rse.cfle = env->rse.dirty < 0 || env->rse.dirty_nat < 0",
        "ia64_rse_sync_logical_in(env)",
        "ia64_alat_invalidate_stacked_gr_range",
    ), "partition-neutral return CFM transition")
    forbid(return_partition_core, (
        "ia64_set_cfm(env, pfm", "ia64_set_cfm(env, pfm &",
    ), "partition-neutral return CFM transition")
    require(return_partition_adjust, (
        "if (growth > env->rse.invalid + env->rse.clean)",
        "ia64_assign_cfm(env, 0)",
    ), "partition-neutral bad-PFS return transition")
    forbid(return_partition_adjust, (
        "ia64_set_cfm(env, 0)",
    ), "partition-neutral bad-PFS return transition")
    return_partition_cfm = return_partition_core.find("ia64_assign_cfm")
    return_partition_bol = return_partition_core.find(
        "ia64_rse_set_bol", return_partition_cfm
    )
    return_partition_restore = return_partition_core.find(
        "ia64_rse_restore_frame_partitions", return_partition_bol
    )
    return_partition_cfle = return_partition_core.find(
        "env->rse.cfle", return_partition_restore
    )
    if not (0 <= return_partition_cfm < return_partition_bol <
            return_partition_restore < return_partition_cfle):
        raise AssertionError("return must assign decoded CFM without synthetic "
                             "partition growth, retreat BOF, restore partitions, "
                             "then publish CFLE")

    loop_opcodes = {
        "IA64_OP_BR_CLOOP",
        "IA64_OP_BR_CTOP",
        "IA64_OP_BR_CEXIT",
        "IA64_OP_BR_WTOP",
        "IA64_OP_BR_WEXIT",
    }
    classified_loop_opcodes = set(re.findall(
        r"case (IA64_OP_BR_[A-Z0-9_]+):", loop_classifier
    ))
    if classified_loop_opcodes != loop_opcodes:
        raise AssertionError(
            "typed loop classifier is not exactly the five architectural "
            f"forms: got={sorted(classified_loop_opcodes)}"
        )
    require(supported, (
        "ia64_tr_decoded_is_conditional_branch(opcode)",
    ), "typed loop opcode admission")
    require(rewrite_plan, (
        "ia64_tr_decoded_is_loop_branch(insn->opcode)",
        "insn->opcode != IA64_OP_BR_CLOOP",
        "ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_LC)",
        "ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_LC)",
        "ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_EC)",
        "ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_EC)",
        "plan->source_cfm = true",
        "plan->dest_cfm = true",
        "plan->dest_pr = p63",
        "plan->must_pr = p63",
        "g_assert(plan->forward_pr == 0)",
        "plan->branch_source_pr = UINT64_C(1) << insn->qp",
    ), "typed loop ordered-resource planning")
    require(loop_resource_assert, (
        "instruction->source_ar[0] == 0",
        "instruction->dest_ar[0] == 0",
        "expected_ar = lc",
        "expected_ar = lc | ec",
        "expected_ar = ec",
        "instruction->source_cfm",
        "instruction->dest_cfm",
        "instruction->branch_source_pr == expected_branch_pr",
        "instruction->dest_pr == p63",
        "instruction->must_pr == p63",
        "(instruction->forward_pr & p63) == 0",
    ), "typed loop transaction-resource audit")
    require(loop_lower, (
        "ia64_tr_assert_loop_branch_resources(instruction, insn)",
        "arm->direct_target = bundle_ip + (uint64_t)insn->imm",
        "if (insn->opcode == IA64_OP_BR_CLOOP)",
        "ia64_tr_load_ar(ctx, lc, IA64_AR_LC)",
        "tcg_gen_setcondi_i64(TCG_COND_NE, lc_nonzero, lc, 0)",
        "tcg_gen_subi_i64(decremented, lc, 1)",
        "ia64_tr_store_ar(ctx, IA64_AR_LC, decremented)",
        "ia64_tr_group_prepare_pr(ctx, 63)",
        "ia64_tr_load_ar(ctx, ec, IA64_AR_EC)",
        "TCG_COND_GTU, ec_gt_one, ec, 1",
        "ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp)",
        "tcg_gen_or_i64(active, predicate_true, ec_gt_one)",
        "tcg_gen_or_i64(rotate, predicate_true, ec_nonzero)",
        "tcg_gen_andc_i64(decrement_ec, ec_nonzero, predicate_true)",
        "ia64_tr_group_stage_pr_const(p63, false)",
        "tcg_gen_or_i64(active, lc_nonzero, ec_gt_one)",
        "tcg_gen_or_i64(rotate, lc_nonzero, ec_nonzero)",
        "tcg_gen_andc_i64(decrement_ec, ec_nonzero, lc_nonzero)",
        "ia64_tr_group_stage_pr_bool(p63, lc_nonzero)",
        "ia64_tr_store_ar(ctx, IA64_AR_EC, decremented)",
        "tcg_gen_xori_i64(taken, active, 1)",
        "ia64_tr_group_finish_instruction_success(ctx, insn)",
        "ia64_tr_group_close(ctx)",
        "ia64_tr_split_state_cache_at_typed_branch(ctx)",
        "gen_helper_rotate_modulo_registers(tcg_env)",
        "tcg_gen_brcondi_i64(TCG_COND_NE, taken, 0, arm->taken)",
    ), "complete typed loop lowering")
    forbid(loop_lower, (
        "gen_helper_exec_bundle",
        "gen_helper_exec_bundle_lookup_ptr",
        "gen_helper_exec_slot",
        "gen_helper_finish_direct_branch_bundle",
        "gen_helper_finish_indirect_branch_bundle",
        "gen_helper_loop_counted_update",
        "gen_helper_loop_while_update",
        "ia64_rse_sync_logical_in",
        "ia64_rse_sync_logical_out",
        "ia64_exec_b_branch_relative",
        "ia64_tr_translate_direct_branch",
        "insn->raw >>",
    ), "complete typed loop lowering")
    if loop_lower.count("gen_helper_rotate_modulo_registers(tcg_env)") != 1:
        raise AssertionError("typed loop lowering must contain exactly one "
                             "focused modulo-rotation helper call site")
    cloop_begin = loop_lower.find(
        "if (insn->opcode == IA64_OP_BR_CLOOP)"
    )
    modulo_begin = loop_lower.find("} else {", cloop_begin)
    if not (0 <= cloop_begin < modulo_begin):
        raise AssertionError("typed loop lowering lost its CLOOP/modulo split")
    forbid(loop_lower[cloop_begin:modulo_begin], (
        "gen_helper_rotate_modulo_registers",
        "ia64_tr_group_prepare_pr",
        "IA64_AR_EC",
    ), "direct CLOOP lowering")
    loop_finish = loop_lower.find(
        "ia64_tr_group_finish_instruction_success(ctx, insn)"
    )
    loop_close = loop_lower.find("ia64_tr_group_close(ctx)", loop_finish)
    rotation_guard = loop_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_EQ, rotate, 0", loop_close
    )
    rotation_call = loop_lower.find(
        "gen_helper_rotate_modulo_registers(tcg_env)", rotation_guard
    )
    taken_split = loop_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_NE, taken, 0, arm->taken)",
        rotation_call,
    )
    if not (0 <= loop_finish < loop_close < rotation_guard < rotation_call <
            taken_split):
        raise AssertionError("loop p63/counter state must retire before a "
                             "runtime-guarded rotation and taken split")
    forbid(source + helper_source + insn_source, (
        "loop_counted_update",
        "loop_while_update",
    ), "obsolete whole-loop semantic helpers")
    require(helper_source, (
        "DEF_HELPER_1(rotate_modulo_registers, void, env)",
    ), "focused modulo-rotation helper declaration")
    require(rotation_helper, (
        "IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE)",
        "ia64_rotate_modulo_scheduled_registers(env)",
    ), "focused modulo-rotation helper wrapper")
    forbid(rotation_helper, (
        "exec_bundle",
        "exec_slot",
        "ia64_exec_b_branch_relative",
        "ia64_rse_sync_logical_in",
    ), "focused modulo-rotation helper wrapper")
    require(rotation_core, (
        "rotating_gr_count = env->rse.sor * 8",
        "rotating_gr_count <= IA64_GR_COUNT - IA64_STATIC_GR_COUNT",
        "ia64_rse_sync_logical_out(env)",
        "ia64_alat_invalidate_rotating_grs(env, rotating_gr_count)",
        "memmove(&env->gr[IA64_STATIC_GR_COUNT + 1]",
        "(rotating_gr_count - 1) * sizeof(env->gr[0])",
        "env->gr[IA64_STATIC_GR_COUNT] = last",
        "env->rse.rrb_gr",
        "env->rse.rrb_fr",
        "env->rse.rrb_pr",
        "ia64_update_cfm_rename_bases(env)",
        "env->rse.logical_dirty[0]",
        "env->rse.logical_dirty[1]",
    ), "bounded modulo-rotation semantic core")
    forbid(rotation_core, (
        "ia64_rse_sync_logical_in",
        "ia64_exec_b_branch_relative",
        "ia64_exec_bundle",
    ), "bounded modulo-rotation semantic core")
    if rotation_core.count("ia64_rse_sync_logical_out(env)") != 1:
        raise AssertionError("modulo rotation must perform exactly one "
                             "dirty-only logical sync-out and no sync-in")

    # Discover rather than name the private mirror-permutation routine.  The
    # stable contract is that the semantic core invokes exactly one helper
    # which rotates all three GR overlay components, and no PR/BR provenance.
    overlay_candidates = []
    for function in re.finditer(
            r"(?m)^static void ([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            insn_source):
        finish = insn_source.find("\n}\n", function.end())
        if finish < 0:
            continue
        body = insn_source[function.start():finish + 3]
        if all(token in body for token in (
                "issue_group", "saved_gr", "saved_nat",
                "saved_gr_mask", "typed_active")):
            overlay_candidates.append((function.group(1), body))
    if len(overlay_candidates) != 1:
        raise AssertionError("modulo rotation must have exactly one bounded "
                             "typed GR-overlay permutation routine; got "
                             f"{[name for name, _ in overlay_candidates]}")
    overlay_name, overlay_rotation = overlay_candidates[0]
    require(overlay_rotation, (
        "if (!group->typed_active || rotating_count == 0)",
        "group->saved_gr[IA64_STATIC_GR_COUNT + rotating_count - 1]",
        "group->saved_nat[IA64_STATIC_GR_COUNT + rotating_count - 1]",
        "memmove(&group->saved_gr[IA64_STATIC_GR_COUNT + 1]",
        "memmove(&group->saved_nat[IA64_STATIC_GR_COUNT + 1]",
        "(rotating_count - 1) * sizeof(group->saved_gr[0])",
        "(rotating_count - 1) * sizeof(group->saved_nat[0])",
        "group->saved_gr_mask[0]",
        "group->saved_gr_mask[1]",
    ), "typed rotating GR/NaT source overlay")
    forbid(overlay_rotation, (
        "saved_pr",
        "pr_saved",
        "branch_pr_forward_mask",
        "saved_br",
        "saved_br_mask",
        "branch_br_forward_mask",
        "env->pr",
        "rrb_pr",
    ), "typed rotating GR/NaT source overlay")
    if f"{overlay_name}(env, rotating_gr_count);" not in rotation_core:
        raise AssertionError("stable modulo semantic core does not invoke "
                             "the discovered typed GR-overlay permutation")

    require(branch_cfg_preflight, (
        "ia64_tr_decoded_is_conditional_branch",
        "if (insn->qp == 0)",
        "ia64_tr_decoded_is_loop_branch(insn->opcode)",
        "continue;",
        "*last_slot = slot + insn->slot_span - 1",
        "ia64_tr_preflight_decoded_bundle_through(decoded,",
        "IA64_SLOT_COUNT - 1",
    ), "typed branch-CFG admission")
    forbid(branch_cfg_preflight, (
        "IA64TcgDirectBranch",
        "ia64_tcg_build_direct_branch",
        "ia64_tcg_direct_branch_rejection",
        "gen_helper_",
    ), "typed branch-CFG admission")
    p0_gate = branch_cfg_preflight.find("if (insn->qp == 0)")
    p0_loop_gate = branch_cfg_preflight.find(
        "ia64_tr_decoded_is_loop_branch(insn->opcode)", p0_gate
    )
    p0_loop_continue = branch_cfg_preflight.find(
        "continue;", p0_loop_gate
    )
    p0_bound = branch_cfg_preflight.find(
        "*last_slot = slot + insn->slot_span - 1", p0_loop_continue
    )
    p0_validate = branch_cfg_preflight.find(
        "ia64_tr_preflight_decoded_bundle_through(decoded,", p0_bound
    )
    full_validate = branch_cfg_preflight.find(
        "IA64_SLOT_COUNT - 1", p0_validate
    )
    if not (0 <= p0_gate < p0_loop_gate < p0_loop_continue < p0_bound <
            p0_validate < full_validate):
        raise AssertionError("p0 loop forms must retain their dynamic false "
                             "path; only simple p0 branches may truncate "
                             "before the full conditional-path check")

    require(typed_direct_branch_exit, (
        "if (taken)",
        "ia64_tr_store_typed_taken_visibility_state",
        "ia64_tr_store_source_visibility_state",
        "ia64_tr_commit_ip(target)",
        "ia64_tr_flush_fast_bundle_ticks(ctx)",
        "ia64_tr_emit_exit_request_guard",
        "tcg_gen_goto_tb",
        "tcg_gen_lookup_and_goto_ptr",
    ), "typed direct-branch exit arm")
    branch_publish = typed_direct_branch_exit.find(
        "ia64_tr_commit_ip(target)"
    )
    branch_flush = typed_direct_branch_exit.find(
        "ia64_tr_flush_fast_bundle_ticks(ctx)"
    )
    branch_guard = typed_direct_branch_exit.find(
        "ia64_tr_emit_exit_request_guard"
    )
    if not (0 <= branch_publish < branch_flush < branch_guard):
        raise AssertionError("each typed direct arm must publish frontier/IP "
                             "before an exit-capable tick flush")

    require(typed_indirect_branch_exit, (
        "ia64_tr_store_typed_taken_visibility_state",
        "ia64_tr_commit_ip_value(target)",
        "ia64_tr_flush_fast_bundle_ticks(ctx)",
        "ia64_tr_emit_exit_request_guard",
        "tcg_gen_lookup_and_goto_ptr",
    ), "typed indirect-branch exit arm")
    forbid(typed_indirect_branch_exit, (
        "gen_helper_", "tcg_gen_goto_tb",
        "ia64_tr_store_source_visibility_state",
    ), "typed indirect-branch exit arm")
    indirect_publish = typed_indirect_branch_exit.find(
        "ia64_tr_commit_ip_value(target)"
    )
    indirect_flush = typed_indirect_branch_exit.find(
        "ia64_tr_flush_fast_bundle_ticks(ctx)", indirect_publish
    )
    indirect_guard = typed_indirect_branch_exit.find(
        "ia64_tr_emit_exit_request_guard", indirect_flush
    )
    indirect_lookup = typed_indirect_branch_exit.find(
        "tcg_gen_lookup_and_goto_ptr", indirect_guard
    )
    if not (0 <= indirect_publish < indirect_flush < indirect_guard <
            indirect_lookup):
        raise AssertionError("typed indirect arm must commit its dynamic IP "
                             "and frontier before its exit-capable flush")

    require(branch_br_load, (
        "instruction->branch_source_br == bit",
        "issue_group.branch_br_forward_mask",
        "ia64_tr_load_br(ctx, live, reg)",
        "ia64_tr_group_load_ordinary_br(ctx, ordinary, reg)",
        "tcg_gen_movcond_i64(TCG_COND_NE, value, forward",
        "live, ordinary",
    ), "typed indirect branch BR source selection")
    forbid(branch_br_load, (
        "gen_helper_", "gen_helper_exec_bundle", "gen_helper_exec_slot",
        "fallback",
    ), "typed indirect branch BR source selection")

    require(typed_branch_split, (
        "ia64_tr_decoded_is_conditional_branch",
        "ia64_tr_group_load_branch_predicate",
        "if (insn->opcode == IA64_OP_BR_INDIRECT)",
        "ia64_tr_group_load_branch_br",
        "tcg_gen_andi_i64(arm->indirect_target, arm->indirect_target",
        "~UINT64_C(0xf)",
        "ia64_tr_group_finish_instruction_success",
        "ia64_tr_group_close",
        "ia64_tr_split_state_cache_at_typed_branch",
        "tcg_gen_br(arm->taken)",
        "tcg_gen_brcondi_i64(TCG_COND_NE, predicate, 0, arm->taken)",
        "return unconditional",
    ), "typed branch runtime split")
    forbid(typed_branch_split, (
        "IA64TcgDirectBranch",
        "ia64_tcg_build_direct_branch",
        "ia64_tr_translate_direct_branch",
        "ia64_tcg_direct_branch_rejection",
        "gen_helper_finish_direct_branch_bundle",
        "gen_helper_exec_bundle",
        "gen_helper_exec_slot",
        "insn->raw >>",
        "ia64_tr_flush_fast_bundle_ticks(ctx)",
    ), "typed branch runtime split")
    branch_load = typed_branch_split.find(
        "ia64_tr_group_load_branch_predicate"
    )
    indirect_load = typed_branch_split.find(
        "ia64_tr_group_load_branch_br", branch_load
    )
    indirect_align = typed_branch_split.find(
        "tcg_gen_andi_i64(arm->indirect_target", indirect_load
    )
    branch_finish = typed_branch_split.find(
        "ia64_tr_group_finish_instruction_success", branch_load
    )
    branch_close = typed_branch_split.find(
        "ia64_tr_group_close", branch_finish
    )
    branch_split = typed_branch_split.find(
        "tcg_gen_brcondi_i64", branch_close
    )
    if not (0 <= branch_load < indirect_load < indirect_align <
            branch_finish < branch_close < branch_split):
        raise AssertionError("typed branch must load predicate/BR provenance, "
                             "align the dynamic target, retire, close when "
                             "needed, then split runtime control flow")

    require(typed_branch_cfg_exits, (
        "if (has_fallthrough)",
        "ia64_tr_emit_typed_direct_branch_exit",
        "gen_set_label(arms[i].taken)",
        "if (arms[i].indirect)",
        "ia64_tr_emit_typed_indirect_branch_exit",
        "arms[i].direct_target",
    ), "ordered typed branch CFG exits")
    forbid(typed_branch_cfg_exits, (
        "gen_helper_", "gen_helper_exec_bundle", "gen_helper_exec_slot",
        "finish_indirect_branch_bundle",
    ), "ordered typed branch CFG exits")

    require(typed_taken_visibility, (
        "issue_group.saved_gr_mask",
        "issue_group.saved_br_mask",
        "issue_group.branch_br_forward_mask",
        "issue_group.pr_saved",
        "issue_group.branch_pr_forward_mask",
        "issue_group.typed_active",
        "instruction_group_start",
        "instruction_group_dirty",
    ), "taken-branch fresh visibility state")
    forbid(typed_taken_visibility, (
        "gen_helper_", "ia64_tr_store_source_visibility_state",
    ), "taken-branch fresh visibility state")

    require(rewrite_liveness, (
        "live_pr |= plan->source_pr | plan->branch_source_pr",
        "live_br |= plan->source_br | plan->branch_source_br",
    ), "branch-aware reverse liveness")

    require(machine_source, (
        ".version_id = 4",
        "VMSTATE_UINT64_ARRAY_V(issue_group.saved_br",
        "VMSTATE_UINT64_V(issue_group.branch_pr_forward_mask",
        "VMSTATE_UINT8_V(issue_group.saved_br_mask",
        "VMSTATE_UINT8_V(issue_group.branch_br_forward_mask",
        "ia64_issue_group_overlay_post_load",
        "env->pr ^ env->issue_group.saved_pr",
        "version_id < 2",
        "version_id < 3",
        "version_id < 4",
        "env->issue_group.saved_br_mask = 0",
        "env->issue_group.branch_br_forward_mask = 0",
        "env->issue_group.saved_br_mask != 0",
        "env->issue_group.branch_br_forward_mask != 0",
        "branch_pr_forward_mask & 1",
    ), "migrated branch-forward state")
    require(machine_source, (
        ".version_id = 5",
        "if (version_id < 5)",
        "env->issue_group.saved_pfs = 0",
        "env->issue_group.pfs_saved = false",
        "env->issue_group.branch_pfs_forwarded = false",
        "VMSTATE_UINT64_V(issue_group.saved_pfs, CPUIA64State, 5)",
        "VMSTATE_BOOL_V(issue_group.pfs_saved, CPUIA64State, 5)",
        "VMSTATE_BOOL_V(issue_group.branch_pfs_forwarded",
        "env->issue_group.pfs_saved ||",
        "env->issue_group.branch_pfs_forwarded ||",
        "env->issue_group.branch_pfs_forwarded &&",
        "!env->issue_group.pfs_saved",
    ), "versioned migrated AR.PFS overlay state")
    require(cpu_header, (
        "uint64_t saved_br[IA64_BR_COUNT]",
        "uint64_t branch_pr_forward_mask",
        "uint8_t saved_br_mask",
        "uint8_t branch_br_forward_mask",
        "env->issue_group.saved_br_mask = 0",
        "env->issue_group.branch_br_forward_mask = 0",
        "env->issue_group.branch_pr_forward_mask = 0",
        "uint64_t saved_pfs",
        "bool pfs_saved",
        "bool branch_pfs_forwarded",
        "env->issue_group.pfs_saved = false",
        "env->issue_group.branch_pfs_forwarded = false",
    ), "branch-forward reset state")
    require(legacy_impl, (
        "env->issue_group.saved_br_mask != 0",
        "env->issue_group.branch_br_forward_mask != 0",
        "env->issue_group.branch_pr_forward_mask != 0",
        "env->issue_group.pfs_saved",
        "env->issue_group.branch_pfs_forwarded",
    ), "legacy runtime forwarding-owner guard")

    continuation_gate = group_preflight.find("if (continuation_only)")
    continuation_scan_bound = group_preflight.find(
        "branch_cfg ? branch_last_slot : IA64_SLOT_COUNT - 1",
        continuation_gate,
    )
    continuation_p0_bound = group_preflight.find(
        "if (branch_cfg && branch_last_slot < accepted_last_slot)",
        continuation_scan_bound,
    )
    fresh_branch_gate = group_preflight.find(
        "else if (branch_cfg)", continuation_p0_bound
    )
    if not (0 <= continuation_gate < continuation_scan_bound <
            continuation_p0_bound < fresh_branch_gate):
        raise AssertionError("continuation-only ownership must scan no later "
                             "than the first p0 edge and truncate the accepted "
                             "suffix before fresh branch-CFG admission")

    require(classifier_source, (
        "IA64_TCG_TB_BOUNDARY_BRANCH",
        "major == 0xc || major == 0xd",
    ), "long-branch TB boundary classification")
    forbid(supported, ("case IA64_OP_MUX:", "case IA64_OP_MPYSH:",
                       "case IA64_OP_MPYUH:", "case IA64_OP_SHL_IMM:",
                       "case IA64_OP_SHR_IMM:",
                       "case IA64_OP_SHRU_IMM:"),
           "validated typed opcode whitelist")

    require(source, (
        "typedef struct IA64TrInstructionTransaction",
        "typedef struct IA64TrGrWrite",
        "typedef struct IA64TrBrWrite",
        "typedef struct IA64TrPrWrite",
        "typedef struct IA64TrPrImageWrite",
        "g_assert(ia64_tr_group_is_empty(ctx));",
    ), "per-instruction transaction state")
    require(transaction, (
        "ia64_tr_group_load_ordinary_gr_pair",
        "ia64_tr_group_load_ordinary_br",
        "ia64_tr_group_load_ordinary_predicate",
        "ia64_tr_group_preserve_ordinary_gr_source",
        "ia64_tr_group_preserve_ordinary_br_source",
        "ia64_tr_group_preserve_ordinary_pr_source",
        "ia64_tr_group_clear_ordinary_source_overlay",
        "ia64_tr_group_begin_instruction",
        "ia64_tr_group_finish_instruction_success",
        "ia64_tr_group_publish_prefix_for_noreturn_fault",
        "ia64_tr_group_close",
        "ia64_tr_store_static_gr_ref_pair",
        "ia64_tr_store_br",
        "ia64_tr_write_pr_bool",
        "ia64_tr_emit_gr_alat_invalidate",
        "ia64_tr_group_prepare_pr",
        "ia64_tr_group_stage_pr_bool",
        "last_successful_bundle",
        "instruction->pre_ic",
        "ia64_tr_sync_state_cache(ctx);",
    ), "instruction-group transaction")
    forbid(transaction, ("gen_helper_exec_bundle", "gen_helper_exec_slot",
                         "IA64TcgFastSlot"),
           "instruction-group transaction")
    gr_preserve = transaction_retire.find(
        "ia64_tr_group_preserve_ordinary_gr_source"
    )
    gr_store = transaction_retire.find("ia64_tr_store_static_gr", gr_preserve)
    pr_preserve = transaction_retire.find(
        "ia64_tr_group_preserve_ordinary_pr_source"
    )
    pr_store = transaction_retire.find("ia64_tr_write_pr_bool", pr_preserve)
    pr_image_store = transaction_retire.find(
        "ia64_tr_write_pr_image_masked", pr_preserve
    )
    br_preserve_pos = transaction_retire.find(
        "ia64_tr_group_preserve_ordinary_br_source"
    )
    br_store = transaction_retire.find("ia64_tr_store_br", br_preserve_pos)
    br_forward_store = transaction_retire.find(
        "ia64_tr_group_update_branch_forward_br", br_store
    )
    if not (0 <= gr_preserve < gr_store and 0 <= pr_preserve < pr_store):
        raise AssertionError("each eager typed write must preserve its "
                             "group-entry value before changing live state")
    if not (0 <= pr_preserve < pr_image_store):
        raise AssertionError("a packed PR-image write must preserve its "
                             "group-entry image before changing live state")
    if not (0 <= br_preserve_pos < br_store < br_forward_store):
        raise AssertionError("each eager BR write must preserve its "
                             "group-entry value, retire live state, then "
                             "publish branch-forward provenance")

    require(pr_image_load, (
        "group->pr_may_written",
        "group->pr_must_saved",
        "issue_group.saved_pr",
        "issue_group.pr_saved",
        "tcg_gen_movcond_i64",
        "tcg_gen_ori_i64(value, value, 1)",
    ), "ordinary packed PR-image overlay selection")
    require(pr_move_lower, (
        "ia64_tr_group_load_ordinary_pr_image",
        "ia64_tr_group_stage_gr(gr_write, image, tcg_constant_i64(0))",
        "ia64_tr_group_prepare_pr_image",
        "ia64_tr_group_load_ordinary_gr_pair",
        "gen_helper_raise_register_nat_consumption",
        "ia64_tr_group_stage_pr_image",
        "IA64_TR_PR_ROTATING_MASK",
    ), "typed packed PR-move lowering")
    forbid(pr_move_lower, (
        "gen_helper_exec_bundle",
        "gen_helper_exec_slot",
        "ia64_tr_group_prepare_pr(ctx",
        "ia64_tr_write_pr_bool",
        "ia64_tr_predicate_bit",
    ), "typed packed PR-move lowering")
    require(br_move_lower, (
        "IA64_OP_MOV_BRGR",
        "IA64_OP_MOV_GRBR",
        "ia64_tr_group_prepare_gr",
        "ia64_tr_group_load_ordinary_br",
        "ia64_tr_group_stage_gr",
        "ia64_tr_group_prepare_br",
        "ia64_tr_group_load_ordinary_gr_pair",
        "ia64_tr_emit_decoded_register_nat_consumption",
        "ia64_tr_group_stage_br",
    ), "typed ordered BR-move lowering")
    forbid(br_move_lower, (
        "gen_helper_exec_bundle",
        "gen_helper_exec_slot",
        "ia64_tr_emit_exec_slot",
        "IA64TcgFastSlot",
        "fallback",
        "insn->raw >>",
    ), "typed ordered BR-move lowering")
    brgr_guard = br_move_lower.find(
        "ia64_tr_emit_decoded_predicate_guard(ctx, insn)"
    )
    brgr_read = br_move_lower.find(
        "ia64_tr_group_load_ordinary_br", brgr_guard
    )
    brgr_stage = br_move_lower.find(
        "ia64_tr_group_stage_gr", brgr_read
    )
    grbr_block = br_move_lower.find("IA64TrBrWrite *br_write")
    grbr_guard = br_move_lower.find(
        "ia64_tr_emit_decoded_predicate_guard(ctx, insn)", grbr_block
    )
    grbr_read = br_move_lower.find(
        "ia64_tr_group_load_ordinary_gr_pair", grbr_guard
    )
    grbr_nat_branch = br_move_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0", grbr_read
    )
    grbr_fault = br_move_lower.find(
        "ia64_tr_emit_decoded_register_nat_consumption", grbr_nat_branch
    )
    grbr_stage = br_move_lower.find(
        "ia64_tr_group_stage_br", grbr_fault
    )
    if not (0 <= brgr_guard < brgr_read < brgr_stage < grbr_block <
            grbr_guard < grbr_read < grbr_nat_branch < grbr_fault <
            grbr_stage):
        raise AssertionError("typed BR moves must qualify before ordinary "
                             "source reads, and mov b=r must fault on NaT "
                             "before staging the BR result")
    require(rewrite_plan, (
        "plan->source_br = 1u << insn->r2",
        "plan->dest_br = bit",
        "plan->forward_br = bit",
        "plan->must_br = bit",
    ), "BR-move ordered-resource planning")
    require(rewrite_liveness, (
        "uint8_t live_br",
        "plan->preserve_br = plan->dest_br & live_br",
        "live_br |= plan->source_br",
    ), "BR-move liveness and first-write preservation")
    require(call_admission, (
        "insn->opcode == IA64_OP_MOV_ARGR",
        "insn->opcode == IA64_OP_MOV_GRAR",
        "insn->unit == IA64_INSN_UNIT_I",
        "insn->slot_span == 1",
        "insn->r2 == IA64_AR_PFS",
    ), "exact I-unit AR.PFS move admission")
    require(rewrite_plan, (
        "if (insn->opcode == IA64_OP_MOV_ARGR)",
        "ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_PFS)",
        "if (insn->opcode == IA64_OP_MOV_GRAR)",
        "plan->source_gr[half] =",
        "ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_PFS)",
        "plan->forward_pfs = true",
        "plan->must_pfs = insn->qp == 0",
    ), "AR.PFS move resource planning")
    require(pfs_ordinary_load, (
        "group->pfs_may_saved",
        "group->pfs_must_saved",
        "issue_group.saved_pfs",
        "issue_group.pfs_saved",
        "tcg_gen_movcond_i64",
    ), "ordinary AR.PFS saved/live selection")
    forbid(pfs_ordinary_load, (
        "gen_helper_", "exec_bundle", "exec_slot",
    ), "ordinary AR.PFS saved/live selection")
    require(pfs_branch_load, (
        "instruction->branch_source_pfs",
        "issue_group.branch_pfs_forwarded",
        "ia64_tr_load_ar(ctx, live, IA64_AR_PFS)",
        "ia64_tr_group_load_ordinary_pfs(ctx, ordinary)",
        "tcg_gen_movcond_i64",
    ), "branch-only AR.PFS forwarding selector")
    require(pfs_write, (
        "if (!group->pfs_must_saved)",
        "if (group->pfs_may_saved)",
        "issue_group.pfs_saved",
        "ia64_tr_load_ar(ctx, old_pfs, IA64_AR_PFS)",
        "issue_group.saved_pfs",
        "ia64_tr_store_ar(ctx, IA64_AR_PFS, value)",
        "issue_group.branch_pfs_forwarded",
        "group->pfs_may_saved = true",
        "group->pfs_must_saved |= must_write",
        "group->branch_pfs_forward_may_nonzero = true",
    ), "first-actual-write AR.PFS preservation")
    old_load = pfs_write.find(
        "ia64_tr_load_ar(ctx, old_pfs, IA64_AR_PFS)"
    )
    saved_store = pfs_write.find("issue_group.saved_pfs", old_load)
    saved_valid = pfs_write.find("issue_group.pfs_saved", saved_store)
    live_store = pfs_write.find(
        "ia64_tr_store_ar(ctx, IA64_AR_PFS, value)", saved_valid
    )
    branch_forward_store = pfs_write.find(
        "issue_group.branch_pfs_forwarded", live_store
    )
    if not (0 <= old_load < saved_store < saved_valid < live_store <
            branch_forward_store):
        raise AssertionError("AR.PFS must preserve the first actual live "
                             "value, publish validity, retire live PFS, then "
                             "publish branch-forward provenance")
    require(pfs_move_lower, (
        "insn->unit == IA64_INSN_UNIT_I",
        "insn->slot_span == 1",
        "insn->r2 == IA64_AR_PFS",
        "ia64_tr_group_load_ordinary_pfs",
        "ia64_tr_group_stage_gr",
        "ia64_tr_group_load_ordinary_gr_pair",
        "ia64_tr_emit_decoded_register_nat_consumption",
        "ia64_tr_group_write_pfs",
    ), "typed AR.PFS move lowering")
    forbid(pfs_move_lower, (
        "gen_helper_exec_bundle", "gen_helper_exec_slot",
        "ia64_tr_emit_exec_slot", "IA64TcgFastSlot", "fallback",
        "insn->raw >>", "issue_group.branch_pfs_forwarded",
    ), "typed AR.PFS move lowering")
    argr_guard = pfs_move_lower.find(
        "ia64_tr_emit_decoded_predicate_guard(ctx, insn)"
    )
    argr_read = pfs_move_lower.find(
        "ia64_tr_group_load_ordinary_pfs", argr_guard
    )
    argr_stage = pfs_move_lower.find(
        "ia64_tr_group_stage_gr", argr_read
    )
    grar_block = pfs_move_lower.find("TCGLabel *nat_clear")
    grar_guard = pfs_move_lower.find(
        "ia64_tr_emit_decoded_predicate_guard(ctx, insn)", grar_block
    )
    grar_read = pfs_move_lower.find(
        "ia64_tr_group_load_ordinary_gr_pair", grar_guard
    )
    grar_nat_branch = pfs_move_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0", grar_read
    )
    grar_fault = pfs_move_lower.find(
        "ia64_tr_emit_decoded_register_nat_consumption", grar_nat_branch
    )
    grar_write = pfs_move_lower.find(
        "ia64_tr_group_write_pfs", grar_fault
    )
    grar_guard_end = pfs_move_lower.find(
        "ia64_tr_finish_fast_slot_predicate_guard(skip)", grar_write
    )
    if not (0 <= argr_guard < argr_read < argr_stage < grar_block <
            grar_guard < grar_read < grar_nat_branch < grar_fault <
            grar_write < grar_guard_end):
        raise AssertionError("typed AR.PFS moves must qualify before source "
                             "reads; GR-to-PFS must fault on NaT before the "
                             "only actual write/forward publication")
    require(source_overlay_clear, (
        "group->pfs_may_saved",
        "issue_group.pfs_saved",
        "group->branch_pfs_forward_may_nonzero",
        "issue_group.branch_pfs_forwarded",
    ), "AR.PFS stop-boundary overlay clear")
    require(typed_taken_visibility, (
        "issue_group.pfs_saved",
        "issue_group.branch_pfs_forwarded",
    ), "taken-branch AR.PFS overlay clear")
    require(fresh_visibility, (
        "env->issue_group.pfs_saved = false",
        "env->issue_group.branch_pfs_forwarded = false",
        "ia64_env_begin_source_visibility_epoch",
        "ia64_env_clear_ordinary_source_overlay(env)",
    ), "fresh-epoch AR.PFS overlay clear")
    grpr_block = pr_move_lower.find(
        "if (insn->opcode == IA64_OP_MOV_GRPR) {"
    )
    pr_guard = pr_move_lower.find(
        "ia64_tr_emit_decoded_predicate_guard(ctx, insn)", grpr_block
    )
    pr_source = pr_move_lower.find(
        "ia64_tr_group_load_ordinary_gr_pair", pr_guard
    )
    pr_nat_branch = pr_move_lower.find(
        "tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0", pr_source
    )
    pr_fault = pr_move_lower.find(
        "ia64_tr_emit_decoded_register_nat_consumption", pr_nat_branch
    )
    pr_stage = pr_move_lower.find(
        "ia64_tr_group_stage_pr_image", pr_fault
    )
    if not (0 <= pr_guard < pr_source < pr_nat_branch < pr_fault < pr_stage):
        raise AssertionError("mov pr=r must qualify before reading its "
                             "ordinary GR/NaT source, then fault before its "
                             "packed PR-image write")
    require(rewrite_plan, (
        "plan->source_pr = UINT64_MAX & ~UINT64_C(1)",
        "plan->source_gr[half] = ia64_tr_nonzero_register_bit(insn->r1)",
        "plan->dest_pr = mask",
        "plan->dest_pr = IA64_TR_PR_ROTATING_MASK",
        "plan->must_pr = IA64_TR_PR_ROTATING_MASK",
    ), "packed PR-move liveness planning")
    require(rewrite_plan, (
        "ia64_tr_decoded_is_integer_compare_opcode(insn->opcode)",
        "source_count = ia64_tr_decoded_sources(insn, sources)",
        "insn->pred_update == IA64_PRED_UPDATE_NORMAL",
        "(insn->compare_unc || insn->qp == 0)",
        "plan->must_pr = plan->dest_pr",
    ), "integer-compare liveness and conditional-write planning")
    require(nat_helper, (
        "ia64_deliver_exception_fast",
        "IA64_EXCEPTION_REGISTER_NAT_CONSUMPTION",
        "IA64_EXCEPTION_ACCESS_NONE",
        "fault_exit_pending_tb_translate",
        "cpu_loop_exit(cpu)",
    ), "typed Register NaT Consumption helper")
    require(helper_source, (
        "DEF_HELPER_FLAGS_1(raise_register_nat_consumption, "
        "TCG_CALL_NO_RETURN",
    ), "Register NaT Consumption helper declaration")

    require(transaction_begin, (
        "tcg_get_insn_start_param",
        "tcg_set_insn_start_param",
        "IA64_INSN_START_TYPED_GROUP",
        "issue_group.typed_active",
    ), "typed activation unwind marker")
    require(optional_gr_prepare, (
        "tcg_gen_movi_i64(write->value, 0)",
        "tcg_gen_movi_i64(write->nat, 0)",
        "tcg_gen_movi_i64(write->written, 0)",
    ), "optional staged GR payload initialization")
    require(optional_pr_prepare, (
        "tcg_gen_movi_i64(write->value, 0)",
        "tcg_gen_movi_i64(write->written, 0)",
    ), "optional staged PR payload initialization")
    require(optional_pr_image_prepare, (
        "tcg_gen_movi_i64(write->value, 0)",
        "tcg_gen_movi_i64(write->written, 0)",
    ), "optional staged PR-image payload initialization")
    require(optional_br_prepare, (
        "write->preserve_source",
        "write->must_write",
        "write->forward_to_branch",
        "tcg_gen_movi_i64(write->value, 0)",
        "tcg_gen_movi_i64(write->written, 0)",
    ), "optional staged BR payload initialization")
    for label, prepare in (
        ("GR", optional_gr_prepare),
        ("BR", optional_br_prepare),
        ("PR", optional_pr_prepare),
        ("PR-image", optional_pr_image_prepare),
    ):
        payload_init = prepare.find("tcg_gen_movi_i64(write->value, 0)")
        written_init = prepare.find("tcg_gen_movi_i64(write->written, 0)")
        if not (0 <= payload_init < written_init):
            raise AssertionError(f"optional staged {label} payload must be "
                                 "defined before its merge-visible written "
                                 "flag")
    require(restore_opc, (
        "ia64_env_restore_source_visibility(&cpu->env, data[2]);",
    ), "host-PC source-visibility restore")
    require(restore_visibility, (
        "if (!env->instruction_group_dirty)",
        "IA64_INSN_START_TYPED_GROUP",
        "env->issue_group.typed_active",
    ), "typed-owner restoration from insn_start")

    begin = typed_bundle.find("ia64_tr_group_begin_instruction")
    emit = typed_bundle.find("ia64_tr_emit_decoded_instruction", begin)
    finish = typed_bundle.find(
        "ia64_tr_group_finish_instruction_success", emit
    )
    close = typed_bundle.find("ia64_tr_group_close", finish)
    if not (0 <= begin < emit < finish < close):
        raise AssertionError("typed instructions must begin, emit, retire, "
                             "then close their issue group in order")

    require(group_preflight, (
        "remaining_bundles",
        "tcg_op_buf_has_space",
        "IA64_TR_REWRITE_OPS_PER_BUNDLE",
        "translator_is_same_page",
        "ia64_tcg_tb_boundary_ends_tb",
        "ia64_decode_instruction_bundle",
        "ia64_tr_preflight_decoded_bundle",
        "decoded.ends_at_group_boundary",
    ), "rewrite-region preflight")
    forbid(group_preflight, ("gen_helper_", "ia64_tr_emit_"),
           "rewrite-region preflight")

    require(logical_globals, (
        "cpu_logical_gr[IA64_GR_COUNT - IA64_STATIC_GR_COUNT]",
        "cpu_logical_nat[2]",
        "cpu_logical_dirty[2]",
        "cpu_logical_gr_names",
        '"logical_nat0", "logical_nat1"',
        '"logical_dirty0", "logical_dirty1"',
    ), "persistent logical stacked-GR globals")
    require(logical_init, (
        "for (unsigned i = 0; i < ARRAY_SIZE(cpu_logical_gr); i++)",
        '"r%u", IA64_STATIC_GR_COUNT + i',
        "tcg_global_mem_new_i64",
        "offsetof(CPUIA64State, gr[IA64_STATIC_GR_COUNT + i])",
        "offsetof(CPUIA64State, rse.logical_nat[i])",
        "offsetof(CPUIA64State, rse.logical_dirty[i])",
    ), "96-value logical mirror global initialization")
    require(logical_access, (
        "reg - IA64_STATIC_GR_COUNT",
        "ia64_tr_logical_gr_index",
        "ia64_tr_logical_gr_word",
        "ia64_tr_logical_gr_mask",
        "cpu_logical_gr[",
        "cpu_logical_nat[",
        "tcg_gen_ori_i64(cpu_logical_dirty[word]",
        "ia64_tr_write_logical_gr_nat",
    ), "fixed logical stacked-GR lowering")
    require(logical_pair, (
        "ia64_tr_read_logical_gr_nat(nat, ref->reg)",
        "ia64_tr_write_logical_gr_nat(ctx, ref->reg, nat_value)",
        "ia64_tr_mark_logical_gr_dirty(ref->reg)",
    ), "logical staged GR/NaT pair lowering")
    forbid(source, (
        "rse.stacked_gr",
        "rse.stacked_nat",
        "rse.current_frame_base",
        "rse.clean_count",
        "rse.rrb_gr",
        "ia64_tr_stacked_gr_slot",
        "ia64_tr_stacked_gr_address",
        "ia64_tr_stacked_nat_address",
        "ia64_tr_ensure_stacked_frame_base",
        "TCGv_ptr",
        "tcg_gen_remu_i64",
    ), "ordinary physical stacked-GR lowering")
    require(logical_nat_guards, (
        "uint64_t logical_mask[2]",
        "cpu_logical_nat[word]",
        "source_mask_hi >> IA64_STATIC_GR_COUNT",
    ), "logical stacked-NaT guards")
    forbid(logical_nat_guards, (
        "uses_stacked_gr",
        "rse.sor",
        "gen_helper_fast_gr_nat_any",
    ), "logical stacked-NaT guards")
    require(focused_alloc, (
        "ia64_tr_publish_faulting_slot(ctx, slot)",
        "gen_helper_fast_alloc(tcg_env, tcg_constant_i64(raw))",
        "ia64_tr_finish_faulting_slot()",
    ), "focused alloc transition")
    forbid(focused_alloc, (
        "ia64_make_cfm",
        "offsetof(CPUIA64State, cfm)",
        "offsetof(CPUIA64State, rse.sof)",
        "offsetof(CPUIA64State, rse.sor)",
    ), "focused alloc transition")
    require(helper_source, (
        "DEF_HELPER_2(fast_alloc, void, env, i64)",
    ), "alloc read/write-global helper declaration")
    forbid(decoded_prime, (
        "stacked",
        "current_frame_base",
        "ensure_stacked",
    ), "decoded logical-GR priming")
    require(legacy_branch, (
        "branch.kind != IA64_TCG_DIRECT_BRANCH_CALL",
        "branch.kind != IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL",
    ), "helper-owned call-frame transition")
    forbid(source, (
        "VIBTANIUM_TCG_INLINE_CALL",
        "ia64_tr_emit_call_effects",
    ), "unsafe inline call-frame remapping")

    require(helper_frontier, (
        "g_assert(!ctx->typed_group_active)",
        "ia64_tr_store_legacy_helper_frontier",
    ), "full-bundle legacy-helper frontier")
    require(partial_helper, (
        "g_assert(!ctx->typed_group_active)",
        "ia64_tr_store_legacy_helper_frontier",
        "gen_helper_exec_slot",
    ), "partial legacy-helper frontier")
    require(execution_epoch, (
        "ia64_slot_is_m_serialization",
        "ia64_slot_is_m_processor_mask",
        "ia64_slot_is_m_mov_to_processor_status",
        "for (unsigned slot = start_slot;",
        "ia64_tr_emit_exec_slot(ctx, bundle, pc, slot, flow_exit);",
        "ia64_tr_publish_restart_ri(boundary_slot + 1);",
    ), "slot-precise PSR/serialization epoch split")
    epoch_scan = execution_epoch.find(
        "ia64_tr_first_execution_epoch_end_slot(bundle, start_slot)"
    )
    epoch_execute = execution_epoch.find(
        "ia64_tr_emit_exec_slot(ctx, bundle, pc, slot, flow_exit);",
        epoch_scan,
    )
    epoch_restart = execution_epoch.find(
        "ia64_tr_publish_restart_ri(boundary_slot + 1);",
        epoch_execute,
    )
    if not (0 <= epoch_scan < epoch_execute < epoch_restart):
        raise AssertionError("execution epochs must scan from the incoming RI, "
                             "execute through the first boundary, then publish "
                             "the first unexecuted RI")
    forbid(helper_frontier + partial_helper, (
        "ia64_tr_store_source_visibility_state",
    ), "legacy helper ownership handoff")
    require(legacy_impl, (
        "env->issue_group.typed_active",
        "env->issue_group.saved_gr_mask[0]",
        "env->issue_group.saved_gr_mask[1]",
        "env->issue_group.pr_saved",
        "cpu_abort(cpu",
    ), "legacy runtime ownership guard")
    guard = legacy_impl.find("if (unlikely(")
    first_execution = legacy_impl.find("if (!partial)")
    if not (0 <= guard < first_execution):
        raise AssertionError("legacy ownership guard must run before generic "
                             "bundle execution begins")
    if legacy_wrappers.count("ia64_exec_bundle_impl(") != 3:
        raise AssertionError("all three generic TCG helpers must funnel "
                             "through the guarded legacy implementation")

    group_select = source.find("ia64_tr_preflight_rewrite_region(",
                               source.find("static void ia64_tr_translate_insn"))
    start_slot_select = source.find(
        "ia64_tcg_tb_boundary_for_bundle_from_slot_with_physical(",
        source.find("static void ia64_tr_translate_insn"),
    )
    typed_select = source.find("ia64_tr_try_decoded_bundle(", group_select)
    legacy_select = source.find("ia64_tr_translate_fast_bundle(", typed_select)
    if not (0 <= start_slot_select < group_select < typed_select < legacy_select):
        raise AssertionError("rewrite must preflight a complete region and "
                             "run before the legacy hybrid selectors, using a "
                             "boundary scan that starts at the incoming RI")

    print("IA-64 full-TCG structural guardrails: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
