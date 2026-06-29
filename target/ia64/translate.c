/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "bundle.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "exec/memop.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "exec/translator.h"
#include "perf.h"
#include "tcg-skeleton.h"
#include "tcg/tcg-op.h"
#include "trace-target_ia64.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef HELPER_H

typedef struct DisasContext {
    DisasContextBase base;
    CPUIA64State *env;
} DisasContext;

#define DISAS_EXIT DISAS_TARGET_0

static TCGv_i64 cpu_ip;

void ia64_translate_init(void)
{
    cpu_ip = tcg_global_mem_new_i64(tcg_env,
                                    offsetof(CPUIA64State, ip),
                                    "ip");
}

static void ia64_tr_init_disas_context(DisasContextBase *dcbase,
                                       CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    int bound;

    ctx->base.is_jmp = DISAS_NEXT;
    ctx->env = cpu_env(cs);

    /*
     * Instruction fetch exceptions raised while translating a later bundle in
     * a TB must not skip earlier, already translated-but-not-executed bundles.
     * Keep each TB inside the starting TARGET_PAGE_SIZE page so the next page
     * is fetched only after the current page's bundles have retired.
     */
    bound = -(ctx->base.pc_first | TARGET_PAGE_MASK) / IA64_BUNDLE_SIZE;
    ctx->base.max_insns = MIN(ctx->base.max_insns, bound);
}

static void ia64_tr_tb_start(DisasContextBase *dcbase, CPUState *cs)
{
    if (ia64_perf_enabled()) {
        gen_helper_perf_tb_exec();
    }
}

static void ia64_tr_insn_start(DisasContextBase *dcbase, CPUState *cs)
{
    tcg_gen_insn_start(dcbase->pc_next, 0, 0);
}

static void ia64_tr_emit_exec_bundle(const IA64DecodedBundle *bundle,
                                     uint64_t pc)
{
    tcg_gen_movi_i64(cpu_ip, pc);
    gen_helper_exec_bundle(tcg_env,
                           tcg_constant_i32(bundle->tmpl),
                           tcg_constant_i64(bundle->slot[0]),
                           tcg_constant_i64(bundle->slot[1]),
                           tcg_constant_i64(bundle->slot[2]));
}

static void ia64_tr_load_static_gr(TCGv_i64 dest, uint8_t reg)
{
    if (reg == 0) {
        tcg_gen_movi_i64(dest, 0);
        return;
    }

    tcg_gen_ld_i64(dest, tcg_env,
                   offsetof(CPUIA64State, gr) + reg * sizeof(uint64_t));
}

static void ia64_tr_store_static_gr(uint8_t reg, TCGv_i64 value)
{
    if (reg == 0) {
        return;
    }

    tcg_gen_st_i64(value, tcg_env,
                   offsetof(CPUIA64State, gr) + reg * sizeof(uint64_t));
}

static void ia64_tr_set_psr_ri(uint8_t slot)
{
    TCGv_i64 psr = tcg_temp_new_i64();

    tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_andi_i64(psr, psr, ~IA64_PSR_RI_MASK);
    if (slot != 0) {
        tcg_gen_ori_i64(psr, psr, (uint64_t)slot << IA64_PSR_RI_SHIFT);
    }
    tcg_gen_st_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
}

static void ia64_tr_load_fast_source2(TCGv_i64 dest,
                                      const IA64TcgFastSlot *slot)
{
    if (slot->source2_immediate) {
        tcg_gen_movi_i64(dest, slot->immediate);
    } else {
        ia64_tr_load_static_gr(dest, slot->source2);
    }
}

static MemOp ia64_tr_ldst_memop(uint8_t width)
{
    switch (width) {
    case 1:
        return MO_UB;
    case 2:
        return MO_LEUW;
    case 4:
        return MO_LEUL;
    case 8:
        return MO_LEUQ;
    default:
        g_assert_not_reached();
    }
}

static int ia64_tr_data_mmu_index(DisasContext *ctx)
{
    return ia64_tcg_data_mmu_index_for_tb_flags(ctx->base.tb->flags);
}

static void ia64_tr_emit_ldst_base_update(const IA64TcgFastSlot *slot,
                                          TCGv_i64 address)
{
    TCGv_i64 updated;

    if (!slot->base_update) {
        return;
    }

    updated = tcg_temp_new_i64();
    tcg_gen_addi_i64(updated, address, slot->immediate);
    ia64_tr_store_static_gr(slot->base, updated);
}

static void ia64_tr_emit_fast_slot(DisasContext *ctx,
                                   const IA64TcgFastSlot *slot,
                                   TCGv_i64 ldst_address)
{
    TCGv_i64 result;
    TCGv_i64 source2;
    TCGv_i64 source3;

    if (slot->op == IA64_TCG_FAST_OP_NOP) {
        return;
    }

    result = tcg_temp_new_i64();
    source2 = tcg_temp_new_i64();
    source3 = tcg_temp_new_i64();

    switch (slot->op) {
    case IA64_TCG_FAST_OP_ALU_ADD:
        ia64_tr_load_static_gr(source3, slot->source3);
        if (slot->source2_immediate) {
            tcg_gen_addi_i64(result, source3, slot->immediate);
        } else {
            ia64_tr_load_static_gr(source2, slot->source2);
            tcg_gen_add_i64(result, source2, source3);
            if (slot->immediate != 0) {
                tcg_gen_addi_i64(result, result, slot->immediate);
            }
        }
        break;
    case IA64_TCG_FAST_OP_ALU_LOGIC:
        ia64_tr_load_static_gr(source3, slot->source3);
        ia64_tr_load_fast_source2(source2, slot);
        switch (slot->logic_op) {
        case IA64_TCG_FAST_LOGIC_AND:
            tcg_gen_and_i64(result, source2, source3);
            break;
        case IA64_TCG_FAST_LOGIC_ANDCM:
            tcg_gen_andc_i64(result, source2, source3);
            break;
        case IA64_TCG_FAST_LOGIC_OR:
            tcg_gen_or_i64(result, source2, source3);
            break;
        case IA64_TCG_FAST_LOGIC_XOR:
            tcg_gen_xor_i64(result, source2, source3);
            break;
        default:
            g_assert_not_reached();
        }
        break;
    case IA64_TCG_FAST_OP_ADDL:
        ia64_tr_load_static_gr(source3, slot->source3);
        tcg_gen_addi_i64(result, source3, slot->immediate);
        break;
    case IA64_TCG_FAST_OP_LDST_LOAD:
        g_assert(ldst_address != NULL);
        ia64_tr_set_psr_ri(slot->slot_index);
        tcg_gen_qemu_ld_i64(result, ldst_address, ia64_tr_data_mmu_index(ctx),
                            ia64_tr_ldst_memop(slot->width));
        ia64_tr_store_static_gr(slot->target, result);
        ia64_tr_emit_ldst_base_update(slot, ldst_address);
        return;
    case IA64_TCG_FAST_OP_LDST_STORE:
        g_assert(ldst_address != NULL);
        ia64_tr_load_static_gr(source2, slot->source2);
        ia64_tr_set_psr_ri(slot->slot_index);
        tcg_gen_qemu_st_i64(source2, ldst_address,
                            ia64_tr_data_mmu_index(ctx),
                            ia64_tr_ldst_memop(slot->width));
        gen_helper_finish_fast_store(tcg_env, ldst_address,
                                     tcg_constant_i32(slot->width));
        ia64_tr_emit_ldst_base_update(slot, ldst_address);
        return;
    default:
        g_assert_not_reached();
    }

    ia64_tr_store_static_gr(slot->target, result);
}

static bool ia64_tr_fast_bundle_has_ldst(const IA64TcgFastBundle *fast)
{
    return ia64_perf_fast_count(fast->op_counts,
                                IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT) != 0 ||
           ia64_perf_fast_count(fast->op_counts,
                                IA64_PERF_FAST_COUNT_LDST_STORE_SHIFT) != 0;
}

static bool ia64_tr_translate_fast_bundle(DisasContext *ctx,
                                          const IA64DecodedBundle *bundle,
                                          uint64_t pc)
{
    IA64TcgFastBundle fast;
    TCGLabel *fallback;
    TCGLabel *done;
    TCGv_i64 tmp;
    TCGv_i64 ldst_address[IA64_SLOT_COUNT] = { NULL, };
    bool has_ldst;

    if (!ia64_tcg_build_fast_bundle(bundle, &fast)) {
        return false;
    }

    has_ldst = ia64_tr_fast_bundle_has_ldst(&fast);
    fallback = gen_new_label();
    done = gen_new_label();
    tmp = tcg_temp_new_i64();

    tcg_gen_ld_i64(tmp, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_andi_i64(tmp, tmp, IA64_PSR_RI_MASK);
    tcg_gen_brcondi_i64(TCG_COND_NE, tmp, 0, fallback);
    if (fast.source_nat_mask != 0) {
        tcg_gen_ld_i64(tmp, tcg_env,
                       offsetof(CPUIA64State, nat.gr_nat[0]));
        tcg_gen_andi_i64(tmp, tmp, fast.source_nat_mask);
        tcg_gen_brcondi_i64(TCG_COND_NE, tmp, 0, fallback);
    }
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (fast.slot[slot].op == IA64_TCG_FAST_OP_LDST_LOAD ||
            fast.slot[slot].op == IA64_TCG_FAST_OP_LDST_STORE) {
            ldst_address[slot] = tcg_temp_new_i64();
            ia64_tr_load_static_gr(ldst_address[slot], fast.slot[slot].base);
            if (fast.slot[slot].width > 1) {
                tcg_gen_andi_i64(tmp, ldst_address[slot],
                                 fast.slot[slot].width - 1);
                tcg_gen_brcondi_i64(TCG_COND_NE, tmp, 0, fallback);
            }
        }
    }

    tcg_gen_movi_i64(cpu_ip, pc);
    gen_helper_start_fast_bundle(tcg_env,
                                 tcg_constant_i32(fast.slot_count),
                                 tcg_constant_i32(fast.op_counts));
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        ia64_tr_emit_fast_slot(ctx, &fast.slot[slot], ldst_address[slot]);
    }
    gen_helper_finish_fast_bundle(tcg_env,
                                  tcg_constant_i64(pc + IA64_BUNDLE_SIZE),
                                  tcg_constant_i64(fast.dest_mask));
    tcg_gen_br(done);

    gen_set_label(fallback);
    if (has_ldst && ia64_perf_enabled()) {
        gen_helper_perf_tcg_ldst_fallback();
    }
    ia64_tr_emit_exec_bundle(bundle, pc);
    gen_set_label(done);
    return true;
}

static void ia64_tr_emit_main_loop_exit(void)
{
    if (ia64_perf_enabled()) {
        gen_helper_perf_tb_exit_main_loop();
    }
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_emit_direct_branch_exit(DisasContext *ctx,
                                            uint64_t target,
                                            bool taken,
                                            int tb_slot,
                                            uint8_t nop_count)
{
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 chain_ok = tcg_temp_new_i32();

    gen_helper_finish_direct_branch_bundle(chain_ok, tcg_env,
                                           tcg_constant_i64(target),
                                           tcg_constant_i32(taken ? 1 : 0),
                                           tcg_constant_i32(nop_count));
    tcg_gen_brcondi_i32(TCG_COND_EQ, chain_ok, 0, main_loop_exit);
    tcg_gen_goto_tb(tb_slot);
    tcg_gen_exit_tb(ctx->base.tb, tb_slot);

    gen_set_label(main_loop_exit);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_count_branch_fallback(const IA64DecodedBundle *bundle)
{
    if (ia64_tcg_bundle_has_indirect_branch(bundle)) {
        IA64_PERF_INC(IA64_PERF_TCG_BRANCH_INDIRECT_FALLBACK);
    }
    if (ia64_tcg_bundle_has_direct_branch(bundle)) {
        IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK);
    }
}

static bool ia64_tr_translate_direct_branch(DisasContext *ctx,
                                            const IA64DecodedBundle *bundle,
                                            uint64_t pc)
{
    IA64TcgDirectBranch branch;
    TCGLabel *fallback;
    TCGLabel *not_taken = NULL;
    TCGv_i64 tmp;

    if (!ia64_tcg_build_direct_branch(bundle, pc, &branch)) {
        return false;
    }
    if (!translator_use_goto_tb(&ctx->base, branch.target_ip) ||
        !translator_use_goto_tb(&ctx->base, branch.fallthrough_ip)) {
        IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK);
        return false;
    }

    fallback = gen_new_label();
    tmp = tcg_temp_new_i64();

    tcg_gen_ld_i64(tmp, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_andi_i64(tmp, tmp, IA64_PSR_RI_MASK);
    tcg_gen_brcondi_i64(TCG_COND_NE, tmp, 0, fallback);

    tcg_gen_movi_i64(cpu_ip, pc);
    if (branch.conditional) {
        not_taken = gen_new_label();
        tcg_gen_ld_i64(tmp, tcg_env, offsetof(CPUIA64State, pr));
        tcg_gen_andi_i64(tmp, tmp, 1ULL << branch.predicate);
        tcg_gen_brcondi_i64(TCG_COND_EQ, tmp, 0, not_taken);
    }

    ia64_tr_emit_direct_branch_exit(ctx, branch.target_ip, true, 0,
                                    branch.nop_count);
    if (branch.conditional) {
        gen_set_label(not_taken);
        ia64_tr_emit_direct_branch_exit(ctx, branch.fallthrough_ip, false, 1,
                                        branch.nop_count);
    }

    gen_set_label(fallback);
    if (ia64_perf_enabled()) {
        gen_helper_perf_direct_branch_fallback();
    }
    ia64_tr_emit_exec_bundle(bundle, pc);
    ia64_tr_emit_main_loop_exit();
    return true;
}

static void ia64_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    IA64DecodedBundle bundle;
    IA64TcgTbBoundary boundary;
    char bundle_text[160];
    uint64_t pc = ctx->base.pc_next;
    uint64_t lo;
    uint64_t hi;

    lo = translator_ldq_end(ctx->env, &ctx->base, pc, MO_LE);
    hi = translator_ldq_end(ctx->env, &ctx->base, pc + 8, MO_LE);
    ia64_decode_bundle_words(lo, hi, &bundle);
    IA64_PERF_INC(IA64_PERF_BUNDLE_DECODED);
    if (!bundle.valid) {
        IA64_PERF_INC(IA64_PERF_BUNDLE_DECODE_INVALID);
    }
    ia64_format_decoded_bundle(&bundle, bundle_text, sizeof(bundle_text));
    trace_ia64_bundle_decode(pc, bundle_text);

    ctx->base.pc_next = pc + IA64_BUNDLE_SIZE;
    boundary = ia64_tcg_tb_boundary_for_bundle(&bundle, pc);
    if (boundary == IA64_TCG_TB_BOUNDARY_BRANCH &&
        ia64_tr_translate_direct_branch(ctx, &bundle, pc)) {
        ctx->base.is_jmp = DISAS_NORETURN;
        return;
    }
    if (boundary == IA64_TCG_TB_BOUNDARY_BRANCH) {
        ia64_tr_count_branch_fallback(&bundle);
    }
    if (ia64_tcg_tb_boundary_ends_tb(boundary) ||
        !ia64_tr_translate_fast_bundle(ctx, &bundle, pc)) {
        if (!ia64_tcg_tb_boundary_ends_tb(boundary) &&
            ia64_tcg_bundle_has_ldst_immediate(&bundle)) {
            IA64_PERF_INC(IA64_PERF_TCG_LDST_FALLBACK);
        }
        ia64_tr_emit_exec_bundle(&bundle, pc);
    }
    if (ia64_tcg_tb_boundary_ends_tb(boundary)) {
        trace_ia64_tcg_tb_boundary(pc,
                                   ia64_tcg_tb_boundary_name(boundary));
        IA64_PERF_INC(IA64_PERF_TB_EXIT_FLOW_TRANSLATED);
        ctx->base.is_jmp = DISAS_EXIT;
    }
}

static void ia64_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_TOO_MANY:
        tcg_gen_movi_i64(cpu_ip, ctx->base.pc_next);
        ia64_tr_emit_main_loop_exit();
        break;
    case DISAS_EXIT:
        ia64_tr_emit_main_loop_exit();
        break;
    case DISAS_NORETURN:
        break;
    default:
        g_assert_not_reached();
    }
}

static const TranslatorOps ia64_tr_ops = {
    .init_disas_context = ia64_tr_init_disas_context,
    .tb_start = ia64_tr_tb_start,
    .insn_start = ia64_tr_insn_start,
    .translate_insn = ia64_tr_translate_insn,
    .tb_stop = ia64_tr_tb_stop,
};

void ia64_translate_code(CPUState *cs, TranslationBlock *tb, int *max_insns,
                         vaddr pc, void *host_pc)
{
    IA64CPU *cpu = IA64_CPU(cs);
    DisasContext ctx;

    IA64_PERF_INC(IA64_PERF_TB_TRANSLATED);
    if (cpu->env.fault_exit_pending_tb_translate) {
        IA64_PERF_INC(IA64_PERF_TB_TRANSLATED_AFTER_FAULT);
        cpu->env.fault_exit_pending_tb_translate = false;
    }
    IA64_PERF_INC((IA64PerfCounter)(IA64_PERF_TB_GENERATED_REGION0 +
                                    (pc >> 61)));
    translator_loop(cs, tb, max_insns, pc, host_pc, &ia64_tr_ops, &ctx.base,
                    TCG_TYPE_VA);
}
