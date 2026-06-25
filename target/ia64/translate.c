/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "bundle.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "exec/memop.h"
#include "exec/translator.h"
#include "tcg/tcg-op.h"
#include "trace-target_ia64.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef HELPER_H

typedef struct DisasContext {
    DisasContextBase base;
    CPUIA64State *env;
} DisasContext;

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

    ctx->base.is_jmp = DISAS_NEXT;
    ctx->env = cpu_env(cs);
}

static void ia64_tr_tb_start(DisasContextBase *dcbase, CPUState *cs)
{
}

static void ia64_tr_insn_start(DisasContextBase *dcbase, CPUState *cs)
{
    tcg_gen_insn_start(dcbase->pc_next, 0, 0);
}

static void ia64_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    IA64DecodedBundle bundle;
    char bundle_text[160];
    uint64_t lo;
    uint64_t hi;

    lo = translator_ldq_end(ctx->env, &ctx->base, ctx->base.pc_next, MO_LE);
    hi = translator_ldq_end(ctx->env, &ctx->base, ctx->base.pc_next + 8, MO_LE);
    ia64_decode_bundle_words(lo, hi, &bundle);
    ia64_format_decoded_bundle(&bundle, bundle_text, sizeof(bundle_text));
    trace_ia64_bundle_decode(ctx->base.pc_next, bundle_text);

    tcg_gen_movi_i64(cpu_ip, ctx->base.pc_next);
    gen_helper_raise_unimplemented(tcg_env);
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void ia64_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
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
    DisasContext ctx;

    translator_loop(cs, tb, max_insns, pc, host_pc, &ia64_tr_ops, &ctx.base,
                    TCG_TYPE_VA);
}
