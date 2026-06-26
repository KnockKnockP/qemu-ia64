/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "bundle.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "exec/memop.h"
#include "exec/translator.h"
#include "hw/ia64/efi.h"
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

#define IA64_REGION_OFFSET_MASK UINT64_C(0x1fffffffffffffff)

enum {
    IA64_EFI_SERVICE_DESCRIPTOR_COUNT =
        VIBTANIUM_EFI_BOOT_SERVICE_COUNT +
        VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT +
        VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT +
        VIBTANIUM_EFI_CON_IN_SERVICE_COUNT +
        VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT +
        VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT +
        VIBTANIUM_EFI_FILE_SERVICE_COUNT,
};

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

static bool ia64_pc_is_efi_call_gate(uint64_t pc)
{
    uint64_t offset;

    pc &= IA64_REGION_OFFSET_MASK;
    if (pc == VIBTANIUM_EFI_PAL_PROC || pc == VIBTANIUM_EFI_SAL_PROC) {
        return true;
    }

    if (pc < VIBTANIUM_EFI_CALL_GATE_BASE) {
        return false;
    }

    offset = pc - VIBTANIUM_EFI_CALL_GATE_BASE;
    if ((offset & (IA64_BUNDLE_SIZE - 1)) != 0) {
        return false;
    }

    return offset / IA64_BUNDLE_SIZE < IA64_EFI_SERVICE_DESCRIPTOR_COUNT;
}

static bool ia64_slot_may_change_flow(IA64SlotType type, uint64_t raw)
{
    uint8_t major;

    if (type == IA64_SLOT_TYPE_B) {
        major = ia64_slot_major_opcode(raw);
        if (major == 0x1 || major == 0x4 || major == 0x5) {
            return true;
        }
        if (major == 0x0) {
            uint8_t x6 = (raw >> 27) & 0x3f;

            return x6 == 0x08 || x6 == 0x20 || x6 == 0x21;
        }
    } else if (type == IA64_SLOT_TYPE_M && ia64_slot_major_opcode(raw) == 0x0) {
        uint8_t x3 = (raw >> 33) & 0x7;

        if (x3 == 4 || x3 == 5) {
            return true;
        }
        if (x3 == 0) {
            uint8_t x2 = (raw >> 31) & 0x3;
            uint8_t x4 = (raw >> 27) & 0xf;

            return x2 == 0 && x4 == 0;
        }
    }

    return false;
}

static bool ia64_bundle_may_change_flow(const IA64DecodedBundle *bundle,
                                        uint64_t pc)
{
    if (!bundle->valid || ia64_pc_is_efi_call_gate(pc)) {
        return true;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (ia64_slot_may_change_flow(bundle->info->slot_type[slot],
                                      bundle->slot[slot])) {
            return true;
        }
    }

    return false;
}

static void ia64_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    IA64DecodedBundle bundle;
    char bundle_text[160];
    uint64_t pc = ctx->base.pc_next;
    uint64_t lo;
    uint64_t hi;

    lo = translator_ldq_end(ctx->env, &ctx->base, pc, MO_LE);
    hi = translator_ldq_end(ctx->env, &ctx->base, pc + 8, MO_LE);
    ia64_decode_bundle_words(lo, hi, &bundle);
    ia64_format_decoded_bundle(&bundle, bundle_text, sizeof(bundle_text));
    trace_ia64_bundle_decode(pc, bundle_text);

    ctx->base.pc_next = pc + IA64_BUNDLE_SIZE;
    tcg_gen_movi_i64(cpu_ip, pc);
    gen_helper_exec_bundle(tcg_env,
                           tcg_constant_i32(bundle.tmpl),
                           tcg_constant_i64(bundle.slot[0]),
                           tcg_constant_i64(bundle.slot[1]),
                           tcg_constant_i64(bundle.slot[2]));
    if (ia64_bundle_may_change_flow(&bundle, pc)) {
        ctx->base.is_jmp = DISAS_EXIT;
    }
}

static void ia64_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_TOO_MANY:
        tcg_gen_movi_i64(cpu_ip, ctx->base.pc_next);
        tcg_gen_exit_tb(NULL, 0);
        break;
    case DISAS_EXIT:
        tcg_gen_exit_tb(NULL, 0);
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
    DisasContext ctx;

    translator_loop(cs, tb, max_insns, pc, host_pc, &ia64_tr_ops, &ctx.base,
                    TCG_TYPE_VA);
}
