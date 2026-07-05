/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu-param.h"
#include "firmware.h"
#include "insn.h"
#include "perf.h"
#include "tcg-classify.h"

#define IA64_REGION_OFFSET_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_KERNEL_PAGE_OFFSET UINT64_C(0xe000000000000000)
#define IA64_TCG_FAST_GR_LIMIT 64
#define IA64_TCG_TARGET_PAGE_MASK (~((UINT64_C(1) << TARGET_PAGE_BITS) - 1))

bool ia64_tcg_pc_is_efi_call_gate(uint64_t pc)
{
    uint64_t region;
    uint64_t offset;

    region = pc & ~IA64_REGION_OFFSET_MASK;
    if (region != 0 && region != IA64_KERNEL_PAGE_OFFSET) {
        return false;
    }
    pc &= IA64_REGION_OFFSET_MASK;
    if (pc == IA64_FIRMWARE_EFI_PAL_PROC ||
        pc == IA64_FIRMWARE_EFI_SAL_PROC) {
        return true;
    }

    if (pc < IA64_FIRMWARE_EFI_CALL_GATE_BASE) {
        return false;
    }

    offset = pc - IA64_FIRMWARE_EFI_CALL_GATE_BASE;
    if ((offset & (IA64_BUNDLE_SIZE - 1)) != 0) {
        return false;
    }

    return offset / IA64_BUNDLE_SIZE <
           IA64_FIRMWARE_EFI_CLASSIFY_SERVICE_COUNT;
}

const char *ia64_tcg_tb_boundary_name(IA64TcgTbBoundary boundary)
{
    switch (boundary) {
    case IA64_TCG_TB_BOUNDARY_NONE:
        return "none";
    case IA64_TCG_TB_BOUNDARY_INVALID_TEMPLATE:
        return "invalid-template";
    case IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE:
        return "efi-call-gate";
    case IA64_TCG_TB_BOUNDARY_BREAK:
        return "break";
    case IA64_TCG_TB_BOUNDARY_SPECULATION_CHECK:
        return "speculation-check";
    case IA64_TCG_TB_BOUNDARY_VIRTUAL_TRANSLATION:
        return "virtual-translation";
    case IA64_TCG_TB_BOUNDARY_BRANCH:
        return "branch";
    case IA64_TCG_TB_BOUNDARY_CPU_STATE:
        return "cpu-state";
    case IA64_TCG_TB_BOUNDARY_TRANSLATION_STATE:
        return "translation-state";
    case IA64_TCG_TB_BOUNDARY_RSE_STATE:
        return "rse-state";
    default:
        return "unknown";
    }
}

bool ia64_tcg_tb_boundary_ends_tb(IA64TcgTbBoundary boundary)
{
    return boundary != IA64_TCG_TB_BOUNDARY_NONE;
}

static IA64TcgFallbackReason ia64_tcg_fallback_reason_for_boundary(
    IA64TcgTbBoundary boundary)
{
    switch (boundary) {
    case IA64_TCG_TB_BOUNDARY_NONE:
        return IA64_TCG_FALLBACK_NONE;
    case IA64_TCG_TB_BOUNDARY_INVALID_TEMPLATE:
        return IA64_TCG_FALLBACK_INVALID_TEMPLATE;
    case IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE:
        return IA64_TCG_FALLBACK_BOUNDARY_EFI_CALL_GATE;
    case IA64_TCG_TB_BOUNDARY_BREAK:
        return IA64_TCG_FALLBACK_BOUNDARY_BREAK;
    case IA64_TCG_TB_BOUNDARY_SPECULATION_CHECK:
        return IA64_TCG_FALLBACK_BOUNDARY_SPECULATION_CHECK;
    case IA64_TCG_TB_BOUNDARY_VIRTUAL_TRANSLATION:
        return IA64_TCG_FALLBACK_BOUNDARY_VIRTUAL_TRANSLATION;
    case IA64_TCG_TB_BOUNDARY_BRANCH:
        return IA64_TCG_FALLBACK_BOUNDARY_BRANCH;
    case IA64_TCG_TB_BOUNDARY_CPU_STATE:
        return IA64_TCG_FALLBACK_BOUNDARY_CPU_STATE;
    case IA64_TCG_TB_BOUNDARY_TRANSLATION_STATE:
        return IA64_TCG_FALLBACK_BOUNDARY_TRANSLATION_STATE;
    case IA64_TCG_TB_BOUNDARY_RSE_STATE:
        return IA64_TCG_FALLBACK_BOUNDARY_RSE_STATE;
    default:
        return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
    }
}

const char *ia64_tcg_fallback_reason_name(IA64TcgFallbackReason reason)
{
    switch (reason) {
    case IA64_TCG_FALLBACK_NONE:
        return "none";
    case IA64_TCG_FALLBACK_INVALID_TEMPLATE:
        return "invalid-template";
    case IA64_TCG_FALLBACK_BOUNDARY_EFI_CALL_GATE:
        return "boundary.efi-call-gate";
    case IA64_TCG_FALLBACK_BOUNDARY_BREAK:
        return "boundary.break";
    case IA64_TCG_FALLBACK_BOUNDARY_SPECULATION_CHECK:
        return "boundary.speculation-check";
    case IA64_TCG_FALLBACK_BOUNDARY_VIRTUAL_TRANSLATION:
        return "boundary.virtual-translation";
    case IA64_TCG_FALLBACK_BOUNDARY_BRANCH:
        return "boundary.branch";
    case IA64_TCG_FALLBACK_BOUNDARY_CPU_STATE:
        return "boundary.cpu-state";
    case IA64_TCG_FALLBACK_BOUNDARY_TRANSLATION_STATE:
        return "boundary.translation-state";
    case IA64_TCG_FALLBACK_BOUNDARY_RSE_STATE:
        return "boundary.rse-state";
    case IA64_TCG_FALLBACK_FAST_LONG_IMMEDIATE:
        return "fast.long-immediate";
    case IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT:
        return "fast.predicated-slot";
    case IA64_TCG_FALLBACK_FAST_STATIC_GR:
        return "fast.static-gr";
    case IA64_TCG_FALLBACK_FAST_LDST_SLOT:
        return "fast.ldst-slot";
    case IA64_TCG_FALLBACK_FAST_LDST_TRACE:
        return "fast.ldst-trace";
    case IA64_TCG_FALLBACK_FAST_LDST_REGISTER_UPDATE:
        return "fast.ldst-register-update";
    case IA64_TCG_FALLBACK_FAST_LDST_MEMORY_CLASS:
        return "fast.ldst-memory-class";
    case IA64_TCG_FALLBACK_FAST_LDST_DEPENDENCY:
        return "fast.ldst-dependency";
    case IA64_TCG_FALLBACK_FAST_LDST_TARGET:
        return "fast.ldst-target";
    case IA64_TCG_FALLBACK_FAST_LDST_HOST_CODE_SIZE:
        return "fast.ldst-host-code-size";
    case IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT:
        return "fast.unsupported-slot";
    case IA64_TCG_FALLBACK_RUNTIME_GUARD:
        return "runtime-guard";
    default:
        return "unknown";
    }
}

static int64_t ia64_tcg_sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t mask = (1ULL << bits) - 1;

    value &= mask;
    return (int64_t)((value ^ sign) - sign);
}

static bool ia64_tcg_fast_static_gr(uint32_t reg)
{
    return reg < IA64_TCG_FAST_GR_LIMIT;
}

static void ia64_tcg_fast_note_gr(IA64TcgFastSlot *slot, uint32_t reg)
{
    if (reg >= IA64_STATIC_GR_COUNT && reg < IA64_TCG_FAST_GR_LIMIT) {
        slot->uses_stacked_gr = true;
    }
}

static bool ia64_tcg_fast_add_source(IA64TcgFastSlot *slot, uint32_t reg)
{
    if (!ia64_tcg_fast_static_gr(reg)) {
        return false;
    }
    ia64_tcg_fast_note_gr(slot, reg);
    if (reg != 0) {
        slot->source_nat_mask |= 1ULL << reg;
    }
    return true;
}

static bool ia64_tcg_fast_set_target(IA64TcgFastSlot *slot, uint32_t reg)
{
    if (!ia64_tcg_fast_static_gr(reg)) {
        return false;
    }
    ia64_tcg_fast_note_gr(slot, reg);
    slot->target = reg;
    if (reg != 0) {
        slot->dest_mask = 1ULL << reg;
    }
    return true;
}

static void ia64_tcg_fast_count_op(IA64TcgFastBundle *fast, unsigned shift)
{
    fast->op_counts += 1u << shift;
}

static bool ia64_tcg_ldst_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_LDST_TRACE") != NULL ||
                  g_getenv("VIBTANIUM_LDST_TRACE_ADDR") != NULL ||
                  g_getenv("VIBTANIUM_LDST_TRACE_PADDR") != NULL ||
                  g_getenv("VIBTANIUM_LDST_DECODE_TRACE") != NULL;
    }
    return enabled != 0;
}

static bool ia64_tcg_system_mov_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_BRANCH_TRACE") != NULL ||
                  g_getenv("VIBTANIUM_AR_TRACE") != NULL;
    }
    return enabled != 0 ||
           ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_MOVSYS);
}

static bool ia64_tcg_fast_ar_is_plain(uint32_t reg)
{
    /*
     * ia64_read_ar/ia64_write_ar treat every application register as a plain
     * env->ar[] cell except the RSE-coupled group and the clock-backed ITC;
     * those keep interpreter semantics.
     */
    switch (reg) {
    case IA64_AR_RSC:
    case IA64_AR_BSP:
    case IA64_AR_BSPSTORE:
    case IA64_AR_RNAT:
    case IA64_AR_UNAT:
    case IA64_AR_ITC:
        return false;
    default:
        return reg < IA64_AR_COUNT;
    }
}

static bool ia64_tcg_fast_ldst_store_class(uint8_t memory_class)
{
    return memory_class == 0x0c || memory_class == 0x0d ||
           memory_class == 0x0e;
}

static bool ia64_tcg_fast_ldst_load_class(uint8_t memory_class)
{
    switch (memory_class) {
    case 0:
    case 1:
    case 4:
    case 5:
    case 6:
        return true;
    default:
        /*
         * Advanced loads (classes 2/3) and check loads (classes 8/9/A) need
         * ALAT state handling around the target write, so leave them on the
         * interpreter path for now.
         */
        return false;
    }
}

static bool ia64_tcg_ldst_is_memory_access(const IA64LdstImmediate *ldst)
{
    return ldst->kind == IA64_LDST_IMM_LOAD ||
           ldst->kind == IA64_LDST_IMM_STORE;
}

uint32_t ia64_tcg_fast_disable_mask(void)
{
    /*
     * VIBTANIUM_TCG_FAST_DISABLE selectively routes fast-path features back
     * to the interpreter helpers, for isolating miscompares to a lowering
     * feature without rebuilding.  Comma-separated: "bundle" (fast ALU
     * bundles), "branch" (all direct-branch lowering, including the indirect
     * kind), "indirect" (indirect-branch kind only), "movsys" (mov to/from
     * BR/AR fast ops), "alloc" (alloc fast op), or "all".
     */
    static int mask = -1;

    if (mask < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_FAST_DISABLE");
        int parsed = 0;

        if (value != NULL) {
            gchar **parts = g_strsplit(value, ",", -1);

            for (gchar **p = parts; *p != NULL; p++) {
                const gchar *name = g_strstrip(*p);

                if (g_ascii_strcasecmp(name, "bundle") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_BUNDLE;
                } else if (g_ascii_strcasecmp(name, "branch") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_BRANCH;
                } else if (g_ascii_strcasecmp(name, "indirect") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_INDIRECT;
                } else if (g_ascii_strcasecmp(name, "movsys") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_MOVSYS;
                } else if (g_ascii_strcasecmp(name, "alloc") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_ALLOC;
                } else if (g_ascii_strcasecmp(name, "all") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_BUNDLE |
                              IA64_TCG_FAST_DISABLE_BRANCH |
                              IA64_TCG_FAST_DISABLE_INDIRECT |
                              IA64_TCG_FAST_DISABLE_MOVSYS |
                              IA64_TCG_FAST_DISABLE_ALLOC;
                }
            }
            g_strfreev(parts);
        }
        mask = parsed;
    }
    return (uint32_t)mask;
}

bool ia64_tcg_fast_disabled(IA64TcgFastDisable feature)
{
    return (ia64_tcg_fast_disable_mask() & feature) != 0;
}

IA64TcgFastLdstMode ia64_tcg_fast_ldst_mode(void)
{
    /*
     * Fast memory slots lower to direct SoftMMU qemu_ld/st ops.  The crashes
     * that historically kept inline memory lowering opt-in were not host
     * code size: the old lowering emitted an extra insn_start per memory
     * slot, overflowing TCG's per-instruction metadata (gen_insn_data and
     * gen_insn_end_off are sized by tb->icount) and corrupting the TCG pool.
     * The fast path now keeps one insn_start per bundle and publishes the
     * executing slot through env->ri before each memory access instead.
     * VIBTANIUM_TCG_LDST_INLINE=helper keeps the compact decoded helper
     * lowering; =0 (or off) is a kill-switch back to the full interpreter
     * for memory bundles.
     */
    static int mode = -1;

    if (mode < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_LDST_INLINE");

        if (value != NULL && (strcmp(value, "0") == 0 ||
                              g_ascii_strcasecmp(value, "off") == 0)) {
            mode = IA64_TCG_FAST_LDST_OFF;
        } else if (value != NULL &&
                   g_ascii_strcasecmp(value, "helper") == 0) {
            mode = IA64_TCG_FAST_LDST_HELPER;
        } else {
            mode = IA64_TCG_FAST_LDST_DIRECT;
        }
    }
    return mode;
}

bool ia64_tcg_fast_ldst_memory_inline_enabled(void)
{
    return ia64_tcg_fast_ldst_mode() != IA64_TCG_FAST_LDST_OFF;
}

static IA64TcgFallbackReason ia64_tcg_fast_ldst_fallback_reason(
    const IA64LdstImmediate *ldst, unsigned slot_index)
{
    (void)slot_index;

    if (ia64_tcg_ldst_trace_enabled()) {
        return IA64_TCG_FALLBACK_FAST_LDST_TRACE;
    }
    if (ldst->update_from_register) {
        return IA64_TCG_FALLBACK_FAST_LDST_REGISTER_UPDATE;
    }
    if (!ia64_tcg_fast_static_gr(ldst->base)) {
        return IA64_TCG_FALLBACK_FAST_STATIC_GR;
    }

    switch (ldst->kind) {
    case IA64_LDST_IMM_LOAD:
        if (!ia64_tcg_fast_ldst_load_class(ldst->memory_class)) {
            return IA64_TCG_FALLBACK_FAST_LDST_MEMORY_CLASS;
        }
        if (ldst->target == 0) {
            return IA64_TCG_FALLBACK_FAST_LDST_TARGET;
        }
        if (!ia64_tcg_fast_static_gr(ldst->target)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    case IA64_LDST_IMM_STORE:
        if (!ia64_tcg_fast_ldst_store_class(ldst->memory_class)) {
            return IA64_TCG_FALLBACK_FAST_LDST_MEMORY_CLASS;
        }
        if (!ia64_tcg_fast_static_gr(ldst->source)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    case IA64_LDST_IMM_PREFETCH:
        return IA64_TCG_FALLBACK_NONE;
    default:
        return IA64_TCG_FALLBACK_FAST_LDST_MEMORY_CLASS;
    }
}

static bool ia64_tcg_fast_set_base_update(IA64TcgFastSlot *slot,
                                          uint32_t reg)
{
    if (!ia64_tcg_fast_static_gr(reg)) {
        return false;
    }
    ia64_tcg_fast_note_gr(slot, reg);
    if (reg != 0) {
        slot->dest_mask |= 1ULL << reg;
    }
    return true;
}

static bool ia64_tcg_build_fast_ldst_slot(const IA64LdstImmediate *ldst,
                                          unsigned slot_index,
                                          IA64TcgFastSlot *slot,
                                          IA64TcgFastBundle *fast)
{
    if (ia64_tcg_ldst_trace_enabled()) {
        return false;
    }
    if (ldst->update_from_register ||
        !ia64_tcg_fast_add_source(slot, ldst->base)) {
        return false;
    }

    switch (ldst->kind) {
    case IA64_LDST_IMM_LOAD:
        if (!ia64_tcg_fast_ldst_load_class(ldst->memory_class) ||
            ldst->target == 0 ||
            !ia64_tcg_fast_set_target(slot, ldst->target)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_LDST_LOAD;
        ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT);
        break;
    case IA64_LDST_IMM_STORE:
        if (!ia64_tcg_fast_ldst_store_class(ldst->memory_class) ||
            !ia64_tcg_fast_add_source(slot, ldst->source)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_LDST_STORE;
        slot->source2 = ldst->source;
        ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_LDST_STORE_SHIFT);
        break;
    case IA64_LDST_IMM_PREFETCH:
        slot->op = IA64_TCG_FAST_OP_NOP;
        break;
    default:
        return false;
    }

    if (ldst->base_update &&
        !ia64_tcg_fast_set_base_update(slot, ldst->base)) {
        return false;
    }

    slot->base = ldst->base;
    slot->width = ldst->width;
    slot->base_update = ldst->base_update;
    slot->immediate = ldst->immediate;
    slot->slot_index = slot_index;
    return true;
}

static bool ia64_tcg_build_fast_slot(IA64SlotType type, uint64_t raw,
                                     unsigned slot_index,
                                     IA64TcgFastSlot *slot,
                                     IA64TcgFastBundle *fast)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2a;
    uint8_t x2b;
    uint8_t x4;
    IA64LdstImmediate ldst;
    IA64CompareInstruction cmp;
    IA64PredicateTestInstruction pred_test;
    IA64ExtractInstruction extract;
    IA64DepositInstruction deposit;
    IA64IntegerExtendInstruction int_ext;
    uint8_t qp;

    memset(slot, 0, sizeof(*slot));
    slot->slot_index = slot_index;
    qp = ia64_slot_predicate(raw);
    if (qp >= 16) {
        return false;
    }
    slot->qualifying_predicate = qp;

    if (ia64_insn_slot_supported(type, raw) ||
        ia64_slot_is_i_nop(type, raw)) {
        slot->op = IA64_TCG_FAST_OP_NOP;
        ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_NOP_SHIFT);
        return true;
    }

    if (ia64_slot_is_alu_add(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        x2a = (raw >> 34) & 0x3;
        r3 = (raw >> 20) & 0x7f;

        if (!ia64_tcg_fast_set_target(slot, r1) ||
            !ia64_tcg_fast_add_source(slot, r3)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_ALU_ADD;
        slot->source3 = r3;
        if (x2a == 2) {
            slot->source2_immediate = true;
            slot->immediate =
                ia64_tcg_sign_extend((((raw >> 36) & 0x1) << 13) |
                                     (((raw >> 27) & 0x3f) << 7) |
                                     ((raw >> 13) & 0x7f), 14);
        } else {
            r2 = (raw >> 13) & 0x7f;
            if (!ia64_tcg_fast_add_source(slot, r2)) {
                return false;
            }
            slot->source2 = r2;
            slot->immediate = (raw >> 27) & 0x3;
        }
        ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_ALU_ADD_SHIFT);
        return true;
    }

    if (ia64_slot_is_alu_sub(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        x2b = (raw >> 27) & 0x3;
        x4 = (raw >> 29) & 0xf;

        if (!ia64_tcg_fast_set_target(slot, r1) ||
            !ia64_tcg_fast_add_source(slot, r3)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_ALU_SUB;
        slot->source3 = r3;
        if (x4 == 9) {
            slot->source2_immediate = true;
            slot->immediate =
                ia64_tcg_sign_extend((((raw >> 36) & 0x1) << 7) |
                                     ((raw >> 13) & 0x7f), 8);
        } else {
            if (!ia64_tcg_fast_add_source(slot, r2)) {
                return false;
            }
            slot->source2 = r2;
            slot->immediate = x2b == 0 ? 1 : 0;
        }
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_alu_logic(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        x2b = (raw >> 27) & 0x3;
        x4 = (raw >> 29) & 0xf;

        if (!ia64_tcg_fast_set_target(slot, r1) ||
            !ia64_tcg_fast_add_source(slot, r3)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_ALU_LOGIC;
        slot->logic_op = x2b;
        slot->source3 = r3;
        if (x4 == 0xb) {
            slot->source2_immediate = true;
            slot->immediate =
                ia64_tcg_sign_extend((((raw >> 36) & 0x1) << 7) |
                                     ((raw >> 13) & 0x7f), 8);
        } else {
            if (!ia64_tcg_fast_add_source(slot, r2)) {
                return false;
            }
            slot->source2 = r2;
        }
        ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_ALU_LOGIC_SHIFT);
        return true;
    }

    if (ia64_slot_is_alu_addp4(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        x2a = (raw >> 34) & 0x3;

        if (!ia64_tcg_fast_set_target(slot, r1) ||
            !ia64_tcg_fast_add_source(slot, r3)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_ALU_ADDP4;
        slot->source3 = r3;
        if (x2a == 3) {
            slot->source2_immediate = true;
            slot->immediate =
                ia64_tcg_sign_extend((((raw >> 36) & 0x1) << 13) |
                                     (((raw >> 27) & 0x3f) << 7) |
                                     ((raw >> 13) & 0x7f), 14);
        } else {
            if (!ia64_tcg_fast_add_source(slot, r2)) {
                return false;
            }
            slot->source2 = r2;
        }
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_alu_shladd(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        x2b = (raw >> 27) & 0x3;
        x4 = (raw >> 29) & 0xf;

        if (!ia64_tcg_fast_set_target(slot, r1) ||
            !ia64_tcg_fast_add_source(slot, r2) ||
            !ia64_tcg_fast_add_source(slot, r3)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_ALU_SHLADD;
        slot->source2 = r2;
        slot->source3 = r3;
        slot->immediate = x2b + 1;
        slot->addp4 = x4 == 6;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_addl(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r3 = (raw >> 20) & 0x3;

        if (!ia64_tcg_fast_set_target(slot, r1) ||
            !ia64_tcg_fast_add_source(slot, r3)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_ADDL;
        slot->source3 = r3;
        slot->immediate = ia64_addl_immediate(raw);
        ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_ADDL_SHIFT);
        return true;
    }

    if (ia64_decode_extract(type, raw, &extract)) {
        if (!ia64_tcg_fast_set_target(slot, extract.target) ||
            !ia64_tcg_fast_add_source(slot, extract.source3)) {
            return false;
        }

        slot->op = IA64_TCG_FAST_OP_EXTRACT;
        slot->source3 = extract.source3;
        slot->position = extract.position;
        slot->length = MIN((uint8_t)(64 - extract.position),
                           extract.length);
        slot->sign_extend = extract.sign_extend;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_decode_deposit(type, raw, &deposit)) {
        if (!ia64_tcg_fast_set_target(slot, deposit.target) ||
            (!deposit.source_immediate &&
             !ia64_tcg_fast_add_source(slot, deposit.source2)) ||
            (!deposit.deposit_zero &&
             !ia64_tcg_fast_add_source(slot, deposit.source3))) {
            return false;
        }

        slot->op = IA64_TCG_FAST_OP_DEPOSIT;
        slot->source2 = deposit.source2;
        slot->source3 = deposit.source3;
        slot->position = deposit.position;
        slot->length = MIN((uint8_t)(64 - deposit.position),
                           deposit.length);
        slot->source2_immediate = deposit.source_immediate;
        slot->deposit_zero = deposit.deposit_zero;
        slot->immediate = deposit.immediate;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_decode_integer_extend(type, raw, &int_ext)) {
        if ((int_ext.kind != IA64_EXT_ZXT && int_ext.kind != IA64_EXT_SXT) ||
            !ia64_tcg_fast_set_target(slot, int_ext.target) ||
            !ia64_tcg_fast_add_source(slot, int_ext.source3)) {
            return false;
        }

        slot->op = IA64_TCG_FAST_OP_INTEGER_EXTEND;
        slot->integer_extend_kind = int_ext.kind;
        slot->source3 = int_ext.source3;
        slot->width = int_ext.width;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_i_bit_count(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r3 = (raw >> 20) & 0x7f;

        if (!ia64_tcg_fast_set_target(slot, r1) ||
            !ia64_tcg_fast_add_source(slot, r3)) {
            return false;
        }

        slot->op = IA64_TCG_FAST_OP_BIT_COUNT;
        slot->source3 = r3;
        slot->shift_kind = (raw >> 30) & 0x3;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_i_variable_shift(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        x2b = (raw >> 28) & 0x3;
        x2a = (raw >> 30) & 0x3;

        if (!ia64_tcg_fast_set_target(slot, r1) ||
            !ia64_tcg_fast_add_source(slot, r2) ||
            !ia64_tcg_fast_add_source(slot, r3)) {
            return false;
        }

        slot->op = IA64_TCG_FAST_OP_VARIABLE_SHIFT;
        slot->source2 = r2;
        slot->source3 = r3;
        if (x2b == 0 && x2a == 1) {
            slot->shift_kind = IA64_TCG_FAST_SHIFT_LEFT;
        } else if (x2b == 0 && x2a == 0) {
            slot->shift_kind = IA64_TCG_FAST_SHIFT_RIGHT_UNSIGNED;
        } else {
            slot->shift_kind = IA64_TCG_FAST_SHIFT_RIGHT_SIGNED;
        }
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_decode_compare(type, raw, &cmp)) {
        if (cmp.p1 == cmp.p2 || cmp.p1 >= 16 || cmp.p2 >= 16 ||
            (qp != 0 && cmp.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) ||
            !ia64_tcg_fast_add_source(slot, cmp.source3) ||
            (!cmp.source_immediate &&
             !ia64_tcg_fast_add_source(slot, cmp.source2))) {
            return false;
        }

        slot->op = IA64_TCG_FAST_OP_COMPARE;
        slot->predicate1 = cmp.p1;
        slot->predicate2 = cmp.p2;
        slot->compare_relation = cmp.relation;
        slot->predicate_write_kind = cmp.write_kind;
        slot->width = cmp.width;
        slot->source2 = cmp.source2;
        slot->source3 = cmp.source3;
        slot->source2_immediate = cmp.source_immediate;
        slot->immediate = cmp.immediate;
        ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_COMPARE_SHIFT);
        return true;
    }

    if (ia64_decode_predicate_test(type, raw, &pred_test)) {
        if (pred_test.p1 == pred_test.p2 ||
            pred_test.p1 >= 16 || pred_test.p2 >= 16 ||
            pred_test.immediate >= 64 ||
            (qp != 0 &&
             pred_test.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) ||
            (pred_test.kind != IA64_PRED_TEST_FEATURE &&
             !ia64_tcg_fast_static_gr(pred_test.source3))) {
            return false;
        }
        if (pred_test.kind == IA64_PRED_TEST_BIT &&
            !ia64_tcg_fast_add_source(slot, pred_test.source3)) {
            return false;
        }

        slot->op = IA64_TCG_FAST_OP_PREDICATE_TEST;
        slot->predicate1 = pred_test.p1;
        slot->predicate2 = pred_test.p2;
        slot->predicate_write_kind = pred_test.write_kind;
        slot->predicate_test_kind = pred_test.kind;
        slot->predicate_test_relation = pred_test.relation;
        slot->source3 = pred_test.source3;
        slot->immediate = pred_test.immediate;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_m34_alloc(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        /*
         * The helper reruns the interpreter's alloc.  Rotating frames stay on
         * the interpreter: the whole-bundle sor==0 guard is evaluated before
         * the alloc executes, so an alloc that enables rotation would stale
         * the mapping used by later fast slots.
         */
        if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_ALLOC) ||
            ((raw >> 27) & 0x0f) != 0 ||
            !ia64_tcg_fast_set_target(slot, r1)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_ALLOC;
        slot->immediate = (int64_t)raw;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_i_mov_from_branch(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        if (ia64_tcg_system_mov_trace_enabled() ||
            !ia64_tcg_fast_set_target(slot, r1)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_MOV_FROM_BR;
        slot->system_reg = (raw >> 13) & 0x7;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_i_mov_to_branch(type, raw)) {
        r2 = (raw >> 13) & 0x7f;
        if (ia64_tcg_system_mov_trace_enabled() ||
            !ia64_tcg_fast_add_source(slot, r2)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_MOV_TO_BR;
        slot->source2 = r2;
        slot->system_reg = (raw >> 6) & 0x7;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_mov_from_application(type, raw)) {
        uint32_t ar3 = (raw >> 20) & 0x7f;

        r1 = (raw >> 6) & 0x7f;
        if (ia64_tcg_system_mov_trace_enabled() ||
            !ia64_tcg_fast_ar_is_plain(ar3) ||
            !ia64_tcg_fast_set_target(slot, r1)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_MOV_FROM_AR;
        slot->system_reg = ar3;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_mov_to_application(type, raw)) {
        uint32_t ar3 = (raw >> 20) & 0x7f;

        r2 = (raw >> 13) & 0x7f;
        if (ia64_tcg_system_mov_trace_enabled() ||
            !ia64_tcg_fast_ar_is_plain(ar3) ||
            !ia64_tcg_fast_add_source(slot, r2)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_MOV_TO_AR;
        slot->source2 = r2;
        slot->system_reg = ar3;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_slot_is_mov_to_application_immediate(type, raw)) {
        uint32_t ar3 = (raw >> 20) & 0x7f;

        if (ia64_tcg_system_mov_trace_enabled() ||
            !ia64_tcg_fast_ar_is_plain(ar3)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_MOV_TO_AR;
        slot->source2_immediate = true;
        slot->immediate =
            ia64_tcg_sign_extend((((raw >> 36) & 0x1) << 7) |
                                 ((raw >> 13) & 0x7f), 8);
        slot->system_reg = ar3;
        ia64_tcg_fast_count_op(fast,
                               IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        return true;
    }

    if (ia64_decode_ldst_immediate(type, raw, &ldst) &&
        ia64_tcg_build_fast_ldst_slot(&ldst, slot_index, slot, fast)) {
        return true;
    }

    return false;
}

static IA64TcgFallbackReason ia64_tcg_fast_slot_fallback_reason(
    IA64SlotType type, uint64_t raw, unsigned slot_index)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    IA64LdstImmediate ldst;
    IA64CompareInstruction cmp;
    IA64PredicateTestInstruction pred_test;
    IA64ExtractInstruction extract;
    IA64DepositInstruction deposit;
    IA64IntegerExtendInstruction int_ext;
    uint8_t qp = ia64_slot_predicate(raw);

    if (qp >= 16) {
        return IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT;
    }

    if (ia64_insn_slot_supported(type, raw) ||
        ia64_slot_is_i_nop(type, raw)) {
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_alu_add(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        if (!ia64_tcg_fast_static_gr(r1) ||
            !ia64_tcg_fast_static_gr(r3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        if (((raw >> 34) & 0x3) != 2) {
            r2 = (raw >> 13) & 0x7f;
            if (!ia64_tcg_fast_static_gr(r2)) {
                return IA64_TCG_FALLBACK_FAST_STATIC_GR;
            }
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_alu_sub(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        if (!ia64_tcg_fast_static_gr(r1) ||
            !ia64_tcg_fast_static_gr(r3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        if (((raw >> 29) & 0xf) != 9 &&
            !ia64_tcg_fast_static_gr(r2)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_alu_logic(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        if (!ia64_tcg_fast_static_gr(r1) ||
            !ia64_tcg_fast_static_gr(r3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        if (((raw >> 29) & 0xf) != 0xb &&
            !ia64_tcg_fast_static_gr(r2)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_alu_addp4(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        if (!ia64_tcg_fast_static_gr(r1) ||
            !ia64_tcg_fast_static_gr(r3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        if (((raw >> 34) & 0x3) != 3 &&
            !ia64_tcg_fast_static_gr(r2)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_alu_shladd(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        if (!ia64_tcg_fast_static_gr(r1) ||
            !ia64_tcg_fast_static_gr(r2) ||
            !ia64_tcg_fast_static_gr(r3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_addl(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r3 = (raw >> 20) & 0x3;
        if (!ia64_tcg_fast_static_gr(r1) ||
            !ia64_tcg_fast_static_gr(r3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_decode_extract(type, raw, &extract)) {
        if (!ia64_tcg_fast_static_gr(extract.target) ||
            !ia64_tcg_fast_static_gr(extract.source3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_decode_deposit(type, raw, &deposit)) {
        if (!ia64_tcg_fast_static_gr(deposit.target) ||
            (!deposit.source_immediate &&
             !ia64_tcg_fast_static_gr(deposit.source2)) ||
            (!deposit.deposit_zero &&
             !ia64_tcg_fast_static_gr(deposit.source3))) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_decode_integer_extend(type, raw, &int_ext)) {
        if (int_ext.kind != IA64_EXT_ZXT && int_ext.kind != IA64_EXT_SXT) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        if (!ia64_tcg_fast_static_gr(int_ext.target) ||
            !ia64_tcg_fast_static_gr(int_ext.source3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_i_bit_count(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        if (!ia64_tcg_fast_static_gr(r1) ||
            !ia64_tcg_fast_static_gr(r3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_i_variable_shift(type, raw)) {
        r1 = (raw >> 6) & 0x7f;
        r2 = (raw >> 13) & 0x7f;
        r3 = (raw >> 20) & 0x7f;
        if (!ia64_tcg_fast_static_gr(r1) ||
            !ia64_tcg_fast_static_gr(r2) ||
            !ia64_tcg_fast_static_gr(r3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_decode_compare(type, raw, &cmp)) {
        if (cmp.p1 == cmp.p2 || cmp.p1 >= 16 || cmp.p2 >= 16) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        if (qp != 0 &&
            cmp.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
            return IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT;
        }
        if (!ia64_tcg_fast_static_gr(cmp.source3) ||
            (!cmp.source_immediate &&
             !ia64_tcg_fast_static_gr(cmp.source2))) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_decode_predicate_test(type, raw, &pred_test)) {
        if (pred_test.p1 == pred_test.p2 ||
            pred_test.p1 >= 16 || pred_test.p2 >= 16 ||
            pred_test.immediate >= 64) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        if (qp != 0 &&
            pred_test.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
            return IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT;
        }
        if (pred_test.kind != IA64_PRED_TEST_FEATURE &&
            !ia64_tcg_fast_static_gr(pred_test.source3)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_m34_alloc(type, raw)) {
        if (((raw >> 27) & 0x0f) != 0) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        if (!ia64_tcg_fast_static_gr((raw >> 6) & 0x7f)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_i_mov_from_branch(type, raw)) {
        if (ia64_tcg_system_mov_trace_enabled()) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        if (!ia64_tcg_fast_static_gr((raw >> 6) & 0x7f)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_i_mov_to_branch(type, raw)) {
        if (ia64_tcg_system_mov_trace_enabled()) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        if (!ia64_tcg_fast_static_gr((raw >> 13) & 0x7f)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_mov_from_application(type, raw)) {
        if (ia64_tcg_system_mov_trace_enabled() ||
            !ia64_tcg_fast_ar_is_plain((raw >> 20) & 0x7f)) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        if (!ia64_tcg_fast_static_gr((raw >> 6) & 0x7f)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_mov_to_application(type, raw)) {
        if (ia64_tcg_system_mov_trace_enabled() ||
            !ia64_tcg_fast_ar_is_plain((raw >> 20) & 0x7f)) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        if (!ia64_tcg_fast_static_gr((raw >> 13) & 0x7f)) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_mov_to_application_immediate(type, raw)) {
        if (ia64_tcg_system_mov_trace_enabled() ||
            !ia64_tcg_fast_ar_is_plain((raw >> 20) & 0x7f)) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_decode_ldst_immediate(type, raw, &ldst)) {
        return ia64_tcg_fast_ldst_fallback_reason(&ldst, slot_index);
    }

    return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
}

static bool ia64_tcg_fast_slot_is_ldst(const IA64TcgFastSlot *slot)
{
    return slot->op == IA64_TCG_FAST_OP_LDST_LOAD ||
           slot->op == IA64_TCG_FAST_OP_LDST_STORE;
}

static bool ia64_tcg_fast_slot_has_prior_base_dependency(
    const IA64TcgFastSlot *slot, uint64_t prior_dest_mask)
{
    return ia64_tcg_fast_slot_is_ldst(slot) && slot->base != 0 &&
           (prior_dest_mask & (1ULL << slot->base)) != 0;
}

static bool ia64_tcg_bundle_has_ldst_base_dependency(
    const IA64DecodedBundle *bundle)
{
    IA64TcgFastBundle scratch;
    IA64TcgFastSlot slot;
    uint64_t prior_dest_mask = 0;

    memset(&scratch, 0, sizeof(scratch));
    for (int i = 0; i < IA64_SLOT_COUNT; i++) {
        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[i],
                                      bundle->slot[i], i, &slot, &scratch)) {
            return false;
        }
        if (ia64_tcg_fast_slot_has_prior_base_dependency(&slot,
                                                         prior_dest_mask)) {
            return true;
        }
        prior_dest_mask |= slot.dest_mask;
    }

    return false;
}

static bool ia64_tcg_slot_has_ldst_memory_access(IA64SlotType type,
                                                 uint64_t raw)
{
    IA64LdstImmediate ldst;

    return ia64_decode_ldst_immediate(type, raw, &ldst) &&
           ia64_tcg_ldst_is_memory_access(&ldst);
}

IA64TcgFallbackReason ia64_tcg_fallback_reason_for_bundle(
    const IA64DecodedBundle *bundle, uint64_t pc)
{
    IA64TcgTbBoundary boundary;
    IA64TcgFallbackReason reason;
    bool has_ldst_memory_access = false;

    if (!bundle || !bundle->valid) {
        return IA64_TCG_FALLBACK_INVALID_TEMPLATE;
    }

    boundary = ia64_tcg_tb_boundary_for_bundle(bundle, pc);
    reason = ia64_tcg_fallback_reason_for_boundary(boundary);
    if (reason != IA64_TCG_FALLBACK_NONE) {
        return reason;
    }

    if (bundle->info->long_immediate) {
        return IA64_TCG_FALLBACK_FAST_LONG_IMMEDIATE;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        reason = ia64_tcg_fast_slot_fallback_reason(
            bundle->info->slot_type[slot], bundle->slot[slot], slot);
        if (reason != IA64_TCG_FALLBACK_NONE) {
            return reason;
        }
        if (ia64_tcg_slot_has_ldst_memory_access(
                bundle->info->slot_type[slot], bundle->slot[slot])) {
            has_ldst_memory_access = true;
        }
    }

    if (ia64_tcg_bundle_has_ldst_base_dependency(bundle)) {
        return IA64_TCG_FALLBACK_FAST_LDST_DEPENDENCY;
    }
    if (has_ldst_memory_access &&
        !ia64_tcg_fast_ldst_memory_inline_enabled()) {
        return IA64_TCG_FALLBACK_FAST_LDST_HOST_CODE_SIZE;
    }

    return IA64_TCG_FALLBACK_RUNTIME_GUARD;
}

bool ia64_tcg_build_fast_bundle(const IA64DecodedBundle *bundle,
                                IA64TcgFastBundle *fast)
{
    uint64_t prior_dest_mask = 0;

    if (!bundle || !fast || !bundle->valid || bundle->info->long_immediate) {
        return false;
    }

    memset(fast, 0, sizeof(*fast));
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[slot],
                                      bundle->slot[slot],
                                      slot,
                                      &fast->slot[slot], fast)) {
            return false;
        }
        if (ia64_tcg_fast_slot_has_prior_base_dependency(&fast->slot[slot],
                                                         prior_dest_mask)) {
            return false;
        }
        fast->slot_count++;
        fast->source_nat_mask |= fast->slot[slot].source_nat_mask;
        fast->dest_mask |= fast->slot[slot].dest_mask;
        prior_dest_mask |= fast->slot[slot].dest_mask;
    }

    return fast->slot_count == IA64_SLOT_COUNT;
}

bool ia64_tcg_bundle_has_ldst_immediate(const IA64DecodedBundle *bundle)
{
    IA64LdstImmediate ldst;

    if (!bundle || !bundle->valid) {
        return false;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (ia64_decode_ldst_immediate(bundle->info->slot_type[slot],
                                       bundle->slot[slot], &ldst)) {
            return true;
        }
    }

    return false;
}

static IA64TcgFallbackPlanOp ia64_tcg_fallback_plan_for_slot(
    IA64SlotType type, uint64_t raw)
{
    IA64LdstImmediate ldst;
    IA64FloatingMemoryInstruction fldst;
    IA64FloatingCompareInstruction fcmp;
    IA64FloatingClassInstruction fclass;
    IA64CompareInstruction cmp;
    IA64PredicateTestInstruction pred_test;
    IA64ExtractInstruction extract;
    IA64DepositInstruction deposit;
    IA64IntegerExtendInstruction int_ext;

    /*
     * Smoke/NOP slots are already the first cheap checks in the helper ladder.
     * Leave them generic so the plan only targets slots that skip real work.
     */
    if (ia64_slot_is_m34_alloc(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_ALLOC;
    }
    if (ia64_slot_is_i_mov_from_branch(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_MOV_FROM_BRANCH;
    }
    if (ia64_slot_is_i_mov_to_branch(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_MOV_TO_BRANCH;
    }
    if (ia64_slot_is_mov_to_application(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION;
    }
    if (ia64_slot_is_mov_from_application(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_MOV_FROM_APPLICATION;
    }
    if (ia64_slot_is_mov_to_application_immediate(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION_IMM;
    }
    if (ia64_decode_extract(type, raw, &extract)) {
        return IA64_TCG_FALLBACK_PLAN_EXTRACT;
    }
    if (ia64_decode_deposit(type, raw, &deposit)) {
        return IA64_TCG_FALLBACK_PLAN_DEPOSIT;
    }
    if (ia64_decode_integer_extend(type, raw, &int_ext)) {
        return IA64_TCG_FALLBACK_PLAN_INTEGER_EXTEND;
    }
    if (ia64_decode_floating_memory(type, raw, &fldst)) {
        return IA64_TCG_FALLBACK_PLAN_FLOATING_MEMORY;
    }
    if (ia64_decode_floating_compare(type, raw, &fcmp)) {
        return IA64_TCG_FALLBACK_PLAN_FLOATING_COMPARE;
    }
    if (ia64_decode_floating_class(type, raw, &fclass)) {
        return IA64_TCG_FALLBACK_PLAN_FLOATING_CLASS;
    }
    if (ia64_decode_ldst_immediate(type, raw, &ldst)) {
        return IA64_TCG_FALLBACK_PLAN_LDST_IMMEDIATE;
    }
    if (ia64_decode_compare(type, raw, &cmp)) {
        return IA64_TCG_FALLBACK_PLAN_COMPARE;
    }
    if (ia64_decode_predicate_test(type, raw, &pred_test)) {
        return IA64_TCG_FALLBACK_PLAN_PREDICATE_TEST;
    }
    if (ia64_slot_is_alu_add(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_ALU_ADD;
    }
    if (ia64_slot_is_alu_sub(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_ALU_SUB;
    }
    if (ia64_slot_is_alu_logic(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_ALU_LOGIC;
    }
    if (ia64_slot_is_alu_addp4(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_ALU_ADDP4;
    }
    if (ia64_slot_is_alu_shladd(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_ALU_SHLADD;
    }
    if (ia64_slot_is_i_packed_i2(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_I_PACKED_I2;
    }
    if (ia64_slot_is_i_mux(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_I_MUX;
    }
    if (ia64_slot_is_i_bit_count(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_I_BIT_COUNT;
    }
    if (ia64_slot_is_i_variable_shift(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_I_VARIABLE_SHIFT;
    }
    if (ia64_slot_is_addl(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_ADDL;
    }
    if (ia64_slot_is_b_branch_relative(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_BRANCH_RELATIVE;
    }
    if (ia64_slot_is_b_call_relative(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_BRANCH_CALL_RELATIVE;
    }
    if (ia64_slot_is_b_indirect_branch(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_BRANCH_INDIRECT;
    }
    if (ia64_slot_is_b_predict_or_nop(type, raw)) {
        return IA64_TCG_FALLBACK_PLAN_BRANCH_PREDICT_OR_NOP;
    }

    return IA64_TCG_FALLBACK_PLAN_GENERIC;
}

uint32_t ia64_tcg_fallback_plan_for_bundle(const IA64DecodedBundle *bundle)
{
    uint32_t plan = 0;

    if (!bundle || !bundle->valid) {
        return plan;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64TcgFallbackPlanOp op;

        if (bundle->info->long_immediate && slot >= 1) {
            op = IA64_TCG_FALLBACK_PLAN_GENERIC;
        } else {
            op = ia64_tcg_fallback_plan_for_slot(
                bundle->info->slot_type[slot], bundle->slot[slot]);
        }
        plan |= (uint32_t)op << (slot * IA64_TCG_FALLBACK_PLAN_SLOT_BITS);
    }

    return plan;
}

static bool ia64_tcg_same_page(uint64_t left, uint64_t right)
{
    return ((left ^ right) & IA64_TCG_TARGET_PAGE_MASK) == 0;
}

static bool ia64_tcg_build_direct_branch_prefix(
    const IA64DecodedBundle *bundle, IA64TcgFastBundle *prefix)
{
    uint64_t prior_dest_mask = 0;

    /*
     * Prefix slots run in program order before the branch condition is
     * evaluated, so predicated slots and slots writing the branch predicate
     * keep interpreter semantics: legal encodings separate the producer and
     * the branch with a stop, and the branch reads the freshly written
     * value either way.
     */
    memset(prefix, 0, sizeof(*prefix));
    for (int slot = 0; slot < 2; slot++) {
        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[slot],
                                      bundle->slot[slot],
                                      slot,
                                      &prefix->slot[slot], prefix)) {
            return false;
        }
        if (ia64_tcg_fast_slot_has_prior_base_dependency(&prefix->slot[slot],
                                                         prior_dest_mask)) {
            return false;
        }
        prefix->slot_count++;
        prefix->source_nat_mask |= prefix->slot[slot].source_nat_mask;
        prefix->dest_mask |= prefix->slot[slot].dest_mask;
        prior_dest_mask |= prefix->slot[slot].dest_mask;
    }

    return true;
}

static uint8_t ia64_tcg_fast_bundle_nop_count(const IA64TcgFastBundle *fast)
{
    unsigned count = ia64_perf_fast_count(fast->op_counts,
                                          IA64_PERF_FAST_COUNT_NOP_SHIFT);

    return count > UINT8_MAX ? UINT8_MAX : count;
}

bool ia64_tcg_bundle_has_direct_branch(const IA64DecodedBundle *bundle)
{
    if (!bundle || !bundle->valid) {
        return false;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = bundle->info->slot_type[slot];
        uint64_t raw = bundle->slot[slot];

        if (ia64_slot_is_b_branch_relative(type, raw) ||
            ia64_slot_is_b_call_relative(type, raw)) {
            return true;
        }
    }

    return false;
}

bool ia64_tcg_bundle_has_indirect_branch(const IA64DecodedBundle *bundle)
{
    if (!bundle || !bundle->valid) {
        return false;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (ia64_slot_is_b_indirect_branch(bundle->info->slot_type[slot],
                                           bundle->slot[slot])) {
            return true;
        }
    }

    return false;
}

bool ia64_tcg_build_direct_branch(const IA64DecodedBundle *bundle,
                                  uint64_t pc,
                                  IA64TcgDirectBranch *branch)
{
    uint64_t raw;
    uint64_t target;
    uint64_t fallthrough;
    uint8_t btype;
    uint8_t predicate;
    IA64TcgDirectBranchKind kind;
    uint8_t call_branch_reg = 0;

    if (!bundle || !branch || !bundle->valid || bundle->info->long_immediate) {
        return false;
    }

    /*
     * Keep branch lowering auditably small: only bundles with a final simple
     * relative branch, counted-loop branch, call, plain indirect branch, or
     * return and two safe fast-prefix slots can use direct TCG control flow.
     * rfi, cover/clrrrb/bsw/epc forms, modulo-scheduled loop branches, and
     * rotating predicate reads stay on the helper path.
     */
    raw = bundle->slot[2];
    predicate = ia64_slot_predicate(raw);
    if (ia64_slot_is_b_branch_relative(bundle->info->slot_type[2], raw)) {
        btype = (raw >> 6) & 0x7;
        switch (btype) {
        case 0:
        case 1:
            if (predicate >= 16) {
                return false;
            }
            kind = IA64_TCG_DIRECT_BRANCH_COND;
            break;
        case 5:
            if (predicate != 0) {
                return false;
            }
            kind = IA64_TCG_DIRECT_BRANCH_CLOOP;
            break;
        default:
            return false;
        }
    } else if (ia64_slot_is_b_call_relative(bundle->info->slot_type[2],
                                            raw)) {
        if (predicate >= 16) {
            return false;
        }
        kind = IA64_TCG_DIRECT_BRANCH_CALL;
        call_branch_reg = (raw >> 6) & 0x7;
    } else if (ia64_slot_is_b_indirect_branch(bundle->info->slot_type[2],
                                              raw)) {
        uint8_t major = ia64_slot_major_opcode(raw);
        uint8_t x6 = (raw >> 27) & 0x3f;

        if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_INDIRECT) ||
            predicate >= 16 ||
            !(major == 0x1 ||
              (major == 0x0 && (x6 == 0x20 || x6 == 0x21)))) {
            return false;
        }
        kind = IA64_TCG_DIRECT_BRANCH_INDIRECT;
    } else {
        return false;
    }

    fallthrough = pc + IA64_BUNDLE_SIZE;
    /*
     * The not-taken path must stay chainable, so the fallthrough keeps the
     * same-page rule.  Calls routinely target other pages and indirect
     * targets are runtime values; the translator falls back to a TB lookup
     * for those, so only conditional and counted branches require a
     * same-page target.
     */
    if (!ia64_tcg_same_page(pc, fallthrough)) {
        return false;
    }
    if (kind == IA64_TCG_DIRECT_BRANCH_INDIRECT) {
        target = 0;
    } else {
        target = pc + ia64_branch_displacement(raw);
        if (target == 0) {
            return false;
        }
        if (kind != IA64_TCG_DIRECT_BRANCH_CALL &&
            !ia64_tcg_same_page(pc, target)) {
            return false;
        }
    }

    memset(branch, 0, sizeof(*branch));
    if (!ia64_tcg_build_direct_branch_prefix(bundle, &branch->prefix)) {
        return false;
    }
    branch->target_ip = target;
    branch->fallthrough_ip = fallthrough;
    branch->branch_raw = raw;
    branch->kind = kind;
    branch->slot = 2;
    branch->predicate = predicate;
    branch->nop_count = ia64_tcg_fast_bundle_nop_count(&branch->prefix);
    branch->call_branch_reg = call_branch_reg;
    branch->conditional = kind == IA64_TCG_DIRECT_BRANCH_CLOOP ||
                          predicate != 0;
    return true;
}

static IA64TcgTbBoundary ia64_tcg_slot_boundary(IA64SlotType type,
                                                uint64_t raw)
{
    uint8_t major;

    /*
     * Keep precise exception IP/slot behavior simple: any instruction that can
     * redirect flow or change TB-relevant architectural state remains the last
     * bundle in the TB until a later phase represents that state in flags or
     * emits direct TCG for the operation.
     */
    if (ia64_slot_is_i_break(type, raw) || ia64_slot_is_m_break(type, raw) ||
        ia64_slot_is_b_break(type, raw)) {
        return IA64_TCG_TB_BOUNDARY_BREAK;
    }
    if (ia64_slot_is_check_speculative(type, raw) ||
        ia64_slot_is_m_check_advanced(type, raw)) {
        return IA64_TCG_TB_BOUNDARY_SPECULATION_CHECK;
    }
    if (ia64_slot_is_m_virtual_translation(type, raw)) {
        return IA64_TCG_TB_BOUNDARY_VIRTUAL_TRANSLATION;
    }
    if (ia64_slot_is_m_processor_mask(type, raw) ||
        ia64_slot_is_m_mov_to_processor_status(type, raw) ||
        ia64_slot_is_m_mov_to_control(type, raw)) {
        return IA64_TCG_TB_BOUNDARY_CPU_STATE;
    }
    if (ia64_slot_is_m_mov_to_region_register(type, raw) ||
        ia64_slot_is_m_insert_translation(type, raw) ||
        ia64_slot_is_m_purge_translation(type, raw) ||
        ia64_slot_is_m_invala(type, raw)) {
        return IA64_TCG_TB_BOUNDARY_TRANSLATION_STATE;
    }
    if (ia64_slot_is_m_flushrs(type, raw) ||
        ia64_slot_is_m_loadrs(type, raw)) {
        return IA64_TCG_TB_BOUNDARY_RSE_STATE;
    }

    if (type == IA64_SLOT_TYPE_B) {
        major = ia64_slot_major_opcode(raw);
        if (major == 0x1 || major == 0x4 || major == 0x5) {
            return IA64_TCG_TB_BOUNDARY_BRANCH;
        }
        if (major == 0x0) {
            uint8_t x6 = (raw >> 27) & 0x3f;

            switch (x6) {
            case 0x02: /* cover */
                return IA64_TCG_TB_BOUNDARY_RSE_STATE;
            case 0x04: /* clrrrb */
            case 0x05: /* clrrrb.pr */
            case 0x0c: /* bsw.0 */
            case 0x0d: /* bsw.1 */
            case 0x10: /* epc */
                return IA64_TCG_TB_BOUNDARY_CPU_STATE;
            case 0x08: /* rfi */
            case 0x20: /* br */
            case 0x21: /* br.ret */
                return IA64_TCG_TB_BOUNDARY_BRANCH;
            default:
                break;
            }
        }
    }

    return IA64_TCG_TB_BOUNDARY_NONE;
}

IA64TcgTbBoundary ia64_tcg_tb_boundary_for_bundle(
    const IA64DecodedBundle *bundle, uint64_t pc)
{
    if (!bundle || !bundle->valid) {
        return IA64_TCG_TB_BOUNDARY_INVALID_TEMPLATE;
    }
    if (ia64_tcg_pc_is_efi_call_gate(pc)) {
        return IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64TcgTbBoundary boundary =
            ia64_tcg_slot_boundary(bundle->info->slot_type[slot],
                                   bundle->slot[slot]);

        if (ia64_tcg_tb_boundary_ends_tb(boundary)) {
            return boundary;
        }
    }

    return IA64_TCG_TB_BOUNDARY_NONE;
}
