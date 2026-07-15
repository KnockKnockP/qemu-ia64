/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu-param.h"
#include "firmware.h"
#include "insn.h"
#include "perf.h"
#include "tcg-classify.h"

#define IA64_REGION_OFFSET_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_KERNEL_PAGE_OFFSET UINT64_C(0xe000000000000000)
#define IA64_TCG_FAST_GR_LIMIT IA64_GR_COUNT
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
        pc == IA64_FIRMWARE_EFI_SAL_PROC ||
        pc == IA64_FIRMWARE_EFI_START_IMAGE_RETURN_GATE ||
        pc == IA64_FIRMWARE_EFI_EVENT_NOTIFY_RETURN_GATE) {
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

bool ia64_tcg_bundle_is_firmware_call_gate_candidate(
    const IA64DecodedBundle *bundle)
{
    const uint64_t nop = UINT64_C(1) << 27;
    const uint64_t br_b0 = UINT64_C(0x20) << 27;
    const uint64_t br_ret_b0 = UINT64_C(0x21) << 27;

    return bundle && bundle->valid && bundle->tmpl == 0x11 &&
           bundle->slot[0] == nop && bundle->slot[1] == nop &&
           (bundle->slot[2] == br_b0 || bundle->slot[2] == br_ret_b0);
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
    case IA64_TCG_TB_BOUNDARY_SERIALIZATION:
        return "serialization";
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
    case IA64_TCG_TB_BOUNDARY_SERIALIZATION:
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
    return reg < IA64_TCG_FAST_GR_LIMIT &&
           (reg < 64 ||
            !ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_UPPER_GR));
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
        if (reg < 64) {
            slot->source_nat_mask |= 1ULL << reg;
        } else {
            slot->source_nat_mask_hi |= 1ULL << (reg - 64);
        }
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
        if (reg < 64) {
            slot->dest_mask = 1ULL << reg;
            slot->finalize_mask = 1ULL << reg;
        } else {
            slot->dest_mask_hi = 1ULL << (reg - 64);
            slot->finalize_mask_hi = 1ULL << (reg - 64);
        }
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
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 8:
    case 9:
    case 0x0a:
        return true;
    default:
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
     * feature without rebuilding.  The value is a comma-separated list of
     * feature names; see the parser below for the supported names.  "all"
     * disables every fast-path feature.
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
                } else if (g_ascii_strcasecmp(name, "upper-gr") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_UPPER_GR;
                } else if (g_ascii_strcasecmp(name, "predicate") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_PREDICATE;
                } else if (g_ascii_strcasecmp(name, "movl") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_MOVL;
                } else if (g_ascii_strcasecmp(name, "memory-class") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_MEMORY_CLASS;
                } else if (g_ascii_strcasecmp(name, "fp") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_FP;
                } else if (g_ascii_strcasecmp(name, "partial") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_PARTIAL;
                } else if (g_ascii_strcasecmp(name, "all") == 0) {
                    parsed |= IA64_TCG_FAST_DISABLE_BUNDLE |
                              IA64_TCG_FAST_DISABLE_BRANCH |
                              IA64_TCG_FAST_DISABLE_INDIRECT |
                              IA64_TCG_FAST_DISABLE_MOVSYS |
                              IA64_TCG_FAST_DISABLE_ALLOC |
                              IA64_TCG_FAST_DISABLE_UPPER_GR |
                              IA64_TCG_FAST_DISABLE_PREDICATE |
                              IA64_TCG_FAST_DISABLE_MOVL |
                              IA64_TCG_FAST_DISABLE_MEMORY_CLASS |
                              IA64_TCG_FAST_DISABLE_FP |
                              IA64_TCG_FAST_DISABLE_PARTIAL;
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
    if (!ia64_tcg_fast_static_gr(ldst->base)) {
        return IA64_TCG_FALLBACK_FAST_STATIC_GR;
    }
    if (ldst->update_from_register &&
        !ia64_tcg_fast_static_gr(ldst->update_source)) {
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
        if (reg < 64) {
            slot->dest_mask |= 1ULL << reg;
            slot->finalize_mask |= 1ULL << reg;
        } else {
            slot->dest_mask_hi |= 1ULL << (reg - 64);
            slot->finalize_mask_hi |= 1ULL << (reg - 64);
        }
    }
    return true;
}

static void ia64_tcg_fast_preserve_target_state(IA64TcgFastSlot *slot,
                                                 uint32_t reg)
{
    if (reg < 64) {
        slot->finalize_mask &= ~(UINT64_C(1) << reg);
    } else {
        slot->finalize_mask_hi &= ~(UINT64_C(1) << (reg - 64));
    }
}

static bool ia64_tcg_build_fast_ldst_slot(const IA64LdstImmediate *ldst,
                                          unsigned slot_index,
                                          IA64TcgFastSlot *slot,
                                          IA64TcgFastBundle *fast)
{
    if (ia64_tcg_ldst_trace_enabled()) {
        return false;
    }
    if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_MEMORY_CLASS) &&
        !((ldst->kind == IA64_LDST_IMM_LOAD &&
           (ldst->memory_class == 0 || ldst->memory_class == 4 ||
            ldst->memory_class == 5)) ||
          (ldst->kind == IA64_LDST_IMM_STORE &&
           (ldst->memory_class == 0x0c || ldst->memory_class == 0x0d)) ||
          ldst->kind == IA64_LDST_IMM_PREFETCH)) {
        return false;
    }
    if (!ia64_tcg_fast_add_source(slot, ldst->base) ||
        (ldst->update_from_register &&
         !ia64_tcg_fast_add_source(slot, ldst->update_source))) {
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
        if (ldst->memory_class != 0 && ldst->memory_class != 4 &&
            ldst->memory_class != 5) {
            ia64_tcg_fast_preserve_target_state(slot, ldst->target);
        }
        ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT);
        break;
    case IA64_LDST_IMM_STORE:
        if (!ia64_tcg_fast_ldst_store_class(ldst->memory_class) ||
            !ia64_tcg_fast_static_gr(ldst->source)) {
            return false;
        }
        ia64_tcg_fast_note_gr(slot, ldst->source);
        if (ldst->memory_class != 0x0e &&
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
    slot->update_source = ldst->update_source;
    slot->width = ldst->width;
    slot->memory_class = ldst->memory_class;
    slot->base_update = ldst->base_update;
    slot->update_from_register = ldst->update_from_register;
    slot->immediate = ldst->immediate;
    slot->slot_index = slot_index;
    return true;
}

static bool ia64_tcg_build_fast_slot(IA64SlotType type, uint64_t raw,
                                     unsigned slot_index, bool starts_group,
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
    IA64FloatingMemoryInstruction fldst;
    IA64FloatingCompareInstruction fcmp;
    IA64FloatingClassInstruction fclass;
    uint8_t qp;

    memset(slot, 0, sizeof(*slot));
    slot->slot_index = slot_index;
    slot->starts_group = starts_group;
    qp = ia64_slot_predicate(raw);
    if (qp >= 16 &&
        ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_PREDICATE)) {
        return false;
    }
    slot->qualifying_predicate = qp;

    if (ia64_slot_is_nop_or_hint(type, raw)) {
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
        if (cmp.p1 == cmp.p2 ||
            ((cmp.p1 >= 16 || cmp.p2 >= 16) &&
             ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_PREDICATE)) ||
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
            ((pred_test.p1 >= 16 || pred_test.p2 >= 16) &&
             ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_PREDICATE)) ||
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

    if (ia64_decode_floating_memory(type, raw, &fldst)) {
        if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_FP)) {
            return false;
        }
        if (!ia64_tcg_fast_add_source(slot, fldst.base) ||
            (fldst.update_from_register &&
             !ia64_tcg_fast_add_source(slot, fldst.update_source)) ||
            (fldst.base_update &&
             !ia64_tcg_fast_set_base_update(slot, fldst.base))) {
            return false;
        }
        if (fldst.base_update) {
            ia64_tcg_fast_preserve_target_state(slot, fldst.base);
        }
        slot->op = IA64_TCG_FAST_OP_FP_SLOT;
        slot->slot_type = type;
        slot->raw = raw;
        slot->base = fldst.base;
        return true;
    }

    if (ia64_decode_floating_compare(type, raw, &fcmp)) {
        if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_FP) ||
            fcmp.p1 == fcmp.p2 ||
            (qp != 0 &&
             fcmp.write_kind == IA64_PRED_WRITE_UNCONDITIONAL)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_FP_SLOT;
        slot->slot_type = type;
        slot->raw = raw;
        return true;
    }

    if (ia64_decode_floating_class(type, raw, &fclass)) {
        if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_FP) ||
            fclass.p1 == fclass.p2 ||
            (qp != 0 &&
             fclass.write_kind == IA64_PRED_WRITE_UNCONDITIONAL)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_FP_SLOT;
        slot->slot_type = type;
        slot->raw = raw;
        return true;
    }

    if (ia64_slot_is_f_reciprocal_approx(type, raw) ||
        ia64_slot_is_f_misc(type, raw) ||
        ia64_slot_is_f_multiply_add(type, raw) ||
        ia64_slot_is_f_select_or_xma(type, raw)) {
        if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_FP)) {
            return false;
        }
        slot->op = IA64_TCG_FAST_OP_FP_SLOT;
        slot->slot_type = type;
        slot->raw = raw;
        return true;
    }

    if (ia64_decode_ldst_immediate(type, raw, &ldst) &&
        ia64_tcg_build_fast_ldst_slot(&ldst, slot_index, slot, fast)) {
        /* Fault delivery needs the exact decoded memory slot for ISR.sp/ed. */
        slot->slot_type = type;
        slot->raw = raw;
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
    IA64FloatingMemoryInstruction fldst;
    IA64FloatingCompareInstruction fcmp;
    IA64FloatingClassInstruction fclass;
    uint8_t qp = ia64_slot_predicate(raw);

    if (ia64_slot_is_nop_or_hint(type, raw)) {
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
        if (cmp.p1 == cmp.p2) {
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
        if (pred_test.p1 == pred_test.p2 || pred_test.immediate >= 64) {
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

    if (ia64_decode_floating_memory(type, raw, &fldst)) {
        if (!ia64_tcg_fast_static_gr(fldst.base) ||
            (fldst.update_from_register &&
             !ia64_tcg_fast_static_gr(fldst.update_source))) {
            return IA64_TCG_FALLBACK_FAST_STATIC_GR;
        }
        return IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_decode_floating_compare(type, raw, &fcmp)) {
        if (fcmp.p1 == fcmp.p2) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        return qp != 0 &&
               fcmp.write_kind == IA64_PRED_WRITE_UNCONDITIONAL
            ? IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT
            : IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_decode_floating_class(type, raw, &fclass)) {
        if (fclass.p1 == fclass.p2) {
            return IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT;
        }
        return qp != 0 &&
               fclass.write_kind == IA64_PRED_WRITE_UNCONDITIONAL
            ? IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT
            : IA64_TCG_FALLBACK_NONE;
    }

    if (ia64_slot_is_f_reciprocal_approx(type, raw) ||
        ia64_slot_is_f_misc(type, raw) ||
        ia64_slot_is_f_multiply_add(type, raw) ||
        ia64_slot_is_f_select_or_xma(type, raw)) {
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
    const IA64TcgFastSlot *slot, uint64_t prior_dest_mask,
    uint64_t prior_dest_mask_hi)
{
    if (!ia64_tcg_fast_slot_is_ldst(slot) || slot->base == 0) {
        return false;
    }
    return slot->base < 64
        ? (prior_dest_mask & (1ULL << slot->base)) != 0
        : (prior_dest_mask_hi & (1ULL << (slot->base - 64))) != 0;
}

static bool ia64_tcg_bundle_has_ldst_base_dependency(
    const IA64DecodedBundle *bundle)
{
    IA64TcgFastBundle scratch;
    IA64TcgFastSlot slot;
    uint64_t prior_dest_mask = 0;
    uint64_t prior_dest_mask_hi = 0;

    memset(&scratch, 0, sizeof(scratch));
    for (int i = 0; i < IA64_SLOT_COUNT; i++) {
        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[i],
                                      bundle->slot[i], i,
                                      i != 0 &&
                                          bundle->info->stop_after_slot[i - 1],
                                      &slot, &scratch)) {
            return false;
        }
        if (ia64_tcg_fast_slot_has_prior_base_dependency(&slot,
                                                         prior_dest_mask,
                                                         prior_dest_mask_hi)) {
            return true;
        }
        prior_dest_mask |= slot.dest_mask;
        prior_dest_mask_hi |= slot.dest_mask_hi;
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
    IA64TcgFastBundle fast;
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
        return ia64_tcg_build_fast_bundle(bundle, &fast)
            ? IA64_TCG_FALLBACK_RUNTIME_GUARD
            : IA64_TCG_FALLBACK_FAST_LONG_IMMEDIATE;
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
    uint64_t prior_dest_mask_hi = 0;

    if (!bundle || !fast || !bundle->valid) {
        return false;
    }

    memset(fast, 0, sizeof(*fast));
    if (bundle->info->long_immediate) {
        IA64TcgFastSlot *lx = &fast->slot[1];
        uint64_t l_raw = bundle->slot[1];
        uint64_t x_raw = bundle->slot[2];

        if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_MOVL) ||
            !ia64_tcg_build_fast_slot(bundle->info->slot_type[0],
                                      bundle->slot[0], 0, false,
                                      &fast->slot[0], fast)) {
            return false;
        }
        fast->slot_count++;
        fast->source_nat_mask = fast->slot[0].source_nat_mask;
        fast->source_nat_mask_hi = fast->slot[0].source_nat_mask_hi;
        fast->dest_mask = fast->slot[0].dest_mask;
        fast->dest_mask_hi = fast->slot[0].dest_mask_hi;
        fast->finalize_mask = fast->slot[0].finalize_mask;
        fast->finalize_mask_hi = fast->slot[0].finalize_mask_hi;

        memset(lx, 0, sizeof(*lx));
        lx->slot_index = 1;
        lx->qualifying_predicate = ia64_slot_predicate(x_raw);
        if (ia64_slot_pair_is_lx_movl(l_raw, x_raw)) {
            if (!ia64_tcg_fast_set_target(lx, (x_raw >> 6) & 0x7f)) {
                return false;
            }
            lx->op = IA64_TCG_FAST_OP_MOVL;
            lx->immediate = (int64_t)ia64_lx_movl_imm64(l_raw, x_raw);
            ia64_tcg_fast_count_op(
                fast, IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT);
        } else if (ia64_slot_pair_is_lx_nop_or_hint(l_raw, x_raw)) {
            lx->op = IA64_TCG_FAST_OP_NOP;
            ia64_tcg_fast_count_op(fast, IA64_PERF_FAST_COUNT_NOP_SHIFT);
        } else {
            return false;
        }
        fast->slot_count++;
        fast->dest_mask |= lx->dest_mask;
        fast->dest_mask_hi |= lx->dest_mask_hi;
        fast->finalize_mask |= lx->finalize_mask;
        fast->finalize_mask_hi |= lx->finalize_mask_hi;

        fast->slot[2].op = IA64_TCG_FAST_OP_NOP;
        fast->slot[2].slot_index = 2;
        fast->slot_count++;
        return true;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[slot],
                                      bundle->slot[slot],
                                      slot,
                                      slot != 0 &&
                                          bundle->info->stop_after_slot[
                                              slot - 1],
                                      &fast->slot[slot], fast)) {
            return false;
        }
        if (ia64_tcg_fast_slot_has_prior_base_dependency(&fast->slot[slot],
                                                         prior_dest_mask,
                                                         prior_dest_mask_hi)) {
            return false;
        }
        fast->slot_count++;
        fast->source_nat_mask |= fast->slot[slot].source_nat_mask;
        fast->source_nat_mask_hi |= fast->slot[slot].source_nat_mask_hi;
        fast->dest_mask |= fast->slot[slot].dest_mask;
        fast->dest_mask_hi |= fast->slot[slot].dest_mask_hi;
        fast->finalize_mask |= fast->slot[slot].finalize_mask;
        fast->finalize_mask_hi |= fast->slot[slot].finalize_mask_hi;
        prior_dest_mask |= fast->slot[slot].dest_mask;
        prior_dest_mask_hi |= fast->slot[slot].dest_mask_hi;
    }

    return fast->slot_count == IA64_SLOT_COUNT;
}

static void ia64_tcg_partial_add_fast_slot(IA64TcgFastBundle *partial,
                                           const IA64TcgFastSlot *slot,
                                           uint32_t op_counts)
{
    partial->slot[slot->slot_index] = *slot;
    partial->slot_count++;
    partial->op_counts += op_counts;
    partial->source_nat_mask |= slot->source_nat_mask;
    partial->source_nat_mask_hi |= slot->source_nat_mask_hi;
    partial->dest_mask |= slot->dest_mask;
    partial->dest_mask_hi |= slot->dest_mask_hi;
    partial->finalize_mask |= slot->finalize_mask;
    partial->finalize_mask_hi |= slot->finalize_mask_hi;
}

bool ia64_tcg_build_partial_bundle(const IA64DecodedBundle *bundle,
                                   IA64TcgFastBundle *partial)
{
    uint64_t prior_dest_mask = 0;
    uint64_t prior_dest_mask_hi = 0;
    unsigned helper_count = 0;

    if (!bundle || !partial || !bundle->valid ||
        bundle->info->long_immediate ||
        ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_PARTIAL)) {
        return false;
    }

    memset(partial, 0, sizeof(*partial));
    for (int slot_index = 0; slot_index < IA64_SLOT_COUNT; slot_index++) {
        IA64TcgFastBundle slot_counts = { 0 };
        IA64TcgFastSlot slot;
        IA64SlotType type = bundle->info->slot_type[slot_index];
        bool fast;

        /* alloc changes the mapping cached by later stacked-register slots. */
        if (ia64_slot_is_m34_alloc(type, bundle->slot[slot_index])) {
            return false;
        }
        fast = ia64_tcg_build_fast_slot(
            type, bundle->slot[slot_index], slot_index,
            slot_index != 0 &&
                bundle->info->stop_after_slot[slot_index - 1],
            &slot, &slot_counts);

        /*
         * The ordinary bundle path reads every memory base before executing
         * slot 0.  The partial path reads it at its actual slot, so route the
         * dependent memory slot through the single-slot oracle and retain the
         * producer as generated code.
         */
        if (fast && ia64_tcg_fast_slot_has_prior_base_dependency(
                        &slot, prior_dest_mask, prior_dest_mask_hi)) {
            fast = false;
        }

        if (!fast) {
            partial->helper_mask |= 1u << slot_index;
            helper_count++;
            memset(&partial->slot[slot_index], 0,
                   sizeof(partial->slot[slot_index]));
            partial->slot[slot_index].slot_index = slot_index;
        } else {
            ia64_tcg_partial_add_fast_slot(partial, &slot,
                                           slot_counts.op_counts);
        }

        if (fast) {
            prior_dest_mask |= slot.dest_mask;
            prior_dest_mask_hi |= slot.dest_mask_hi;
        }
    }

    /* One decoded helper is cheaper than interpreting all three slots. */
    return helper_count == 1 && partial->slot_count == IA64_SLOT_COUNT - 1;
}

uint8_t ia64_tcg_unsupported_slot_mask(const IA64DecodedBundle *bundle)
{
    IA64TcgFastBundle scratch = { 0 };
    uint8_t mask = 0;

    if (!bundle || !bundle->valid || bundle->info->long_immediate) {
        return 0;
    }
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64TcgFastSlot decoded;

        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[slot],
                                      bundle->slot[slot], slot,
                                      slot != 0 &&
                                          bundle->info->stop_after_slot[
                                              slot - 1],
                                      &decoded, &scratch)) {
            mask |= 1u << slot;
        }
    }
    return mask;
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

typedef struct IA64TcgFallbackBitStream {
    uint64_t value;
    unsigned shift;
} IA64TcgFallbackBitStream;

static void ia64_tcg_fallback_put(IA64TcgFallbackBitStream *stream,
                                  uint64_t value, unsigned bits)
{
    g_assert(stream->shift + bits <= IA64_TCG_FALLBACK_DESC_OP_SHIFT);
    g_assert(bits == 64 || (value & ~MAKE_64BIT_MASK(0, bits)) == 0);
    stream->value |= value << stream->shift;
    stream->shift += bits;
}

static uint64_t ia64_tcg_fallback_get(IA64TcgFallbackBitStream *stream,
                                      unsigned bits)
{
    uint64_t value;

    value = extract64(stream->value, stream->shift, bits);
    stream->shift += bits;
    return value;
}

static int64_t ia64_tcg_fallback_sign_extend(uint64_t value, unsigned bits)
{
    return (int64_t)(value << (64 - bits)) >> (64 - bits);
}

static uint8_t ia64_tcg_fallback_width_code(uint8_t width)
{
    switch (width) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
        return 2;
    case 8:
        return 3;
    case 10:
        return 4;
    case 16:
        return 5;
    default:
        g_assert_not_reached();
    }
}

static uint8_t ia64_tcg_fallback_width_from_code(uint8_t code)
{
    static const uint8_t widths[] = { 1, 2, 4, 8, 10, 16 };

    return code < ARRAY_SIZE(widths) ? widths[code] : 0;
}

static uint64_t ia64_tcg_fallback_pack_desc(
    const IA64TcgFallbackDecodedSlot *decoded)
{
    IA64TcgFallbackBitStream stream = { 0 };

    ia64_tcg_fallback_put(&stream, decoded->predicate, 6);
    switch (decoded->op) {
    case IA64_TCG_FALLBACK_PLAN_EXTRACT:
        ia64_tcg_fallback_put(&stream, decoded->u.extract.target, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.extract.source3, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.extract.position, 6);
        ia64_tcg_fallback_put(&stream, decoded->u.extract.length, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.extract.sign_extend, 1);
        break;
    case IA64_TCG_FALLBACK_PLAN_DEPOSIT:
        ia64_tcg_fallback_put(&stream, decoded->u.deposit.target, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.deposit.source2, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.deposit.source3, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.deposit.position, 6);
        ia64_tcg_fallback_put(&stream, decoded->u.deposit.length, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.deposit.deposit_zero, 1);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.deposit.source_immediate, 1);
        ia64_tcg_fallback_put(&stream, decoded->u.deposit.immediate & 0xff, 8);
        break;
    case IA64_TCG_FALLBACK_PLAN_INTEGER_EXTEND:
        ia64_tcg_fallback_put(&stream, decoded->u.integer_extend.kind, 2);
        ia64_tcg_fallback_put(&stream, decoded->u.integer_extend.target, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.integer_extend.source3, 7);
        ia64_tcg_fallback_put(
            &stream,
            ia64_tcg_fallback_width_code(decoded->u.integer_extend.width),
            2);
        break;
    case IA64_TCG_FALLBACK_PLAN_FLOATING_MEMORY:
        ia64_tcg_fallback_put(&stream, decoded->u.floating_memory.kind, 2);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_memory.format, 3);
        ia64_tcg_fallback_put(
            &stream,
            ia64_tcg_fallback_width_code(decoded->u.floating_memory.width),
            3);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_memory.freg, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_memory.freg2, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_memory.base, 7);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_memory.update_source, 7);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_memory.memory_class, 4);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_memory.base_update, 1);
        ia64_tcg_fallback_put(
            &stream, decoded->u.floating_memory.update_from_register, 1);
        ia64_tcg_fallback_put(
            &stream, (uint64_t)decoded->u.floating_memory.immediate & 0x1ff,
            9);
        break;
    case IA64_TCG_FALLBACK_PLAN_FLOATING_COMPARE:
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_compare.relation, 2);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_compare.write_kind, 3);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_compare.status_field, 2);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_compare.p1, 6);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_compare.p2, 6);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_compare.source2, 7);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_compare.source3, 7);
        break;
    case IA64_TCG_FALLBACK_PLAN_FLOATING_CLASS:
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_class.write_kind, 3);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_class.p1, 6);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_class.p2, 6);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.floating_class.source2, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.floating_class.mask, 9);
        break;
    case IA64_TCG_FALLBACK_PLAN_LDST_IMMEDIATE:
        ia64_tcg_fallback_put(&stream, decoded->u.ldst.kind, 2);
        ia64_tcg_fallback_put(
            &stream, ia64_tcg_fallback_width_code(decoded->u.ldst.width), 2);
        ia64_tcg_fallback_put(&stream, decoded->u.ldst.target, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.ldst.source, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.ldst.base, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.ldst.update_source, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.ldst.memory_class, 4);
        ia64_tcg_fallback_put(&stream, decoded->u.ldst.base_update, 1);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.ldst.update_from_register, 1);
        ia64_tcg_fallback_put(
            &stream, (uint64_t)decoded->u.ldst.immediate & 0x1ff, 9);
        break;
    case IA64_TCG_FALLBACK_PLAN_COMPARE:
        ia64_tcg_fallback_put(&stream, decoded->u.compare.relation, 4);
        ia64_tcg_fallback_put(&stream, decoded->u.compare.write_kind, 3);
        ia64_tcg_fallback_put(&stream, decoded->u.compare.width == 4, 1);
        ia64_tcg_fallback_put(&stream, decoded->u.compare.p1, 6);
        ia64_tcg_fallback_put(&stream, decoded->u.compare.p2, 6);
        ia64_tcg_fallback_put(&stream, decoded->u.compare.source2, 7);
        ia64_tcg_fallback_put(&stream, decoded->u.compare.source3, 7);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.compare.source_immediate, 1);
        ia64_tcg_fallback_put(
            &stream, (uint64_t)decoded->u.compare.immediate & 0xff, 8);
        break;
    case IA64_TCG_FALLBACK_PLAN_PREDICATE_TEST:
        ia64_tcg_fallback_put(&stream,
                              decoded->u.predicate_test.kind, 2);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.predicate_test.relation, 1);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.predicate_test.write_kind, 3);
        ia64_tcg_fallback_put(&stream, decoded->u.predicate_test.p1, 6);
        ia64_tcg_fallback_put(&stream, decoded->u.predicate_test.p2, 6);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.predicate_test.source3, 7);
        ia64_tcg_fallback_put(&stream,
                              decoded->u.predicate_test.immediate, 6);
        break;
    case IA64_TCG_FALLBACK_PLAN_BRANCH_RELATIVE:
    case IA64_TCG_FALLBACK_PLAN_BRANCH_CALL_RELATIVE:
    case IA64_TCG_FALLBACK_PLAN_BRANCH_INDIRECT:
        ia64_tcg_fallback_put(&stream, decoded->u.branch.type, 3);
        ia64_tcg_fallback_put(&stream, decoded->u.branch.branch_reg, 3);
        ia64_tcg_fallback_put(&stream, decoded->u.branch.target_reg, 3);
        ia64_tcg_fallback_put(&stream, decoded->u.branch.major, 4);
        ia64_tcg_fallback_put(&stream, decoded->u.branch.x6, 6);
        ia64_tcg_fallback_put(
            &stream, (uint64_t)decoded->u.branch.displacement & 0x1ffffff,
            25);
        break;
    default:
        break;
    }

    g_assert(decoded->op < IA64_TCG_FALLBACK_PLAN_COUNT);
    return stream.value |
           ((uint64_t)decoded->op << IA64_TCG_FALLBACK_DESC_OP_SHIFT);
}

static IA64TcgFallbackBitStream ia64_tcg_fallback_payload(uint64_t desc)
{
    IA64TcgFallbackBitStream stream = {
        .value = desc & IA64_TCG_FALLBACK_DESC_PAYLOAD_MASK,
        .shift = 6,
    };

    return stream;
}

void ia64_tcg_fallback_unpack_extract(uint64_t desc,
                                      IA64ExtractInstruction *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->target = ia64_tcg_fallback_get(&stream, 7);
    decoded->source3 = ia64_tcg_fallback_get(&stream, 7);
    decoded->position = ia64_tcg_fallback_get(&stream, 6);
    decoded->length = ia64_tcg_fallback_get(&stream, 7);
    decoded->sign_extend = ia64_tcg_fallback_get(&stream, 1);
}

void ia64_tcg_fallback_unpack_deposit(uint64_t desc,
                                      IA64DepositInstruction *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->target = ia64_tcg_fallback_get(&stream, 7);
    decoded->source2 = ia64_tcg_fallback_get(&stream, 7);
    decoded->source3 = ia64_tcg_fallback_get(&stream, 7);
    decoded->position = ia64_tcg_fallback_get(&stream, 6);
    decoded->length = ia64_tcg_fallback_get(&stream, 7);
    decoded->deposit_zero = ia64_tcg_fallback_get(&stream, 1);
    decoded->source_immediate = ia64_tcg_fallback_get(&stream, 1);
    decoded->immediate = (uint64_t)ia64_tcg_fallback_sign_extend(
        ia64_tcg_fallback_get(&stream, 8), 8);
}

void ia64_tcg_fallback_unpack_integer_extend(
    uint64_t desc, IA64IntegerExtendInstruction *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->kind = ia64_tcg_fallback_get(&stream, 2);
    decoded->target = ia64_tcg_fallback_get(&stream, 7);
    decoded->source3 = ia64_tcg_fallback_get(&stream, 7);
    decoded->width = ia64_tcg_fallback_width_from_code(
        ia64_tcg_fallback_get(&stream, 2));
}

void ia64_tcg_fallback_unpack_floating_memory(
    uint64_t desc, IA64FloatingMemoryInstruction *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->kind = ia64_tcg_fallback_get(&stream, 2);
    decoded->format = ia64_tcg_fallback_get(&stream, 3);
    decoded->width = ia64_tcg_fallback_width_from_code(
        ia64_tcg_fallback_get(&stream, 3));
    decoded->freg = ia64_tcg_fallback_get(&stream, 7);
    decoded->freg2 = ia64_tcg_fallback_get(&stream, 7);
    decoded->base = ia64_tcg_fallback_get(&stream, 7);
    decoded->update_source = ia64_tcg_fallback_get(&stream, 7);
    decoded->memory_class = ia64_tcg_fallback_get(&stream, 4);
    decoded->base_update = ia64_tcg_fallback_get(&stream, 1);
    decoded->update_from_register = ia64_tcg_fallback_get(&stream, 1);
    decoded->immediate = ia64_tcg_fallback_sign_extend(
        ia64_tcg_fallback_get(&stream, 9), 9);
}

void ia64_tcg_fallback_unpack_floating_compare(
    uint64_t desc, IA64FloatingCompareInstruction *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->relation = ia64_tcg_fallback_get(&stream, 2);
    decoded->write_kind = ia64_tcg_fallback_get(&stream, 3);
    decoded->status_field = ia64_tcg_fallback_get(&stream, 2);
    decoded->p1 = ia64_tcg_fallback_get(&stream, 6);
    decoded->p2 = ia64_tcg_fallback_get(&stream, 6);
    decoded->source2 = ia64_tcg_fallback_get(&stream, 7);
    decoded->source3 = ia64_tcg_fallback_get(&stream, 7);
}

void ia64_tcg_fallback_unpack_floating_class(
    uint64_t desc, IA64FloatingClassInstruction *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->write_kind = ia64_tcg_fallback_get(&stream, 3);
    decoded->p1 = ia64_tcg_fallback_get(&stream, 6);
    decoded->p2 = ia64_tcg_fallback_get(&stream, 6);
    decoded->source2 = ia64_tcg_fallback_get(&stream, 7);
    decoded->mask = ia64_tcg_fallback_get(&stream, 9);
}

void ia64_tcg_fallback_unpack_ldst(uint64_t desc,
                                   IA64LdstImmediate *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->kind = ia64_tcg_fallback_get(&stream, 2);
    decoded->width = ia64_tcg_fallback_width_from_code(
        ia64_tcg_fallback_get(&stream, 2));
    decoded->target = ia64_tcg_fallback_get(&stream, 7);
    decoded->source = ia64_tcg_fallback_get(&stream, 7);
    decoded->base = ia64_tcg_fallback_get(&stream, 7);
    decoded->update_source = ia64_tcg_fallback_get(&stream, 7);
    decoded->memory_class = ia64_tcg_fallback_get(&stream, 4);
    decoded->base_update = ia64_tcg_fallback_get(&stream, 1);
    decoded->update_from_register = ia64_tcg_fallback_get(&stream, 1);
    decoded->immediate = ia64_tcg_fallback_sign_extend(
        ia64_tcg_fallback_get(&stream, 9), 9);
}

void ia64_tcg_fallback_unpack_compare(uint64_t desc,
                                      IA64CompareInstruction *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->relation = ia64_tcg_fallback_get(&stream, 4);
    decoded->write_kind = ia64_tcg_fallback_get(&stream, 3);
    decoded->width = ia64_tcg_fallback_get(&stream, 1) ? 4 : 8;
    decoded->p1 = ia64_tcg_fallback_get(&stream, 6);
    decoded->p2 = ia64_tcg_fallback_get(&stream, 6);
    decoded->source2 = ia64_tcg_fallback_get(&stream, 7);
    decoded->source3 = ia64_tcg_fallback_get(&stream, 7);
    decoded->source_immediate = ia64_tcg_fallback_get(&stream, 1);
    decoded->immediate = ia64_tcg_fallback_sign_extend(
        ia64_tcg_fallback_get(&stream, 8), 8);
}

void ia64_tcg_fallback_unpack_predicate_test(
    uint64_t desc, IA64PredicateTestInstruction *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->kind = ia64_tcg_fallback_get(&stream, 2);
    decoded->relation = ia64_tcg_fallback_get(&stream, 1);
    decoded->write_kind = ia64_tcg_fallback_get(&stream, 3);
    decoded->p1 = ia64_tcg_fallback_get(&stream, 6);
    decoded->p2 = ia64_tcg_fallback_get(&stream, 6);
    decoded->source3 = ia64_tcg_fallback_get(&stream, 7);
    decoded->immediate = ia64_tcg_fallback_get(&stream, 6);
}

void ia64_tcg_fallback_unpack_branch(uint64_t desc,
                                     IA64TcgFallbackBranch *decoded)
{
    IA64TcgFallbackBitStream stream = ia64_tcg_fallback_payload(desc);

    decoded->type = ia64_tcg_fallback_get(&stream, 3);
    decoded->branch_reg = ia64_tcg_fallback_get(&stream, 3);
    decoded->target_reg = ia64_tcg_fallback_get(&stream, 3);
    decoded->major = ia64_tcg_fallback_get(&stream, 4);
    decoded->x6 = ia64_tcg_fallback_get(&stream, 6);
    decoded->displacement = ia64_tcg_fallback_sign_extend(
        ia64_tcg_fallback_get(&stream, 25), 25);
}

bool ia64_tcg_fallback_unpack_desc(uint64_t desc,
                                   IA64TcgFallbackDecodedSlot *decoded)
{
    IA64TcgFallbackBitStream stream = {
        .value = desc & IA64_TCG_FALLBACK_DESC_PAYLOAD_MASK,
    };

    if (!decoded || ia64_tcg_fallback_desc_op(desc) >=
                        IA64_TCG_FALLBACK_PLAN_COUNT) {
        return false;
    }
    decoded->op = ia64_tcg_fallback_desc_op(desc);
    decoded->predicate = ia64_tcg_fallback_get(&stream, 6);
    switch (decoded->op) {
    case IA64_TCG_FALLBACK_PLAN_EXTRACT:
        decoded->u.extract.target = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.extract.source3 = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.extract.position = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.extract.length = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.extract.sign_extend = ia64_tcg_fallback_get(&stream, 1);
        break;
    case IA64_TCG_FALLBACK_PLAN_DEPOSIT:
        decoded->u.deposit.target = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.deposit.source2 = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.deposit.source3 = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.deposit.position = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.deposit.length = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.deposit.deposit_zero = ia64_tcg_fallback_get(&stream, 1);
        decoded->u.deposit.source_immediate =
            ia64_tcg_fallback_get(&stream, 1);
        decoded->u.deposit.immediate = (uint64_t)ia64_tcg_fallback_sign_extend(
            ia64_tcg_fallback_get(&stream, 8), 8);
        break;
    case IA64_TCG_FALLBACK_PLAN_INTEGER_EXTEND:
        decoded->u.integer_extend.kind = ia64_tcg_fallback_get(&stream, 2);
        decoded->u.integer_extend.target = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.integer_extend.source3 = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.integer_extend.width = ia64_tcg_fallback_width_from_code(
            ia64_tcg_fallback_get(&stream, 2));
        break;
    case IA64_TCG_FALLBACK_PLAN_FLOATING_MEMORY:
        decoded->u.floating_memory.kind = ia64_tcg_fallback_get(&stream, 2);
        decoded->u.floating_memory.format =
            ia64_tcg_fallback_get(&stream, 3);
        decoded->u.floating_memory.width = ia64_tcg_fallback_width_from_code(
            ia64_tcg_fallback_get(&stream, 3));
        decoded->u.floating_memory.freg = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.floating_memory.freg2 = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.floating_memory.base = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.floating_memory.update_source =
            ia64_tcg_fallback_get(&stream, 7);
        decoded->u.floating_memory.memory_class =
            ia64_tcg_fallback_get(&stream, 4);
        decoded->u.floating_memory.base_update =
            ia64_tcg_fallback_get(&stream, 1);
        decoded->u.floating_memory.update_from_register =
            ia64_tcg_fallback_get(&stream, 1);
        decoded->u.floating_memory.immediate = ia64_tcg_fallback_sign_extend(
            ia64_tcg_fallback_get(&stream, 9), 9);
        break;
    case IA64_TCG_FALLBACK_PLAN_FLOATING_COMPARE:
        decoded->u.floating_compare.relation =
            ia64_tcg_fallback_get(&stream, 2);
        decoded->u.floating_compare.write_kind =
            ia64_tcg_fallback_get(&stream, 3);
        decoded->u.floating_compare.status_field =
            ia64_tcg_fallback_get(&stream, 2);
        decoded->u.floating_compare.p1 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.floating_compare.p2 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.floating_compare.source2 =
            ia64_tcg_fallback_get(&stream, 7);
        decoded->u.floating_compare.source3 =
            ia64_tcg_fallback_get(&stream, 7);
        break;
    case IA64_TCG_FALLBACK_PLAN_FLOATING_CLASS:
        decoded->u.floating_class.write_kind =
            ia64_tcg_fallback_get(&stream, 3);
        decoded->u.floating_class.p1 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.floating_class.p2 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.floating_class.source2 =
            ia64_tcg_fallback_get(&stream, 7);
        decoded->u.floating_class.mask = ia64_tcg_fallback_get(&stream, 9);
        break;
    case IA64_TCG_FALLBACK_PLAN_LDST_IMMEDIATE:
        decoded->u.ldst.kind = ia64_tcg_fallback_get(&stream, 2);
        decoded->u.ldst.width = ia64_tcg_fallback_width_from_code(
            ia64_tcg_fallback_get(&stream, 2));
        decoded->u.ldst.target = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.ldst.source = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.ldst.base = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.ldst.update_source = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.ldst.memory_class = ia64_tcg_fallback_get(&stream, 4);
        decoded->u.ldst.base_update = ia64_tcg_fallback_get(&stream, 1);
        decoded->u.ldst.update_from_register =
            ia64_tcg_fallback_get(&stream, 1);
        decoded->u.ldst.immediate = ia64_tcg_fallback_sign_extend(
            ia64_tcg_fallback_get(&stream, 9), 9);
        break;
    case IA64_TCG_FALLBACK_PLAN_COMPARE:
        decoded->u.compare.relation = ia64_tcg_fallback_get(&stream, 4);
        decoded->u.compare.write_kind = ia64_tcg_fallback_get(&stream, 3);
        decoded->u.compare.width = ia64_tcg_fallback_get(&stream, 1) ? 4 : 8;
        decoded->u.compare.p1 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.compare.p2 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.compare.source2 = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.compare.source3 = ia64_tcg_fallback_get(&stream, 7);
        decoded->u.compare.source_immediate =
            ia64_tcg_fallback_get(&stream, 1);
        decoded->u.compare.immediate = ia64_tcg_fallback_sign_extend(
            ia64_tcg_fallback_get(&stream, 8), 8);
        break;
    case IA64_TCG_FALLBACK_PLAN_PREDICATE_TEST:
        decoded->u.predicate_test.kind =
            ia64_tcg_fallback_get(&stream, 2);
        decoded->u.predicate_test.relation =
            ia64_tcg_fallback_get(&stream, 1);
        decoded->u.predicate_test.write_kind =
            ia64_tcg_fallback_get(&stream, 3);
        decoded->u.predicate_test.p1 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.predicate_test.p2 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.predicate_test.source3 =
            ia64_tcg_fallback_get(&stream, 7);
        decoded->u.predicate_test.immediate =
            ia64_tcg_fallback_get(&stream, 6);
        break;
    case IA64_TCG_FALLBACK_PLAN_BRANCH_RELATIVE:
    case IA64_TCG_FALLBACK_PLAN_BRANCH_CALL_RELATIVE:
    case IA64_TCG_FALLBACK_PLAN_BRANCH_INDIRECT:
        decoded->u.branch.type = ia64_tcg_fallback_get(&stream, 3);
        decoded->u.branch.branch_reg = ia64_tcg_fallback_get(&stream, 3);
        decoded->u.branch.target_reg = ia64_tcg_fallback_get(&stream, 3);
        decoded->u.branch.major = ia64_tcg_fallback_get(&stream, 4);
        decoded->u.branch.x6 = ia64_tcg_fallback_get(&stream, 6);
        decoded->u.branch.displacement = ia64_tcg_fallback_sign_extend(
            ia64_tcg_fallback_get(&stream, 25), 25);
        break;
    default:
        break;
    }
    return true;
}

static uint64_t ia64_tcg_fallback_plan_for_slot(IA64SlotType type,
                                                 uint64_t raw)
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
    IA64TcgFallbackDecodedSlot decoded = {
        .op = IA64_TCG_FALLBACK_PLAN_GENERIC,
        .predicate = ia64_slot_predicate(raw),
    };

    /*
     * Smoke/NOP slots are already the first cheap checks in the helper ladder.
     * Leave them generic so the plan only targets slots that skip real work.
     */
    if (ia64_slot_is_m34_alloc(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_ALLOC;
        goto done;
    }
    if (ia64_slot_is_i_mov_from_branch(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_MOV_FROM_BRANCH;
        goto done;
    }
    if (ia64_slot_is_i_mov_to_branch(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_MOV_TO_BRANCH;
        goto done;
    }
    if (ia64_slot_is_mov_to_application(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION;
        goto done;
    }
    if (ia64_slot_is_mov_from_application(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_MOV_FROM_APPLICATION;
        goto done;
    }
    if (ia64_slot_is_mov_to_application_immediate(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION_IMM;
        goto done;
    }
    if (ia64_decode_extract(type, raw, &extract)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_EXTRACT;
        decoded.u.extract = extract;
        goto done;
    }
    if (ia64_decode_deposit(type, raw, &deposit)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_DEPOSIT;
        decoded.u.deposit = deposit;
        goto done;
    }
    if (ia64_decode_integer_extend(type, raw, &int_ext)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_INTEGER_EXTEND;
        decoded.u.integer_extend = int_ext;
        goto done;
    }
    if (ia64_decode_floating_memory(type, raw, &fldst)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_FLOATING_MEMORY;
        decoded.u.floating_memory = fldst;
        goto done;
    }
    if (ia64_decode_floating_compare(type, raw, &fcmp)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_FLOATING_COMPARE;
        decoded.u.floating_compare = fcmp;
        goto done;
    }
    if (ia64_decode_floating_class(type, raw, &fclass)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_FLOATING_CLASS;
        decoded.u.floating_class = fclass;
        goto done;
    }
    if (ia64_decode_ldst_immediate(type, raw, &ldst)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_LDST_IMMEDIATE;
        decoded.u.ldst = ldst;
        goto done;
    }
    if (ia64_decode_compare(type, raw, &cmp)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_COMPARE;
        decoded.u.compare = cmp;
        goto done;
    }
    if (ia64_decode_predicate_test(type, raw, &pred_test)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_PREDICATE_TEST;
        decoded.u.predicate_test = pred_test;
        goto done;
    }
    if (ia64_slot_is_alu_add(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_ALU_ADD;
        goto done;
    }
    if (ia64_slot_is_alu_sub(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_ALU_SUB;
        goto done;
    }
    if (ia64_slot_is_alu_logic(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_ALU_LOGIC;
        goto done;
    }
    if (ia64_slot_is_alu_addp4(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_ALU_ADDP4;
        goto done;
    }
    if (ia64_slot_is_alu_shladd(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_ALU_SHLADD;
        goto done;
    }
    if (ia64_slot_is_i_packed_i2(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_I_PACKED_I2;
        goto done;
    }
    if (ia64_slot_is_i_multiply_shift(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_I_MULTIPLY_SHIFT;
        goto done;
    }
    if (ia64_slot_is_i_mux(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_I_MUX;
        goto done;
    }
    if (ia64_slot_is_i_bit_count(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_I_BIT_COUNT;
        goto done;
    }
    if (ia64_slot_is_i_variable_shift(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_I_VARIABLE_SHIFT;
        goto done;
    }
    if (ia64_slot_is_addl(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_ADDL;
        goto done;
    }
    if (ia64_slot_is_b_branch_relative(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_BRANCH_RELATIVE;
        decoded.u.branch.type = (raw >> 6) & 0x7;
        decoded.u.branch.displacement = ia64_branch_displacement(raw);
        goto done;
    }
    if (ia64_slot_is_b_call_relative(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_BRANCH_CALL_RELATIVE;
        decoded.u.branch.branch_reg = (raw >> 6) & 0x7;
        decoded.u.branch.displacement = ia64_branch_displacement(raw);
        goto done;
    }
    if (ia64_slot_is_b_indirect_branch(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_BRANCH_INDIRECT;
        decoded.u.branch.major = ia64_slot_major_opcode(raw);
        decoded.u.branch.x6 = (raw >> 27) & 0x3f;
        decoded.u.branch.branch_reg = (raw >> 6) & 0x7;
        decoded.u.branch.target_reg = (raw >> 13) & 0x7;
        goto done;
    }
    if (ia64_slot_is_b_predict_or_nop(type, raw)) {
        decoded.op = IA64_TCG_FALLBACK_PLAN_BRANCH_PREDICT_OR_NOP;
    }

done:
    return ia64_tcg_fallback_pack_desc(&decoded);
}

IA64TcgFallbackPlan ia64_tcg_fallback_plan_for_bundle(
    const IA64DecodedBundle *bundle)
{
    IA64TcgFallbackPlan plan = { 0 };

    if (!bundle || !bundle->valid) {
        return plan;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (bundle->info->long_immediate && slot >= 1) {
            IA64TcgFallbackDecodedSlot decoded = {
                .op = IA64_TCG_FALLBACK_PLAN_GENERIC,
                .predicate = ia64_slot_predicate(bundle->slot[slot]),
            };

            plan.slot[slot] = ia64_tcg_fallback_pack_desc(&decoded);
        } else {
            plan.slot[slot] = ia64_tcg_fallback_plan_for_slot(
                bundle->info->slot_type[slot], bundle->slot[slot]);
        }
    }

    return plan;
}

static bool ia64_tcg_build_direct_branch_prefix(
    const IA64DecodedBundle *bundle, int branch_slot,
    IA64TcgFastBundle *prefix,
    IA64TcgBranchReject *reject, int *prefix_slot)
{
    uint64_t prior_dest_mask = 0;
    uint64_t prior_dest_mask_hi = 0;

    /*
     * Prefix slots run in program order before the branch condition is
     * evaluated, so predicated slots and slots writing the branch predicate
     * keep interpreter semantics: legal encodings separate the producer and
     * the branch with a stop, and the branch reads the freshly written
     * value either way.
     */
    memset(prefix, 0, sizeof(*prefix));
    for (int slot = 0; slot < branch_slot; slot++) {
        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[slot],
                                      bundle->slot[slot],
                                      slot,
                                      slot != 0 &&
                                          bundle->info->stop_after_slot[
                                              slot - 1],
                                      &prefix->slot[slot], prefix)) {
            /*
             * Keep one decoded helper at the end of the prefix.  With no
             * later prefix slot, its unknown write set cannot invalidate a
             * generated operand; the branch predicate/BR is loaded after the
             * helper returns.
             */
            if (prefix->helper_mask == 0 && slot + 1 == branch_slot) {
                prefix->helper_mask |= 1u << slot;
                prefix->slot_count++;
                continue;
            }
            *reject = IA64_TCG_BRANCH_REJECT_PREFIX_UNSUPPORTED;
            *prefix_slot = slot;
            return false;
        }
        if (ia64_tcg_fast_slot_has_prior_base_dependency(&prefix->slot[slot],
                                                         prior_dest_mask,
                                                         prior_dest_mask_hi)) {
            *reject = IA64_TCG_BRANCH_REJECT_PREFIX_LDST_DEPENDENCY;
            *prefix_slot = slot;
            return false;
        }
        prefix->slot_count++;
        prefix->source_nat_mask |= prefix->slot[slot].source_nat_mask;
        prefix->source_nat_mask_hi |= prefix->slot[slot].source_nat_mask_hi;
        prefix->dest_mask |= prefix->slot[slot].dest_mask;
        prefix->dest_mask_hi |= prefix->slot[slot].dest_mask_hi;
        prefix->finalize_mask |= prefix->slot[slot].finalize_mask;
        prefix->finalize_mask_hi |= prefix->slot[slot].finalize_mask_hi;
        prior_dest_mask |= prefix->slot[slot].dest_mask;
        prior_dest_mask_hi |= prefix->slot[slot].dest_mask_hi;
    }

    return true;
}

bool ia64_tcg_build_speculation_check(const IA64DecodedBundle *bundle,
                                      uint64_t pc,
                                      IA64TcgSpecCheck *check)
{
    uint64_t prior_dest_mask = 0;
    uint64_t prior_dest_mask_hi = 0;
    int check_slot = -1;

    if (!bundle || !check || !bundle->valid || bundle->info->long_immediate) {
        return false;
    }

    memset(check, 0, sizeof(*check));
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = bundle->info->slot_type[slot];
        uint64_t raw = bundle->slot[slot];

        if (ia64_slot_is_check_speculative(type, raw) ||
            ia64_slot_is_m_check_advanced(type, raw)) {
            if (check_slot >= 0) {
                return false;
            }
            check_slot = slot;
        }
    }
    if (check_slot < 0) {
        return false;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64TcgFastBundle slot_counts = { 0 };
        IA64TcgFastSlot fast_slot;

        if (slot == check_slot) {
            continue;
        }
        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[slot],
                                      bundle->slot[slot], slot,
                                      slot != 0 &&
                                          bundle->info->stop_after_slot[
                                              slot - 1],
                                      &fast_slot,
                                      &slot_counts) ||
            fast_slot.op == IA64_TCG_FAST_OP_ALLOC ||
            fast_slot.op == IA64_TCG_FAST_OP_FP_SLOT ||
            ia64_tcg_fast_slot_has_prior_base_dependency(
                &fast_slot, prior_dest_mask, prior_dest_mask_hi)) {
            return false;
        }
        ia64_tcg_partial_add_fast_slot(&check->surrounding, &fast_slot,
                                       slot_counts.op_counts);
        prior_dest_mask |= fast_slot.dest_mask;
        prior_dest_mask_hi |= fast_slot.dest_mask_hi;
    }

    check->raw = bundle->slot[check_slot];
    check->slot = check_slot;
    check->predicate = ia64_slot_predicate(check->raw);
    check->fallthrough_ip = pc + IA64_BUNDLE_SIZE;
    if (ia64_slot_is_check_speculative(
            bundle->info->slot_type[check_slot], check->raw)) {
        uint8_t x3 = (check->raw >> 33) & 0x7;

        check->source = (check->raw >> 13) & 0x7f;
        check->kind = bundle->info->slot_type[check_slot] == IA64_SLOT_TYPE_M &&
                              x3 == 3
                          ? IA64_TCG_SPEC_CHECK_FR_NATVAL
                          : IA64_TCG_SPEC_CHECK_GR_NAT;
        /* Rotating FR mapping is kept on the complete-bundle oracle. */
        if (check->kind == IA64_TCG_SPEC_CHECK_FR_NATVAL &&
            check->source >= 32) {
            return false;
        }
        check->target_ip =
            pc + ia64_check_speculative_displacement(check->raw);
    } else {
        uint8_t x3 = (check->raw >> 33) & 0x7;

        check->source = (check->raw >> 6) & 0x7f;
        check->clear = (x3 & 1) != 0;
        check->kind = x3 >= 6 ? IA64_TCG_SPEC_CHECK_FR_ALAT
                              : IA64_TCG_SPEC_CHECK_GR_ALAT;
        check->target_ip = pc + ia64_branch_displacement(check->raw);
    }

    return check->target_ip != 0;
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

static bool ia64_tcg_build_direct_branch_internal(
    const IA64DecodedBundle *bundle, uint64_t pc,
    IA64TcgDirectBranch *branch, IA64TcgBranchReject *reject,
    int *prefix_slot)
{
    uint64_t raw;
    uint64_t target;
    uint64_t fallthrough;
    uint8_t btype;
    uint8_t predicate;
    uint8_t branch_slot = IA64_SLOT_COUNT;
    IA64TcgDirectBranchKind kind;
    uint8_t call_branch_reg = 0;
    uint8_t target_branch_reg = 0;

    unsigned branch_count = 0;

    *reject = IA64_TCG_BRANCH_REJECT_UNSUPPORTED_TYPE;
    *prefix_slot = -1;
    if (!bundle || !branch || !bundle->valid || bundle->info->long_immediate) {
        return false;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = bundle->info->slot_type[slot];
        uint64_t candidate = bundle->slot[slot];

        if (ia64_slot_is_b_branch_relative(type, candidate) ||
            ia64_slot_is_b_call_relative(type, candidate) ||
            ia64_slot_is_b_indirect_branch(type, candidate)) {
            branch_count++;
            branch_slot = slot;
        }
    }
    if (branch_count > 1) {
        *reject = IA64_TCG_BRANCH_REJECT_MULTIPLE_BRANCH;
        return false;
    }
    if (branch_count != 1 || branch_slot >= IA64_SLOT_COUNT) {
        return false;
    }

    /* Later B slots are harmless only when they are architecturally hints. */
    for (int slot = branch_slot + 1; slot < IA64_SLOT_COUNT; slot++) {
        if (!ia64_slot_is_b_predict_or_nop(bundle->info->slot_type[slot],
                                           bundle->slot[slot])) {
            *reject = IA64_TCG_BRANCH_REJECT_NOT_SLOT2;
            return false;
        }
    }

    /*
     * Keep branch lowering auditably small: only bundles with a final simple
     * relative branch, counted-loop branch, call, plain indirect branch, or
     * return and two safe fast-prefix slots can use direct TCG control flow.
     * rfi, cover/clrrrb/bsw/epc forms and modulo-scheduled loop branches stay
     * on the helper path; rotating predicate reads are mapped at runtime.
     */
    raw = bundle->slot[branch_slot];
    predicate = ia64_slot_predicate(raw);
    if (predicate >= 16 &&
        ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_PREDICATE)) {
        *reject = IA64_TCG_BRANCH_REJECT_ROTATING_PREDICATE;
        return false;
    }
    if (ia64_slot_is_b_branch_relative(bundle->info->slot_type[branch_slot],
                                       raw)) {
        btype = (raw >> 6) & 0x7;
        switch (btype) {
        case 0:
        case 1:
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
    } else if (ia64_slot_is_b_call_relative(bundle->info->slot_type[branch_slot],
                                            raw)) {
        kind = IA64_TCG_DIRECT_BRANCH_CALL;
        call_branch_reg = (raw >> 6) & 0x7;
    } else if (ia64_slot_is_b_indirect_branch(bundle->info->slot_type[branch_slot],
                                              raw)) {
        uint8_t major = ia64_slot_major_opcode(raw);
        uint8_t x6 = (raw >> 27) & 0x3f;

        if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_INDIRECT) ||
            !(major == 0x1 ||
              (major == 0x0 &&
               (x6 == 0x08 || x6 == 0x20 || x6 == 0x21)))) {
            *reject = IA64_TCG_BRANCH_REJECT_INDIRECT_UNSUPPORTED;
            return false;
        }
        target_branch_reg = (raw >> 13) & 0x7;
        if (major == 0x1) {
            kind = IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL;
            call_branch_reg = (raw >> 6) & 0x7;
        } else if (x6 == 0x08) {
            kind = IA64_TCG_DIRECT_BRANCH_RFI;
        } else if (x6 == 0x21) {
            kind = IA64_TCG_DIRECT_BRANCH_RET;
        } else {
            kind = IA64_TCG_DIRECT_BRANCH_INDIRECT;
        }
    } else {
        return false;
    }

    fallthrough = pc + IA64_BUNDLE_SIZE;
    if (kind == IA64_TCG_DIRECT_BRANCH_INDIRECT ||
        kind == IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL ||
        kind == IA64_TCG_DIRECT_BRANCH_RET ||
        kind == IA64_TCG_DIRECT_BRANCH_RFI) {
        target = 0;
    } else {
        target = pc + ia64_branch_displacement(raw);
        if (target == 0) {
            return false;
        }
    }

    memset(branch, 0, sizeof(*branch));
    if (!ia64_tcg_build_direct_branch_prefix(bundle, branch_slot,
                                              &branch->prefix,
                                              reject, prefix_slot)) {
        return false;
    }
    branch->target_ip = target;
    branch->fallthrough_ip = fallthrough;
    branch->branch_raw = raw;
    branch->kind = kind;
    branch->slot = branch_slot;
    branch->predicate = predicate;
    branch->nop_count = ia64_tcg_fast_bundle_nop_count(&branch->prefix);
    branch->call_branch_reg = call_branch_reg;
    branch->target_branch_reg = target_branch_reg;
    branch->conditional = kind == IA64_TCG_DIRECT_BRANCH_CLOOP ||
                          predicate != 0;
    *reject = IA64_TCG_BRANCH_REJECT_NONE;
    return true;
}

bool ia64_tcg_build_direct_branch(const IA64DecodedBundle *bundle,
                                  uint64_t pc,
                                  IA64TcgDirectBranch *branch)
{
    IA64TcgBranchReject reject;
    int prefix_slot;

    return ia64_tcg_build_direct_branch_internal(bundle, pc, branch,
                                                  &reject, &prefix_slot);
}

IA64TcgBranchReject ia64_tcg_direct_branch_rejection(
    const IA64DecodedBundle *bundle, uint64_t pc, int *prefix_slot)
{
    IA64TcgDirectBranch branch;
    IA64TcgBranchReject reject;
    int local_prefix_slot;

    if (!prefix_slot) {
        prefix_slot = &local_prefix_slot;
    }
    ia64_tcg_build_direct_branch_internal(bundle, pc, &branch, &reject,
                                          prefix_slot);
    return reject;
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
    if (ia64_slot_is_m_serialization(type, raw)) {
        return IA64_TCG_TB_BOUNDARY_SERIALIZATION;
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
    if (type == IA64_SLOT_TYPE_X) {
        major = ia64_slot_major_opcode(raw);
        if (major == 0xc || major == 0xd) {
            /* X3 brl.cond and X4 brl.call are control-flow boundaries. */
            return IA64_TCG_TB_BOUNDARY_BRANCH;
        }
    }

    return IA64_TCG_TB_BOUNDARY_NONE;
}

IA64TcgTbBoundary ia64_tcg_tb_boundary_for_bundle(
    const IA64DecodedBundle *bundle, uint64_t pc)
{
    return ia64_tcg_tb_boundary_for_bundle_with_physical(
        bundle, pc, 0, false);
}

IA64TcgTbBoundary ia64_tcg_tb_boundary_for_bundle_with_physical(
    const IA64DecodedBundle *bundle, uint64_t pc, uint64_t physical_pc,
    bool physical_pc_valid)
{
    return ia64_tcg_tb_boundary_for_bundle_from_slot_with_physical(
        bundle, pc, physical_pc, physical_pc_valid, 0);
}

IA64TcgTbBoundary ia64_tcg_tb_boundary_for_bundle_from_slot_with_physical(
    const IA64DecodedBundle *bundle, uint64_t pc, uint64_t physical_pc,
    bool physical_pc_valid, unsigned start_slot)
{
    if (!bundle || !bundle->valid) {
        return IA64_TCG_TB_BOUNDARY_INVALID_TEMPLATE;
    }
    if (start_slot >= IA64_SLOT_COUNT) {
        start_slot = 0;
    }
    if (start_slot == 0 &&
        (ia64_tcg_pc_is_efi_call_gate(pc) ||
        (physical_pc_valid &&
         ia64_tcg_pc_is_efi_call_gate(physical_pc)))) {
        return IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE;
    }

    for (unsigned slot = start_slot; slot < IA64_SLOT_COUNT; slot++) {
        IA64TcgTbBoundary boundary =
            ia64_tcg_slot_boundary(bundle->info->slot_type[slot],
                                   bundle->slot[slot]);

        if (ia64_tcg_tb_boundary_ends_tb(boundary)) {
            return boundary;
        }
    }

    return IA64_TCG_TB_BOUNDARY_NONE;
}
