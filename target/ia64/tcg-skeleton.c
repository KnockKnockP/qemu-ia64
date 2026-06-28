/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exec-smoke.h"
#include "hw/ia64/efi.h"
#include "perf.h"
#include "tcg-skeleton.h"

#define IA64_REGION_OFFSET_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_TCG_FAST_GR_LIMIT 16

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

bool ia64_tcg_pc_is_efi_call_gate(uint64_t pc)
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

static bool ia64_tcg_fast_add_source(IA64TcgFastSlot *slot, uint32_t reg)
{
    if (!ia64_tcg_fast_static_gr(reg)) {
        return false;
    }
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

static bool ia64_tcg_build_fast_slot(IA64SlotType type, uint64_t raw,
                                     IA64TcgFastSlot *slot,
                                     IA64TcgFastBundle *fast)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2a;
    uint8_t x2b;
    uint8_t x4;

    memset(slot, 0, sizeof(*slot));
    if (ia64_slot_predicate(raw) != 0) {
        return false;
    }

    if (ia64_exec_smoke_slot_supported(type, raw) ||
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

    return false;
}

bool ia64_tcg_build_fast_bundle(const IA64DecodedBundle *bundle,
                                IA64TcgFastBundle *fast)
{
    if (!bundle || !fast || !bundle->valid || bundle->info->long_immediate) {
        return false;
    }

    memset(fast, 0, sizeof(*fast));
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (!ia64_tcg_build_fast_slot(bundle->info->slot_type[slot],
                                      bundle->slot[slot],
                                      &fast->slot[slot], fast)) {
            return false;
        }
        fast->slot_count++;
        fast->source_nat_mask |= fast->slot[slot].source_nat_mask;
        fast->dest_mask |= fast->slot[slot].dest_mask;
    }

    return fast->slot_count == IA64_SLOT_COUNT;
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
    if (ia64_slot_is_i_break(type, raw) || ia64_slot_is_m_break(type, raw)) {
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

            if (x6 == 0x08 || x6 == 0x20 || x6 == 0x21) {
                return IA64_TCG_TB_BOUNDARY_BRANCH;
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
