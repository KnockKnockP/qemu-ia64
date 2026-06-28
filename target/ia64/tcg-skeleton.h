/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_TCG_SKELETON_H
#define IA64_TCG_SKELETON_H

#include "bundle.h"

typedef enum IA64TcgTbBoundary {
    IA64_TCG_TB_BOUNDARY_NONE,
    IA64_TCG_TB_BOUNDARY_INVALID_TEMPLATE,
    IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
    IA64_TCG_TB_BOUNDARY_BREAK,
    IA64_TCG_TB_BOUNDARY_SPECULATION_CHECK,
    IA64_TCG_TB_BOUNDARY_VIRTUAL_TRANSLATION,
    IA64_TCG_TB_BOUNDARY_BRANCH,
    IA64_TCG_TB_BOUNDARY_CPU_STATE,
    IA64_TCG_TB_BOUNDARY_TRANSLATION_STATE,
    IA64_TCG_TB_BOUNDARY_RSE_STATE,
} IA64TcgTbBoundary;

/*
 * P03 keeps IA-64 execution conservative: the translator decodes bundles into
 * real QEMU TBs, but still calls the correct bundle helper for semantics.  TBs
 * may contain multiple fall-through bundles only while the following state is
 * stable for already-translated code:
 *
 * - template, slot order, stop bits, and instruction-group boundaries;
 * - instruction fetch mapping and page boundary;
 * - PSR bits represented in TB flags, including IT/DT-sensitive state;
 * - precise exception bundle address plus PSR.ri slot position;
 * - branch, RSE, and translation-control state.
 *
 * Future TCG fast paths should use this module as the single boundary policy
 * before lowering individual slots.
 */
IA64TcgTbBoundary ia64_tcg_tb_boundary_for_bundle(
    const IA64DecodedBundle *bundle, uint64_t pc);
const char *ia64_tcg_tb_boundary_name(IA64TcgTbBoundary boundary);
bool ia64_tcg_tb_boundary_ends_tb(IA64TcgTbBoundary boundary);
bool ia64_tcg_pc_is_efi_call_gate(uint64_t pc);

#endif
