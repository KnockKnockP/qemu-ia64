/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-ldst.h"
#include "bundle.h"
#include "cpu.h"
#include "exec-smoke.h"
#include "exec/helper-proto.h"

static void abort_unsupported_slot(CPUIA64State *env,
                                   const IA64DecodedBundle *decoded,
                                   int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": unsupported instruction %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

static uint64_t ia64_ldst_read(CPUIA64State *env, uint64_t address,
                               uint8_t width)
{
    switch (width) {
    case 1:
        return cpu_ldub_data_ra(env, address, GETPC());
    case 2:
        return cpu_lduw_le_data_ra(env, address, GETPC());
    case 4:
        return cpu_ldl_le_data_ra(env, address, GETPC());
    case 8:
        return cpu_ldq_le_data_ra(env, address, GETPC());
    default:
        g_assert_not_reached();
    }
}

static void ia64_ldst_write(CPUIA64State *env, uint64_t address,
                            uint8_t width, uint64_t value)
{
    switch (width) {
    case 1:
        cpu_stb_data_ra(env, address, value, GETPC());
        break;
    case 2:
        cpu_stw_le_data_ra(env, address, value, GETPC());
        break;
    case 4:
        cpu_stl_le_data_ra(env, address, value, GETPC());
        break;
    case 8:
        cpu_stq_le_data_ra(env, address, value, GETPC());
        break;
    default:
        g_assert_not_reached();
    }
}

static bool exec_ldst_immediate(CPUIA64State *env,
                                const IA64LdstImmediate *decoded)
{
    uint64_t address = env->gr[decoded->base];
    uint64_t update;

    if (decoded->width > 1 && (address & (decoded->width - 1)) != 0) {
        return false;
    }

    switch (decoded->kind) {
    case IA64_LDST_IMM_LOAD:
        if (decoded->target != 0) {
            env->gr[decoded->target] =
                ia64_ldst_read(env, address, decoded->width);
        }
        break;
    case IA64_LDST_IMM_STORE:
        ia64_ldst_write(env, address, decoded->width,
                        env->gr[decoded->source]);
        break;
    case IA64_LDST_IMM_PREFETCH:
        break;
    default:
        g_assert_not_reached();
    }

    if (decoded->base_update) {
        update = decoded->update_from_register
            ? env->gr[decoded->update_source]
            : (uint64_t)decoded->immediate;
        if (decoded->base != 0) {
            env->gr[decoded->base] = address + update;
        }
    }
    env->gr[0] = 0;
    return true;
}

void HELPER(exec_bundle)(CPUIA64State *env,
                         uint32_t tmpl,
                         uint64_t slot0,
                         uint64_t slot1,
                         uint64_t slot2)
{
    IA64DecodedBundle decoded;
    uint64_t next_ip = env->ip + IA64_BUNDLE_SIZE;

    decoded.tmpl = tmpl & 0x1f;
    decoded.slot[0] = slot0 & IA64_SLOT_MASK;
    decoded.slot[1] = slot1 & IA64_SLOT_MASK;
    decoded.slot[2] = slot2 & IA64_SLOT_MASK;
    decoded.info = ia64_template_info(decoded.tmpl);
    decoded.valid = decoded.info->valid;

    if (!decoded.valid) {
        abort_unsupported_slot(env, &decoded, 0);
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = decoded.info->slot_type[slot];
        uint64_t raw = decoded.slot[slot];
        uint8_t qp = ia64_slot_predicate(raw);
        IA64LdstImmediate ldst;
        IA64CompareInstruction cmp;

        if (decoded.info->long_immediate && slot == 1) {
            uint8_t x_qp = ia64_slot_predicate(decoded.slot[2]);

            if (x_qp == 0 || (env->pr & (1ULL << x_qp)) != 0) {
                if (!ia64_exec_lx_movl(env, decoded.slot[1],
                                       decoded.slot[2])) {
                    abort_unsupported_slot(env, &decoded, 1);
                }
            }
            slot++;
            continue;
        }

        if (qp != 0 && ((env->pr & (1ULL << qp)) == 0)) {
            continue;
        }
        if (ia64_exec_smoke_slot_supported(type, raw)) {
            continue;
        }
        if (ia64_slot_is_i_nop(type, raw)) {
            continue;
        }
        if (ia64_slot_is_m34_alloc(type, raw)) {
            ia64_exec_m34_alloc(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_ip(type, raw)) {
            ia64_exec_i_mov_ip(env, raw, env->ip);
            continue;
        }
        if (ia64_slot_is_i_mov_from_branch(type, raw)) {
            ia64_exec_i_mov_from_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_branch(type, raw)) {
            ia64_exec_i_mov_to_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_from_predicate(type, raw)) {
            ia64_exec_i_mov_from_predicate(env, raw);
            continue;
        }
        if (ia64_decode_ldst_immediate(type, raw, &ldst) &&
            exec_ldst_immediate(env, &ldst)) {
            continue;
        }
        if (ia64_decode_compare(type, raw, &cmp) &&
            ia64_exec_compare(env, &cmp)) {
            continue;
        }
        if (ia64_slot_is_alu_add(type, raw)) {
            ia64_exec_alu_add(env, raw);
            continue;
        }
        if (ia64_slot_is_addl(type, raw)) {
            ia64_exec_addl(env, raw);
            continue;
        }
        if (ia64_slot_is_b_branch_relative(type, raw)) {
            ia64_exec_b_branch_relative(env, raw, env->ip, &next_ip);
            continue;
        }
        if (ia64_slot_is_b_call_relative(type, raw)) {
            ia64_exec_b_call_relative(env, raw, env->ip, &next_ip);
            continue;
        }
        if (ia64_slot_is_b_indirect_branch(type, raw)) {
            ia64_exec_b_indirect_branch(env, raw, &next_ip);
            continue;
        }
        if (ia64_slot_is_b_predict_or_nop(type, raw)) {
            continue;
        }
        if (decoded.info->long_immediate && type == IA64_SLOT_TYPE_X) {
            abort_unsupported_slot(env, &decoded, 1);
        }

        abort_unsupported_slot(env, &decoded, slot);
    }

    env->ip = next_ip;
    env->cr[IA64_CR_IIP] = env->ip;
}
