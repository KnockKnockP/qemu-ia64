/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exception.h"
#include "exec-smoke.h"
#include "mem.h"

void ia64_cpu_reset_synthetic_itanium2(CPUIA64State *env)
{
    memset(env, 0, offsetof(CPUIA64State, end_reset_fields));

    /*
     * Synthetic reset: enough for a stable placeholder CPU, not yet validated
     * against PAL/SAL-visible Itanium 2 reset state.
     */
    env->pr = 1;
    env->gr[0] = 0;
    env->ip = 0;
    env->psr = 0;
    env->cfm = 0;

    env->ar[IA64_AR_RSC] = env->rse.rsc;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_RNAT] = env->rse.rnat;
    env->ar[IA64_AR_UNAT] = env->nat.unat;
    env->ar[IA64_AR_PFS] = 0;
    env->ar[IA64_AR_FPSR] = 0;

    env->cr[IA64_CR_IPSR] = env->psr;
    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IFS] = env->cfm;
    env->memory.identity_region0_only = true;
    ia64_clear_exception(env);
}

const char *ia64_exec_smoke_status_name(IA64ExecSmokeStatus status)
{
    switch (status) {
    case IA64_EXEC_SMOKE_OK:
        return "ok";
    case IA64_EXEC_SMOKE_RESERVED_TEMPLATE:
        return "reserved-template";
    case IA64_EXEC_SMOKE_UNSUPPORTED_SLOT:
        return "unsupported-slot";
    default:
        return "unknown";
    }
}

bool ia64_exec_smoke_slot_supported(IA64SlotType type, uint64_t raw)
{
    switch (type) {
    case IA64_SLOT_TYPE_M:
    case IA64_SLOT_TYPE_I:
        return raw == IA64_SMOKE_NOP_RAW;
    default:
        return false;
    }
}

uint64_t ia64_make_cfm(uint32_t sof, uint32_t sol, uint32_t sor)
{
    return (sof & 0x7f) | ((uint64_t)(sol & 0x7f) << 7) |
           ((uint64_t)(sor & 0x0f) << 14);
}

bool ia64_slot_is_m34_alloc(IA64SlotType type, uint64_t raw)
{
    uint8_t x3;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1) {
        return false;
    }

    x3 = (raw >> 33) & 0x7;
    return x3 == 6;
}

bool ia64_exec_m34_alloc(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t sof;
    uint32_t sol;
    uint32_t sor;
    uint64_t old_cfm;

    if (!env || !ia64_slot_is_m34_alloc(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    sof = (raw >> 13) & 0x7f;
    sol = (raw >> 20) & 0x7f;
    sor = (raw >> 27) & 0x0f;
    old_cfm = env->cfm;

    if (r1 != 0) {
        env->gr[r1] = env->ar[IA64_AR_PFS];
    }
    env->ar[IA64_AR_PFS] = old_cfm;
    env->cfm = ia64_make_cfm(sof, sol, sor);
    env->rse.sof = sof;
    env->rse.sol = sol;
    env->rse.sor = sor;
    return true;
}

static bool ia64_slot_is_i_misc_x6(IA64SlotType type, uint64_t raw,
                                   uint8_t x6)
{
    if (type != IA64_SLOT_TYPE_I || ia64_slot_major_opcode(raw) != 0x0) {
        return false;
    }
    if (((raw >> 33) & 0x7) != 0) {
        return false;
    }
    return ((raw >> 27) & 0x3f) == x6;
}

bool ia64_slot_is_i_nop(IA64SlotType type, uint64_t raw)
{
    uint8_t y = (raw >> 26) & 0x1;

    return ia64_slot_is_i_misc_x6(type, raw, 0x1) && y == 0;
}

bool ia64_slot_is_i_mov_ip(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x30);
}

bool ia64_exec_i_mov_ip(CPUIA64State *env, uint64_t raw, uint64_t bundle_ip)
{
    uint32_t r1;

    if (!env || !ia64_slot_is_i_mov_ip(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    if (r1 != 0) {
        env->gr[r1] = bundle_ip;
    }
    return true;
}

bool ia64_slot_is_i_mov_from_branch(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x31);
}

bool ia64_exec_i_mov_from_branch(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t b2;

    if (!env || !ia64_slot_is_i_mov_from_branch(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    b2 = (raw >> 13) & 0x7;
    if (r1 != 0) {
        env->gr[r1] = env->br[b2];
    }
    return true;
}

bool ia64_slot_is_i_mov_to_branch(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_I && ia64_slot_major_opcode(raw) == 0x0 &&
           ((raw >> 33) & 0x7) == 7;
}

bool ia64_exec_i_mov_to_branch(CPUIA64State *env, uint64_t raw)
{
    uint32_t b1;
    uint32_t r2;

    if (!env || !ia64_slot_is_i_mov_to_branch(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    b1 = (raw >> 6) & 0x7;
    r2 = (raw >> 13) & 0x7f;
    env->br[b1] = env->gr[r2];
    return true;
}

bool ia64_slot_is_i_mov_from_predicate(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x33);
}

bool ia64_exec_i_mov_from_predicate(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;

    if (!env || !ia64_slot_is_i_mov_from_predicate(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    if (r1 != 0) {
        env->gr[r1] = env->pr | 1;
    }
    return true;
}

bool ia64_slot_pair_is_lx_movl(uint64_t l_raw, uint64_t x_raw)
{
    return ia64_slot_major_opcode(x_raw) == 0x6;
}

uint64_t ia64_lx_movl_imm64(uint64_t l_raw, uint64_t x_raw)
{
    return (((x_raw >> 36) & 0x1) << 63) |
           ((l_raw & IA64_SLOT_MASK) << 22) |
           (((x_raw >> 21) & 0x1) << 21) |
           (((x_raw >> 22) & 0x1f) << 16) |
           (((x_raw >> 27) & 0x1ff) << 7) |
           ((x_raw >> 13) & 0x7f);
}

bool ia64_exec_lx_movl(CPUIA64State *env, uint64_t l_raw, uint64_t x_raw)
{
    uint32_t r1;

    if (!env || !ia64_slot_pair_is_lx_movl(l_raw, x_raw)) {
        return false;
    }

    r1 = (x_raw >> 6) & 0x7f;
    if (r1 != 0) {
        env->gr[r1] = ia64_lx_movl_imm64(l_raw, x_raw);
    }
    return true;
}

static int64_t ia64_sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t mask = (1ULL << bits) - 1;

    value &= mask;
    return (int64_t)((value ^ sign) - sign);
}

bool ia64_slot_is_alu_add(IA64SlotType type, uint64_t raw)
{
    uint8_t ve;
    uint8_t x2a;
    uint8_t x4;
    uint8_t x2b;

    if ((type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    ve = (raw >> 33) & 0x1;
    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    x2b = (raw >> 27) & 0x3;
    if (ve != 0) {
        return false;
    }
    if (x2a == 0) {
        return x4 == 0 && x2b <= 1;
    }
    return x2a == 2;
}

bool ia64_exec_alu_add(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2a;
    uint8_t immediate;

    if (!env || (!ia64_slot_is_alu_add(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_add(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    x2a = (raw >> 34) & 0x3;
    r3 = (raw >> 20) & 0x7f;

    if (x2a == 2) {
        int64_t imm14 = ia64_sign_extend((((raw >> 36) & 0x1) << 13) |
                                         (((raw >> 27) & 0x3f) << 7) |
                                         ((raw >> 13) & 0x7f), 14);

        if (r1 != 0) {
            env->gr[r1] = (uint64_t)imm14 + env->gr[r3];
        }
    } else {
        r2 = (raw >> 13) & 0x7f;
        immediate = (raw >> 27) & 0x3;

        if (r1 != 0) {
            env->gr[r1] = env->gr[r2] + env->gr[r3] + immediate;
        }
    }
    env->gr[0] = 0;
    return true;
}

bool ia64_slot_is_addl(IA64SlotType type, uint64_t raw)
{
    return (type == IA64_SLOT_TYPE_M || type == IA64_SLOT_TYPE_I) &&
           ia64_slot_major_opcode(raw) == 0x9;
}

int64_t ia64_addl_immediate(uint64_t raw)
{
    uint64_t encoded = (((raw >> 36) & 0x1) << 21) |
                       (((raw >> 22) & 0x1f) << 16) |
                       (((raw >> 27) & 0x1ff) << 7) |
                       ((raw >> 13) & 0x7f);

    return ia64_sign_extend(encoded, 22);
}

bool ia64_exec_addl(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r3;

    if (!env || (!ia64_slot_is_addl(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_addl(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r3 = (raw >> 20) & 0x3;
    if (r1 != 0) {
        env->gr[r1] = (uint64_t)ia64_addl_immediate(raw) + env->gr[r3];
    }
    env->gr[0] = 0;
    return true;
}

bool ia64_decode_ldst_immediate(IA64SlotType type, uint64_t raw,
                                IA64LdstImmediate *decoded)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x6;
    uint8_t memory_class;
    uint8_t size_code;
    bool update_from_register;
    bool update_from_immediate;
    bool load_like;
    bool store_like;

    if (!decoded || type != IA64_SLOT_TYPE_M ||
        (major != 0x4 && major != 0x5)) {
        return false;
    }
    if (major == 0x4 && ((raw >> 27) & 0x1) != 0) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    x6 = (raw >> 30) & 0x3f;
    memory_class = x6 >> 2;
    size_code = x6 & 0x3;
    update_from_register = major == 0x4 && ((raw >> 36) & 0x1) != 0;
    update_from_immediate = major == 0x5;
    load_like = memory_class == 0 || memory_class == 4 || memory_class == 5;
    store_like = memory_class == 0x0c || memory_class == 0x0d;

    decoded->width = 1u << size_code;
    decoded->target = (raw >> 6) & 0x7f;
    decoded->source = (raw >> 13) & 0x7f;
    decoded->base = (raw >> 20) & 0x7f;
    decoded->update_source = decoded->source;
    decoded->memory_class = memory_class;
    decoded->base_update = update_from_register || update_from_immediate;
    decoded->update_from_register = update_from_register;

    if (update_from_immediate) {
        decoded->immediate = ia64_sign_extend((((raw >> 36) & 0x1) << 8) |
                                              (((raw >> 27) & 0x1) << 7) |
                                              ((raw >> 13) & 0x7f), 9);
    }

    if (memory_class == 0x0b) {
        decoded->kind = IA64_LDST_IMM_PREFETCH;
        return true;
    }
    if (load_like) {
        decoded->kind = IA64_LDST_IMM_LOAD;
        return true;
    }
    if (store_like) {
        if (update_from_register) {
            return false;
        }
        decoded->kind = IA64_LDST_IMM_STORE;
        if (update_from_immediate) {
            decoded->immediate =
                ia64_sign_extend((((raw >> 36) & 0x1) << 8) |
                                 (((raw >> 27) & 0x1) << 7) |
                                 ((raw >> 6) & 0x7f), 9);
        }
        return true;
    }

    return false;
}

static IA64CompareRelation ia64_normal_compare_relation(uint8_t major)
{
    switch (major) {
    case 0xc:
        return IA64_CMP_LT;
    case 0xd:
        return IA64_CMP_LTU;
    case 0xe:
        return IA64_CMP_EQ;
    default:
        g_assert_not_reached();
    }
}

static IA64PredicateWriteKind ia64_parallel_compare_write_kind(uint8_t major)
{
    switch (major) {
    case 0xc:
        return IA64_PRED_WRITE_AND;
    case 0xd:
        return IA64_PRED_WRITE_OR;
    case 0xe:
        return IA64_PRED_WRITE_OR_ANDCM;
    default:
        g_assert_not_reached();
    }
}

static IA64CompareRelation ia64_compare_to_zero_relation(uint8_t ta, uint8_t c)
{
    if (ta == 0 && c == 0) {
        return IA64_CMP_GT;
    }
    if (ta == 0 && c == 1) {
        return IA64_CMP_LE;
    }
    if (ta == 1 && c == 0) {
        return IA64_CMP_GE;
    }
    return IA64_CMP_LT;
}

bool ia64_decode_compare(IA64SlotType type, uint64_t raw,
                         IA64CompareInstruction *decoded)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x2;
    uint8_t tb;
    uint8_t ta;
    uint8_t c;
    uint8_t r2;

    if (!decoded || (type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        (major < 0xc || major > 0xe)) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    x2 = (raw >> 34) & 0x3;
    tb = (raw >> 36) & 0x1;
    ta = (raw >> 33) & 0x1;
    c = (raw >> 12) & 0x1;
    r2 = (raw >> 13) & 0x7f;

    decoded->p1 = (raw >> 6) & 0x3f;
    decoded->p2 = (raw >> 27) & 0x3f;
    decoded->source2 = r2;
    decoded->source3 = (raw >> 20) & 0x7f;

    if (x2 == 0 || x2 == 1) {
        decoded->width = x2 == 1 ? 4 : 8;
        if (tb == 0 && ta == 0) {
            decoded->write_kind = c == 0 ? IA64_PRED_WRITE_NORMAL
                                         : IA64_PRED_WRITE_UNCONDITIONAL;
            decoded->relation = ia64_normal_compare_relation(major);
            return true;
        }
        if (tb == 0 && ta == 1) {
            decoded->write_kind = ia64_parallel_compare_write_kind(major);
            decoded->relation = c == 0 ? IA64_CMP_EQ : IA64_CMP_NE;
            return true;
        }
        if (tb == 1 && r2 == 0) {
            decoded->write_kind = ia64_parallel_compare_write_kind(major);
            decoded->relation = ia64_compare_to_zero_relation(ta, c);
            return true;
        }
        return false;
    }

    decoded->width = x2 == 3 ? 4 : 8;
    decoded->source_immediate = true;
    decoded->immediate = ia64_sign_extend(((uint64_t)tb << 7) | r2, 8);
    if (ta == 0) {
        decoded->write_kind = c == 0 ? IA64_PRED_WRITE_NORMAL
                                     : IA64_PRED_WRITE_UNCONDITIONAL;
        decoded->relation = ia64_normal_compare_relation(major);
        return true;
    }
    decoded->write_kind = ia64_parallel_compare_write_kind(major);
    decoded->relation = c == 0 ? IA64_CMP_EQ : IA64_CMP_NE;
    return true;
}

static uint64_t ia64_compare_left_operand(CPUIA64State *env,
                                          const IA64CompareInstruction *decoded)
{
    if (decoded->source_immediate) {
        return (uint64_t)decoded->immediate;
    }
    return env->gr[decoded->source2];
}

static bool ia64_compare_matches(uint64_t left, uint64_t right,
                                 uint8_t width,
                                 IA64CompareRelation relation)
{
    if (width == 4) {
        left = (uint32_t)left;
        right = (uint32_t)right;
    }

    switch (relation) {
    case IA64_CMP_EQ:
        return left == right;
    case IA64_CMP_NE:
        return left != right;
    case IA64_CMP_LT:
        return width == 4 ? (int32_t)left < (int32_t)right
                          : (int64_t)left < (int64_t)right;
    case IA64_CMP_LE:
        return width == 4 ? (int32_t)left <= (int32_t)right
                          : (int64_t)left <= (int64_t)right;
    case IA64_CMP_GT:
        return width == 4 ? (int32_t)left > (int32_t)right
                          : (int64_t)left > (int64_t)right;
    case IA64_CMP_GE:
        return width == 4 ? (int32_t)left >= (int32_t)right
                          : (int64_t)left >= (int64_t)right;
    case IA64_CMP_LTU:
        return left < right;
    case IA64_CMP_LEU:
        return left <= right;
    case IA64_CMP_GTU:
        return left > right;
    case IA64_CMP_GEU:
        return left >= right;
    default:
        g_assert_not_reached();
    }
}

static void ia64_set_predicate(CPUIA64State *env, uint8_t predicate,
                               bool value)
{
    if (predicate == 0) {
        env->pr |= 1;
        return;
    }
    if (value) {
        env->pr |= 1ULL << predicate;
    } else {
        env->pr &= ~(1ULL << predicate);
    }
    env->pr |= 1;
}

bool ia64_exec_compare(CPUIA64State *env,
                       const IA64CompareInstruction *decoded)
{
    uint64_t left;
    uint64_t right;
    bool result;

    if (!env || !decoded || decoded->p1 == decoded->p2) {
        return false;
    }

    left = ia64_compare_left_operand(env, decoded);
    right = env->gr[decoded->source3];
    result = ia64_compare_matches(left, right, decoded->width,
                                  decoded->relation);

    switch (decoded->write_kind) {
    case IA64_PRED_WRITE_AND:
        if (!result) {
            ia64_set_predicate(env, decoded->p1, false);
            ia64_set_predicate(env, decoded->p2, false);
        }
        break;
    case IA64_PRED_WRITE_OR:
        if (result) {
            ia64_set_predicate(env, decoded->p1, true);
            ia64_set_predicate(env, decoded->p2, true);
        }
        break;
    case IA64_PRED_WRITE_OR_ANDCM:
        if (result) {
            ia64_set_predicate(env, decoded->p1, true);
            ia64_set_predicate(env, decoded->p2, false);
        }
        break;
    case IA64_PRED_WRITE_UNCONDITIONAL:
    case IA64_PRED_WRITE_NORMAL:
        ia64_set_predicate(env, decoded->p1, result);
        ia64_set_predicate(env, decoded->p2, !result);
        break;
    default:
        g_assert_not_reached();
    }
    return true;
}

bool ia64_slot_is_b_branch_relative(IA64SlotType type, uint64_t raw)
{
    uint8_t btype = (raw >> 6) & 0x7;

    return type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x4 &&
           btype != 2 && btype != 3 && btype != 5 && btype != 6 &&
           btype != 7;
}

bool ia64_slot_is_b_call_relative(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x5;
}

bool ia64_slot_is_b_indirect_branch(IA64SlotType type, uint64_t raw)
{
    uint8_t x6 = (raw >> 27) & 0x3f;

    return type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x0 &&
           (x6 == 0x20 || x6 == 0x21);
}

bool ia64_slot_is_b_predict_or_nop(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);

    return type == IA64_SLOT_TYPE_B && (major == 0x2 || major == 0x7);
}

int64_t ia64_branch_displacement(uint64_t raw)
{
    uint64_t encoded = (((raw >> 36) & 0x1) << 20) |
                       ((raw >> 13) & ((1ULL << 20) - 1));

    return ia64_sign_extend(encoded, 21) << 4;
}

bool ia64_exec_b_branch_relative(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t bundle_ip,
                                 uint64_t *target_ip)
{
    if (!env || !target_ip ||
        !ia64_slot_is_b_branch_relative(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }

    *target_ip = bundle_ip + ia64_branch_displacement(raw);
    return true;
}

static void ia64_restore_frame_from_pfs(CPUIA64State *env)
{
    env->cfm = env->ar[IA64_AR_PFS];
    env->rse.sof = env->cfm & 0x7f;
    env->rse.sol = (env->cfm >> 7) & 0x7f;
    env->rse.sor = (env->cfm >> 14) & 0x0f;
}

bool ia64_exec_b_call_relative(CPUIA64State *env,
                               uint64_t raw,
                               uint64_t bundle_ip,
                               uint64_t *target_ip)
{
    uint32_t b1;
    uint32_t sof;
    uint32_t sol;
    uint32_t output_count;
    uint64_t old_cfm;

    if (!env || !target_ip ||
        !ia64_slot_is_b_call_relative(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }

    b1 = (raw >> 6) & 0x7;
    old_cfm = env->cfm;
    sof = old_cfm & 0x7f;
    sol = (old_cfm >> 7) & 0x7f;
    output_count = sof >= sol ? sof - sol : 0;

    env->br[b1] = bundle_ip + IA64_BUNDLE_SIZE;
    env->ar[IA64_AR_PFS] = old_cfm;
    env->cfm = ia64_make_cfm(output_count, 0, 0);
    env->rse.sof = output_count;
    env->rse.sol = 0;
    env->rse.sor = 0;
    *target_ip = bundle_ip + ia64_branch_displacement(raw);
    return true;
}

bool ia64_exec_b_indirect_branch(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t *target_ip)
{
    uint8_t x6;
    uint32_t b2;

    if (!env || !target_ip ||
        !ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    b2 = (raw >> 13) & 0x7;
    *target_ip = env->br[b2] & ~0xfULL;
    if (x6 == 0x21) {
        ia64_restore_frame_from_pfs(env);
    }
    return true;
}

static void ia64_exec_smoke_set_message(IA64ExecSmokeReport *report,
                                        const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

static void ia64_exec_smoke_set_message(IA64ExecSmokeReport *report,
                                        const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(report->message, sizeof(report->message), fmt, ap);
    va_end(ap);
}

IA64ExecSmokeStatus
ia64_exec_smoke_bundle(CPUIA64State *env,
                       const uint8_t bundle[IA64_BUNDLE_SIZE],
                       IA64ExecSmokeReport *report)
{
    memset(report, 0, sizeof(*report));
    report->failed_slot = -1;
    report->ip_before = env->ip;
    report->ip_after = env->ip;

    ia64_decode_bundle(bundle, &report->bundle);

    if (!report->bundle.valid) {
        report->status = IA64_EXEC_SMOKE_RESERVED_TEMPLATE;
        ia64_exec_smoke_set_message(
            report,
            "reserved IA-64 template 0x%02x at ip=0x%016" PRIx64,
            report->bundle.tmpl, report->ip_before);
        return report->status;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = report->bundle.info->slot_type[slot];
        uint64_t raw = report->bundle.slot[slot];

        if (!ia64_exec_smoke_slot_supported(type, raw)) {
            report->status = IA64_EXEC_SMOKE_UNSUPPORTED_SLOT;
            report->failed_slot = slot;
            ia64_exec_smoke_set_message(
                report,
                "unsupported IA-64 smoke instruction at ip=0x%016" PRIx64
                " slot=%d type=%s raw=0x%011" PRIx64
                " template=0x%02x %s",
                report->ip_before, slot, ia64_slot_type_name(type), raw,
                report->bundle.tmpl, report->bundle.info->name);
            return report->status;
        }
    }

    env->ip += IA64_BUNDLE_SIZE;
    report->status = IA64_EXEC_SMOKE_OK;
    report->ip_after = env->ip;
    ia64_exec_smoke_set_message(
        report,
        "executed IA-64 smoke NOP bundle at ip=0x%016" PRIx64
        " next=0x%016" PRIx64,
        report->ip_before, report->ip_after);

    return report->status;
}
