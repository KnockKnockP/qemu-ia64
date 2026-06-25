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
    ia64_set_cfm(env, 0);
    env->fr[0].raw[1] = 0x1ffff;
    env->fr[1].raw[0] = 0x8000000000000000ULL;
    env->fr[1].raw[1] = 0xffff;

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

void ia64_set_cfm(CPUIA64State *env, uint64_t cfm)
{
    if (!env) {
        return;
    }

    env->cfm = cfm;
    env->rse.sof = cfm & 0x7f;
    env->rse.sol = (cfm >> 7) & 0x7f;
    env->rse.sor = (cfm >> 14) & 0x0f;
    env->rse.rrb_gr = (cfm >> 18) & 0x7f;
    env->rse.rrb_fr = (cfm >> 25) & 0x7f;
    env->rse.rrb_pr = (cfm >> 32) & 0x3f;
    env->cr[IA64_CR_IFS] = cfm;
}

static uint32_t ia64_stacked_gr_slot(CPUIA64State *env, uint32_t reg)
{
    uint32_t offset = reg - IA64_STATIC_GR_COUNT;
    uint32_t rotating_count = env->rse.sor * 8;
    uint32_t slot;

    if (rotating_count != 0 && offset < rotating_count) {
        offset = (offset + env->rse.rrb_gr) % rotating_count;
    }

    slot = env->rse.current_frame_base + offset;
    return slot % IA64_STACKED_GR_COUNT;
}

uint64_t ia64_read_gr(CPUIA64State *env, uint32_t reg)
{
    if (!env || reg >= IA64_GR_COUNT || reg == 0) {
        return 0;
    }
    if (reg < IA64_STATIC_GR_COUNT) {
        return env->gr[reg];
    }
    return env->rse.stacked_gr[ia64_stacked_gr_slot(env, reg)];
}

void ia64_write_gr(CPUIA64State *env, uint32_t reg, uint64_t value)
{
    if (!env || reg >= IA64_GR_COUNT || reg == 0) {
        if (env) {
            env->gr[0] = 0;
        }
        return;
    }
    if (reg < IA64_STATIC_GR_COUNT) {
        env->gr[reg] = value;
    } else {
        env->rse.stacked_gr[ia64_stacked_gr_slot(env, reg)] = value;
    }
    env->gr[0] = 0;
}

static int64_t ia64_sign_extend(uint64_t value, unsigned bits);

static void ia64_rse_invalidate(CPUIA64State *env, uint32_t first,
                                uint32_t last)
{
    last = MIN(last, (uint32_t)IA64_STACKED_GR_COUNT);
    for (uint32_t slot = first; slot < last; slot++) {
        env->rse.stacked_gr[slot] = 0;
    }
}

static uint32_t ia64_map_fr(CPUIA64State *env, uint32_t reg)
{
    if (reg < 32) {
        return reg;
    }
    return 32 + ((reg - 32 + env->rse.rrb_fr) % (IA64_FR_COUNT - 32));
}

static void ia64_write_fr_parts(CPUIA64State *env, uint32_t reg,
                                bool sign, uint32_t exponent,
                                uint64_t significand)
{
    uint32_t mapped;

    if (!env || reg >= IA64_FR_COUNT || reg < 2) {
        return;
    }

    mapped = ia64_map_fr(env, reg);
    env->fr[mapped].raw[0] = significand;
    env->fr[mapped].raw[1] = (exponent & 0x1ffff) |
                             ((uint64_t)(sign ? 1 : 0) << 17);
}

static uint64_t ia64_read_fr_significand(CPUIA64State *env, uint32_t reg)
{
    if (!env || reg >= IA64_FR_COUNT) {
        return 0;
    }
    return env->fr[ia64_map_fr(env, reg)].raw[0];
}

static void ia64_write_fr_significand(CPUIA64State *env, uint32_t reg,
                                      uint64_t value)
{
    ia64_write_fr_parts(env, reg, false, 0x1003e, value);
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
    uint64_t old_pfs;

    if (!env || !ia64_slot_is_m34_alloc(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    sof = (raw >> 13) & 0x7f;
    sol = (raw >> 20) & 0x7f;
    sor = (raw >> 27) & 0x0f;
    old_cfm = env->cfm;
    old_pfs = env->ar[IA64_AR_PFS];

    if (sof < (old_cfm & 0x7f)) {
        ia64_rse_invalidate(env, env->rse.current_frame_base + sof,
                            env->rse.current_frame_base + (old_cfm & 0x7f));
    }
    ia64_set_cfm(env, ia64_make_cfm(sof, sol, sor));
    ia64_write_gr(env, r1, old_pfs);
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

static bool ia64_slot_is_m_system_x6(IA64SlotType type, uint64_t raw,
                                     uint8_t x6)
{
    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1) {
        return false;
    }
    if (((raw >> 33) & 0x7) != 0) {
        return false;
    }
    return ((raw >> 27) & 0x3f) == x6;
}

static uint64_t ia64_read_ar(CPUIA64State *env, uint32_t reg)
{
    if (!env || reg >= IA64_AR_COUNT) {
        return 0;
    }

    switch (reg) {
    case IA64_AR_RSC:
        return env->rse.rsc;
    case IA64_AR_BSP:
        return env->rse.bsp;
    case IA64_AR_BSPSTORE:
        return env->rse.bspstore;
    case IA64_AR_RNAT:
        return env->rse.rnat;
    case IA64_AR_UNAT:
        return env->nat.unat;
    default:
        return env->ar[reg];
    }
}

static void ia64_write_ar(CPUIA64State *env, uint32_t reg, uint64_t value)
{
    if (!env || reg >= IA64_AR_COUNT) {
        return;
    }

    env->ar[reg] = value;
    switch (reg) {
    case IA64_AR_RSC:
        env->rse.rsc = value;
        break;
    case IA64_AR_BSP:
        env->rse.bsp = value;
        break;
    case IA64_AR_BSPSTORE:
        env->rse.bspstore = value;
        break;
    case IA64_AR_RNAT:
        env->rse.rnat = value;
        env->nat.rnat = value;
        break;
    case IA64_AR_UNAT:
        env->nat.unat = value;
        break;
    default:
        break;
    }
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
    ia64_write_gr(env, r1, bundle_ip);
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
    ia64_write_gr(env, r1, env->br[b2]);
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
    env->br[b1] = ia64_read_gr(env, r2);
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
    ia64_write_gr(env, r1, env->pr | 1);
    return true;
}

bool ia64_slot_is_i_mov_to_predicate(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_I && ia64_slot_major_opcode(raw) == 0x0 &&
           ((raw >> 33) & 0x7) == 3;
}

bool ia64_exec_i_mov_to_predicate(CPUIA64State *env, uint64_t raw)
{
    uint32_t r2;
    uint64_t value;
    uint64_t encoded_mask;
    uint64_t write_mask;

    if (!env || !ia64_slot_is_i_mov_to_predicate(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r2 = (raw >> 13) & 0x7f;
    value = ia64_read_gr(env, r2);
    encoded_mask = (((raw >> 36) & 0x1) << 15) |
                   (((raw >> 25) & 0xff) << 7) |
                   ((raw >> 6) & 0x7f);
    write_mask = (uint64_t)ia64_sign_extend(encoded_mask << 1, 17);
    env->pr = (env->pr & ~write_mask) | (value & write_mask) | 1;
    return true;
}

bool ia64_slot_is_i_mov_to_rotating_predicate_immediate(IA64SlotType type,
                                                        uint64_t raw)
{
    return type == IA64_SLOT_TYPE_I && ia64_slot_major_opcode(raw) == 0x0 &&
           ((raw >> 33) & 0x7) == 2;
}

bool ia64_exec_i_mov_to_rotating_predicate_immediate(CPUIA64State *env,
                                                     uint64_t raw)
{
    uint64_t imm44;

    if (!env ||
        !ia64_slot_is_i_mov_to_rotating_predicate_immediate(IA64_SLOT_TYPE_I,
                                                            raw)) {
        return false;
    }

    imm44 = (((raw >> 36) & 0x1) << 43) | (((raw >> 6) & 0x7ffffff) << 16);
    env->pr = (env->pr & ((1ULL << 16) - 1)) |
              ((uint64_t)ia64_sign_extend(imm44, 44) &
               ~((1ULL << 16) - 1)) | 1;
    return true;
}

bool ia64_slot_is_mov_to_application(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x2a) ||
           ia64_slot_is_m_system_x6(type, raw, 0x2a);
}

bool ia64_exec_mov_to_application(CPUIA64State *env, IA64SlotType type,
                                  uint64_t raw)
{
    uint32_t ar3;
    uint32_t r2;

    if (!env || !ia64_slot_is_mov_to_application(type, raw)) {
        return false;
    }

    ar3 = (raw >> 20) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    ia64_write_ar(env, ar3, ia64_read_gr(env, r2));
    return true;
}

bool ia64_slot_is_mov_from_application(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x32) ||
           ia64_slot_is_m_system_x6(type, raw, 0x22);
}

bool ia64_exec_mov_from_application(CPUIA64State *env, IA64SlotType type,
                                    uint64_t raw)
{
    uint32_t r1;
    uint32_t ar3;

    if (!env || !ia64_slot_is_mov_from_application(type, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    ar3 = (raw >> 20) & 0x7f;
    ia64_write_gr(env, r1, ia64_read_ar(env, ar3));
    return true;
}

bool ia64_slot_is_i_mov_to_application_immediate(IA64SlotType type,
                                                 uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x0a);
}

bool ia64_exec_i_mov_to_application_immediate(CPUIA64State *env,
                                              uint64_t raw)
{
    uint32_t ar3;
    int64_t imm8;

    if (!env ||
        !ia64_slot_is_i_mov_to_application_immediate(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    ar3 = (raw >> 20) & 0x7f;
    imm8 = ia64_sign_extend((((raw >> 36) & 0x1) << 7) |
                            ((raw >> 13) & 0x7f), 8);
    ia64_write_ar(env, ar3, imm8);
    return true;
}

bool ia64_slot_is_m_check_advanced(IA64SlotType type, uint64_t raw)
{
    uint8_t x3;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x0) {
        return false;
    }

    x3 = (raw >> 33) & 0x7;
    return x3 == 4 || x3 == 5;
}

bool ia64_exec_m_check_advanced(CPUIA64State *env, uint64_t raw,
                                uint64_t bundle_ip, uint64_t *target_ip)
{
    if (!env || !target_ip ||
        !ia64_slot_is_m_check_advanced(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    /*
     * The minimal executor does not yet model ALAT allocation or hazards.
     * Treat chk.a/chk.a.clr as a passing check so firmware code that already
     * consumed the loaded value continues through its normal path.
     */
    *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
    return true;
}

bool ia64_slot_is_m_system_noop(IA64SlotType type, uint64_t raw)
{
    uint8_t x2;
    uint8_t x4;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x0 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x2 = (raw >> 31) & 0x3;
    x4 = (raw >> 27) & 0xf;

    if (x2 == 1 && x4 == 0) {
        return true;
    }
    if (x2 == 0 && (x4 == 0x0a || x4 == 0x0c)) {
        return true;
    }
    if (x2 == 2 && (x4 == 0 || x4 == 2 || x4 == 3)) {
        return true;
    }
    if (x2 == 3 && (x4 == 0 || x4 == 1 || x4 == 3)) {
        return true;
    }
    if (x2 == 0 && x4 == 1) {
        uint8_t y = (raw >> 26) & 0x1;
        uint8_t z = (raw >> 10) & 0x3;

        return y == 0 || z == 0;
    }

    return false;
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
    ia64_write_gr(env, r1, ia64_lx_movl_imm64(l_raw, x_raw));
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

        ia64_write_gr(env, r1, (uint64_t)imm14 + ia64_read_gr(env, r3));
    } else {
        r2 = (raw >> 13) & 0x7f;
        immediate = (raw >> 27) & 0x3;

        ia64_write_gr(env, r1,
                      ia64_read_gr(env, r2) + ia64_read_gr(env, r3) +
                      immediate);
    }
    env->gr[0] = 0;
    return true;
}

bool ia64_slot_is_alu_sub(IA64SlotType type, uint64_t raw)
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

    return ve == 0 && x2a == 0 && x4 == 1 && x2b <= 1;
}

bool ia64_exec_alu_sub(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2b;
    uint8_t immediate;

    if (!env || (!ia64_slot_is_alu_sub(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_sub(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2b = (raw >> 27) & 0x3;
    immediate = x2b == 0 ? 1 : 0;

    ia64_write_gr(env, r1,
                  ia64_read_gr(env, r2) - ia64_read_gr(env, r3) -
                  immediate);
    env->gr[0] = 0;
    return true;
}

bool ia64_slot_is_alu_logic(IA64SlotType type, uint64_t raw)
{
    uint8_t ve;
    uint8_t x2a;
    uint8_t x4;

    if ((type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    ve = (raw >> 33) & 0x1;
    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    return ve == 0 && x2a == 0 && (x4 == 3 || x4 == 0xb);
}

bool ia64_exec_alu_logic(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2b;
    uint8_t x4;
    uint64_t source2;
    uint64_t source3;
    uint64_t result;

    if (!env || (!ia64_slot_is_alu_logic(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_logic(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2b = (raw >> 27) & 0x3;
    x4 = (raw >> 29) & 0xf;
    source2 = x4 == 0xb
        ? (uint64_t)ia64_sign_extend((((raw >> 36) & 0x1) << 7) |
                                     ((raw >> 13) & 0x7f), 8)
        : ia64_read_gr(env, r2);
    source3 = ia64_read_gr(env, r3);

    switch (x2b) {
    case 0:
        result = source2 & source3;
        break;
    case 1:
        result = source2 & ~source3;
        break;
    case 2:
        result = source2 | source3;
        break;
    case 3:
        result = source2 ^ source3;
        break;
    default:
        g_assert_not_reached();
    }

    ia64_write_gr(env, r1, result);
    return true;
}

static uint64_t ia64_addp4(uint64_t left, uint64_t right)
{
    uint64_t low32 = (left + right) & UINT32_MAX;
    uint64_t region = ((right >> 30) & 0x3ULL) << 61;

    return region | low32;
}

bool ia64_slot_is_alu_addp4(IA64SlotType type, uint64_t raw)
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
    return ve == 0 && ((x2a == 0 && x4 == 2 && x2b == 0) || x2a == 3);
}

bool ia64_exec_alu_addp4(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2a;
    uint64_t source2;
    uint64_t source3;

    if (!env || (!ia64_slot_is_alu_addp4(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_addp4(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2a = (raw >> 34) & 0x3;
    source2 = x2a == 3
        ? (uint64_t)ia64_sign_extend((((raw >> 36) & 0x1) << 13) |
                                     (((raw >> 27) & 0x3f) << 7) |
                                     ((raw >> 13) & 0x7f), 14)
        : ia64_read_gr(env, r2);
    source3 = ia64_read_gr(env, r3);

    ia64_write_gr(env, r1, ia64_addp4(source2, source3));
    return true;
}

bool ia64_slot_is_alu_shladd(IA64SlotType type, uint64_t raw)
{
    uint8_t ve;
    uint8_t x2a;
    uint8_t x4;

    if ((type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    ve = (raw >> 33) & 0x1;
    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    return ve == 0 && x2a == 0 && (x4 == 4 || x4 == 6);
}

bool ia64_exec_alu_shladd(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2b;
    uint8_t x4;
    uint64_t shifted;
    uint64_t addend;

    if (!env || (!ia64_slot_is_alu_shladd(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_shladd(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2b = (raw >> 27) & 0x3;
    x4 = (raw >> 29) & 0xf;
    shifted = ia64_read_gr(env, r2) << (x2b + 1);
    addend = ia64_read_gr(env, r3);

    ia64_write_gr(env, r1, x4 == 6
                  ? ia64_addp4(shifted, addend)
                  : shifted + addend);
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
    ia64_write_gr(env, r1,
                  (uint64_t)ia64_addl_immediate(raw) +
                  ia64_read_gr(env, r3));
    env->gr[0] = 0;
    return true;
}

bool ia64_slot_is_m_setf(IA64SlotType type, uint64_t raw)
{
    uint8_t x6;
    uint8_t memory_class;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x6) {
        return false;
    }
    if (((raw >> 27) & 0x1) == 0 || ((raw >> 36) & 0x1) != 0) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    memory_class = x6 >> 2;
    return memory_class == 7;
}

bool ia64_exec_m_setf(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint8_t format;
    uint32_t f1;
    uint32_t r2;
    uint64_t value;

    if (!env || !ia64_slot_is_m_setf(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    format = x6 & 0x3;
    f1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    value = ia64_read_gr(env, r2);

    switch (format) {
    case 0:
        ia64_write_fr_parts(env, f1, false, 0x1003e, value);
        return true;
    default:
        return false;
    }
}

bool ia64_slot_is_m_getf(IA64SlotType type, uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x4) {
        return false;
    }
    if (((raw >> 27) & 0x1) == 0) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    return x6 >= 0x1c && x6 <= 0x1f;
}

bool ia64_exec_m_getf(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint8_t format;
    uint32_t r1;
    uint32_t f2;
    uint32_t mapped;
    uint64_t value;

    if (!env || !ia64_slot_is_m_getf(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    format = x6 & 0x3;
    r1 = (raw >> 6) & 0x7f;
    f2 = (raw >> 13) & 0x7f;
    mapped = ia64_map_fr(env, f2);

    switch (format) {
    case 0:
        value = env->fr[mapped].raw[0];
        break;
    case 1:
        value = env->fr[mapped].raw[1] & 0x3ffff;
        break;
    default:
        return false;
    }

    ia64_write_gr(env, r1, value);
    return true;
}

static bool ia64_floating_memory_format(uint8_t size_code,
                                        uint8_t memory_class,
                                        IA64FloatingMemoryFormat *format,
                                        uint8_t *width)
{
    if (memory_class == 6 || memory_class == 0x0e) {
        *format = IA64_FLOAT_FMT_SPILL_FILL;
        *width = 16;
        return true;
    }

    switch (size_code) {
    case 0:
        *format = IA64_FLOAT_FMT_EXTENDED;
        *width = 16;
        return true;
    case 1:
        *format = IA64_FLOAT_FMT_SIGNIFICAND;
        *width = 8;
        return true;
    case 2:
        *format = IA64_FLOAT_FMT_SINGLE;
        *width = 4;
        return true;
    case 3:
        *format = IA64_FLOAT_FMT_DOUBLE;
        *width = 8;
        return true;
    default:
        return false;
    }
}

bool ia64_decode_floating_memory(IA64SlotType type, uint64_t raw,
                                 IA64FloatingMemoryInstruction *decoded)
{
    uint8_t major;
    uint8_t x6;
    uint8_t memory_class;
    uint8_t size_code;
    uint8_t width;
    IA64FloatingMemoryFormat format;
    bool base_update_with_register;
    bool base_update_with_immediate;

    if (!decoded || type != IA64_SLOT_TYPE_M) {
        return false;
    }

    major = ia64_slot_major_opcode(raw);
    if (major != 0x6 && major != 0x7) {
        return false;
    }
    if (major == 0x6 && ((raw >> 27) & 0x1) != 0) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    memory_class = x6 >> 2;
    size_code = x6 & 0x3;
    if (!ia64_floating_memory_format(size_code, memory_class,
                                     &format, &width)) {
        return false;
    }

    base_update_with_register = major == 0x6 && ((raw >> 36) & 0x1) != 0;
    base_update_with_immediate = major == 0x7;
    memset(decoded, 0, sizeof(*decoded));
    decoded->format = format;
    decoded->width = width;
    decoded->base = (raw >> 20) & 0x7f;
    decoded->memory_class = memory_class;
    decoded->base_update =
        base_update_with_register || base_update_with_immediate;
    decoded->update_from_register = base_update_with_register;

    if (base_update_with_immediate) {
        decoded->immediate = ia64_sign_extend(
            (((raw >> 36) & 0x1) << 8) |
            (((raw >> 27) & 0x1) << 7) |
            ((raw >> 13) & 0x7f),
            9);
    } else {
        decoded->update_source = (raw >> 13) & 0x7f;
    }

    if (memory_class == 0x0c || memory_class == 0x0e) {
        decoded->kind = IA64_FLOAT_MEM_STORE;
        decoded->freg = (raw >> 13) & 0x7f;
    } else if (memory_class == 0 || memory_class == 1 ||
               memory_class == 2 || memory_class == 3 ||
               memory_class == 6 || memory_class == 8 ||
               memory_class == 9) {
        decoded->kind = IA64_FLOAT_MEM_LOAD;
        decoded->freg = (raw >> 6) & 0x7f;
    } else {
        return false;
    }

    return true;
}

static uint64_t ia64_bit_mask(unsigned bits)
{
    return bits >= 64 ? UINT64_MAX : ((1ULL << bits) - 1);
}

bool ia64_decode_extract(IA64SlotType type, uint64_t raw,
                         IA64ExtractInstruction *decoded)
{
    uint8_t x2;
    uint8_t x;

    if (!decoded || type != IA64_SLOT_TYPE_I ||
        ia64_slot_major_opcode(raw) != 0x5) {
        return false;
    }

    x2 = (raw >> 34) & 0x3;
    x = (raw >> 33) & 0x1;
    if (x2 != 1 || x != 0) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    decoded->target = (raw >> 6) & 0x7f;
    decoded->source3 = (raw >> 20) & 0x7f;
    decoded->position = (raw >> 14) & 0x3f;
    decoded->length = ((raw >> 27) & 0x3f) + 1;
    decoded->sign_extend = ((raw >> 13) & 0x1) != 0;
    return true;
}

bool ia64_exec_extract(CPUIA64State *env,
                       const IA64ExtractInstruction *decoded)
{
    uint8_t length;
    uint64_t value;
    uint64_t result;

    if (!env || !decoded || decoded->position >= 64) {
        return false;
    }

    length = MIN((uint8_t)(64 - decoded->position), decoded->length);
    value = ia64_read_gr(env, decoded->source3) >> decoded->position;
    result = value & ia64_bit_mask(length);
    if (decoded->sign_extend && length != 0 &&
        (result & (1ULL << (length - 1))) != 0) {
        result |= ~ia64_bit_mask(length);
    }

    ia64_write_gr(env, decoded->target, result);
    return true;
}

bool ia64_decode_integer_extend(IA64SlotType type, uint64_t raw,
                                IA64IntegerExtendInstruction *decoded)
{
    uint8_t x6;

    if (!decoded || type != IA64_SLOT_TYPE_I ||
        ia64_slot_major_opcode(raw) != 0x0 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    memset(decoded, 0, sizeof(*decoded));
    decoded->target = (raw >> 6) & 0x7f;
    decoded->source3 = (raw >> 20) & 0x7f;

    switch (x6) {
    case 0x10:
    case 0x11:
    case 0x12:
        decoded->kind = IA64_EXT_ZXT;
        decoded->width = x6 == 0x10 ? 1 : x6 == 0x11 ? 2 : 4;
        return true;
    case 0x14:
    case 0x15:
    case 0x16:
        decoded->kind = IA64_EXT_SXT;
        decoded->width = x6 == 0x14 ? 1 : x6 == 0x15 ? 2 : 4;
        return true;
    case 0x18:
    case 0x19:
        decoded->kind = IA64_EXT_CZX_LEFT;
        decoded->width = x6 == 0x18 ? 1 : 2;
        return true;
    case 0x1c:
    case 0x1d:
        decoded->kind = IA64_EXT_CZX_RIGHT;
        decoded->width = x6 == 0x1c ? 1 : 2;
        return true;
    default:
        return false;
    }
}

static uint64_t ia64_compute_zero_index(uint64_t value, uint8_t width,
                                        bool from_left)
{
    unsigned element_bits = width * 8;
    unsigned elements = 8 / width;
    uint64_t mask = ia64_bit_mask(element_bits);

    for (unsigned index = 0; index < elements; index++) {
        unsigned lane = from_left ? elements - index - 1 : index;
        if (((value >> (lane * element_bits)) & mask) == 0) {
            return index;
        }
    }

    return elements;
}

bool ia64_exec_integer_extend(CPUIA64State *env,
                              const IA64IntegerExtendInstruction *decoded)
{
    uint64_t value;
    uint64_t result;

    if (!env || !decoded || decoded->width == 0) {
        return false;
    }

    value = ia64_read_gr(env, decoded->source3);
    switch (decoded->kind) {
    case IA64_EXT_ZXT:
        result = value & ia64_bit_mask(decoded->width * 8);
        break;
    case IA64_EXT_SXT:
        result = (uint64_t)ia64_sign_extend(value, decoded->width * 8);
        break;
    case IA64_EXT_CZX_LEFT:
        result = ia64_compute_zero_index(value, decoded->width, true);
        break;
    case IA64_EXT_CZX_RIGHT:
        result = ia64_compute_zero_index(value, decoded->width, false);
        break;
    default:
        return false;
    }

    ia64_write_gr(env, decoded->target, result);
    return true;
}

bool ia64_slot_is_f_select_or_xma(IA64SlotType type, uint64_t raw)
{
    uint8_t x;
    uint8_t x2;

    if (type != IA64_SLOT_TYPE_F || ia64_slot_major_opcode(raw) != 0xe) {
        return false;
    }

    x = (raw >> 36) & 0x1;
    x2 = (raw >> 34) & 0x3;
    return x == 0 || x2 == 0 || x2 == 2 || x2 == 3;
}

bool ia64_slot_is_f_multiply_add(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);

    return type == IA64_SLOT_TYPE_F && major >= 0x8 && major <= 0xd;
}

static void ia64_copy_fr(CPUIA64State *env, uint32_t target, uint32_t source)
{
    uint32_t mapped_target;
    uint32_t mapped_source;

    if (!env || target >= IA64_FR_COUNT || source >= IA64_FR_COUNT ||
        target < 2) {
        return;
    }

    mapped_target = ia64_map_fr(env, target);
    mapped_source = ia64_map_fr(env, source);
    env->fr[mapped_target] = env->fr[mapped_source];
}

bool ia64_exec_f_multiply_add(CPUIA64State *env, uint64_t raw)
{
    uint8_t major;
    uint32_t f1;
    uint32_t f2;
    uint32_t f3;
    uint32_t f4;
    uint64_t source2;
    uint64_t source3;
    uint64_t source4;
    uint64_t result;

    if (!env || !ia64_slot_is_f_multiply_add(IA64_SLOT_TYPE_F, raw)) {
        return false;
    }

    major = ia64_slot_major_opcode(raw);
    f1 = (raw >> 6) & 0x7f;
    f2 = (raw >> 13) & 0x7f;
    f3 = (raw >> 20) & 0x7f;
    f4 = (raw >> 27) & 0x7f;

    if ((major == 0x8 || major == 0x9) && (f2 == 0 || f3 == 0)) {
        ia64_copy_fr(env, f1, f4);
        return true;
    }

    source2 = ia64_read_fr_significand(env, f2);
    source3 = ia64_read_fr_significand(env, f3);
    source4 = ia64_read_fr_significand(env, f4);

    switch (major) {
    case 0x8:
    case 0x9:
        result = (uint64_t)((__int128)(int64_t)source2 *
                            (__int128)(int64_t)source3 + source4);
        break;
    case 0x0a:
    case 0x0b:
        result = (uint64_t)((__int128)(int64_t)source2 *
                            (__int128)(int64_t)source3 - source4);
        break;
    case 0x0c:
    case 0x0d:
        result = (uint64_t)(-((__int128)(int64_t)source2 *
                              (__int128)(int64_t)source3) + source4);
        break;
    default:
        return false;
    }

    ia64_write_fr_significand(env, f1, result);
    return true;
}

bool ia64_slot_is_f_reciprocal_approx(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);

    if (type != IA64_SLOT_TYPE_F || (major != 0x0 && major != 0x1)) {
        return false;
    }

    return ((raw >> 33) & 0x1) != 0;
}

bool ia64_exec_f_reciprocal_approx(CPUIA64State *env, uint64_t raw)
{
    uint32_t f1;
    uint32_t f2;
    uint32_t f3;
    uint8_t p2;
    bool q;
    bool denominator_nonzero;

    if (!env || !ia64_slot_is_f_reciprocal_approx(IA64_SLOT_TYPE_F, raw)) {
        return false;
    }

    f1 = (raw >> 6) & 0x7f;
    q = ((raw >> 36) & 0x1) != 0;
    f2 = q ? 1 : (raw >> 13) & 0x7f;
    f3 = (raw >> 20) & 0x7f;
    p2 = (raw >> 27) & 0x3f;
    denominator_nonzero = ia64_read_fr_significand(env, f3) != 0;

    if (denominator_nonzero) {
        ia64_copy_fr(env, f1, f2);
        if (p2 != 0) {
            env->pr |= 1ULL << p2;
        }
    } else if (p2 != 0) {
        env->pr &= ~(1ULL << p2);
    }
    env->pr |= 1;
    return true;
}

bool ia64_slot_is_f_misc(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x;
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_F || major != 0x0) {
        return false;
    }

    x = (raw >> 33) & 0x1;
    x6 = (raw >> 27) & 0x3f;
    if (x != 0) {
        return false;
    }

    return (x6 >= 0x10 && x6 <= 0x12) ||
           (x6 >= 0x18 && x6 <= 0x1c);
}

bool ia64_exec_f_misc(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint32_t f1;
    uint32_t f2;
    uint32_t f3;
    uint32_t target;
    uint32_t source2;
    uint32_t source3;
    bool sign;
    uint64_t exponent;

    if (!env || !ia64_slot_is_f_misc(IA64_SLOT_TYPE_F, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    f1 = (raw >> 6) & 0x7f;
    f2 = (raw >> 13) & 0x7f;
    f3 = (raw >> 20) & 0x7f;

    if (x6 >= 0x18 && x6 <= 0x1c) {
        ia64_copy_fr(env, f1, f2);
        return true;
    }

    if (f1 >= IA64_FR_COUNT || f1 < 2 ||
        f2 >= IA64_FR_COUNT || f3 >= IA64_FR_COUNT) {
        return true;
    }

    target = ia64_map_fr(env, f1);
    source2 = ia64_map_fr(env, f2);
    source3 = ia64_map_fr(env, f3);
    sign = (env->fr[source2].raw[1] >> 17) & 1;
    if (x6 == 0x11) {
        sign = !sign;
    }
    exponent = x6 == 0x12
        ? env->fr[source2].raw[1] & 0x1ffff
        : env->fr[source3].raw[1] & 0x1ffff;

    env->fr[target].raw[0] = env->fr[source3].raw[0];
    env->fr[target].raw[1] = exponent | ((uint64_t)sign << 17);
    return true;
}

bool ia64_exec_f_select_or_xma(CPUIA64State *env, uint64_t raw)
{
    uint8_t x;
    uint8_t x2;
    uint32_t f1;
    uint32_t f2;
    uint32_t f3;
    uint32_t f4;
    uint64_t source2;
    uint64_t source3;
    uint64_t source4;
    uint64_t result;

    if (!env || !ia64_slot_is_f_select_or_xma(IA64_SLOT_TYPE_F, raw)) {
        return false;
    }

    x = (raw >> 36) & 0x1;
    x2 = (raw >> 34) & 0x3;
    f1 = (raw >> 6) & 0x7f;
    f2 = (raw >> 13) & 0x7f;
    f3 = (raw >> 20) & 0x7f;
    f4 = (raw >> 27) & 0x7f;
    source2 = ia64_read_fr_significand(env, f2);
    source3 = ia64_read_fr_significand(env, f3);
    source4 = ia64_read_fr_significand(env, f4);

    if (x == 0) {
        result = (source3 & source2) | (source4 & ~source2);
    } else if (x2 == 0) {
        __int128 product =
            (__int128)(int64_t)source3 * (__int128)(int64_t)source4;
        result = (uint64_t)(product + source2);
    } else if (x2 == 2) {
        unsigned __int128 product =
            (unsigned __int128)source3 * (unsigned __int128)source4;
        result = (uint64_t)((product + source2) >> 64);
    } else {
        __int128 product =
            (__int128)(int64_t)source3 * (__int128)(int64_t)source4;
        result = (uint64_t)((product + source2) >> 64);
    }

    ia64_write_fr_significand(env, f1, result);
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
    load_like = memory_class == 0 || memory_class == 1 ||
                memory_class == 2 || memory_class == 3 ||
                memory_class == 4 || memory_class == 5 ||
                memory_class == 6 || memory_class == 8 ||
                memory_class == 9 || memory_class == 0x0a;
    store_like = memory_class == 0x0c || memory_class == 0x0d ||
                 (memory_class == 0x0e && size_code == 3);

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
    return ia64_read_gr(env, decoded->source2);
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
    right = ia64_read_gr(env, decoded->source3);
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
    return type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x4;
}

bool ia64_slot_is_b_call_relative(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x5;
}

bool ia64_slot_is_b_indirect_branch(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x6 = (raw >> 27) & 0x3f;

    return type == IA64_SLOT_TYPE_B &&
           (major == 0x1 || (major == 0x0 && (x6 == 0x20 || x6 == 0x21)));
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

static void ia64_set_loop_predicate_63(CPUIA64State *env, bool value)
{
    if (value) {
        env->pr |= 1ULL << 63;
    } else {
        env->pr &= ~(1ULL << 63);
    }
    env->pr |= 1;
}

static void ia64_update_cfm_rename_bases(CPUIA64State *env)
{
    env->cfm = (env->cfm & ~((((1ULL << 7) - 1) << 18) |
                             (((1ULL << 7) - 1) << 25) |
                             (((1ULL << 6) - 1) << 32))) |
               ((uint64_t)(env->rse.rrb_gr & 0x7f) << 18) |
               ((uint64_t)(env->rse.rrb_fr & 0x7f) << 25) |
               ((uint64_t)(env->rse.rrb_pr & 0x3f) << 32);
    env->cr[IA64_CR_IFS] = env->cfm;
}

static void ia64_rotate_modulo_scheduled_registers(CPUIA64State *env)
{
    uint32_t rotating_gr_count = env->rse.sor * 8;

    if (rotating_gr_count != 0) {
        env->rse.rrb_gr =
            (env->rse.rrb_gr + rotating_gr_count - 1) % rotating_gr_count;
    }
    env->rse.rrb_fr = (env->rse.rrb_fr + 95) % 96;
    env->rse.rrb_pr = (env->rse.rrb_pr + 47) % 48;
    ia64_update_cfm_rename_bases(env);
}

bool ia64_exec_b_branch_relative(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t bundle_ip,
                                 uint64_t *target_ip)
{
    uint8_t btype;
    int64_t displacement;
    bool taken = true;

    if (!env || !target_ip ||
        !ia64_slot_is_b_branch_relative(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }

    btype = (raw >> 6) & 0x7;
    displacement = ia64_branch_displacement(raw);

    switch (btype) {
    case 2:
    case 3:
    {
        uint8_t qp = raw & 0x3f;
        bool qualifying_predicate =
            qp == 0 || (env->pr & (1ULL << qp)) != 0;
        uint64_t epilog_count = ia64_read_ar(env, IA64_AR_EC);
        bool continue_loop;

        if (qualifying_predicate) {
            ia64_set_loop_predicate_63(env, false);
            ia64_rotate_modulo_scheduled_registers(env);
        } else if (epilog_count != 0) {
            ia64_write_ar(env, IA64_AR_EC, epilog_count - 1);
            ia64_set_loop_predicate_63(env, false);
            ia64_rotate_modulo_scheduled_registers(env);
        } else {
            ia64_set_loop_predicate_63(env, false);
        }

        continue_loop = qualifying_predicate || epilog_count > 1;
        taken = btype == 3 ? continue_loop : !continue_loop;
        break;
    }
    case 5:
    {
        uint64_t loop_count = ia64_read_ar(env, IA64_AR_LC);

        taken = loop_count != 0;
        if (taken) {
            ia64_write_ar(env, IA64_AR_LC, loop_count - 1);
        }
        break;
    }
    case 6:
    case 7:
    {
        uint64_t loop_count = ia64_read_ar(env, IA64_AR_LC);
        uint64_t epilog_count = ia64_read_ar(env, IA64_AR_EC);
        bool active = loop_count != 0 || epilog_count > 1;

        if (loop_count != 0) {
            ia64_write_ar(env, IA64_AR_LC, loop_count - 1);
            ia64_set_loop_predicate_63(env, true);
            ia64_rotate_modulo_scheduled_registers(env);
        } else if (epilog_count != 0) {
            ia64_write_ar(env, IA64_AR_EC, epilog_count - 1);
            ia64_set_loop_predicate_63(env, false);
            ia64_rotate_modulo_scheduled_registers(env);
        } else {
            ia64_set_loop_predicate_63(env, false);
        }

        taken = btype == 7 ? active : !active;
        break;
    }
    default:
        break;
    }

    if (taken) {
        *target_ip = bundle_ip + displacement;
    } else {
        *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
    }
    return true;
}

static uint32_t ia64_cfm_sof(uint64_t cfm)
{
    return cfm & 0x7f;
}

static uint32_t ia64_cfm_sol(uint64_t cfm)
{
    return (cfm >> 7) & 0x7f;
}

static void ia64_enter_call_frame(CPUIA64State *env)
{
    uint64_t caller_cfm = env->cfm;
    uint32_t caller_sof = ia64_cfm_sof(caller_cfm);
    uint32_t caller_sol = ia64_cfm_sol(caller_cfm);
    uint32_t output_count = caller_sof >= caller_sol
        ? caller_sof - caller_sol
        : 0;

    env->ar[IA64_AR_PFS] = caller_cfm;
    env->rse.current_frame_base =
        (env->rse.current_frame_base + caller_sol) % IA64_STACKED_GR_COUNT;
    ia64_set_cfm(env, ia64_make_cfm(output_count, 0, 0));
}

static void ia64_restore_frame_from_pfs(CPUIA64State *env)
{
    uint64_t restored_cfm = env->ar[IA64_AR_PFS] & ((1ULL << 38) - 1);
    uint32_t restored_sof = ia64_cfm_sof(restored_cfm);
    uint32_t restored_sol = ia64_cfm_sol(restored_cfm);
    uint32_t caller_base = env->rse.current_frame_base >= restored_sol
        ? env->rse.current_frame_base - restored_sol
        : 0;

    ia64_rse_invalidate(env, caller_base + restored_sof,
                        env->rse.current_frame_base + 96);
    env->rse.current_frame_base = caller_base;
    ia64_set_cfm(env, restored_cfm);
}

bool ia64_return_from_call_frame(CPUIA64State *env, uint64_t target_ip)
{
    if (!env) {
        return false;
    }

    ia64_restore_frame_from_pfs(env);
    env->ip = target_ip & ~0xfULL;
    env->cr[IA64_CR_IIP] = env->ip;
    return true;
}

bool ia64_exec_b_call_relative(CPUIA64State *env,
                               uint64_t raw,
                               uint64_t bundle_ip,
                               uint64_t *target_ip)
{
    uint32_t b1;

    if (!env || !target_ip ||
        !ia64_slot_is_b_call_relative(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }

    b1 = (raw >> 6) & 0x7;
    env->br[b1] = bundle_ip + IA64_BUNDLE_SIZE;
    ia64_enter_call_frame(env);
    *target_ip = bundle_ip + ia64_branch_displacement(raw);
    return true;
}

bool ia64_exec_b_indirect_branch(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t bundle_ip,
                                 uint64_t *target_ip)
{
    uint8_t major;
    uint8_t x6;
    uint32_t b1;
    uint32_t b2;

    if (!env || !target_ip ||
        !ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }

    major = ia64_slot_major_opcode(raw);
    x6 = (raw >> 27) & 0x3f;
    b1 = (raw >> 6) & 0x7;
    b2 = (raw >> 13) & 0x7;
    *target_ip = env->br[b2] & ~0xfULL;
    if (major == 0x1) {
        env->br[b1] = bundle_ip + IA64_BUNDLE_SIZE;
        ia64_enter_call_frame(env);
    } else if (x6 == 0x21) {
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
