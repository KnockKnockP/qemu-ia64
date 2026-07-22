/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "insn.h"
#include "machine-check.h"

#define IA64_INTERRUPT_VECTOR_MASK UINT64_C(0xff)
#define IA64_LOCAL_VECTOR_MASK_BIT UINT64_C(0x0000000000010000)
#define IA64_RSC_IMPLEMENTED_MASK \
    (UINT64_C(0x1f) | (UINT64_C(0x3fff) << IA64_RSC_LOADRS_SHIFT))

#define IA64_PSP_MULTIPLE_ERROR_BIT (UINT64_C(1) << 4)
#define IA64_PSP_MIN_STATE_BIT (UINT64_C(1) << 5)
#define IA64_PSP_SYNCHRONIZED_BIT (UINT64_C(1) << 6)
#define IA64_PSP_CONTINUABLE_BIT (UINT64_C(1) << 7)
#define IA64_PSP_ISOLATED_BIT (UINT64_C(1) << 8)
#define IA64_PSP_PRECISE_IP_BIT (UINT64_C(1) << 13)
#define IA64_PSP_PRECISE_MIN_STATE_BIT (UINT64_C(1) << 14)
#define IA64_PSP_RSE_VALID_BIT (UINT64_C(1) << 17)
#define IA64_PSP_CR_VALID_BIT (UINT64_C(1) << 20)
#define IA64_PSP_PC_VALID_BIT (UINT64_C(1) << 21)
#define IA64_PSP_DR_VALID_BIT (UINT64_C(1) << 22)
#define IA64_PSP_TR_VALID_BIT (UINT64_C(1) << 23)
#define IA64_PSP_RR_VALID_BIT (UINT64_C(1) << 24)
#define IA64_PSP_AR_VALID_BIT (UINT64_C(1) << 25)
#define IA64_PSP_BR_VALID_BIT (UINT64_C(1) << 26)
#define IA64_PSP_PR_VALID_BIT (UINT64_C(1) << 27)
#define IA64_PSP_FR_VALID_BIT (UINT64_C(1) << 28)
#define IA64_PSP_BANK1_VALID_BIT (UINT64_C(1) << 29)
#define IA64_PSP_BANK0_VALID_BIT (UINT64_C(1) << 30)
#define IA64_PSP_GR_VALID_BIT (UINT64_C(1) << 31)
#define IA64_PSP_TLB_CHECK_BIT (UINT64_C(1) << 60)

static uint64_t ia64_machine_check_processor_state_parameter(
    const CPUIA64State *env, IA64MachineCheckCause cause)
{
    uint64_t psp = IA64_PSP_SYNCHRONIZED_BIT |
                   IA64_PSP_ISOLATED_BIT |
                   IA64_PSP_PRECISE_IP_BIT |
                   IA64_PSP_RSE_VALID_BIT |
                   IA64_PSP_CR_VALID_BIT |
                   IA64_PSP_PC_VALID_BIT |
                   IA64_PSP_DR_VALID_BIT |
                   IA64_PSP_TR_VALID_BIT |
                   IA64_PSP_RR_VALID_BIT |
                   IA64_PSP_AR_VALID_BIT |
                   IA64_PSP_BR_VALID_BIT |
                   IA64_PSP_PR_VALID_BIT |
                   IA64_PSP_FR_VALID_BIT |
                   IA64_PSP_BANK1_VALID_BIT |
                   IA64_PSP_BANK0_VALID_BIT |
                   IA64_PSP_GR_VALID_BIT;

    if (env->machine_check.registered) {
        psp |= IA64_PSP_MIN_STATE_BIT |
               IA64_PSP_CONTINUABLE_BIT |
               IA64_PSP_PRECISE_MIN_STATE_BIT;
    }
    if (cause == IA64_MACHINE_CHECK_TRANSLATION_OVERLAP) {
        psp |= IA64_PSP_TLB_CHECK_BIT;
    }
    return psp;
}

static uint64_t ia64_machine_check_nat_word(const CPUIA64State *env)
{
    const uint64_t bank_mask = UINT64_C(0x00000000ffff0000);
    uint64_t visible = env->nat.gr_nat[0];
    uint64_t inactive = env->nat.gr_nat[1];
    uint64_t bank0;
    uint64_t bank1;

    if (ia64_env_psr((CPUIA64State *)env) & IA64_PSR_BN_BIT) {
        bank0 = inactive & bank_mask;
        bank1 = visible & bank_mask;
    } else {
        bank0 = visible & bank_mask;
        bank1 = inactive & bank_mask;
    }
    return (visible & UINT64_C(0x000000000000fffe)) |
           bank0 | ((bank1 & bank_mask) << 16);
}

static void ia64_machine_check_capture_min_state(CPUIA64State *env)
{
    uint64_t *image = env->machine_check.min_state;
    uint64_t psr = ia64_env_psr(env);
    uint64_t ifs = (env->cfm & IA64_CFM_MASK) | IA64_IFS_VALID_BIT;

    memset(image, 0, sizeof(env->machine_check.min_state));
    image[IA64_MIN_STATE_NAT] = ia64_machine_check_nat_word(env);
    for (unsigned reg = 1; reg <= 15; reg++) {
        image[IA64_MIN_STATE_GR1 + reg - 1] = env->gr[reg];
    }
    for (unsigned reg = 0; reg < 16; reg++) {
        image[IA64_MIN_STATE_BANK0_GR16 + reg] = env->gr[16 + reg];
        image[IA64_MIN_STATE_BANK1_GR16 + reg] = env->banked_gr[reg];
    }
    image[IA64_MIN_STATE_PR] = env->pr;
    image[IA64_MIN_STATE_BR0] = env->br[0];
    image[IA64_MIN_STATE_RSC] = ia64_read_application_register(
        env, IA64_AR_RSC);
    image[IA64_MIN_STATE_IIP] = env->ip;
    image[IA64_MIN_STATE_IPSR] = psr;
    image[IA64_MIN_STATE_IFS] = ifs;
    if (psr & IA64_PSR_IC_BIT) {
        image[IA64_MIN_STATE_XIP] = env->ip;
        image[IA64_MIN_STATE_XPSR] = psr;
        image[IA64_MIN_STATE_XFS] = ifs;
    } else {
        image[IA64_MIN_STATE_XIP] = env->cr[IA64_CR_IIP];
        image[IA64_MIN_STATE_XPSR] = env->cr[IA64_CR_IPSR];
        image[IA64_MIN_STATE_XFS] = env->cr[IA64_CR_IFS];
    }
    image[IA64_MIN_STATE_BR1] = env->br[1];
}

bool ia64_machine_check_register_min_state(CPUIA64State *env,
                                           uint64_t physical_address,
                                           uint64_t size_kb)
{
    if (!env || (physical_address & (IA64_MIN_STATE_ALIGNMENT - 1)) != 0 ||
        (size_kb != 0 && size_kb != IA64_MIN_STATE_SIZE / 1024)) {
        return false;
    }
    env->machine_check.registered = true;
    env->machine_check.min_state_address = physical_address;
    return true;
}

bool ia64_machine_check_capture(CPUIA64State *env,
                                IA64MachineCheckCause cause)
{
    IA64MachineCheckState *state;

    if (!env || cause <= IA64_MACHINE_CHECK_NONE ||
        cause > IA64_MACHINE_CHECK_TRANSLATION_OVERLAP) {
        return false;
    }
    state = &env->machine_check;
    if (state->pending) {
        state->processor_state_parameter |= IA64_PSP_MULTIPLE_ERROR_BIT;
        return false;
    }
    ia64_machine_check_capture_min_state(env);
    state->cause = cause;
    state->processor_state_parameter =
        ia64_machine_check_processor_state_parameter(env, cause);
    state->pending = true;
    return true;
}

bool ia64_machine_check_delivery_ready(const CPUIA64State *env)
{
    return env && env->machine_check.pending &&
           (ia64_env_psr((CPUIA64State *)env) & IA64_PSR_MC_BIT) == 0;
}

const uint64_t *ia64_machine_check_pending_image(const CPUIA64State *env)
{
    return env && env->machine_check.pending ? env->machine_check.min_state
                                             : NULL;
}

void ia64_machine_check_mark_delivered(CPUIA64State *env)
{
    if (!env || !env->machine_check.pending) {
        return;
    }
    env->machine_check.pending = false;
    env->machine_check.active = true;
    memset(env->machine_check.min_state, 0,
           sizeof(env->machine_check.min_state));
}

static bool ia64_machine_check_ifs_valid(uint64_t ifs, bool require_valid)
{
    uint64_t cfm = ifs & IA64_CFM_MASK;
    uint32_t sof = cfm & 0x7f;
    uint32_t sol = (cfm >> 7) & 0x7f;
    uint32_t sor = ((cfm >> 14) & 0xf) * 8;
    uint32_t rrb_gr = (cfm >> 18) & 0x7f;
    uint32_t rrb_fr = (cfm >> 25) & 0x7f;
    uint32_t rrb_pr = (cfm >> 32) & 0x3f;

    return (ifs & ~(IA64_IFS_VALID_BIT | IA64_CFM_MASK)) == 0 &&
           (!require_valid || (ifs & IA64_IFS_VALID_BIT) != 0) &&
           sof <= IA64_RSE_PHYS_STACKED_REGS && sol <= sof && sor <= sof &&
           (sor ? rrb_gr < sor : rrb_gr == 0) &&
           rrb_fr < 96 && rrb_pr < 48;
}

static void ia64_machine_check_restore_nat(CPUIA64State *env,
                                           uint64_t nat_word,
                                           uint64_t psr)
{
    uint64_t static_nat = nat_word & UINT64_C(0x000000000000fffe);
    uint64_t bank0 = nat_word & UINT64_C(0x00000000ffff0000);
    uint64_t bank1 = (nat_word >> 16) & UINT64_C(0x00000000ffff0000);

    env->nat.gr_nat[0] = static_nat;
    env->nat.gr_nat[1] = 0;
    if (psr & IA64_PSR_BN_BIT) {
        env->nat.gr_nat[0] |= bank1;
        env->nat.gr_nat[1] = bank0;
    } else {
        env->nat.gr_nat[0] |= bank0;
        env->nat.gr_nat[1] = bank1;
    }
}

bool ia64_machine_check_resume(CPUIA64State *env,
                               const uint64_t image[IA64_MIN_STATE_WORDS],
                               bool new_context, bool set_cmci)
{
    uint64_t psr;
    uint64_t ifs;

    if (!env || !image || !env->machine_check.active) {
        return false;
    }
    /*
     * Both forms restore the caller-supplied image; the flag identifies
     * whether that image describes the interrupted or a caller-built context.
     */
    (void)new_context;
    psr = image[IA64_MIN_STATE_IPSR];
    ifs = image[IA64_MIN_STATE_IFS];
    if ((image[IA64_MIN_STATE_IIP] & UINT64_C(0xf)) != 0 ||
        (image[IA64_MIN_STATE_RSC] & ~IA64_RSC_IMPLEMENTED_MASK) != 0 ||
        (image[IA64_MIN_STATE_PR] & UINT64_C(1)) == 0 ||
        ia64_psr_ri(psr) == 3 ||
        !ia64_machine_check_ifs_valid(ifs, true) ||
        ((psr & IA64_PSR_IC_BIT) == 0 &&
         ((image[IA64_MIN_STATE_XIP] & UINT64_C(0xf)) != 0 ||
          ia64_psr_ri(image[IA64_MIN_STATE_XPSR]) == 3 ||
          !ia64_machine_check_ifs_valid(image[IA64_MIN_STATE_XFS],
                                        false)))) {
        return false;
    }

    for (unsigned reg = 1; reg <= 15; reg++) {
        env->gr[reg] = image[IA64_MIN_STATE_GR1 + reg - 1];
    }
    for (unsigned reg = 0; reg < 16; reg++) {
        env->gr[16 + reg] = image[IA64_MIN_STATE_BANK0_GR16 + reg];
        env->banked_gr[reg] = image[IA64_MIN_STATE_BANK1_GR16 + reg];
    }
    env->pr = image[IA64_MIN_STATE_PR] | UINT64_C(1);
    env->br[0] = image[IA64_MIN_STATE_BR0];
    env->br[1] = image[IA64_MIN_STATE_BR1];
    ia64_write_application_register(env, IA64_AR_RSC,
                                    image[IA64_MIN_STATE_RSC]);
    ia64_env_replace_psr(env, psr);
    ia64_machine_check_restore_nat(env, image[IA64_MIN_STATE_NAT], psr);
    ia64_set_cfm(env, ifs & IA64_CFM_MASK);
    env->ip = image[IA64_MIN_STATE_IIP] & ~UINT64_C(0xf);
    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IPSR] = psr;
    env->cr[IA64_CR_IFS] = ifs;
    if ((psr & IA64_PSR_IC_BIT) == 0) {
        env->cr[IA64_CR_IIP] = image[IA64_MIN_STATE_XIP] & ~UINT64_C(0xf);
        env->cr[IA64_CR_IPSR] = image[IA64_MIN_STATE_XPSR];
        env->cr[IA64_CR_IFS] = image[IA64_MIN_STATE_XFS];
    }
    env->gr[0] = 0;
    ia64_env_begin_source_visibility_epoch(env);

    env->machine_check.active = false;
    env->machine_check.cause = IA64_MACHINE_CHECK_NONE;
    env->machine_check.processor_state_parameter = 0;
    env->machine_check.cmci_pending |= set_cmci;
    ia64_machine_check_refresh_cmci(env);
    return true;
}

void ia64_machine_check_refresh_cmci(CPUIA64State *env)
{
    uint64_t cmcv;
    uint64_t vector;

    if (!env || !env->machine_check.cmci_pending) {
        return;
    }
    cmcv = env->cr[IA64_CR_CMCV];
    vector = cmcv & IA64_INTERRUPT_VECTOR_MASK;
    if ((cmcv & IA64_LOCAL_VECTOR_MASK_BIT) == 0 && vector >= 16 &&
        ia64_queue_external_interrupt(env, vector)) {
        env->machine_check.cmci_pending = false;
    }
}
