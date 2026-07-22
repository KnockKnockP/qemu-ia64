/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_MACHINE_CHECK_H
#define IA64_MACHINE_CHECK_H

#include "cpu.h"

typedef enum IA64MinStateWord {
    IA64_MIN_STATE_NAT = 0x000 / 8,
    IA64_MIN_STATE_GR1 = 0x008 / 8,
    IA64_MIN_STATE_BANK0_GR16 = 0x080 / 8,
    IA64_MIN_STATE_BANK1_GR16 = 0x100 / 8,
    IA64_MIN_STATE_PR = 0x180 / 8,
    IA64_MIN_STATE_BR0 = 0x188 / 8,
    IA64_MIN_STATE_RSC = 0x190 / 8,
    IA64_MIN_STATE_IIP = 0x198 / 8,
    IA64_MIN_STATE_IPSR = 0x1a0 / 8,
    IA64_MIN_STATE_IFS = 0x1a8 / 8,
    IA64_MIN_STATE_XIP = 0x1b0 / 8,
    IA64_MIN_STATE_XPSR = 0x1b8 / 8,
    IA64_MIN_STATE_XFS = 0x1c0 / 8,
    IA64_MIN_STATE_BR1 = 0x1c8 / 8,
} IA64MinStateWord;

bool ia64_machine_check_register_min_state(CPUIA64State *env,
                                           uint64_t physical_address,
                                           uint64_t size_kb);
bool ia64_machine_check_capture(CPUIA64State *env,
                                IA64MachineCheckCause cause);
bool ia64_machine_check_delivery_ready(const CPUIA64State *env);
const uint64_t *ia64_machine_check_pending_image(const CPUIA64State *env);
void ia64_machine_check_mark_delivered(CPUIA64State *env);
bool ia64_machine_check_resume(CPUIA64State *env,
                               const uint64_t min_state[IA64_MIN_STATE_WORDS],
                               bool new_context, bool set_cmci);
void ia64_machine_check_refresh_cmci(CPUIA64State *env);

static inline bool ia64_machine_check_state_is_canonical(
    const IA64MachineCheckState *state)
{
    bool image_nonzero = false;

    if (!state || state->cause > IA64_MACHINE_CHECK_TRANSLATION_OVERLAP ||
        (state->registered &&
         (state->min_state_address & (IA64_MIN_STATE_ALIGNMENT - 1)) != 0) ||
        (!state->registered && state->min_state_address != 0) ||
        ((state->pending || state->active) &&
         state->cause == IA64_MACHINE_CHECK_NONE) ||
        (!state->pending && !state->active &&
         (state->cause != IA64_MACHINE_CHECK_NONE ||
          state->processor_state_parameter != 0))) {
        return false;
    }
    for (unsigned i = 0; i < IA64_MIN_STATE_WORDS; i++) {
        image_nonzero |= state->min_state[i] != 0;
    }
    return state->pending == image_nonzero &&
           (state->pending || state->processor_state_parameter == 0 ||
            state->active);
}

#endif
