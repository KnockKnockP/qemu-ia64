/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_DEBUG_TRACE_H
#define IA64_DEBUG_TRACE_H

#include "bundle.h"
#include "cpu.h"

bool ia64_debug_hooks_active(void);

void ia64_trace_execve(CPUIA64State *env);
void ia64_trace_epc_syscall(CPUIA64State *env);
void ia64_trace_syscall_return(CPUIA64State *env);
void ia64_trace_uevent_netlink(CPUIA64State *env);
void ia64_trace_linux_syscall_break(CPUIA64State *env,
                                    const char *mnemonic,
                                    uint64_t iim, uint64_t next_ip);

void ia64_progress_trace_bundle(CPUIA64State *env);
void ia64_progress_trace_event(CPUIA64State *env, const char *event,
                               uint64_t value, uint64_t source_ip,
                               unsigned source_ri, uint64_t next_ip);
void ia64_progress_trace_break_slot(CPUIA64State *env,
                                    const IA64DecodedBundle *decoded,
                                    int slot,
                                    const char *mnemonic,
                                    uint64_t iim);
void ia64_bundle_trace_decoded(CPUIA64State *env,
                               const IA64DecodedBundle *decoded,
                               unsigned start_slot);
void ia64_state_trace_bundle(CPUIA64State *env);

#endif
