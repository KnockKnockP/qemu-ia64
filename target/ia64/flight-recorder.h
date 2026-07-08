/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_FLIGHT_RECORDER_H
#define IA64_FLIGHT_RECORDER_H

#include "cpu.h"

#ifndef VIBTANIUM_DIAGNOSTICS
#ifdef CONFIG_DEBUG_TCG
#define VIBTANIUM_DIAGNOSTICS 1
#else
#define VIBTANIUM_DIAGNOSTICS 0
#endif
#endif

#if VIBTANIUM_DIAGNOSTICS

bool ia64_diag_enabled(void);
bool ia64_diag_invariants_enabled(void);

void ia64_diag_dump(const char *reason);
void ia64_diag_check_kernel_low_stack(CPUIA64State *env, const char *where);
void ia64_diag_record_efi_commit(CPUIA64State *env, const char *state,
                                 const char *image, uint64_t load_base,
                                 uint64_t size);
void ia64_diag_record_efi_handoff(CPUIA64State *env, const char *image,
                                  uint64_t entry, uint64_t global_pointer);
void ia64_diag_record_firmware_write(CPUIA64State *env, const char *name,
                                     uint64_t address, uint64_t size,
                                     uint64_t clear_size, bool live_cpu);
void ia64_diag_record_exception(CPUIA64State *env, const char *kind,
                                uint64_t source_ip, uint64_t address,
                                uint64_t vector, uint64_t old_psr);
void ia64_diag_record_external_interrupt(CPUIA64State *env,
                                         uint64_t interrupt_request);
void ia64_diag_record_rfi(CPUIA64State *env, uint64_t bundle_ip,
                          uint64_t target);

#else

static inline bool ia64_diag_enabled(void)
{
    return false;
}

static inline bool ia64_diag_invariants_enabled(void)
{
    return false;
}

static inline void ia64_diag_dump(const char *reason)
{
}

static inline void ia64_diag_check_kernel_low_stack(CPUIA64State *env,
                                                   const char *where)
{
}

static inline void ia64_diag_record_efi_commit(CPUIA64State *env,
                                               const char *state,
                                               const char *image,
                                               uint64_t load_base,
                                               uint64_t size)
{
}

static inline void ia64_diag_record_efi_handoff(CPUIA64State *env,
                                                const char *image,
                                                uint64_t entry,
                                                uint64_t global_pointer)
{
}

static inline void ia64_diag_record_firmware_write(CPUIA64State *env,
                                                   const char *name,
                                                   uint64_t address,
                                                   uint64_t size,
                                                   uint64_t clear_size,
                                                   bool live_cpu)
{
}

static inline void ia64_diag_record_exception(CPUIA64State *env,
                                              const char *kind,
                                              uint64_t source_ip,
                                              uint64_t address,
                                              uint64_t vector,
                                              uint64_t old_psr)
{
}

static inline void ia64_diag_record_external_interrupt(CPUIA64State *env,
                                                       uint64_t interrupt_request)
{
}

static inline void ia64_diag_record_rfi(CPUIA64State *env,
                                        uint64_t bundle_ip,
                                        uint64_t target)
{
}

#endif

#endif
