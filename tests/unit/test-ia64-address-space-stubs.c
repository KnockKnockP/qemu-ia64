/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "system/memory.h"
#include "target/ia64/cpu.h"
#include "target/ia64/firmware.h"

void ia64_test_cpu_interrupt_reset(void);
unsigned int ia64_test_cpu_interrupt_count(void);

static unsigned int cpu_interrupt_calls;

void ia64_cpu_tlb_flush(CPUIA64State *env)
{
}

void cpu_interrupt(CPUState *cpu, int mask)
{
    cpu_interrupt_calls++;
    qatomic_or(&cpu->interrupt_request, mask);
}

void cpu_set_interrupt(CPUState *cpu, int mask)
{
    cpu_interrupt_calls++;
    qatomic_or(&cpu->interrupt_request, mask);
}

void cpu_reset_interrupt(CPUState *cpu, int mask)
{
    qatomic_and(&cpu->interrupt_request, ~mask);
}

void ia64_test_cpu_interrupt_reset(void)
{
    cpu_interrupt_calls = 0;
}

unsigned int ia64_test_cpu_interrupt_count(void)
{
    return cpu_interrupt_calls;
}

bool ia64_firmware_is_call_gate(uint64_t address)
{
    return false;
}

uint64_t address_space_ldq_be(AddressSpace *as, hwaddr addr,
                              MemTxAttrs attrs, MemTxResult *result)
{
    g_assert_not_reached();
}

uint64_t address_space_ldq_le(AddressSpace *as, hwaddr addr,
                              MemTxAttrs attrs, MemTxResult *result)
{
    g_assert_not_reached();
}
