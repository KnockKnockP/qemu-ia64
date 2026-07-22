/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "pmu.h"

#define IA64_PMC0_WRITABLE_MASK UINT64_C(0x00000000000000f1)
#define IA64_GENERIC_PMC_WRITABLE_MASK UINT64_C(0x000000000000ff7f)
#define IA64_GENERIC_PMD_WRITABLE_MASK \
    ((UINT64_C(1) << IA64_PMU_COUNTER_WIDTH) - 1)

bool ia64_pmu_pmc_implemented(unsigned index)
{
    return index < IA64_PMU_GENERIC_FIRST + IA64_PMU_GENERIC_COUNT;
}

bool ia64_pmu_pmd_implemented(unsigned index)
{
    return index >= IA64_PMU_GENERIC_FIRST &&
           index < IA64_PMU_GENERIC_FIRST + IA64_PMU_GENERIC_COUNT;
}

uint64_t ia64_pmu_pmc_writable_mask(unsigned index)
{
    if (index == 0) {
        return IA64_PMC0_WRITABLE_MASK;
    }
    if (index >= IA64_PMU_GENERIC_FIRST &&
        index < IA64_PMU_GENERIC_FIRST + IA64_PMU_GENERIC_COUNT) {
        return IA64_GENERIC_PMC_WRITABLE_MASK;
    }
    return 0;
}

uint64_t ia64_pmu_pmd_writable_mask(unsigned index)
{
    return ia64_pmu_pmd_implemented(index)
           ? IA64_GENERIC_PMD_WRITABLE_MASK : 0;
}

void ia64_pmu_sanitize_state(CPUIA64State *env)
{
    for (unsigned index = 0; index < IA64_PMC_COUNT; index++) {
        env->pmc[index] &= ia64_pmu_pmc_writable_mask(index);
    }
    for (unsigned index = 0; index < IA64_PMD_COUNT; index++) {
        env->pmd[index] &= ia64_pmu_pmd_writable_mask(index);
    }
}
