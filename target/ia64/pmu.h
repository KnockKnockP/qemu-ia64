/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TARGET_IA64_PMU_H
#define TARGET_IA64_PMU_H

bool ia64_pmu_pmc_implemented(unsigned index);
bool ia64_pmu_pmd_implemented(unsigned index);
uint64_t ia64_pmu_pmc_writable_mask(unsigned index);
uint64_t ia64_pmu_pmd_writable_mask(unsigned index);
void ia64_pmu_sanitize_state(CPUIA64State *env);

#endif /* TARGET_IA64_PMU_H */
