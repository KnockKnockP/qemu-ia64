/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TARGET_IA64_SYSTEM_PLANE_H
#define TARGET_IA64_SYSTEM_PLANE_H

enum IA64SystemPlaneFlags {
    IA64_SYSTEM_PLANE_PROBE_FAULT = 1U << 0,
    IA64_SYSTEM_PLANE_PROBE_IMMEDIATE = 1U << 1,
};

bool ia64_pmu_pmc_implemented(unsigned index);
bool ia64_pmu_pmd_implemented(unsigned index);
void ia64_pmu_sanitize_state(CPUIA64State *env);

#endif /* TARGET_IA64_SYSTEM_PLANE_H */
