/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_INTC_IA64_IOSAPIC_H
#define HW_INTC_IA64_IOSAPIC_H

#include "hw/core/sysbus.h"
#include "target/ia64/cpu-qom.h"

#define TYPE_IA64_IOSAPIC "ia64-iosapic"
OBJECT_DECLARE_SIMPLE_TYPE(IA64IOSAPICState, IA64_IOSAPIC)

void ia64_iosapic_set_cpu(IA64IOSAPICState *s, IA64CPU *cpu);

#endif
