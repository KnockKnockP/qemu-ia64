/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_CPU_QOM_H
#define IA64_CPU_QOM_H

#include "hw/core/cpu.h"

#define TYPE_IA64_CPU "ia64-cpu"

#define IA64_CPU_TYPE_SUFFIX "-" TYPE_IA64_CPU
#define IA64_CPU_TYPE_NAME(model) model IA64_CPU_TYPE_SUFFIX

#define TYPE_ITANIUM2_CPU IA64_CPU_TYPE_NAME("itanium2")

OBJECT_DECLARE_CPU_TYPE(IA64CPU, IA64CPUClass, IA64_CPU)

struct IA64CPUClass {
    CPUClass parent_class;

    DeviceRealize parent_realize;
    ResettablePhases parent_phases;
};

#endif
