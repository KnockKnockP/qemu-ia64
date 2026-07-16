/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_FIRMWARE_H
#define HW_IA64_FIRMWARE_H

typedef struct CPUArchState CPUIA64State;

/* Complete one PAL transaction issued by the guest firmware trampoline. */
bool vibtanium_firmware_dispatch_pal_break(CPUIA64State *env);

#endif
