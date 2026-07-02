/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "firmware.h"

static IA64FirmwareDispatchFn ia64_firmware_dispatch;
static IA64FirmwareCmdlinePendingFn ia64_firmware_cmdline_pending;
static IA64FirmwareCmdlineApplyFn ia64_firmware_cmdline_apply;
static IA64FirmwareRecoverPostLoadFn ia64_firmware_recover;

void ia64_firmware_set_dispatch(IA64FirmwareDispatchFn dispatch)
{
    ia64_firmware_dispatch = dispatch;
}

bool ia64_firmware_dispatch_gate(CPUIA64State *env, uint64_t gate_ip)
{
    if (!ia64_firmware_dispatch) {
        return false;
    }

    return ia64_firmware_dispatch(env, gate_ip);
}

void ia64_firmware_set_cmdline_append_hooks(
    IA64FirmwareCmdlinePendingFn pending,
    IA64FirmwareCmdlineApplyFn apply)
{
    ia64_firmware_cmdline_pending = pending;
    ia64_firmware_cmdline_apply = apply;
}

bool ia64_firmware_linux_cmdline_append_pending(void)
{
    return ia64_firmware_cmdline_pending &&
           ia64_firmware_cmdline_pending();
}

void ia64_firmware_maybe_apply_linux_cmdline_append(CPUIA64State *env)
{
    if (ia64_firmware_cmdline_apply) {
        ia64_firmware_cmdline_apply(env);
    }
}

void ia64_firmware_set_recover_post_load(
    IA64FirmwareRecoverPostLoadFn recover)
{
    ia64_firmware_recover = recover;
}

void ia64_firmware_recover_post_load(uint64_t ip)
{
    if (ia64_firmware_recover) {
        ia64_firmware_recover(ip);
    }
}
