/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exec/helper-proto.h"
#include "hw/core/cpu.h"
#include "firmware.h"

static IA64FirmwareDispatchFn ia64_firmware_dispatch;
static IA64FirmwareCmdlinePendingFn ia64_firmware_cmdline_pending;
static IA64FirmwareCmdlineApplyFn ia64_firmware_cmdline_apply;
static IA64FirmwareRecoverPostLoadFn ia64_firmware_recover;

#define IA64_FIRMWARE_REGION_OFFSET_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_FIRMWARE_KERNEL_REGION      UINT64_C(0xe000000000000000)

bool ia64_firmware_is_call_gate(uint64_t address)
{
    uint64_t region = address & ~IA64_FIRMWARE_REGION_OFFSET_MASK;
    uint64_t physical;
    uint64_t offset;

    if (region != 0 && region != IA64_FIRMWARE_KERNEL_REGION) {
        return false;
    }
    physical = address & IA64_FIRMWARE_REGION_OFFSET_MASK;
    if (physical == IA64_FIRMWARE_EFI_PAL_PROC ||
        physical == IA64_FIRMWARE_EFI_SAL_PROC ||
        physical == IA64_FIRMWARE_EFI_START_IMAGE_RETURN_GATE ||
        physical == IA64_FIRMWARE_EFI_EVENT_NOTIFY_RETURN_GATE) {
        return true;
    }
    if (physical < IA64_FIRMWARE_EFI_CALL_GATE_BASE) {
        return false;
    }
    offset = physical - IA64_FIRMWARE_EFI_CALL_GATE_BASE;
    return (offset & (IA64_FIRMWARE_EFI_CALL_GATE_STRIDE - 1)) == 0 &&
           offset / IA64_FIRMWARE_EFI_CALL_GATE_STRIDE <
               IA64_FIRMWARE_EFI_CLASSIFY_SERVICE_COUNT;
}

void HELPER(firmware_call_gate)(CPUIA64State *env, uint64_t gate_ip,
                                uint64_t dispatch_ip)
{
    CPUState *cpu = env_cpu(env);

    /*
     * Vibtanium's EFI tables contain tiny IA-64 branch gates.  The typed TCG
     * translator stops at those reserved bundles and enters the native
     * service implementation here.  Device and guest-memory accesses are
     * therefore explicit firmware transactions, not a second CPU engine.
     */
    cpu->neg.can_do_io = true;
    env->ip = gate_ip;
    env->cr[IA64_CR_IIP] = gate_ip;
    if (!ia64_firmware_dispatch_gate(env, dispatch_ip)) {
        cpu_abort(cpu,
                  "Vibtanium EFI call gate was not recognized: "
                  "ip=0x%016" PRIx64 " service=0x%016" PRIx64 "\n",
                  gate_ip, dispatch_ip);
    }
    ia64_env_begin_source_visibility_epoch(env);
}

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
