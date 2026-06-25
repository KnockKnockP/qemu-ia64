/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"

void HELPER(raise_unimplemented)(CPUIA64State *env)
{
    cpu_abort(env_cpu(env),
              "IA-64 instruction execution is not implemented yet "
              "(IP=0x%016" PRIx64 ")\n",
              env->ip);
}
