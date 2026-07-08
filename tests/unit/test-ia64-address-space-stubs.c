/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "system/memory.h"

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
