/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/char/serial.h"
#include "hw/char/serial-mm.h"
#include "hw/ia64/vibtanium.h"
#include "vibtanium-internal.h"
#include "system/address-spaces.h"
#include "system/memory.h"

static unsigned vibtanium_sparse_io_port(hwaddr offset)
{
    return ((unsigned)(offset >> 12) << 2) | (offset & 0x3);
}

static unsigned vibtanium_guest_io_port(hwaddr offset)
{
    hwaddr group = offset >> 12;
    hwaddr low = offset & 0xfff;

    /*
     * The guest firmware uses dense addresses for its early ATA, PS/2, VGA,
     * and ACPI accesses.  Once an OS takes over, the same aperture also has
     * to accept the architectural IA-64 sparse encoding.  A sparse encoding
     * is self-identifying; all other offsets retain their dense meaning.
     */
    if ((group & 0x3ff) == (low >> 2)) {
        return (group << 2) | (low & 3);
    }
    return offset;
}

static hwaddr vibtanium_sparse_io_offset(unsigned port)
{
    return (((hwaddr)port >> 2) << 12) | (port & 0xfff);
}

static uint64_t vibtanium_io_port_default_read(unsigned size)
{
    switch (size) {
    case 1:
        return UINT8_MAX;
    case 2:
        return UINT16_MAX;
    case 4:
        return UINT32_MAX;
    default:
        return UINT64_MAX;
    }
}

static bool vibtanium_sparse_io_offset_valid(hwaddr offset, unsigned size)
{
    unsigned port;

    if (offset >= VIBTANIUM_PCI_IO_SPARSE_SIZE || size == 0 || size > 4 ||
        size > VIBTANIUM_PCI_IO_SPARSE_SIZE - offset) {
        return false;
    }

    port = vibtanium_sparse_io_port(offset);
    if (vibtanium_sparse_io_offset(port) != offset ||
        port >= VIBTANIUM_PCI_IO_SIZE ||
        size > VIBTANIUM_PCI_IO_SIZE - port) {
        return false;
    }

    return true;
}

static bool vibtanium_guest_io_offset_valid(hwaddr offset, unsigned size,
                                            unsigned *port)
{
    if (offset >= VIBTANIUM_PCI_IO_SPARSE_SIZE || size == 0 || size > 4 ||
        size > VIBTANIUM_PCI_IO_SPARSE_SIZE - offset) {
        return false;
    }

    *port = vibtanium_guest_io_port(offset);
    return *port < VIBTANIUM_PCI_IO_SIZE &&
           size <= VIBTANIUM_PCI_IO_SIZE - *port;
}

static uint64_t vibtanium_io_port_space_read(VibtaniumMachineState *vms,
                                             unsigned port, unsigned size)
{
    uint8_t data[4] = { UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX };
    uint64_t value = 0;

    if (address_space_read(&vms->pci_io_as, port, MEMTXATTRS_UNSPECIFIED,
                           data, size) != MEMTX_OK) {
        return vibtanium_io_port_default_read(size);
    }

    for (unsigned i = 0; i < size; i++) {
        value |= (uint64_t)data[i] << (i * 8);
    }
    return value;
}

static void vibtanium_io_port_space_write(VibtaniumMachineState *vms,
                                          unsigned port, uint64_t value,
                                          unsigned size)
{
    uint8_t data[4];

    for (unsigned i = 0; i < size; i++) {
        data[i] = value >> (i * 8);
    }
    address_space_write(&vms->pci_io_as, port, MEMTXATTRS_UNSPECIFIED,
                        data, size);
}

static bool vibtanium_i8042_port_offset(unsigned port, hwaddr *i8042_offset)
{
    switch (port) {
    case VIBTANIUM_LEGACY_I8042_DATA_PORT:
        *i8042_offset = 0;
        return true;
    case VIBTANIUM_LEGACY_I8042_COMMAND_PORT:
        *i8042_offset = VIBTANIUM_I8042_MMIO_COMMAND_OFFSET;
        return true;
    default:
        return false;
    }
}

static uint64_t vibtanium_io_port_read_decoded(VibtaniumMachineState *vms,
                                               unsigned port, unsigned size)
{
    hwaddr i8042_offset;
    uint64_t value;

    if (size == 1 && vms->i8042_mmio &&
        vibtanium_i8042_port_offset(port, &i8042_offset) &&
        memory_region_dispatch_read(vms->i8042_mmio, i8042_offset, &value,
                                    MO_8, MEMTXATTRS_UNSPECIFIED) == MEMTX_OK) {
        return value & UINT8_MAX;
    }
    if (size == 1 && port >= VIBTANIUM_LEGACY_COM1_BASE &&
        port < VIBTANIUM_LEGACY_COM1_BASE + VIBTANIUM_LEGACY_COM1_SIZE) {
        return serial_io_ops.read(&vms->uart->serial,
                                  port - VIBTANIUM_LEGACY_COM1_BASE, size);
    }

    return vibtanium_io_port_space_read(vms, port, size);
}

static void vibtanium_io_port_write_decoded(VibtaniumMachineState *vms,
                                            unsigned port, uint64_t value,
                                            unsigned size)
{
    hwaddr i8042_offset;

    if (size == 1 && vms->i8042_mmio &&
        vibtanium_i8042_port_offset(port, &i8042_offset)) {
        memory_region_dispatch_write(vms->i8042_mmio, i8042_offset,
                                     value & UINT8_MAX, MO_8,
                                     MEMTXATTRS_UNSPECIFIED);
        return;
    }
    if (size == 1 && port >= VIBTANIUM_LEGACY_COM1_BASE &&
        port < VIBTANIUM_LEGACY_COM1_BASE + VIBTANIUM_LEGACY_COM1_SIZE) {
        serial_io_ops.write(&vms->uart->serial,
                            port - VIBTANIUM_LEGACY_COM1_BASE, value, size);
        return;
    }

    vibtanium_io_port_space_write(vms, port, value, size);
}

static uint64_t vibtanium_io_port_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    VibtaniumMachineState *vms = opaque;

    if (!vibtanium_sparse_io_offset_valid(offset, size)) {
        return vibtanium_io_port_default_read(size);
    }
    return vibtanium_io_port_read_decoded(
        vms, vibtanium_sparse_io_port(offset), size);
}

static void vibtanium_io_port_write(void *opaque, hwaddr offset,
                                    uint64_t value, unsigned size)
{
    VibtaniumMachineState *vms = opaque;

    if (!vibtanium_sparse_io_offset_valid(offset, size)) {
        return;
    }
    vibtanium_io_port_write_decoded(
        vms, vibtanium_sparse_io_port(offset), value, size);
}

static uint64_t vibtanium_guest_io_port_read(void *opaque, hwaddr offset,
                                             unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    unsigned port;

    if (!vibtanium_guest_io_offset_valid(offset, size, &port)) {
        return vibtanium_io_port_default_read(size);
    }
    return vibtanium_io_port_read_decoded(vms, port, size);
}

static void vibtanium_guest_io_port_write(void *opaque, hwaddr offset,
                                          uint64_t value, unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    unsigned port;

    if (!vibtanium_guest_io_offset_valid(offset, size, &port)) {
        return;
    }
    vibtanium_io_port_write_decoded(vms, port, value, size);
}

static const MemoryRegionOps vibtanium_io_port_ops = {
    .read = vibtanium_io_port_read,
    .write = vibtanium_io_port_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static const MemoryRegionOps vibtanium_guest_io_port_ops = {
    .read = vibtanium_guest_io_port_read,
    .write = vibtanium_guest_io_port_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

void vibtanium_sparse_io_init(VibtaniumMachineState *vms,
                              MemoryRegion *sysmem)
{
    memory_region_init_io(&vms->io_port_space, OBJECT(vms),
                          &vibtanium_io_port_ops, vms,
                          "vibtanium.io-port-space",
                          VIBTANIUM_PCI_IO_SPARSE_SIZE);
    memory_region_add_subregion(sysmem, VIBTANIUM_IO_PORT_BASE,
                                &vms->io_port_space);

    memory_region_init_io(&vms->guest_io_port_space, OBJECT(vms),
                          &vibtanium_guest_io_port_ops, vms,
                          "vibtanium.guest-firmware-io-port-space",
                          VIBTANIUM_PCI_IO_SPARSE_SIZE);
    memory_region_add_subregion(sysmem, VIBTANIUM_GUEST_IO_PORT_BASE,
                                &vms->guest_io_port_space);
}
