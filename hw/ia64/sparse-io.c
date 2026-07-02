/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/char/serial.h"
#include "hw/char/serial-mm.h"
#include "hw/ia64/vibtanium.h"
#include "vibtanium-internal.h"
#include "system/memory.h"

static unsigned vibtanium_sparse_io_port(hwaddr offset)
{
    return ((unsigned)(offset >> 12) << 2) | (offset & 0x3);
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

    if (offset >= VIBTANIUM_IO_PORT_SIZE || size == 0 || size > 4) {
        return false;
    }

    port = vibtanium_sparse_io_port(offset);
    if (vibtanium_sparse_io_offset(port) != offset ||
        port + size > UINT16_MAX + 1) {
        return false;
    }

    return true;
}

static bool vibtanium_vga_crtc_index_port(unsigned port)
{
    return port == VIBTANIUM_LEGACY_VGA_CRTC_INDEX_COLOR ||
           port == VIBTANIUM_LEGACY_VGA_CRTC_INDEX_MONO;
}

static bool vibtanium_vga_crtc_data_port(unsigned port)
{
    return port == VIBTANIUM_LEGACY_VGA_CRTC_DATA_COLOR ||
           port == VIBTANIUM_LEGACY_VGA_CRTC_DATA_MONO;
}

static bool vibtanium_vga_crtc_port(unsigned port)
{
    return vibtanium_vga_crtc_index_port(port) ||
           vibtanium_vga_crtc_data_port(port);
}

static uint64_t vibtanium_vga_crtc_read(VibtaniumMachineState *vms,
                                        unsigned port, unsigned size)
{
    if (size == 1) {
        if (vibtanium_vga_crtc_index_port(port)) {
            return vms->vga_crtc_index;
        }
        if (vibtanium_vga_crtc_data_port(port) &&
            vms->vga_crtc_index < VIBTANIUM_VGA_CRTC_REGISTER_COUNT) {
            return vms->vga_crtc[vms->vga_crtc_index];
        }
        return UINT8_MAX;
    }

    if (size == 2 && vibtanium_vga_crtc_index_port(port)) {
        uint8_t data = UINT8_MAX;

        if (vms->vga_crtc_index < VIBTANIUM_VGA_CRTC_REGISTER_COUNT) {
            data = vms->vga_crtc[vms->vga_crtc_index];
        }
        return vms->vga_crtc_index | ((uint16_t)data << 8);
    }

    return vibtanium_io_port_default_read(size);
}

static bool vibtanium_vga_crtc_write(VibtaniumMachineState *vms,
                                     unsigned port, uint64_t value,
                                     unsigned size)
{
    if (size == 1) {
        if (vibtanium_vga_crtc_index_port(port)) {
            vms->vga_crtc_index = value & UINT8_MAX;
            return true;
        }
        if (vibtanium_vga_crtc_data_port(port)) {
            if (vms->vga_crtc_index < VIBTANIUM_VGA_CRTC_REGISTER_COUNT) {
                vms->vga_crtc[vms->vga_crtc_index] = value & UINT8_MAX;
            }
            return true;
        }
    }

    if (size == 2 && vibtanium_vga_crtc_index_port(port)) {
        uint8_t index = value & UINT8_MAX;

        vms->vga_crtc_index = index;
        if (index < VIBTANIUM_VGA_CRTC_REGISTER_COUNT) {
            vms->vga_crtc[index] = (value >> 8) & UINT8_MAX;
        }
        return true;
    }

    return false;
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

static uint64_t vibtanium_io_port_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    hwaddr i8042_offset;
    uint64_t value;
    unsigned port;

    if (!vibtanium_sparse_io_offset_valid(offset, size)) {
        return vibtanium_io_port_default_read(size);
    }

    port = vibtanium_sparse_io_port(offset);
    if (size == 1 && vms->i8042_mmio &&
        vibtanium_i8042_port_offset(port, &i8042_offset) &&
        memory_region_dispatch_read(vms->i8042_mmio, i8042_offset, &value,
                                    MO_8, MEMTXATTRS_UNSPECIFIED) == MEMTX_OK) {
        return value & UINT8_MAX;
    }
    if (vibtanium_vga_crtc_port(port)) {
        return vibtanium_vga_crtc_read(vms, port, size);
    }
    if (size == 1 && port >= VIBTANIUM_LEGACY_COM1_BASE &&
        port < VIBTANIUM_LEGACY_COM1_BASE + VIBTANIUM_LEGACY_COM1_SIZE) {
        return serial_io_ops.read(&vms->uart->serial,
                                  port - VIBTANIUM_LEGACY_COM1_BASE, size);
    }

    return vibtanium_io_port_default_read(size);
}

static void vibtanium_io_port_write(void *opaque, hwaddr offset,
                                    uint64_t value, unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    hwaddr i8042_offset;
    unsigned port;

    if (!vibtanium_sparse_io_offset_valid(offset, size)) {
        return;
    }

    port = vibtanium_sparse_io_port(offset);
    if (size == 1 && vms->i8042_mmio &&
        vibtanium_i8042_port_offset(port, &i8042_offset)) {
        memory_region_dispatch_write(vms->i8042_mmio, i8042_offset,
                                     value & UINT8_MAX, MO_8,
                                     MEMTXATTRS_UNSPECIFIED);
        return;
    }
    if (vibtanium_vga_crtc_port(port) &&
        vibtanium_vga_crtc_write(vms, port, value, size)) {
        return;
    }
    if (size == 1 && port >= VIBTANIUM_LEGACY_COM1_BASE &&
        port < VIBTANIUM_LEGACY_COM1_BASE + VIBTANIUM_LEGACY_COM1_SIZE) {
        serial_io_ops.write(&vms->uart->serial,
                            port - VIBTANIUM_LEGACY_COM1_BASE, value, size);
    }
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

void vibtanium_sparse_io_init(VibtaniumMachineState *vms,
                              MemoryRegion *sysmem)
{
    memory_region_init_io(&vms->io_port_space, OBJECT(vms),
                          &vibtanium_io_port_ops, vms,
                          "vibtanium.io-port-space",
                          VIBTANIUM_IO_PORT_SIZE);
    memory_region_add_subregion(sysmem, VIBTANIUM_IO_PORT_BASE,
                                &vms->io_port_space);
}
