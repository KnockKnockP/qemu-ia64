/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/char/serial-mm.h"
#include "hw/core/cpu.h"
#include "hw/core/loader.h"
#include "hw/core/sysbus.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/efi-vars.h"
#include "hw/ia64/vibtanium.h"
#include "hw/input/i8042.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "system/block-backend.h"
#include "system/block-backend-io.h"
#include "system/blockdev.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/reset.h"
#include "system/system.h"
#include "target/ia64/exec-smoke.h"

#define VIBTANIUM_DEFAULT_LINUX_APPEND ""
#define VIBTANIUM_IOSAPIC_REG_SELECT 0x00
#define VIBTANIUM_IOSAPIC_WINDOW     0x10
#define VIBTANIUM_IOSAPIC_EOI        0x40
#define VIBTANIUM_IOSAPIC_VERSION    0x01
#define VIBTANIUM_IOSAPIC_RTE_LOW(i)  (0x10 + (i) * 2)
#define VIBTANIUM_IOSAPIC_RTE_HIGH(i) (0x11 + (i) * 2)
#define VIBTANIUM_IOSAPIC_RTE_MASK    (1U << 16)
#define VIBTANIUM_IOSAPIC_DELIVERY_MASK (7U << 8)
#define VIBTANIUM_IOSAPIC_DELIVERY_FIXED 0
#define VIBTANIUM_IOSAPIC_VECTOR_MASK 0xff
#define VIBTANIUM_LEGACY_COM1_IRQ 4
#define VIBTANIUM_LEGACY_I8042_KEYBOARD_IRQ 1
#define VIBTANIUM_LEGACY_I8042_MOUSE_IRQ 12
#define VIBTANIUM_I8042_MMIO_COMMAND_OFFSET 4
#define VIBTANIUM_VGA_CRTC_REGISTER_COUNT 0x19

static void vibtanium_iosapic_reset(VibtaniumMachineState *vms)
{
    for (unsigned i = 0; i < VIBTANIUM_IOSAPIC_REDIRECTION_COUNT; i++) {
        vms->iosapic_rte_low[i] = VIBTANIUM_IOSAPIC_RTE_MASK;
        vms->iosapic_rte_high[i] = 0;
        vms->iosapic_irq_level[i] = false;
    }
    vms->iosapic_select = 0;
}

static void vibtanium_iosapic_system_reset(void *opaque)
{
    vibtanium_iosapic_reset(opaque);
}

static const VMStateDescription vmstate_vibtanium_iosapic = {
    .name = "vibtanium-iosapic",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(iosapic_select, VibtaniumMachineState),
        VMSTATE_UINT32_ARRAY(iosapic_rte_low, VibtaniumMachineState,
                             VIBTANIUM_IOSAPIC_REDIRECTION_COUNT),
        VMSTATE_UINT32_ARRAY(iosapic_rte_high, VibtaniumMachineState,
                             VIBTANIUM_IOSAPIC_REDIRECTION_COUNT),
        VMSTATE_BOOL_ARRAY(iosapic_irq_level, VibtaniumMachineState,
                           VIBTANIUM_IOSAPIC_REDIRECTION_COUNT),
        VMSTATE_END_OF_LIST()
    }
};

static void vibtanium_iosapic_deliver_irq(VibtaniumMachineState *vms,
                                          unsigned input)
{
    CPUIA64State *env = &vms->cpu->env;
    uint32_t low;
    uint32_t delivery_mode;
    uint64_t vector;

    if (input >= VIBTANIUM_IOSAPIC_REDIRECTION_COUNT) {
        return;
    }

    low = vms->iosapic_rte_low[input];
    delivery_mode = low & VIBTANIUM_IOSAPIC_DELIVERY_MASK;
    vector = low & VIBTANIUM_IOSAPIC_VECTOR_MASK;

    if ((low & VIBTANIUM_IOSAPIC_RTE_MASK) ||
        delivery_mode != VIBTANIUM_IOSAPIC_DELIVERY_FIXED) {
        return;
    }

    if (ia64_queue_external_interrupt(env, vector)) {
        cpu_interrupt(CPU(vms->cpu), CPU_INTERRUPT_HARD);
    }
}

static void vibtanium_iosapic_set_irq(void *opaque, int n, int level)
{
    VibtaniumMachineState *vms = opaque;
    unsigned input = n;
    bool old_level;

    if (input >= VIBTANIUM_IOSAPIC_REDIRECTION_COUNT) {
        return;
    }

    old_level = vms->iosapic_irq_level[input];
    vms->iosapic_irq_level[input] = level != 0;

    if (level && !old_level) {
        vibtanium_iosapic_deliver_irq(vms, input);
    }
}

static void vibtanium_uart_irq(void *opaque, int n, int level)
{
    (void)n;
    vibtanium_iosapic_set_irq(opaque, VIBTANIUM_LEGACY_COM1_IRQ, level);
}

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

static void vibtanium_i8042_init(VibtaniumMachineState *vms)
{
    DeviceState *dev = qdev_new(TYPE_I8042_MMIO);

    qdev_prop_set_uint64(dev, "mask", VIBTANIUM_I8042_MMIO_COMMAND_OFFSET);
    qdev_prop_set_uint32(dev, "size", VIBTANIUM_I8042_MMIO_COMMAND_OFFSET + 1);

    qemu_init_irq_child(OBJECT(vms), "i8042-kbd-irq",
                        &vms->i8042_irq[I8042_KBD_IRQ],
                        vibtanium_iosapic_set_irq, vms,
                        VIBTANIUM_LEGACY_I8042_KEYBOARD_IRQ);
    qemu_init_irq_child(OBJECT(vms), "i8042-mouse-irq",
                        &vms->i8042_irq[I8042_MOUSE_IRQ],
                        vibtanium_iosapic_set_irq, vms,
                        VIBTANIUM_LEGACY_I8042_MOUSE_IRQ);
    qdev_connect_gpio_out(dev, I8042_KBD_IRQ,
                          &vms->i8042_irq[I8042_KBD_IRQ]);
    qdev_connect_gpio_out(dev, I8042_MOUSE_IRQ,
                          &vms->i8042_irq[I8042_MOUSE_IRQ]);

    if (!sysbus_realize(SYS_BUS_DEVICE(dev), &error_fatal)) {
        return;
    }
    vms->i8042 = dev;
    vms->i8042_mmio = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0);
    object_unref(OBJECT(dev));
}

static uint64_t vibtanium_local_sapic_ipi_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    (void)opaque;
    (void)offset;
    (void)size;
    return 0;
}

static void vibtanium_local_sapic_ipi_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    CPUIA64State *env = &vms->cpu->env;
    uint64_t delivery_mode = (value >> 8) & 0x7;
    uint64_t vector = value & 0xff;

    (void)offset;
    (void)size;

    if (delivery_mode != 0) {
        return;
    }

    if (ia64_queue_external_interrupt(env, vector)) {
        cpu_interrupt(CPU(vms->cpu), CPU_INTERRUPT_HARD);
    }
}

static const MemoryRegionOps vibtanium_local_sapic_ipi_ops = {
    .read = vibtanium_local_sapic_ipi_read,
    .write = vibtanium_local_sapic_ipi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

static bool vibtanium_iosapic_register_index(uint32_t reg, unsigned *index,
                                             bool *high)
{
    if (reg < VIBTANIUM_IOSAPIC_RTE_LOW(0)) {
        return false;
    }
    reg -= VIBTANIUM_IOSAPIC_RTE_LOW(0);
    if ((reg >> 1) >= VIBTANIUM_IOSAPIC_REDIRECTION_COUNT) {
        return false;
    }

    *index = reg >> 1;
    *high = (reg & 1) != 0;
    return true;
}

static uint64_t vibtanium_iosapic_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    unsigned index;
    bool high;

    if (size != 4) {
        return UINT32_MAX;
    }

    switch (offset) {
    case VIBTANIUM_IOSAPIC_REG_SELECT:
        return vms->iosapic_select;
    case VIBTANIUM_IOSAPIC_WINDOW:
        if (vms->iosapic_select == VIBTANIUM_IOSAPIC_VERSION) {
            return ((VIBTANIUM_IOSAPIC_REDIRECTION_COUNT - 1) << 16) | 0x11;
        }
        if (vibtanium_iosapic_register_index(vms->iosapic_select, &index,
                                             &high)) {
            return high ? vms->iosapic_rte_high[index]
                        : vms->iosapic_rte_low[index];
        }
        return 0;
    case VIBTANIUM_IOSAPIC_EOI:
        return 0;
    default:
        return 0;
    }
}

static void vibtanium_iosapic_write(void *opaque, hwaddr offset,
                                    uint64_t value, unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    uint32_t old_low;
    unsigned index;
    bool high;

    if (size != 4) {
        return;
    }

    switch (offset) {
    case VIBTANIUM_IOSAPIC_REG_SELECT:
        vms->iosapic_select = value;
        break;
    case VIBTANIUM_IOSAPIC_WINDOW:
        if (vibtanium_iosapic_register_index(vms->iosapic_select, &index,
                                             &high)) {
            if (high) {
                vms->iosapic_rte_high[index] = value;
            } else {
                old_low = vms->iosapic_rte_low[index];
                vms->iosapic_rte_low[index] = value;
                if ((old_low & VIBTANIUM_IOSAPIC_RTE_MASK) &&
                    !(vms->iosapic_rte_low[index] &
                      VIBTANIUM_IOSAPIC_RTE_MASK) &&
                    vms->iosapic_irq_level[index]) {
                    vibtanium_iosapic_deliver_irq(vms, index);
                }
            }
        }
        break;
    case VIBTANIUM_IOSAPIC_EOI:
        break;
    default:
        break;
    }
}

static const MemoryRegionOps vibtanium_iosapic_ops = {
    .read = vibtanium_iosapic_read,
    .write = vibtanium_iosapic_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

typedef struct VibtaniumBlockReadOpaque {
    BlockBackend *blk;
} VibtaniumBlockReadOpaque;

typedef struct VibtaniumCachedBlockReadOpaque {
    uint8_t *data;
    uint64_t size;
} VibtaniumCachedBlockReadOpaque;

static bool vibtanium_range_end(uint64_t base, uint64_t size, uint64_t *end)
{
    if (size == 0 || base > UINT64_MAX - size) {
        return false;
    }

    *end = base + size;
    return true;
}

static bool vibtanium_ranges_overlap(uint64_t a_base, uint64_t a_size,
                                     uint64_t b_base, uint64_t b_size)
{
    uint64_t a_end;
    uint64_t b_end;

    if (!vibtanium_range_end(a_base, a_size, &a_end) ||
        !vibtanium_range_end(b_base, b_size, &b_end)) {
        return true;
    }

    return a_base < b_end && b_base < a_end;
}

static const char *vibtanium_efi_reserved_overlap(
    const VibtaniumEfiImage *image)
{
    static const struct {
        const char *name;
        uint64_t base;
        uint64_t size;
    } reserved[] = {
        {
            "EFI firmware tables",
            VIBTANIUM_EFI_BLOB_BASE,
            VIBTANIUM_EFI_BLOB_SIZE,
        },
        {
            "EFI stack",
            VIBTANIUM_EFI_STACK_BASE,
            VIBTANIUM_EFI_STACK_SIZE,
        },
        {
            "EFI backing store",
            VIBTANIUM_EFI_BACKING_STORE_BASE,
            VIBTANIUM_EFI_BACKING_STORE_SIZE,
        },
        {
            "EFI pool",
            VIBTANIUM_EFI_POOL_BASE,
            VIBTANIUM_EFI_POOL_SIZE,
        },
    };

    for (size_t i = 0; i < G_N_ELEMENTS(reserved); i++) {
        if (vibtanium_ranges_overlap(image->load_base, image->size,
                                     reserved[i].base, reserved[i].size)) {
            return reserved[i].name;
        }
    }

    return NULL;
}

static int vibtanium_block_pread(void *opaque,
                                 uint64_t offset,
                                 uint32_t bytes,
                                 void *buffer,
                                 Error **errp)
{
    VibtaniumBlockReadOpaque *read_opaque = opaque;
    int ret;

    ret = blk_pread(read_opaque->blk, offset, bytes, buffer, 0);
    if (ret < 0) {
        error_setg(errp, "block read failed: %s", strerror(-ret));
        return ret;
    }

    return 0;
}

static int vibtanium_cached_block_pread(void *opaque,
                                        uint64_t offset,
                                        uint32_t bytes,
                                        void *buffer,
                                        Error **errp)
{
    VibtaniumCachedBlockReadOpaque *cache = opaque;

    if (!cache || !cache->data ||
        offset > cache->size || bytes > cache->size - offset) {
        error_setg(errp,
                   "cached block read beyond media offset=0x%" PRIx64
                   " bytes=0x%x media-size=0x%" PRIx64,
                   offset, bytes, cache ? cache->size : 0);
        return -EINVAL;
    }

    memcpy(buffer, cache->data + offset, bytes);
    return 0;
}

static bool vibtanium_cache_boot_media(const VibtaniumEfiBlockDevice *src,
                                       VibtaniumEfiBlockDevice *cached,
                                       Error **errp)
{
    const uint32_t chunk_size = 4 * MiB;
    VibtaniumCachedBlockReadOpaque *opaque;
    uint64_t offset = 0;

    if (!src || !src->read || src->size == 0) {
        error_setg(errp, "cannot cache unavailable EFI boot media");
        return false;
    }

    opaque = g_new0(VibtaniumCachedBlockReadOpaque, 1);
    opaque->size = src->size;
    opaque->data = g_try_malloc(src->size);
    if (!opaque->data) {
        g_free(opaque);
        error_setg(errp, "could not allocate EFI boot media cache of 0x%"
                   PRIx64 " bytes",
                   src->size);
        return false;
    }

    while (offset < src->size) {
        uint32_t todo = MIN((uint64_t)chunk_size, src->size - offset);

        if (src->read(src->opaque, offset, todo, opaque->data + offset,
                      errp) < 0) {
            g_free(opaque->data);
            g_free(opaque);
            return false;
        }
        offset += todo;
    }

    *cached = *src;
    cached->read = vibtanium_cached_block_pread;
    cached->opaque = opaque;
    return true;
}

static void vibtanium_write_guest_blob(const char *name,
                                       hwaddr addr,
                                       const void *data,
                                       size_t size,
                                       size_t clear_size)
{
    MemTxResult result;

    result = address_space_write(&address_space_memory, addr,
                                 MEMTXATTRS_UNSPECIFIED, data, size);
    if (result != MEMTX_OK) {
        error_report("could not write IA-64 EFI blob '%s' at 0x%"
                     HWADDR_PRIx, name, addr);
        exit(1);
    }
    if (clear_size > size) {
        result = address_space_set(&address_space_memory, addr + size, 0,
                                   clear_size - size, MEMTXATTRS_UNSPECIFIED);
        if (result != MEMTX_OK) {
            error_report("could not clear IA-64 EFI blob '%s' at 0x%"
                         HWADDR_PRIx, name, addr + size);
            exit(1);
        }
    }
    address_space_flush_icache_range(&address_space_memory, addr, size);
}

static void vibtanium_commit_efi_image(VibtaniumMachineState *vms,
                                       MachineState *machine,
                                       VibtaniumEfiImage *image,
                                       const VibtaniumEfiBlockDevice *boot_media)
{
    g_autofree uint8_t *firmware_blob = NULL;
    size_t firmware_blob_size = 0;
    const char *linux_append = machine->kernel_cmdline;
    const char *overlap;

    if (!linux_append || !linux_append[0]) {
        linux_append = VIBTANIUM_DEFAULT_LINUX_APPEND;
    }

    if (machine->ram_size <= image->load_base ||
        image->size > machine->ram_size - image->load_base) {
        error_report("IA-64 EFI app '%s' image size 0x%" PRIx64
                     " at 0x%016" PRIx64 " does not fit in RAM",
                     image->source_path, (uint64_t)image->size,
                     image->load_base);
        exit(1);
    }
    overlap = vibtanium_efi_reserved_overlap(image);
    if (overlap) {
        error_report("IA-64 EFI app '%s' image at 0x%016" PRIx64
                     " size 0x%" PRIx64 " overlaps reserved %s",
                     image->source_path, image->load_base,
                     (uint64_t)image->size, overlap);
        exit(1);
    }

    firmware_blob = vibtanium_efi_build_firmware_blob(&firmware_blob_size,
                                                      image, boot_media);
    vibtanium_efi_input_set_auto_enter(vms->efi_auto_enter);
    vibtanium_efi_register_boot_media(boot_media);
    vibtanium_efi_register_loaded_image(image->load_base, image->size);
    vibtanium_efi_set_linux_cmdline_append(linux_append);
    vibtanium_write_guest_blob("vibtanium.efi-tables",
                               VIBTANIUM_EFI_BLOB_BASE, firmware_blob,
                               firmware_blob_size, VIBTANIUM_EFI_BLOB_SIZE);
    vibtanium_write_guest_blob("vibtanium.efi-app", image->load_base,
                               image->data, image->size, image->size);
    vibtanium_efi_prepare_cpu(&vms->cpu->env, image);

    warn_report("%s", image->message);
    warn_report("vibtanium EFI handoff image-handle=0x%016" PRIx64
                " system-table=0x%016" PRIx64
                " con-out=0x%016" PRIx64
                " loaded-image=0x%016" PRIx64,
                (uint64_t)VIBTANIUM_EFI_IMAGE_HANDLE,
                (uint64_t)VIBTANIUM_EFI_SYSTEM_TABLE,
                (uint64_t)VIBTANIUM_EFI_CON_OUT,
                (uint64_t)VIBTANIUM_EFI_LOADED_IMAGE);
    warn_report("IA-64 instruction execution is minimal; unsupported "
                "bundles report the current execution frontier");
}

static void vibtanium_warn_frontier(VibtaniumEfiFrontierKind kind,
                                    uint64_t guest_ip,
                                    const char *state,
                                    const char *detail)
{
    char message[384];

    vibtanium_efi_format_frontier(message, sizeof(message), kind, guest_ip,
                                  state, detail);
    warn_report("%s", message);
}

static void vibtanium_trace_loader_frontier(const VibtaniumEfiImage *image)
{
    const char *pending =
        "pending runtime observation; use QEMU trace-events or "
        "VIBTANIUM_EFI_TRACE/VIBTANIUM_IA64_PROGRESS";

    vibtanium_warn_frontier(VIBTANIUM_EFI_FRONTIER_IMAGE_ENTRY, image->entry,
                            "ready", image->source_path);
    vibtanium_warn_frontier(VIBTANIUM_EFI_FRONTIER_FILE_READ, image->entry,
                            "firmware-loader-complete", image->source_path);
    vibtanium_warn_frontier(VIBTANIUM_EFI_FRONTIER_EFI_SERVICE_CALL,
                            image->entry, "dispatch-enabled", pending);
    vibtanium_warn_frontier(VIBTANIUM_EFI_FRONTIER_MEMORY_MAP, image->entry,
                            "runtime-tracepoint-ready", pending);
    vibtanium_warn_frontier(VIBTANIUM_EFI_FRONTIER_EXIT_BOOT_SERVICES,
                            image->entry, "runtime-tracepoint-ready",
                            pending);
    vibtanium_warn_frontier(VIBTANIUM_EFI_FRONTIER_KERNEL_ENTRY, image->entry,
                            "not-observed-at-loader", pending);
    vibtanium_warn_frontier(VIBTANIUM_EFI_FRONTIER_BOOT_PARAMETERS,
                            image->entry, "not-observed-at-loader", pending);
    vibtanium_warn_frontier(VIBTANIUM_EFI_FRONTIER_SAL_PAL_CALL, image->entry,
                            "not-observed-at-loader", pending);
}

static bool vibtanium_load_explicit_efi_app(VibtaniumMachineState *vms,
                                            MachineState *machine)
{
    Error *local_err = NULL;
    VibtaniumEfiImage image;

    if (!machine->kernel_filename) {
        return false;
    }

    if (!vibtanium_efi_image_from_file(machine->kernel_filename,
                                       VIBTANIUM_EFI_APP_BASE, &image,
                                       &local_err)) {
        error_reportf_err(local_err, "could not load IA-64 EFI app '%s': ",
                          machine->kernel_filename);
        exit(1);
    }

    vibtanium_commit_efi_image(vms, machine, &image, NULL);
    vibtanium_trace_loader_frontier(&image);
    vibtanium_efi_image_destroy(&image);
    return true;
}

static bool vibtanium_try_media_efi_app(VibtaniumMachineState *vms,
                                        MachineState *machine,
                                        VibtaniumEfiBlockDevice *dev,
                                        const char *path,
                                        const VibtaniumEfiBootEntry *entry)
{
    Error *local_err = NULL;
    VibtaniumEfiStorageReport report;
    g_autofree uint8_t *file_data = NULL;
    size_t file_size = 0;
    VibtaniumEfiImage image;
    VibtaniumEfiBlockDevice cached_dev;
    char source[384];
    const char *kind = entry ? "boot-entry" : "discovery";
    const char *boot_path = path && *path ? path : VIBTANIUM_EFI_FALLBACK_PATH;

    if (!vibtanium_efi_media_read_path(dev, boot_path,
                                       &file_data, &file_size, source,
                                       sizeof(source), &report, &local_err)) {
        warn_report("vibtanium EFI %s media=%s path=%s status=%s "
                    "reason=%s",
                    kind,
                    dev->name ? dev->name : "<unnamed>",
                    boot_path,
                    vibtanium_efi_storage_status_name(report.status),
                    report.message);
        error_free(local_err);
        return false;
    }

    warn_report("vibtanium EFI %s media=%s path=%s status=%s %s",
                kind,
                dev->name ? dev->name : "<unnamed>",
                boot_path,
                vibtanium_efi_storage_status_name(report.status),
                report.message);

    local_err = NULL;
    if (!vibtanium_efi_image_from_buffer(source, file_data, file_size,
                                         VIBTANIUM_EFI_APP_BASE, &image,
                                         &local_err)) {
        warn_report("vibtanium EFI %s media=%s path=%s status=%s "
                    "reason=%s",
                    kind,
                    dev->name ? dev->name : "<unnamed>",
                    boot_path,
                    vibtanium_efi_status_name(VIBTANIUM_EFI_LOAD_ERROR),
                    error_get_pretty(local_err));
        error_free(local_err);
        return false;
    }

    if (entry && entry->load_options && entry->load_options->len != 0) {
        image.load_options_size = entry->load_options->len;
        image.load_options = g_memdup2(entry->load_options->data,
                                       entry->load_options->len);
    }

    local_err = NULL;
    if (!vibtanium_cache_boot_media(dev, &cached_dev, &local_err)) {
        warn_report("vibtanium EFI %s media=%s path=%s status=%s "
                    "reason=%s",
                    kind,
                    dev->name ? dev->name : "<unnamed>",
                    boot_path,
                    vibtanium_efi_status_name(VIBTANIUM_EFI_DEVICE_ERROR),
                    error_get_pretty(local_err));
        error_free(local_err);
        vibtanium_efi_image_destroy(&image);
        return false;
    }

    warn_report("vibtanium EFI media cache name=%s bytes=%" PRIu64,
                cached_dev.name ? cached_dev.name : "<unnamed>",
                cached_dev.size);

    vibtanium_commit_efi_image(vms, machine, &image, &cached_dev);
    vibtanium_trace_loader_frontier(&image);
    vibtanium_efi_image_destroy(&image);
    return true;
}

static bool vibtanium_try_boot_entry_on_media(VibtaniumMachineState *vms,
                                              MachineState *machine,
                                              const VibtaniumEfiBootEntry *entry)
{
    BlockBackend *blk = NULL;

    while ((blk = blk_next(blk)) != NULL) {
        DriveInfo *dinfo = blk_legacy_dinfo(blk);
        const char *name = blk_name(blk);
        bool available = blk_is_available(blk);
        bool cdrom = dinfo && dinfo->media_cd;
        int64_t length = available ? blk_getlength(blk) : -ENOMEDIUM;
        VibtaniumBlockReadOpaque *read_opaque;
        VibtaniumEfiBlockDevice dev;

        if (!available || length <= 0) {
            continue;
        }

        read_opaque = g_new0(VibtaniumBlockReadOpaque, 1);
        read_opaque->blk = blk;
        dev = (VibtaniumEfiBlockDevice) {
            .name = name && *name ? name : "<unnamed>",
            .size = length,
            .block_size = cdrom ? 2048 : 512,
            .read_only = !blk_is_writable(blk),
            .removable = cdrom,
            .cdrom = cdrom,
            .read = vibtanium_block_pread,
            .opaque = read_opaque,
        };

        if (vibtanium_try_media_efi_app(vms, machine, &dev,
                                        entry->loader_path, entry)) {
            g_free(read_opaque);
            return true;
        }
        g_free(read_opaque);
    }

    return false;
}

static bool vibtanium_boot_nvram_efi_app(VibtaniumMachineState *vms,
                                         MachineState *machine)
{
    g_autoptr(GPtrArray) entries = NULL;
    Error *local_err = NULL;

    if (!vibtanium_efi_vars_boot_entries(&entries, true, &local_err)) {
        error_reportf_err(local_err, "could not read IA-64 EFI boot variables: ");
        exit(1);
    }

    for (size_t i = 0; i < entries->len; i++) {
        VibtaniumEfiBootEntry *entry = g_ptr_array_index(entries, i);

        warn_report("vibtanium EFI boot entry Boot%04X path=%s%s",
                    entry->id, entry->loader_path,
                    entry->from_boot_next ? " source=BootNext" : "");
        if (!vibtanium_try_boot_entry_on_media(vms, machine, entry)) {
            continue;
        }
        local_err = NULL;
        if (!vibtanium_efi_vars_set_boot_current(entry->id, &local_err)) {
            error_reportf_err(local_err,
                              "could not set IA-64 EFI BootCurrent: ");
            exit(1);
        }
        return true;
    }

    return false;
}

static bool vibtanium_discover_efi_app(VibtaniumMachineState *vms,
                                       MachineState *machine)
{
    BlockBackend *blk = NULL;
    unsigned media_index = 0;
    unsigned media_candidates = 0;

    while ((blk = blk_next(blk)) != NULL) {
        DriveInfo *dinfo = blk_legacy_dinfo(blk);
        const char *name = blk_name(blk);
        bool available = blk_is_available(blk);
        bool cdrom = dinfo && dinfo->media_cd;
        int64_t length = available ? blk_getlength(blk) : -ENOMEDIUM;
        VibtaniumBlockReadOpaque *read_opaque = g_new0(VibtaniumBlockReadOpaque, 1);
        VibtaniumEfiBlockDevice dev = {
            .name = name && *name ? name : "<unnamed>",
            .size = length > 0 ? length : 0,
            .block_size = cdrom ? 2048 : 512,
            .read_only = !blk_is_writable(blk),
            .removable = cdrom,
            .cdrom = cdrom,
            .read = vibtanium_block_pread,
            .opaque = read_opaque,
        };

        read_opaque->blk = blk;

        warn_report("vibtanium EFI media[%u] name=%s available=%s cdrom=%s "
                    "writable=%s bytes=%" PRId64,
                    media_index++, dev.name, available ? "yes" : "no",
                    cdrom ? "yes" : "no",
                    dev.read_only ? "no" : "yes", length);

        if (!available) {
            g_free(read_opaque);
            continue;
        }
        if (length <= 0) {
            warn_report("vibtanium EFI media %s skipped: unavailable length "
                        "%" PRId64,
                        dev.name, length);
            g_free(read_opaque);
            continue;
        }

        media_candidates++;
        if (vibtanium_try_media_efi_app(vms, machine, &dev,
                                        VIBTANIUM_EFI_FALLBACK_PATH, NULL)) {
            g_free(read_opaque);
            return true;
        }
        g_free(read_opaque);
    }

    warn_report("vibtanium EFI discovery found no boot app path=%s "
                "media=%u media-candidates=%u",
                VIBTANIUM_EFI_FALLBACK_PATH, media_index,
                media_candidates);
    return false;
}

#define VIBTANIUM_EFI_BOOT_MANAGER_DEFAULT "timeout"
#define VIBTANIUM_EFI_BOOT_MANAGER_TIMEOUT_MS 5000
#define VIBTANIUM_EFI_BOOT_MANAGER_TICK_MS 100
#define VIBTANIUM_EFI_BOOT_MANAGER_COLUMNS 80
#define VIBTANIUM_EFI_BOOT_MANAGER_ROWS 25
#define VIBTANIUM_EFI_BOOT_MANAGER_ATTR 0x1f
#define VIBTANIUM_EFI_BOOT_MANAGER_HILITE 0x70
#define VIBTANIUM_EFI_BOOT_MANAGER_MUTED 0x17
#define VIBTANIUM_EFI_BOOT_MANAGER_ERROR 0x4f

typedef enum VibtaniumEfiBootChoiceKind {
    VIBTANIUM_EFI_BOOT_CHOICE_NVRAM,
    VIBTANIUM_EFI_BOOT_CHOICE_FALLBACK,
    VIBTANIUM_EFI_BOOT_CHOICE_EXPLICIT,
} VibtaniumEfiBootChoiceKind;

typedef enum VibtaniumEfiBootManagerScreen {
    VIBTANIUM_EFI_BOOT_SCREEN_MENU,
    VIBTANIUM_EFI_BOOT_SCREEN_MAINTENANCE,
    VIBTANIUM_EFI_BOOT_SCREEN_EDIT_DESCRIPTION,
    VIBTANIUM_EFI_BOOT_SCREEN_EDIT_PATH,
    VIBTANIUM_EFI_BOOT_SCREEN_EDIT_OPTIONS,
} VibtaniumEfiBootManagerScreen;

typedef struct VibtaniumEfiBootChoice {
    VibtaniumEfiBootChoiceKind kind;
    VibtaniumEfiBootEntry *entry;
    BlockBackend *blk;
    char label[192];
    char detail[320];
    char loader_path[256];
} VibtaniumEfiBootChoice;

struct VibtaniumEfiBootManagerState {
    VibtaniumMachineState *vms;
    MachineState *machine;
    QEMUTimer *timer;
    GPtrArray *choices;
    VibtaniumEfiBootManagerScreen screen;
    size_t selected;
    bool countdown_active;
    bool booted;
    bool has_boot_next;
    int64_t deadline_ms;
    char status[320];
    uint16_t edit_id;
    char edit_description[128];
    char edit_path[256];
    char edit_options[256];
    char edit_buffer[256];
    size_t edit_len;
};

static void vibtanium_boot_choice_free(gpointer opaque)
{
    VibtaniumEfiBootChoice *choice = opaque;

    if (!choice) {
        return;
    }
    vibtanium_efi_boot_entry_free(choice->entry);
    g_free(choice);
}

static VibtaniumEfiBootEntry *vibtanium_boot_entry_dup(
    const VibtaniumEfiBootEntry *entry)
{
    VibtaniumEfiBootEntry *copy;

    if (!entry) {
        return NULL;
    }

    copy = g_new0(VibtaniumEfiBootEntry, 1);
    copy->id = entry->id;
    copy->active = entry->active;
    copy->from_boot_next = entry->from_boot_next;
    g_strlcpy(copy->description, entry->description,
              sizeof(copy->description));
    g_strlcpy(copy->loader_path, entry->loader_path,
              sizeof(copy->loader_path));
    copy->load_options = g_byte_array_new();
    if (entry->load_options && entry->load_options->len != 0) {
        g_byte_array_append(copy->load_options, entry->load_options->data,
                            entry->load_options->len);
    }
    return copy;
}

static void vibtanium_boot_manager_set_status(
    VibtaniumEfiBootManagerState *bm,
    const char *fmt,
    ...) G_GNUC_PRINTF(2, 3);

static void vibtanium_boot_manager_set_status(
    VibtaniumEfiBootManagerState *bm,
    const char *fmt,
    ...)
{
    va_list ap;

    va_start(ap, fmt);
    g_vsnprintf(bm->status, sizeof(bm->status), fmt, ap);
    va_end(ap);
}

static bool vibtanium_blk_media_device(BlockBackend *blk,
                                       VibtaniumBlockReadOpaque **opaque_out,
                                       VibtaniumEfiBlockDevice *dev)
{
    DriveInfo *dinfo;
    const char *name;
    int64_t length;
    bool cdrom;
    VibtaniumBlockReadOpaque *read_opaque;

    if (!blk || !blk_is_available(blk)) {
        return false;
    }

    dinfo = blk_legacy_dinfo(blk);
    cdrom = dinfo && dinfo->media_cd;

    length = blk_getlength(blk);
    if (length <= 0) {
        return false;
    }

    name = blk_name(blk);
    read_opaque = g_new0(VibtaniumBlockReadOpaque, 1);
    read_opaque->blk = blk;
    *dev = (VibtaniumEfiBlockDevice) {
        .name = name && *name ? name : "<unnamed>",
        .size = length,
        .block_size = cdrom ? 2048 : 512,
        .read_only = !blk_is_writable(blk),
        .removable = cdrom,
        .cdrom = cdrom,
        .read = vibtanium_block_pread,
        .opaque = read_opaque,
    };
    *opaque_out = read_opaque;
    return true;
}

static VibtaniumEfiBootChoice *vibtanium_boot_choice_new(
    VibtaniumEfiBootChoiceKind kind)
{
    VibtaniumEfiBootChoice *choice = g_new0(VibtaniumEfiBootChoice, 1);

    choice->kind = kind;
    return choice;
}

static void vibtanium_boot_manager_add_nvram_choices(
    VibtaniumEfiBootManagerState *bm)
{
    g_autoptr(GPtrArray) entries = NULL;
    Error *local_err = NULL;

    if (!vibtanium_efi_vars_boot_entries(&entries, false, &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not read EFI boot variables: %s",
            error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    for (size_t i = 0; i < entries->len; i++) {
        VibtaniumEfiBootEntry *entry = g_ptr_array_index(entries, i);
        VibtaniumEfiBootChoice *choice =
            vibtanium_boot_choice_new(VIBTANIUM_EFI_BOOT_CHOICE_NVRAM);

        choice->entry = vibtanium_boot_entry_dup(entry);
        g_strlcpy(choice->loader_path, entry->loader_path,
                  sizeof(choice->loader_path));
        if (entry->from_boot_next) {
            bm->has_boot_next = true;
            g_snprintf(choice->label, sizeof(choice->label),
                       "BootNext -> Boot%04X  %s", entry->id,
                       entry->description[0] ? entry->description
                                             : entry->loader_path);
        } else {
            g_snprintf(choice->label, sizeof(choice->label),
                       "Boot%04X  %s", entry->id,
                       entry->description[0] ? entry->description
                                             : entry->loader_path);
        }
        g_snprintf(choice->detail, sizeof(choice->detail), "%s",
                   entry->loader_path);
        g_ptr_array_add(bm->choices, choice);
    }
}

static void vibtanium_boot_manager_add_fallback_choices(
    VibtaniumEfiBootManagerState *bm)
{
    BlockBackend *blk = NULL;

    while ((blk = blk_next(blk)) != NULL) {
        VibtaniumBlockReadOpaque *read_opaque = NULL;
        VibtaniumEfiBlockDevice dev;
        VibtaniumEfiStorageReport report;
        g_autofree uint8_t *file_data = NULL;
        g_autofree char *source = NULL;
        size_t file_size = 0;
        Error *local_err = NULL;

        if (!vibtanium_blk_media_device(blk, &read_opaque, &dev)) {
            continue;
        }

        source = g_malloc0(384);
        if (vibtanium_efi_media_read_path(&dev, VIBTANIUM_EFI_FALLBACK_PATH,
                                          &file_data, &file_size, source,
                                          384, &report, &local_err)) {
            VibtaniumEfiBootChoice *choice =
                vibtanium_boot_choice_new(VIBTANIUM_EFI_BOOT_CHOICE_FALLBACK);

            choice->blk = blk;
            g_strlcpy(choice->loader_path, VIBTANIUM_EFI_FALLBACK_PATH,
                      sizeof(choice->loader_path));
            g_snprintf(choice->label, sizeof(choice->label),
                       "%s media  %s", dev.cdrom ? "Removable" : "Fixed",
                       dev.name);
            g_snprintf(choice->detail, sizeof(choice->detail),
                       "%s (%zu bytes)", source, file_size);
            g_ptr_array_add(bm->choices, choice);
        }
        error_free(local_err);
        g_free(read_opaque);
    }
}

static void vibtanium_boot_manager_add_explicit_choice(
    VibtaniumEfiBootManagerState *bm)
{
    MachineState *machine = bm->machine;
    VibtaniumEfiBootChoice *choice;

    if (!machine->kernel_filename) {
        return;
    }

    choice = vibtanium_boot_choice_new(VIBTANIUM_EFI_BOOT_CHOICE_EXPLICIT);
    g_strlcpy(choice->loader_path, machine->kernel_filename,
              sizeof(choice->loader_path));
    g_snprintf(choice->label, sizeof(choice->label),
               "Explicit EFI application");
    g_snprintf(choice->detail, sizeof(choice->detail), "%s",
               machine->kernel_filename);
    g_ptr_array_add(bm->choices, choice);
}

static void vibtanium_boot_manager_rebuild_choices(
    VibtaniumEfiBootManagerState *bm)
{
    uint16_t selected_id = UINT16_MAX;
    VibtaniumEfiBootChoice *old_choice = NULL;

    if (bm->choices && bm->choices->len != 0 &&
        bm->selected < bm->choices->len) {
        old_choice = g_ptr_array_index(bm->choices, bm->selected);
        if (old_choice->entry) {
            selected_id = old_choice->entry->id;
        }
    }

    g_clear_pointer(&bm->choices, g_ptr_array_unref);
    bm->choices =
        g_ptr_array_new_with_free_func(vibtanium_boot_choice_free);
    bm->has_boot_next = false;

    vibtanium_boot_manager_add_nvram_choices(bm);
    vibtanium_boot_manager_add_fallback_choices(bm);
    vibtanium_boot_manager_add_explicit_choice(bm);

    bm->selected = 0;
    if (selected_id != UINT16_MAX) {
        for (size_t i = 0; i < bm->choices->len; i++) {
            VibtaniumEfiBootChoice *choice =
                g_ptr_array_index(bm->choices, i);

            if (choice->entry && choice->entry->id == selected_id) {
                bm->selected = i;
                break;
            }
        }
    }
}

static void vibtanium_boot_manager_print_line(uint32_t row,
                                              uint32_t attribute,
                                              const char *fmt,
                                              ...) G_GNUC_PRINTF(3, 4);

static void vibtanium_boot_manager_print_line(uint32_t row,
                                              uint32_t attribute,
                                              const char *fmt,
                                              ...)
{
    g_autofree char *line = NULL;
    g_autofree char *display = NULL;
    va_list ap;
    size_t len;

    if (row >= VIBTANIUM_EFI_BOOT_MANAGER_ROWS) {
        return;
    }

    va_start(ap, fmt);
    line = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    display = g_strndup(line ? line : "", VIBTANIUM_EFI_BOOT_MANAGER_COLUMNS);
    len = strlen(display);

    vibtanium_efi_console_set_cursor_position(0, row);
    vibtanium_efi_console_set_attribute(attribute);
    for (size_t i = 0; i < len; i++) {
        vibtanium_efi_console_putchar(display[i]);
    }
    for (size_t i = len; i < VIBTANIUM_EFI_BOOT_MANAGER_COLUMNS; i++) {
        vibtanium_efi_console_putchar(' ');
    }
}

static void vibtanium_boot_manager_draw_menu(VibtaniumEfiBootManagerState *bm)
{
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    int64_t remaining = 0;

    vibtanium_efi_console_set_attribute(VIBTANIUM_EFI_BOOT_MANAGER_ATTR);
    vibtanium_efi_console_enable_cursor(false);
    vibtanium_efi_console_clear();

    vibtanium_boot_manager_print_line(
        0, VIBTANIUM_EFI_BOOT_MANAGER_HILITE,
        "                         QEMU IA-64 EFI v1.0                         ");
    vibtanium_boot_manager_print_line(
        1, VIBTANIUM_EFI_BOOT_MANAGER_MUTED,
        "                           Vibtanium firmware                           ");

    if (bm->countdown_active && bm->deadline_ms > now) {
        remaining = (bm->deadline_ms - now + 999) / 1000;
    }

    if (bm->countdown_active) {
        vibtanium_boot_manager_print_line(
            3, VIBTANIUM_EFI_BOOT_MANAGER_ATTR,
            "Default boot in %" PRId64
            " seconds. Press any key to stop automatic boot.",
            remaining);
    } else {
        vibtanium_boot_manager_print_line(
            3, VIBTANIUM_EFI_BOOT_MANAGER_ATTR,
            "Automatic boot paused by user input.");
    }
    if (bm->status[0]) {
        vibtanium_boot_manager_print_line(
            4, VIBTANIUM_EFI_BOOT_MANAGER_ERROR, "%s", bm->status);
    } else {
        vibtanium_boot_manager_print_line(
            4, VIBTANIUM_EFI_BOOT_MANAGER_ATTR,
            "Select an EFI application to launch.");
    }

    if (!bm->choices || bm->choices->len == 0) {
        vibtanium_boot_manager_print_line(
            7, VIBTANIUM_EFI_BOOT_MANAGER_ERROR,
            "No EFI boot entries or media fallback applications found.");
    } else {
        size_t visible = MIN((size_t)7, bm->choices->len);
        size_t top = 0;

        if (bm->selected >= visible) {
            top = bm->selected - visible + 1;
        }
        if (top + visible > bm->choices->len) {
            top = bm->choices->len - visible;
        }

        for (size_t row = 0; row < visible; row++) {
            size_t index = top + row;
            VibtaniumEfiBootChoice *choice =
                g_ptr_array_index(bm->choices, index);
            uint32_t attr = index == bm->selected
                            ? VIBTANIUM_EFI_BOOT_MANAGER_HILITE
                            : VIBTANIUM_EFI_BOOT_MANAGER_ATTR;

            vibtanium_boot_manager_print_line(
                7 + row * 2, attr, "%c %-67s",
                index == bm->selected ? '>' : ' ', choice->label);
            vibtanium_boot_manager_print_line(
                8 + row * 2, attr, "  %-69s", choice->detail);
        }
    }

    vibtanium_boot_manager_print_line(
        21, VIBTANIUM_EFI_BOOT_MANAGER_MUTED,
        "Up/Down: select   Enter: boot   Esc: maintenance");
    vibtanium_boot_manager_print_line(
        22, VIBTANIUM_EFI_BOOT_MANAGER_MUTED,
        "Policy: efi-boot-manager=timeout|pause|off");
    vibtanium_efi_console_update_rect(0, 0, VIBTANIUM_FRAMEBUFFER_WIDTH,
                                      VIBTANIUM_FRAMEBUFFER_HEIGHT);
}

static bool vibtanium_boot_choice_is_nvram(
    const VibtaniumEfiBootChoice *choice)
{
    return choice && choice->kind == VIBTANIUM_EFI_BOOT_CHOICE_NVRAM &&
           choice->entry;
}

static bool vibtanium_boot_choice_is_fallback(
    const VibtaniumEfiBootChoice *choice)
{
    return choice && choice->kind == VIBTANIUM_EFI_BOOT_CHOICE_FALLBACK &&
           choice->blk;
}

static void vibtanium_boot_manager_draw_maintenance(
    VibtaniumEfiBootManagerState *bm)
{
    vibtanium_efi_console_set_attribute(VIBTANIUM_EFI_BOOT_MANAGER_ATTR);
    vibtanium_efi_console_enable_cursor(false);
    vibtanium_efi_console_clear();

    vibtanium_boot_manager_print_line(
        0, VIBTANIUM_EFI_BOOT_MANAGER_HILITE,
        "                         QEMU IA-64 EFI v1.0                         ");
    vibtanium_boot_manager_print_line(
        2, VIBTANIUM_EFI_BOOT_MANAGER_ATTR,
        "Firmware maintenance");
    vibtanium_boot_manager_print_line(
        3, bm->status[0] ? VIBTANIUM_EFI_BOOT_MANAGER_ERROR
                         : VIBTANIUM_EFI_BOOT_MANAGER_MUTED,
        bm->status[0] ? "%s" : "Edits are saved immediately to EFI NVRAM.",
        bm->status);

    if (!bm->choices || bm->choices->len == 0) {
        vibtanium_boot_manager_print_line(
            6, VIBTANIUM_EFI_BOOT_MANAGER_ERROR,
            "No boot entries are available.");
    } else {
        size_t visible = MIN((size_t)12, bm->choices->len);
        size_t top = 0;

        if (bm->selected >= visible) {
            top = bm->selected - visible + 1;
        }
        if (top + visible > bm->choices->len) {
            top = bm->choices->len - visible;
        }

        for (size_t row = 0; row < visible; row++) {
            size_t index = top + row;
            VibtaniumEfiBootChoice *choice =
                g_ptr_array_index(bm->choices, index);
            const char *kind = choice->kind == VIBTANIUM_EFI_BOOT_CHOICE_NVRAM
                               ? "NVRAM"
                               : choice->kind ==
                                 VIBTANIUM_EFI_BOOT_CHOICE_FALLBACK
                                 ? "MEDIA" : "FILE";
            uint32_t attr = index == bm->selected
                            ? VIBTANIUM_EFI_BOOT_MANAGER_HILITE
                            : VIBTANIUM_EFI_BOOT_MANAGER_ATTR;

            vibtanium_boot_manager_print_line(
                6 + row, attr, "%c %-5s %-61s",
                index == bm->selected ? '>' : ' ', kind, choice->label);
        }
    }

    vibtanium_boot_manager_print_line(
        19, VIBTANIUM_EFI_BOOT_MANAGER_MUTED,
        "A: add media fallback   R: remove NVRAM entry   E: edit NVRAM entry");
    vibtanium_boot_manager_print_line(
        20, VIBTANIUM_EFI_BOOT_MANAGER_MUTED,
        "U/D: reorder NVRAM entry   Enter: boot selected   Esc: back");
    vibtanium_efi_console_update_rect(0, 0, VIBTANIUM_FRAMEBUFFER_WIDTH,
                                      VIBTANIUM_FRAMEBUFFER_HEIGHT);
}

static void vibtanium_boot_manager_draw_edit(
    VibtaniumEfiBootManagerState *bm,
    const char *title,
    const char *hint)
{
    vibtanium_efi_console_set_attribute(VIBTANIUM_EFI_BOOT_MANAGER_ATTR);
    vibtanium_efi_console_enable_cursor(true);
    vibtanium_efi_console_clear();

    vibtanium_boot_manager_print_line(
        0, VIBTANIUM_EFI_BOOT_MANAGER_HILITE,
        "                         QEMU IA-64 EFI v1.0                         ");
    vibtanium_boot_manager_print_line(
        3, VIBTANIUM_EFI_BOOT_MANAGER_ATTR, "%s", title);
    vibtanium_boot_manager_print_line(
        5, VIBTANIUM_EFI_BOOT_MANAGER_MUTED, "%s", hint);
    vibtanium_boot_manager_print_line(
        8, VIBTANIUM_EFI_BOOT_MANAGER_HILITE, "%s", bm->edit_buffer);
    vibtanium_boot_manager_print_line(
        20, VIBTANIUM_EFI_BOOT_MANAGER_MUTED,
        "Enter: accept   Backspace: delete   Esc: cancel");
    vibtanium_efi_console_set_cursor_position(
        MIN((uint32_t)bm->edit_len, VIBTANIUM_EFI_BOOT_MANAGER_COLUMNS - 1),
        8);
    vibtanium_efi_console_update_rect(0, 0, VIBTANIUM_FRAMEBUFFER_WIDTH,
                                      VIBTANIUM_FRAMEBUFFER_HEIGHT);
}

static void vibtanium_boot_manager_draw(VibtaniumEfiBootManagerState *bm)
{
    switch (bm->screen) {
    case VIBTANIUM_EFI_BOOT_SCREEN_MENU:
        vibtanium_boot_manager_draw_menu(bm);
        break;
    case VIBTANIUM_EFI_BOOT_SCREEN_MAINTENANCE:
        vibtanium_boot_manager_draw_maintenance(bm);
        break;
    case VIBTANIUM_EFI_BOOT_SCREEN_EDIT_DESCRIPTION:
        vibtanium_boot_manager_draw_edit(
            bm, "Edit boot entry description",
            "ASCII text shown in the firmware menu.");
        break;
    case VIBTANIUM_EFI_BOOT_SCREEN_EDIT_PATH:
        vibtanium_boot_manager_draw_edit(
            bm, "Edit EFI loader path",
            "Example: \\EFI\\BOOT\\BOOTIA64.EFI");
        break;
    case VIBTANIUM_EFI_BOOT_SCREEN_EDIT_OPTIONS:
        vibtanium_boot_manager_draw_edit(
            bm, "Edit optional load options",
            "ASCII options; leave empty to clear.");
        break;
    }
}

static bool vibtanium_boot_manager_consume_boot_next(
    VibtaniumEfiBootManagerState *bm)
{
    Error *local_err = NULL;

    if (!bm->has_boot_next) {
        return true;
    }

    if (!vibtanium_efi_vars_delete_boot_next(&local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not consume BootNext: %s", error_get_pretty(local_err));
        error_free(local_err);
        return false;
    }
    bm->has_boot_next = false;
    return true;
}

static bool vibtanium_boot_manager_boot_choice(
    VibtaniumEfiBootManagerState *bm)
{
    VibtaniumMachineState *vms = bm->vms;
    MachineState *machine = bm->machine;
    VibtaniumEfiBootChoice *choice;
    Error *local_err = NULL;
    bool ok = false;

    if (!bm->choices || bm->choices->len == 0 ||
        bm->selected >= bm->choices->len) {
        vibtanium_boot_manager_set_status(bm, "No boot entry is selected.");
        return false;
    }

    choice = g_ptr_array_index(bm->choices, bm->selected);
    if (!vibtanium_boot_manager_consume_boot_next(bm)) {
        return false;
    }

    switch (choice->kind) {
    case VIBTANIUM_EFI_BOOT_CHOICE_NVRAM:
        warn_report("vibtanium EFI boot manager selected Boot%04X path=%s",
                    choice->entry->id, choice->entry->loader_path);
        ok = vibtanium_try_boot_entry_on_media(vms, machine, choice->entry);
        if (ok &&
            !vibtanium_efi_vars_set_boot_current(choice->entry->id,
                                                 &local_err)) {
            error_reportf_err(local_err,
                              "could not set IA-64 EFI BootCurrent: ");
            exit(1);
        }
        break;
    case VIBTANIUM_EFI_BOOT_CHOICE_FALLBACK: {
        VibtaniumBlockReadOpaque *read_opaque = NULL;
        VibtaniumEfiBlockDevice dev;

        if (vibtanium_blk_media_device(choice->blk, &read_opaque, &dev)) {
            warn_report("vibtanium EFI boot manager selected media=%s path=%s",
                        dev.name, choice->loader_path);
            ok = vibtanium_try_media_efi_app(vms, machine, &dev,
                                             choice->loader_path, NULL);
        }
        g_free(read_opaque);
        break;
    }
    case VIBTANIUM_EFI_BOOT_CHOICE_EXPLICIT:
        warn_report("vibtanium EFI boot manager selected explicit=%s",
                    choice->loader_path);
        ok = vibtanium_load_explicit_efi_app(vms, machine);
        break;
    }

    if (!ok) {
        vibtanium_boot_manager_set_status(
            bm, "Selected entry failed to load: %s", choice->label);
        vibtanium_boot_manager_rebuild_choices(bm);
        return false;
    }

    bm->booted = true;
    timer_del(bm->timer);
    vibtanium_efi_console_enable_cursor(false);
    CPU(vms->cpu)->halted = false;
    cpu_resume(CPU(vms->cpu));
    return true;
}

static void vibtanium_boot_manager_select_delta(
    VibtaniumEfiBootManagerState *bm,
    int delta)
{
    if (!bm->choices || bm->choices->len == 0) {
        return;
    }

    if (delta < 0) {
        bm->selected = bm->selected == 0 ? bm->choices->len - 1
                                         : bm->selected - 1;
    } else if (delta > 0) {
        bm->selected = (bm->selected + 1) % bm->choices->len;
    }
}

static void vibtanium_boot_manager_edit_set_buffer(
    VibtaniumEfiBootManagerState *bm,
    const char *value)
{
    g_strlcpy(bm->edit_buffer, value ? value : "", sizeof(bm->edit_buffer));
    bm->edit_len = strlen(bm->edit_buffer);
}

static void vibtanium_boot_manager_begin_edit(
    VibtaniumEfiBootManagerState *bm)
{
    VibtaniumEfiBootChoice *choice;

    if (!bm->choices || bm->selected >= bm->choices->len) {
        return;
    }

    choice = g_ptr_array_index(bm->choices, bm->selected);
    if (!vibtanium_boot_choice_is_nvram(choice)) {
        vibtanium_boot_manager_set_status(
            bm, "Select an NVRAM Boot#### entry to edit.");
        return;
    }

    bm->edit_id = choice->entry->id;
    g_strlcpy(bm->edit_description, choice->entry->description,
              sizeof(bm->edit_description));
    g_strlcpy(bm->edit_path, choice->entry->loader_path,
              sizeof(bm->edit_path));
    bm->edit_options[0] = '\0';
    if (choice->entry->load_options && choice->entry->load_options->len != 0) {
        size_t len = MIN(choice->entry->load_options->len,
                         sizeof(bm->edit_options) - 1);
        bool printable = true;

        for (size_t i = 0; i < len; i++) {
            uint8_t ch = choice->entry->load_options->data[i];

            if (ch < 0x20 || ch > 0x7e) {
                printable = false;
                break;
            }
        }
        if (printable) {
            memcpy(bm->edit_options, choice->entry->load_options->data, len);
            bm->edit_options[len] = '\0';
        }
    }

    bm->screen = VIBTANIUM_EFI_BOOT_SCREEN_EDIT_DESCRIPTION;
    vibtanium_boot_manager_edit_set_buffer(bm, bm->edit_description);
}

static void vibtanium_boot_manager_finish_edit(
    VibtaniumEfiBootManagerState *bm)
{
    Error *local_err = NULL;
    const uint8_t *options = NULL;
    size_t options_size = 0;

    if (bm->edit_options[0]) {
        options = (const uint8_t *)bm->edit_options;
        options_size = strlen(bm->edit_options);
    }

    if (!vibtanium_efi_vars_write_boot_entry(
            bm->edit_id, bm->edit_description, bm->edit_path, options,
            options_size, &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not save Boot%04X: %s", bm->edit_id,
            error_get_pretty(local_err));
        error_free(local_err);
    } else {
        vibtanium_boot_manager_set_status(
            bm, "Saved Boot%04X.", bm->edit_id);
    }
    bm->screen = VIBTANIUM_EFI_BOOT_SCREEN_MAINTENANCE;
    vibtanium_boot_manager_rebuild_choices(bm);
}

static void vibtanium_boot_manager_edit_accept(
    VibtaniumEfiBootManagerState *bm)
{
    switch (bm->screen) {
    case VIBTANIUM_EFI_BOOT_SCREEN_EDIT_DESCRIPTION:
        g_strlcpy(bm->edit_description, bm->edit_buffer,
                  sizeof(bm->edit_description));
        bm->screen = VIBTANIUM_EFI_BOOT_SCREEN_EDIT_PATH;
        vibtanium_boot_manager_edit_set_buffer(bm, bm->edit_path);
        break;
    case VIBTANIUM_EFI_BOOT_SCREEN_EDIT_PATH:
        g_strlcpy(bm->edit_path, bm->edit_buffer, sizeof(bm->edit_path));
        bm->screen = VIBTANIUM_EFI_BOOT_SCREEN_EDIT_OPTIONS;
        vibtanium_boot_manager_edit_set_buffer(bm, bm->edit_options);
        break;
    case VIBTANIUM_EFI_BOOT_SCREEN_EDIT_OPTIONS:
        g_strlcpy(bm->edit_options, bm->edit_buffer,
                  sizeof(bm->edit_options));
        vibtanium_boot_manager_finish_edit(bm);
        break;
    default:
        break;
    }
}

static void vibtanium_boot_manager_process_edit_key(
    VibtaniumEfiBootManagerState *bm,
    const VibtaniumEfiInputKey *key)
{
    if (key->scan_code == VIBTANIUM_EFI_SCAN_ESC) {
        bm->screen = VIBTANIUM_EFI_BOOT_SCREEN_MAINTENANCE;
        vibtanium_boot_manager_set_status(bm, "Edit canceled.");
        return;
    }
    if (key->unicode_char == '\r') {
        vibtanium_boot_manager_edit_accept(bm);
        return;
    }
    if (key->unicode_char == '\b') {
        if (bm->edit_len > 0) {
            bm->edit_buffer[--bm->edit_len] = '\0';
        }
        return;
    }
    if (key->unicode_char >= 0x20 && key->unicode_char <= 0x7e &&
        bm->edit_len + 1 < sizeof(bm->edit_buffer)) {
        bm->edit_buffer[bm->edit_len++] = key->unicode_char;
        bm->edit_buffer[bm->edit_len] = '\0';
    }
}

static void vibtanium_boot_manager_add_selected_fallback(
    VibtaniumEfiBootManagerState *bm)
{
    VibtaniumEfiBootChoice *choice;
    g_autofree uint16_t *order = NULL;
    g_autofree uint16_t *new_order = NULL;
    size_t order_count = 0;
    Error *local_err = NULL;
    uint16_t id;
    char description[128];

    if (!bm->choices || bm->selected >= bm->choices->len) {
        return;
    }

    choice = g_ptr_array_index(bm->choices, bm->selected);
    if (!vibtanium_boot_choice_is_fallback(choice)) {
        vibtanium_boot_manager_set_status(
            bm, "Select a discovered media entry to add.");
        return;
    }

    if (!vibtanium_efi_vars_allocate_boot_entry_id(&id, &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not allocate Boot#### id: %s",
            error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    g_snprintf(description, sizeof(description), "Media %s",
               blk_name(choice->blk));
    if (!vibtanium_efi_vars_write_boot_entry(
            id, description, choice->loader_path, NULL, 0, &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not create Boot%04X: %s", id,
            error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    if (!vibtanium_efi_vars_boot_order_get(&order, &order_count,
                                           &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not read BootOrder: %s", error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    new_order = g_new0(uint16_t, order_count + 1);
    if (order_count != 0) {
        memcpy(new_order, order, order_count * sizeof(uint16_t));
    }
    new_order[order_count] = id;
    if (!vibtanium_efi_vars_boot_order_set(new_order, order_count + 1,
                                           &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not update BootOrder: %s",
            error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    vibtanium_boot_manager_set_status(bm, "Added Boot%04X.", id);
    vibtanium_boot_manager_rebuild_choices(bm);
}

static void vibtanium_boot_manager_remove_selected_nvram(
    VibtaniumEfiBootManagerState *bm)
{
    VibtaniumEfiBootChoice *choice;
    g_autofree uint16_t *order = NULL;
    g_autofree uint16_t *new_order = NULL;
    size_t order_count = 0;
    size_t new_count = 0;
    Error *local_err = NULL;
    uint16_t id;

    if (!bm->choices || bm->selected >= bm->choices->len) {
        return;
    }

    choice = g_ptr_array_index(bm->choices, bm->selected);
    if (!vibtanium_boot_choice_is_nvram(choice)) {
        vibtanium_boot_manager_set_status(
            bm, "Select an NVRAM Boot#### entry to remove.");
        return;
    }

    id = choice->entry->id;
    if (!vibtanium_efi_vars_delete_boot_entry(id, &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not delete Boot%04X: %s", id,
            error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    if (!vibtanium_efi_vars_boot_order_get(&order, &order_count,
                                           &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not read BootOrder: %s", error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    new_order = g_new0(uint16_t, order_count);
    for (size_t i = 0; i < order_count; i++) {
        if (order[i] != id) {
            new_order[new_count++] = order[i];
        }
    }
    if (!vibtanium_efi_vars_boot_order_set(new_order, new_count,
                                           &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not update BootOrder: %s",
            error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    vibtanium_boot_manager_set_status(bm, "Removed Boot%04X.", id);
    vibtanium_boot_manager_rebuild_choices(bm);
}

static void vibtanium_boot_manager_reorder_selected_nvram(
    VibtaniumEfiBootManagerState *bm,
    int direction)
{
    VibtaniumEfiBootChoice *choice;
    g_autofree uint16_t *order = NULL;
    size_t order_count = 0;
    Error *local_err = NULL;
    uint16_t id;
    size_t pos = SIZE_MAX;

    if (!bm->choices || bm->selected >= bm->choices->len) {
        return;
    }

    choice = g_ptr_array_index(bm->choices, bm->selected);
    if (!vibtanium_boot_choice_is_nvram(choice) ||
        choice->entry->from_boot_next) {
        vibtanium_boot_manager_set_status(
            bm, "Select a BootOrder NVRAM entry to reorder.");
        return;
    }

    id = choice->entry->id;
    if (!vibtanium_efi_vars_boot_order_get(&order, &order_count,
                                           &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not read BootOrder: %s", error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    for (size_t i = 0; i < order_count; i++) {
        if (order[i] == id) {
            pos = i;
            break;
        }
    }
    if (pos == SIZE_MAX ||
        (direction < 0 && pos == 0) ||
        (direction > 0 && pos + 1 >= order_count)) {
        return;
    }

    uint16_t tmp = order[pos];
    order[pos] = order[pos + direction];
    order[pos + direction] = tmp;
    if (!vibtanium_efi_vars_boot_order_set(order, order_count, &local_err)) {
        vibtanium_boot_manager_set_status(
            bm, "Could not update BootOrder: %s",
            error_get_pretty(local_err));
        error_free(local_err);
        return;
    }

    vibtanium_boot_manager_set_status(bm, "Reordered Boot%04X.", id);
    vibtanium_boot_manager_rebuild_choices(bm);
}

static void vibtanium_boot_manager_process_maintenance_key(
    VibtaniumEfiBootManagerState *bm,
    const VibtaniumEfiInputKey *key)
{
    uint16_t ch = key->unicode_char;

    if (key->scan_code == VIBTANIUM_EFI_SCAN_UP) {
        vibtanium_boot_manager_select_delta(bm, -1);
    } else if (key->scan_code == VIBTANIUM_EFI_SCAN_DOWN) {
        vibtanium_boot_manager_select_delta(bm, 1);
    } else if (key->scan_code == VIBTANIUM_EFI_SCAN_ESC) {
        bm->screen = VIBTANIUM_EFI_BOOT_SCREEN_MENU;
        bm->status[0] = '\0';
    } else if (ch == '\r') {
        vibtanium_boot_manager_boot_choice(bm);
    } else if (g_ascii_toupper(ch) == 'A') {
        vibtanium_boot_manager_add_selected_fallback(bm);
    } else if (g_ascii_toupper(ch) == 'R') {
        vibtanium_boot_manager_remove_selected_nvram(bm);
    } else if (g_ascii_toupper(ch) == 'E') {
        vibtanium_boot_manager_begin_edit(bm);
    } else if (g_ascii_toupper(ch) == 'U') {
        vibtanium_boot_manager_reorder_selected_nvram(bm, -1);
    } else if (g_ascii_toupper(ch) == 'D') {
        vibtanium_boot_manager_reorder_selected_nvram(bm, 1);
    }
}

static void vibtanium_boot_manager_process_menu_key(
    VibtaniumEfiBootManagerState *bm,
    const VibtaniumEfiInputKey *key)
{
    if (key->scan_code == VIBTANIUM_EFI_SCAN_UP) {
        vibtanium_boot_manager_select_delta(bm, -1);
    } else if (key->scan_code == VIBTANIUM_EFI_SCAN_DOWN) {
        vibtanium_boot_manager_select_delta(bm, 1);
    } else if (key->scan_code == VIBTANIUM_EFI_SCAN_ESC) {
        bm->screen = VIBTANIUM_EFI_BOOT_SCREEN_MAINTENANCE;
        bm->status[0] = '\0';
    } else if (key->unicode_char == '\r') {
        vibtanium_boot_manager_boot_choice(bm);
    }
}

static void vibtanium_boot_manager_tick(void *opaque)
{
    VibtaniumEfiBootManagerState *bm = opaque;
    VibtaniumEfiInputKey key;
    bool redraw = false;
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_HOST);

    while (!bm->booted && vibtanium_efi_input_dequeue(&key)) {
        if (bm->countdown_active) {
            bm->countdown_active = false;
            redraw = true;
        }
        if (bm->screen == VIBTANIUM_EFI_BOOT_SCREEN_MENU) {
            vibtanium_boot_manager_process_menu_key(bm, &key);
        } else if (bm->screen == VIBTANIUM_EFI_BOOT_SCREEN_MAINTENANCE) {
            vibtanium_boot_manager_process_maintenance_key(bm, &key);
        } else {
            vibtanium_boot_manager_process_edit_key(bm, &key);
        }
        redraw = true;
    }

    if (!bm->booted && bm->countdown_active && now >= bm->deadline_ms) {
        vibtanium_boot_manager_boot_choice(bm);
        redraw = true;
    }

    if (!bm->booted) {
        if (redraw || bm->countdown_active) {
            vibtanium_boot_manager_draw(bm);
        }
        timer_mod(bm->timer, now + VIBTANIUM_EFI_BOOT_MANAGER_TICK_MS);
    }
}

static bool vibtanium_efi_boot_manager_policy_enabled(const char *policy)
{
    return g_strcmp0(policy, "off") != 0 &&
           g_strcmp0(policy, "immediate") != 0;
}

static bool vibtanium_efi_boot_manager_policy_timeout(const char *policy)
{
    return g_strcmp0(policy, "timeout") == 0 ||
           g_strcmp0(policy, "menu") == 0;
}

static bool vibtanium_start_efi_boot_manager(VibtaniumMachineState *vms,
                                             MachineState *machine)
{
    const char *policy = vms->efi_boot_manager
                         ? vms->efi_boot_manager
                         : VIBTANIUM_EFI_BOOT_MANAGER_DEFAULT;
    VibtaniumEfiBootManagerState *bm;
    int64_t now;

    if (!vibtanium_efi_boot_manager_policy_enabled(policy)) {
        return false;
    }

    bm = g_new0(VibtaniumEfiBootManagerState, 1);
    bm->vms = vms;
    bm->machine = machine;
    bm->screen = VIBTANIUM_EFI_BOOT_SCREEN_MENU;
    bm->timer = timer_new_ms(QEMU_CLOCK_HOST, vibtanium_boot_manager_tick, bm);
    bm->choices =
        g_ptr_array_new_with_free_func(vibtanium_boot_choice_free);
    vms->boot_manager = bm;

    vibtanium_boot_manager_rebuild_choices(bm);
    now = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    bm->countdown_active =
        vibtanium_efi_boot_manager_policy_timeout(policy);
    bm->deadline_ms = now + VIBTANIUM_EFI_BOOT_MANAGER_TIMEOUT_MS;

    CPU(vms->cpu)->halted = true;
    vibtanium_efi_console_set_input_active(true);
    vibtanium_boot_manager_draw(bm);
    warn_report("QEMU IA-64 EFI v1.0 boot manager policy=%s entries=%u",
                policy, bm->choices ? bm->choices->len : 0);

    timer_mod(bm->timer, now + VIBTANIUM_EFI_BOOT_MANAGER_TICK_MS);
    return true;
}

static void vibtanium_efi_boot_manager_destroy(VibtaniumMachineState *vms)
{
    VibtaniumEfiBootManagerState *bm = vms->boot_manager;

    if (!bm) {
        return;
    }

    g_clear_pointer(&bm->timer, timer_free);
    g_clear_pointer(&bm->choices, g_ptr_array_unref);
    g_free(bm);
    vms->boot_manager = NULL;
}

static void vibtanium_load_efi_app(VibtaniumMachineState *vms,
                                   MachineState *machine)
{
    if (vibtanium_start_efi_boot_manager(vms, machine)) {
        return;
    }

    if (vibtanium_load_explicit_efi_app(vms, machine)) {
        return;
    }

    if (vibtanium_boot_nvram_efi_app(vms, machine)) {
        return;
    }

    vibtanium_discover_efi_app(vms, machine);
}

static void vibtanium_init(MachineState *machine)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();
    uint64_t kernel_alias_size;
    Error *local_err = NULL;

    if (machine->ram_size > VIBTANIUM_RAM_LIMIT) {
        error_report("vibtanium RAM must fit below the placeholder MMIO window "
                     "(maximum %" PRIu64 " bytes)",
                     (uint64_t)VIBTANIUM_RAM_LIMIT);
        exit(1);
    }
    if (machine->ram_size <= VIBTANIUM_KERNEL_ALIAS_RAM_OFFSET) {
        error_report("vibtanium RAM must be larger than the IA-64 kernel "
                     "alias offset 0x%" PRIx64,
                     (uint64_t)VIBTANIUM_KERNEL_ALIAS_RAM_OFFSET);
        exit(1);
    }
    vibtanium_iosapic_reset(vms);
    qemu_register_reset(vibtanium_iosapic_system_reset, vms);
    vmstate_register(NULL, 0, &vmstate_vibtanium_iosapic, vms);

    vms->cpu = IA64_CPU(cpu_create(machine->cpu_type));

    memory_region_add_subregion(sysmem, VIBTANIUM_RAM_BASE, machine->ram);
    memory_region_init_ram(&vms->vga_legacy, NULL, "vibtanium.vga-legacy",
                           VIBTANIUM_VGA_LEGACY_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(sysmem, VIBTANIUM_VGA_LEGACY_BASE,
                                        &vms->vga_legacy, 1);

    kernel_alias_size = machine->ram_size - VIBTANIUM_KERNEL_ALIAS_RAM_OFFSET;
    memory_region_init_alias(&vms->kernel_alias, OBJECT(machine),
                             "vibtanium.kernel-region-offset-alias",
                             machine->ram,
                             VIBTANIUM_KERNEL_ALIAS_RAM_OFFSET,
                             kernel_alias_size);
    memory_region_add_subregion(sysmem, VIBTANIUM_KERNEL_ALIAS_BASE,
                                &vms->kernel_alias);

    memory_region_init_io(&vms->local_sapic_ipi, OBJECT(machine),
                          &vibtanium_local_sapic_ipi_ops, vms,
                          "vibtanium.local-sapic-ipi",
                          VIBTANIUM_LOCAL_SAPIC_IPI_SIZE);
    memory_region_add_subregion(sysmem, VIBTANIUM_LOCAL_SAPIC_IPI_BASE,
                                &vms->local_sapic_ipi);

    memory_region_init_io(&vms->iosapic, OBJECT(machine),
                          &vibtanium_iosapic_ops, vms,
                          "vibtanium.iosapic",
                          VIBTANIUM_IOSAPIC_SIZE);
    memory_region_add_subregion(sysmem, VIBTANIUM_IOSAPIC_BASE,
                                &vms->iosapic);

    qemu_init_irq_child(OBJECT(machine), "uart-irq", &vms->uart_irq,
                        vibtanium_uart_irq, vms, 0);
    vms->uart = serial_mm_init(sysmem, VIBTANIUM_UART_BASE, 0, &vms->uart_irq,
                               115200, serial_hd(0), DEVICE_LITTLE_ENDIAN);
    vibtanium_i8042_init(vms);

    memory_region_init_io(&vms->io_port_space, OBJECT(machine),
                          &vibtanium_io_port_ops, vms,
                          "vibtanium.io-port-space",
                          VIBTANIUM_IO_PORT_SIZE);
    memory_region_add_subregion(sysmem, VIBTANIUM_IO_PORT_BASE,
                                &vms->io_port_space);

    memory_region_init_ram(&vms->framebuffer, NULL,
                           "vibtanium.efi-framebuffer",
                           VIBTANIUM_FRAMEBUFFER_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, VIBTANIUM_FRAMEBUFFER_BASE,
                                &vms->framebuffer);
    vibtanium_efi_console_init(&vms->framebuffer, &vms->vga_legacy,
                               vms->vga_crtc);

    memory_region_init_ram(&vms->nvram, NULL, "vibtanium.nvram",
                           VIBTANIUM_NVRAM_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, VIBTANIUM_NVRAM_BASE, &vms->nvram);

    memory_region_init_ram(&vms->firmware, NULL, "vibtanium.firmware",
                           VIBTANIUM_FIRMWARE_SIZE,
                           &error_fatal);
    memory_region_set_readonly(&vms->firmware, true);
    memory_region_add_subregion(sysmem, VIBTANIUM_FIRMWARE_BASE,
                                &vms->firmware);

    if (!vibtanium_efi_vars_global_load(vms->nvram_path, &local_err)) {
        error_reportf_err(local_err, "could not load IA-64 EFI NVRAM: ");
        exit(1);
    }

    vibtanium_load_efi_app(vms, machine);
}

static bool vibtanium_get_efi_auto_enter(Object *obj, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    return vms->efi_auto_enter;
}

static void vibtanium_set_efi_auto_enter(Object *obj, bool value, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    vms->efi_auto_enter = value;
}

static char *vibtanium_get_nvram(Object *obj, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    return g_strdup(vms->nvram_path ? vms->nvram_path : "");
}

static void vibtanium_set_nvram(Object *obj, const char *value, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    g_free(vms->nvram_path);
    vms->nvram_path = g_strdup(value && *value ? value : NULL);
}

static bool vibtanium_efi_boot_manager_policy_valid(const char *value)
{
    return !value || !*value ||
           g_strcmp0(value, "timeout") == 0 ||
           g_strcmp0(value, "menu") == 0 ||
           g_strcmp0(value, "pause") == 0 ||
           g_strcmp0(value, "off") == 0 ||
           g_strcmp0(value, "immediate") == 0;
}

static char *vibtanium_get_efi_boot_manager(Object *obj, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    return g_strdup(vms->efi_boot_manager ?
                    vms->efi_boot_manager :
                    VIBTANIUM_EFI_BOOT_MANAGER_DEFAULT);
}

static void vibtanium_set_efi_boot_manager(Object *obj,
                                           const char *value,
                                           Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    if (!vibtanium_efi_boot_manager_policy_valid(value)) {
        error_setg(errp,
                   "invalid efi-boot-manager policy '%s' "
                   "(expected timeout, pause, or off)",
                   value);
        return;
    }

    g_free(vms->efi_boot_manager);
    vms->efi_boot_manager = g_strdup(value && *value ? value : NULL);
}

static void vibtanium_machine_finalize(Object *obj)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    vmstate_unregister(NULL, &vmstate_vibtanium_iosapic, vms);
    qemu_unregister_reset(vibtanium_iosapic_system_reset, vms);
    vibtanium_efi_boot_manager_destroy(vms);
    g_free(vms->nvram_path);
    g_free(vms->efi_boot_manager);
}

static void vibtanium_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Synthetic IA-64 machine skeleton";
    mc->init = vibtanium_init;
    mc->max_cpus = 1;
    mc->default_cpu_type = TYPE_ITANIUM2_CPU;
    mc->default_ram_size = 512 * MiB;
    mc->default_ram_id = "vibtanium.ram";
    mc->no_cdrom = 1;
    mc->no_floppy = 1;
    mc->no_parallel = 1;

    object_class_property_add_bool(oc, "efi-auto-enter",
                                   vibtanium_get_efi_auto_enter,
                                   vibtanium_set_efi_auto_enter);
    object_class_property_set_description(oc, "efi-auto-enter",
        "Queue one EFI Simple Text Input Enter key at firmware reset");

    object_class_property_add_str(oc, "nvram",
                                  vibtanium_get_nvram,
                                  vibtanium_set_nvram);
    object_class_property_set_description(oc, "nvram",
        "Path to a QEMU UefiVarStore JSON file for EFI variables");

    object_class_property_add_str(oc, "efi-boot-manager",
                                  vibtanium_get_efi_boot_manager,
                                  vibtanium_set_efi_boot_manager);
    object_class_property_set_description(oc, "efi-boot-manager",
        "EFI boot manager policy: timeout, pause, or off");
}

static const TypeInfo vibtanium_machine_typeinfo = {
    .name = TYPE_VIBTANIUM_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(VibtaniumMachineState),
    .class_init = vibtanium_machine_class_init,
    .instance_finalize = vibtanium_machine_finalize,
};

static void vibtanium_machine_register_types(void)
{
    type_register_static(&vibtanium_machine_typeinfo);
}

type_init(vibtanium_machine_register_types)
