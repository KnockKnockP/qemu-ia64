/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/aio.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/char/serial-mm.h"
#include "hw/core/cpu.h"
#include "hw/core/sysbus.h"
#include "hw/ide/ide-dev.h"
#include "hw/ide/pci.h"
#ifdef CONFIG_VIBTANIUM_BIT
#include "hw/ia64/efi-bit.h"
#endif
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/efi-vars.h"
#include "hw/ia64/vibtanium.h"
#include "hw/intc/ia64-iosapic.h"
#include "hw/input/i8042.h"
#include "hw/isa/isa.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/pci_host.h"
#include "hw/core/qdev-properties.h"
#include "system/block-backend.h"
#include "system/block-backend-io.h"
#include "system/blockdev.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/reset.h"
#include "system/system.h"
#include "target/ia64/flight-recorder.h"
#include "target/ia64/firmware.h"
#include "target/ia64/insn.h"
#include "vibtanium-internal.h"

#define VIBTANIUM_DEFAULT_LINUX_APPEND ""
#define TYPE_VIBTANIUM_PCI_HOST "vibtanium-pci-host"
#define TYPE_VIBTANIUM_IDE "cmd646-ide"
#define VIBTANIUM_PIB_INTA_OFFSET UINT64_C(0x1e0000)
#define VIBTANIUM_PIB_XTPR_OFFSET UINT64_C(0x1e0008)

typedef struct VibtaniumPciHostState {
    PCIHostState parent_obj;
} VibtaniumPciHostState;

typedef struct VibtaniumPciBarAllocator {
    uint64_t io_next;
    uint64_t mem_next;
} VibtaniumPciBarAllocator;

OBJECT_DECLARE_SIMPLE_TYPE(VibtaniumPciHostState, VIBTANIUM_PCI_HOST)

static void vibtanium_isa_init(VibtaniumMachineState *vms)
{
    vms->isa_bus = isa_bus_new(NULL, get_system_memory(), get_system_io(),
                               &error_fatal);
    for (int i = 0; i < VIBTANIUM_LEGACY_ISA_IRQS; i++) {
        vms->isa_irqs[i] = qdev_get_gpio_in(vms->iosapic, i);
    }
    isa_bus_register_input_irqs(vms->isa_bus, vms->isa_irqs);
}

static void vibtanium_pci_set_irq(void *opaque, int irq_num, int level)
{
    VibtaniumMachineState *vms = opaque;

    if (irq_num < 0 || irq_num >= VIBTANIUM_PCI_INTX_IRQS) {
        return;
    }

    qemu_set_irq(vms->pci_irqs[irq_num], level);
}

static uint64_t vibtanium_align_pci_base(uint64_t base, uint64_t size)
{
    if (base > UINT64_MAX - (size - 1)) {
        error_report("vibtanium PCI region allocation overflow");
        exit(1);
    }

    return (base + size - 1) & ~(size - 1);
}

static uint64_t vibtanium_alloc_pci_region(const char *kind,
                                           uint64_t *next,
                                           uint64_t limit,
                                           uint64_t size,
                                           const PCIDevice *dev,
                                           int region_num)
{
    uint64_t base = vibtanium_align_pci_base(*next, size);

    if (base > limit || size > limit - base) {
        error_report("vibtanium PCI %s BAR allocation failed for %s "
                     "region %d size=0x%" PRIx64,
                     kind, dev->name, region_num, size);
        exit(1);
    }

    *next = base + size;
    return base;
}

static void vibtanium_assign_pci_device_bars(PCIBus *bus,
                                             PCIDevice *dev,
                                             void *opaque)
{
    VibtaniumPciBarAllocator *alloc = opaque;
    uint16_t command = pci_get_word(dev->config + PCI_COMMAND);
    bool assigned = false;

    for (int i = 0; i < PCI_NUM_REGIONS; i++) {
        PCIIORegion *region = &dev->io_regions[i];
        uint64_t addr;
        uint32_t config_addr;

        if (i == PCI_ROM_SLOT || !region->size ||
            pci_get_bar_addr(dev, i) != PCI_BAR_UNMAPPED) {
            continue;
        }

        config_addr = pci_bar(dev, i);
        if (region->type & PCI_BASE_ADDRESS_SPACE_IO) {
            addr = vibtanium_alloc_pci_region(
                "I/O", &alloc->io_next,
                VIBTANIUM_PCI_IO_BASE + VIBTANIUM_PCI_IO_SIZE,
                region->size, dev, i);
            pci_default_write_config(
                dev, config_addr,
                addr | (region->type & ~PCI_BASE_ADDRESS_IO_MASK), 4);
            command |= PCI_COMMAND_IO;
        } else {
            uint64_t flags = region->type & ~PCI_BASE_ADDRESS_MEM_MASK;

            addr = vibtanium_alloc_pci_region(
                "MMIO", &alloc->mem_next,
                VIBTANIUM_PCI_MMIO_BASE + VIBTANIUM_PCI_MMIO_SIZE,
                region->size, dev, i);
            pci_default_write_config(dev, config_addr,
                                     (uint32_t)(addr | flags), 4);
            if (region->type & PCI_BASE_ADDRESS_MEM_TYPE_64) {
                pci_default_write_config(dev, config_addr + 4,
                                         (uint32_t)(addr >> 32), 4);
            }
            command |= PCI_COMMAND_MEMORY;
        }
        assigned = true;
    }

    if (assigned) {
        pci_default_write_config(dev, PCI_COMMAND,
                                 command | PCI_COMMAND_MASTER, 2);
    }
}

static void vibtanium_assign_pci_bars(VibtaniumMachineState *vms)
{
    VibtaniumPciBarAllocator alloc = {
        .io_next = VIBTANIUM_PCI_DYNAMIC_IO_BASE,
        .mem_next = VIBTANIUM_PCI_MMIO_BASE,
    };

    if (!vms->pci_bus) {
        return;
    }

    pci_for_each_device(vms->pci_bus, 0, vibtanium_assign_pci_device_bars,
                        &alloc);
}

static void vibtanium_configure_firmware_pci(VibtaniumMachineState *vms)
{
    if (vms->pci_ide) {
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_0,
                                 VIBTANIUM_IDE_PRIMARY_CMD_BASE |
                                 PCI_BASE_ADDRESS_SPACE_IO, 4);
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_1,
                                 VIBTANIUM_IDE_PRIMARY_CTL_BAR_BASE |
                                 PCI_BASE_ADDRESS_SPACE_IO, 4);
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_2,
                                 VIBTANIUM_IDE_SECONDARY_CMD_BASE |
                                 PCI_BASE_ADDRESS_SPACE_IO, 4);
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_3,
                                 VIBTANIUM_IDE_SECONDARY_CTL_BAR_BASE |
                                 PCI_BASE_ADDRESS_SPACE_IO, 4);
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_4,
                                 VIBTANIUM_IDE_BMDMA_BASE |
                                 PCI_BASE_ADDRESS_SPACE_IO, 4);
        pci_default_write_config(vms->pci_ide, PCI_COMMAND,
                                 PCI_COMMAND_IO | PCI_COMMAND_MASTER,
                                 2);
    }

    vibtanium_assign_pci_bars(vms);
}

static void vibtanium_reset(MachineState *machine, ResetType type)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(machine);

    qemu_devices_reset(type);
    vibtanium_configure_firmware_pci(vms);
}

static void vibtanium_pci_init(VibtaniumMachineState *vms)
{
    MachineClass *mc = MACHINE_GET_CLASS(vms);
    PCIHostState *host;

    vms->pci_host = qdev_new(TYPE_VIBTANIUM_PCI_HOST);
    host = PCI_HOST_BRIDGE(vms->pci_host);

    for (int i = 0; i < VIBTANIUM_PCI_INTX_IRQS; i++) {
        vms->pci_irqs[i] = qdev_get_gpio_in(vms->iosapic,
                                            VIBTANIUM_PCI_INTX_IRQ_BASE + i);
    }
    vms->pci_bus = pci_register_root_bus(
        vms->pci_host, "pci", vibtanium_pci_set_irq, pci_swizzle_map_irq_fn,
        vms, get_system_memory(), get_system_io(), 0, VIBTANIUM_PCI_INTX_IRQS,
        TYPE_PCI_BUS);
    host->bus = vms->pci_bus;
    sysbus_realize_and_unref(SYS_BUS_DEVICE(vms->pci_host), &error_fatal);
    ia64_firmware_set_pci_bus(vms->pci_bus);

    vms->pci_ide = pci_new(PCI_DEVFN(1, 0), TYPE_VIBTANIUM_IDE);
    qdev_prop_set_uint32(&vms->pci_ide->qdev, "secondary", 1);
    pci_realize_and_unref(vms->pci_ide, vms->pci_bus, &error_fatal);
    pci_ide_create_devs(vms->pci_ide);

    pci_init_nic_devices(vms->pci_bus, mc->default_nic);
}

static void vibtanium_i8042_init(VibtaniumMachineState *vms)
{
    DeviceState *dev = qdev_new(TYPE_I8042_MMIO);

    qdev_prop_set_uint64(dev, "mask", VIBTANIUM_I8042_MMIO_COMMAND_OFFSET);
    qdev_prop_set_uint32(dev, "size", VIBTANIUM_I8042_MMIO_COMMAND_OFFSET + 1);

    qdev_connect_gpio_out(dev, I8042_KBD_IRQ,
                          qdev_get_gpio_in(
                              vms->iosapic,
                              VIBTANIUM_LEGACY_I8042_KEYBOARD_IRQ));
    qdev_connect_gpio_out(dev, I8042_MOUSE_IRQ,
                          qdev_get_gpio_in(
                              vms->iosapic,
                              VIBTANIUM_LEGACY_I8042_MOUSE_IRQ));

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
    /*
     * The upper half of the architectural Processor Interrupt Block exposes
     * one-byte INTA and XTPR locations. Vibtanium has no 8259A-compatible
     * ExtINT source, so INTA currently supplies vector zero.
     */
    if (offset == VIBTANIUM_PIB_INTA_OFFSET && size == 1) {
        return 0;
    }

    return 0;
}

static void vibtanium_local_sapic_ipi_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    CPUIA64State *env = &vms->cpu->env;
    uint64_t delivery_mode = (value >> 8) & 0x7;
    uint64_t vector = value & 0xff;

    if (offset == VIBTANIUM_PIB_XTPR_OFFSET && size == 1) {
        vms->local_sapic_xtpr = value;
        return;
    }

    if (offset >= VIBTANIUM_LOCAL_SAPIC_IPI_SIZE ||
        size != 8 || (offset & 7) != 0) {
        return;
    }

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
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

typedef struct VibtaniumBlockReadOpaque {
    BlockBackend *blk;
} VibtaniumBlockReadOpaque;

typedef struct VibtaniumBlockReadRequest {
    BlockBackend *blk;
    uint64_t offset;
    uint32_t bytes;
    void *buffer;
    QemuEvent complete;
    int ret;
} VibtaniumBlockReadRequest;

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

static void vibtanium_block_pread_on_aio_context(void *opaque)
{
    VibtaniumBlockReadRequest *request = opaque;

    request->ret = blk_pread(request->blk, request->offset,
                             request->bytes, request->buffer, 0);
    qemu_event_set(&request->complete);
}

static int vibtanium_block_pread(void *opaque,
                                 uint64_t offset,
                                 uint32_t bytes,
                                 void *buffer,
                                 Error **errp)
{
    VibtaniumBlockReadOpaque *read_opaque = opaque;
    int ret;

    if (qemu_get_current_aio_context() ==
        blk_get_aio_context(read_opaque->blk)) {
        ret = blk_pread(read_opaque->blk, offset, bytes, buffer, 0);
    } else {
        VibtaniumBlockReadRequest request = {
            .blk = read_opaque->blk,
            .offset = offset,
            .bytes = bytes,
            .buffer = buffer,
        };

        qemu_event_init(&request.complete, false);
        aio_bh_schedule_oneshot(
            blk_get_aio_context(read_opaque->blk),
            vibtanium_block_pread_on_aio_context, &request);
        qemu_event_wait(&request.complete);
        qemu_event_destroy(&request.complete);
        ret = request.ret;
    }
    if (ret < 0) {
        error_setg(errp, "block read failed: %s", strerror(-ret));
        return ret;
    }

    return 0;
}

bool vibtanium_blk_media_device(BlockBackend *blk,
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
    if (!dinfo || dinfo->type == IF_NONE) {
        return false;
    }
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
    return true;
}

void vibtanium_blk_media_device_cleanup(VibtaniumEfiBlockDevice *dev)
{
    if (!dev) {
        return;
    }

    vibtanium_efi_storage_cache_cleanup(dev);
    g_free(dev->opaque);
    dev->opaque = NULL;
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

    /*
     * A machine BlockBackend outlives firmware execution.  Retain a fresh
     * callback wrapper instead of eagerly copying an entire ISO or multi-GiB
     * disk.  The EFI storage layer now caches mounted metadata and immutable
     * file contents, while QEMU's block layer handles ordinary read caching.
     */
    if (src->read == vibtanium_block_pread) {
        VibtaniumBlockReadOpaque *source_opaque = src->opaque;
        VibtaniumBlockReadOpaque *retained;

        if (!source_opaque || !source_opaque->blk) {
            error_setg(errp, "cannot retain unavailable EFI block backend");
            return false;
        }
        retained = g_new0(VibtaniumBlockReadOpaque, 1);
        retained->blk = source_opaque->blk;
        *cached = *src;
        cached->opaque = retained;
        cached->cache = NULL;
        return true;
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

static void vibtanium_write_guest_blob(CPUIA64State *env, const char *name,
                                       hwaddr addr,
                                       const void *data,
                                       size_t size,
                                       size_t clear_size)
{
    MemTxResult result;
    bool live_cpu = !vibtanium_efi_cpu_is_pristine_for_handoff(env);

    ia64_diag_record_firmware_write(env, name, addr, size, clear_size,
                                    live_cpu);

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
    VibtaniumEfiFirmwareOptions firmware_options = {
        .hcdp_serial_console = vms->hcdp_serial_console,
    };

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

    if (!vibtanium_efi_cpu_is_pristine_for_handoff(&vms->cpu->env)) {
        ia64_diag_record_efi_commit(&vms->cpu->env, "skip-live-cpu",
                                    image->source_path, image->load_base,
                                    image->size);
        warn_report("vibtanium EFI image commit skipped because CPU state "
                    "is already initialized");
        return;
    }

    ia64_diag_record_efi_commit(&vms->cpu->env, "begin",
                                image->source_path, image->load_base,
                                image->size);
    firmware_blob = vibtanium_efi_build_firmware_blob(&firmware_blob_size,
                                                      image, boot_media,
                                                      &firmware_options);
    vibtanium_efi_input_set_auto_enter(vms->efi_auto_enter);
    vibtanium_efi_register_boot_media(boot_media);
    vibtanium_efi_register_loaded_image(image->load_base, image->size);
    vibtanium_efi_set_linux_cmdline_append(linux_append);
    vibtanium_write_guest_blob(&vms->cpu->env, "vibtanium.efi-tables",
                               VIBTANIUM_EFI_BLOB_BASE, firmware_blob,
                               firmware_blob_size, VIBTANIUM_EFI_BLOB_SIZE);
    vibtanium_write_guest_blob(&vms->cpu->env, "vibtanium.efi-app",
                               image->load_base,
                               image->data, image->size, image->size);
    if (!vibtanium_efi_prepare_cpu(&vms->cpu->env, image)) {
        warn_report("vibtanium EFI CPU handoff skipped unexpectedly");
    } else {
        ia64_diag_record_efi_handoff(&vms->cpu->env, image->source_path,
                                     image->entry, image->global_pointer);
    }

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

bool vibtanium_load_explicit_efi_app(VibtaniumMachineState *vms,
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

bool vibtanium_load_builtin_bit(VibtaniumMachineState *vms,
                                MachineState *machine)
{
#ifdef CONFIG_VIBTANIUM_BIT
    Error *local_err = NULL;
    VibtaniumEfiImage image;
    VibtaniumEfiBlockDevice bit_media;

    if (!vms->built_in_test) {
        return false;
    }

    if (!vibtanium_efi_image_from_buffer("vibtanium-bit.efi",
                                         vibtanium_efi_bit_blob,
                                         vibtanium_efi_bit_blob_size,
                                         VIBTANIUM_EFI_APP_BASE, &image,
                                         &local_err)) {
        error_reportf_err(local_err, "could not load embedded IA-64 BIT: ");
        return false;
    }

    if (!vibtanium_efi_bit_media_device(&bit_media, &local_err)) {
        error_reportf_err(local_err,
                          "could not build embedded IA-64 BIT media: ");
        vibtanium_efi_image_destroy(&image);
        return false;
    }

    g_strlcpy(image.efi_file_path, VIBTANIUM_EFI_FALLBACK_PATH,
              sizeof(image.efi_file_path));
    warn_report("vibtanium EFI boot manager selected embedded BIT "
                "image-bytes=%zu media-bytes=%" PRIu64,
                vibtanium_efi_bit_blob_size, bit_media.size);
    vibtanium_commit_efi_image(vms, machine, &image, &bit_media);
    vibtanium_trace_loader_frontier(&image);
    vibtanium_efi_image_destroy(&image);
    return true;
#else
    (void)vms;
    (void)machine;
    return false;
#endif
}

bool vibtanium_builtin_bit_available(void)
{
#ifdef CONFIG_VIBTANIUM_BIT
    return true;
#else
    return false;
#endif
}

bool vibtanium_try_media_efi_app(VibtaniumMachineState *vms,
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

    g_strlcpy(image.efi_file_path, boot_path, sizeof(image.efi_file_path));
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

    warn_report("vibtanium EFI retained media name=%s bytes=%" PRIu64,
                cached_dev.name ? cached_dev.name : "<unnamed>",
                cached_dev.size);

    vibtanium_commit_efi_image(vms, machine, &image, &cached_dev);
    vibtanium_trace_loader_frontier(&image);
    vibtanium_efi_image_destroy(&image);
    return true;
}

bool vibtanium_try_boot_entry_on_media(VibtaniumMachineState *vms,
                                       MachineState *machine,
                                       const VibtaniumEfiBootEntry *entry)
{
    BlockBackend *blk = NULL;

    while ((blk = blk_next(blk)) != NULL) {
        VibtaniumEfiBlockDevice dev;

        if (!vibtanium_blk_media_device(blk, &dev)) {
            continue;
        }
        if (vibtanium_try_media_efi_app(vms, machine, &dev,
                                        entry->loader_path, entry)) {
            vibtanium_blk_media_device_cleanup(&dev);
            return true;
        }
        vibtanium_blk_media_device_cleanup(&dev);
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
        bool attached = dinfo && dinfo->type != IF_NONE;
        bool cdrom = attached && dinfo->media_cd;
        int64_t length = available ? blk_getlength(blk) : -ENOMEDIUM;
        VibtaniumEfiBlockDevice dev;

        warn_report("vibtanium EFI media[%u] name=%s attached=%s "
                    "available=%s cdrom=%s writable=%s bytes=%" PRId64,
                    media_index++, name && *name ? name : "<unnamed>",
                    attached ? "yes" : "no", available ? "yes" : "no",
                    cdrom ? "yes" : "no",
                    blk_is_writable(blk) ? "yes" : "no", length);

        if (!attached) {
            warn_report("vibtanium EFI media %s skipped: unattached block "
                        "backend is not guest-visible",
                        name && *name ? name : "<unnamed>");
            continue;
        }

        if (!vibtanium_blk_media_device(blk, &dev)) {
            continue;
        }

        media_candidates++;
        if (vibtanium_try_media_efi_app(vms, machine, &dev,
                                        VIBTANIUM_EFI_FALLBACK_PATH, NULL)) {
            vibtanium_blk_media_device_cleanup(&dev);
            return true;
        }
        vibtanium_blk_media_device_cleanup(&dev);
    }

    warn_report("vibtanium EFI discovery found no boot app path=%s "
                "media=%u media-candidates=%u",
                VIBTANIUM_EFI_FALLBACK_PATH, media_index,
                media_candidates);
    return false;
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
    vibtanium_efi_set_guest_ram_size(machine->ram_size);
    vms->cpu = IA64_CPU(cpu_create(machine->cpu_type));
    vms->iosapic = qdev_new(TYPE_IA64_IOSAPIC);
    ia64_iosapic_set_cpu(IA64_IOSAPIC(vms->iosapic), vms->cpu);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(vms->iosapic), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(vms->iosapic), 0, VIBTANIUM_IOSAPIC_BASE);

    ia64_firmware_set_dispatch(vibtanium_efi_dispatch_gate);
    ia64_firmware_set_cmdline_append_hooks(
        vibtanium_efi_linux_cmdline_append_pending,
        vibtanium_efi_maybe_apply_linux_cmdline_append);
    ia64_firmware_set_recover_post_load(
        vibtanium_efi_console_recover_post_load);

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

    memory_region_init_io(&vms->local_sapic_pib, OBJECT(machine),
                          &vibtanium_local_sapic_ipi_ops, vms,
                          "vibtanium.local-sapic-pib",
                          VIBTANIUM_PROCESSOR_INTERRUPT_BLOCK_SIZE);
    memory_region_add_subregion(sysmem,
                                VIBTANIUM_PROCESSOR_INTERRUPT_BLOCK_BASE,
                                &vms->local_sapic_pib);

    vms->uart = serial_mm_init(
        sysmem, VIBTANIUM_UART_BASE, 0,
        qdev_get_gpio_in(vms->iosapic, VIBTANIUM_LEGACY_COM1_IRQ),
        115200, serial_hd(0), DEVICE_LITTLE_ENDIAN);
    vibtanium_i8042_init(vms);

    vibtanium_sparse_io_init(vms, sysmem);
    vibtanium_isa_init(vms);
    vibtanium_pci_init(vms);

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

static bool vibtanium_get_built_in_test(Object *obj, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    return vms->built_in_test;
}

static void vibtanium_set_built_in_test(Object *obj, bool value, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    if (value && !vibtanium_builtin_bit_available()) {
        error_setg(errp,
                   "Built In Test was not compiled into this QEMU build");
        return;
    }

    vms->built_in_test = value;
}

static bool vibtanium_get_hcdp_serial_console(Object *obj, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    return vms->hcdp_serial_console;
}

static void vibtanium_set_hcdp_serial_console(Object *obj, bool value,
                                              Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    vms->hcdp_serial_console = value;
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

    vibtanium_efi_boot_manager_destroy(vms);
    g_free(vms->nvram_path);
    g_free(vms->efi_boot_manager);
}

static void vibtanium_machine_instance_init(Object *obj)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    vms->built_in_test = vibtanium_builtin_bit_available();
}

static void vibtanium_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Synthetic IA-64 machine skeleton";
    mc->init = vibtanium_init;
    mc->max_cpus = 1;
    mc->reset = vibtanium_reset;
    mc->default_cpu_type = TYPE_ITANIUM2_CPU;
    mc->default_ram_size = 512 * MiB;
    mc->default_ram_id = "vibtanium.ram";
    mc->default_nic = "e1000";
    mc->block_default_type = IF_IDE;
    mc->units_per_default_bus = MAX_IDE_DEVS;
    mc->no_cdrom = 0;
    mc->no_floppy = 1;
    mc->no_parallel = 1;

    object_class_property_add_bool(oc, "efi-auto-enter",
                                   vibtanium_get_efi_auto_enter,
                                   vibtanium_set_efi_auto_enter);
    object_class_property_set_description(oc, "efi-auto-enter",
        "Queue one EFI Simple Text Input Enter key at firmware reset");

    object_class_property_add_bool(oc, "built-in-test",
                                   vibtanium_get_built_in_test,
                                   vibtanium_set_built_in_test);
    object_class_property_set_description(oc, "built-in-test",
        "Expose the embedded IA-64 EFI Built In Test in the firmware menu "
        "(requires a vibtanium_bit=true build)");

    object_class_property_add_bool(oc, "hcdp-serial-console",
                                   vibtanium_get_hcdp_serial_console,
                                   vibtanium_set_hcdp_serial_console);
    object_class_property_set_description(oc, "hcdp-serial-console",
        "Expose the IA-64 HCDP UART as the firmware-selected primary console");

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
    .instance_init = vibtanium_machine_instance_init,
    .class_init = vibtanium_machine_class_init,
    .instance_finalize = vibtanium_machine_finalize,
};

static const TypeInfo vibtanium_pci_host_typeinfo = {
    .name = TYPE_VIBTANIUM_PCI_HOST,
    .parent = TYPE_PCI_HOST_BRIDGE,
    .instance_size = sizeof(VibtaniumPciHostState),
};

static void vibtanium_machine_register_types(void)
{
    type_register_static(&vibtanium_pci_host_typeinfo);
    type_register_static(&vibtanium_machine_typeinfo);
}

type_init(vibtanium_machine_register_types)
