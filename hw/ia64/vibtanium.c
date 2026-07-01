/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/char/serial-mm.h"
#include "hw/core/cpu.h"
#include "hw/core/loader.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/vibtanium.h"
#include "system/block-backend.h"
#include "system/blockdev.h"
#include "system/address-spaces.h"
#include "system/system.h"
#include "target/ia64/exec-smoke.h"

#define VIBTANIUM_DEFAULT_LINUX_APPEND ""
#define VIBTANIUM_IOSAPIC_REG_SELECT 0x00
#define VIBTANIUM_IOSAPIC_WINDOW     0x10
#define VIBTANIUM_IOSAPIC_EOI        0x40
#define VIBTANIUM_IOSAPIC_VERSION    0x01
#define VIBTANIUM_IOSAPIC_RTE_LOW(i)  (0x10 + (i) * 2)
#define VIBTANIUM_IOSAPIC_RTE_HIGH(i) (0x11 + (i) * 2)

static void vibtanium_uart_irq(void *opaque, int n, int level)
{
    /*
     * The local SAPIC IPI path exists, but UART/IOSAPIC routing is still a
     * later platform step.
     */
    (void)opaque;
    (void)n;
    (void)level;
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

static uint64_t vibtanium_io_port_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    unsigned port;

    if (!vibtanium_sparse_io_offset_valid(offset, size)) {
        return vibtanium_io_port_default_read(size);
    }

    port = vibtanium_sparse_io_port(offset);
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
    unsigned port;

    if (!vibtanium_sparse_io_offset_valid(offset, size)) {
        return;
    }

    port = vibtanium_sparse_io_port(offset);
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
                vms->iosapic_rte_low[index] = value;
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
    vibtanium_efi_register_boot_media(boot_media);
    vibtanium_efi_register_loaded_image(image->load_base, image->size);
    vibtanium_efi_set_linux_cmdline_append(linux_append);
    rom_add_blob_fixed("vibtanium.efi-tables", firmware_blob,
                       firmware_blob_size, VIBTANIUM_EFI_BLOB_BASE);
    rom_add_blob_fixed("vibtanium.efi-app", image->data, image->size,
                       image->load_base);
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

static bool vibtanium_try_discovered_efi_app(VibtaniumMachineState *vms,
                                             MachineState *machine,
                                             VibtaniumEfiBlockDevice *dev)
{
    Error *local_err = NULL;
    VibtaniumEfiStorageReport report;
    g_autofree uint8_t *file_data = NULL;
    size_t file_size = 0;
    VibtaniumEfiImage image;
    VibtaniumEfiBlockDevice cached_dev;
    char source[384];

    if (!vibtanium_efi_cdrom_read_path(dev, VIBTANIUM_EFI_FALLBACK_PATH,
                                       &file_data, &file_size, source,
                                       sizeof(source), &report, &local_err)) {
        warn_report("vibtanium EFI discovery media=%s path=%s status=%s "
                    "reason=%s",
                    dev->name ? dev->name : "<unnamed>",
                    VIBTANIUM_EFI_FALLBACK_PATH,
                    vibtanium_efi_storage_status_name(report.status),
                    report.message);
        error_free(local_err);
        return false;
    }

    warn_report("vibtanium EFI discovery media=%s path=%s status=%s %s",
                dev->name ? dev->name : "<unnamed>",
                VIBTANIUM_EFI_FALLBACK_PATH,
                vibtanium_efi_storage_status_name(report.status),
                report.message);

    local_err = NULL;
    if (!vibtanium_efi_image_from_buffer(source, file_data, file_size,
                                         VIBTANIUM_EFI_APP_BASE, &image,
                                         &local_err)) {
        warn_report("vibtanium EFI discovery media=%s path=%s status=%s "
                    "reason=%s",
                    dev->name ? dev->name : "<unnamed>",
                    VIBTANIUM_EFI_FALLBACK_PATH,
                    vibtanium_efi_status_name(VIBTANIUM_EFI_LOAD_ERROR),
                    error_get_pretty(local_err));
        error_free(local_err);
        return false;
    }

    local_err = NULL;
    if (!vibtanium_cache_boot_media(dev, &cached_dev, &local_err)) {
        warn_report("vibtanium EFI discovery media=%s path=%s status=%s "
                    "reason=%s",
                    dev->name ? dev->name : "<unnamed>",
                    VIBTANIUM_EFI_FALLBACK_PATH,
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

static bool vibtanium_discover_efi_app(VibtaniumMachineState *vms,
                                       MachineState *machine)
{
    BlockBackend *blk = NULL;
    unsigned media_index = 0;
    unsigned cdrom_candidates = 0;

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
            .block_size = 2048,
            .read_only = true,
            .removable = cdrom,
            .cdrom = cdrom,
            .read = vibtanium_block_pread,
            .opaque = read_opaque,
        };

        read_opaque->blk = blk;

        warn_report("vibtanium EFI media[%u] name=%s available=%s cdrom=%s "
                    "bytes=%" PRId64,
                    media_index++, dev.name, available ? "yes" : "no",
                    cdrom ? "yes" : "no", length);

        if (!available) {
            g_free(read_opaque);
            continue;
        }
        if (!cdrom) {
            warn_report("vibtanium EFI media %s skipped: not read-only "
                        "CD-ROM media",
                        dev.name);
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

        cdrom_candidates++;
        if (vibtanium_try_discovered_efi_app(vms, machine, &dev)) {
            g_free(read_opaque);
            return true;
        }
        g_free(read_opaque);
    }

    warn_report("vibtanium EFI discovery found no boot app path=%s "
                "media=%u cdrom-candidates=%u",
                VIBTANIUM_EFI_FALLBACK_PATH, media_index,
                cdrom_candidates);
    return false;
}

static void vibtanium_load_efi_app(VibtaniumMachineState *vms,
                                   MachineState *machine)
{
    if (vibtanium_load_explicit_efi_app(vms, machine)) {
        return;
    }

    vibtanium_discover_efi_app(vms, machine);
}

static void vibtanium_init(MachineState *machine)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();
    uint64_t kernel_alias_size;

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

    vms->cpu = IA64_CPU(cpu_create(machine->cpu_type));

    memory_region_add_subregion(sysmem, VIBTANIUM_RAM_BASE, machine->ram);
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
    vibtanium_efi_console_init(&vms->framebuffer);

    memory_region_init_ram(&vms->nvram, NULL, "vibtanium.nvram",
                           VIBTANIUM_NVRAM_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, VIBTANIUM_NVRAM_BASE, &vms->nvram);

    memory_region_init_ram(&vms->firmware, NULL, "vibtanium.firmware",
                           VIBTANIUM_FIRMWARE_SIZE,
                           &error_fatal);
    memory_region_set_readonly(&vms->firmware, true);
    memory_region_add_subregion(sysmem, VIBTANIUM_FIRMWARE_BASE,
                                &vms->firmware);

    vibtanium_load_efi_app(vms, machine);
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
}

static const TypeInfo vibtanium_machine_typeinfo = {
    .name = TYPE_VIBTANIUM_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(VibtaniumMachineState),
    .class_init = vibtanium_machine_class_init,
};

static void vibtanium_machine_register_types(void)
{
    type_register_static(&vibtanium_machine_typeinfo);
}

type_init(vibtanium_machine_register_types)
