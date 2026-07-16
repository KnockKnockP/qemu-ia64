/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/core/cpu.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/efi-vars.h"
#include "hw/ia64/vibtanium.h"
#include "vibtanium-internal.h"
#include "system/block-backend.h"
#include "system/blockdev.h"

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
        VibtaniumEfiBlockDevice dev;
        VibtaniumEfiStorageReport report;
        g_autofree uint8_t *file_data = NULL;
        g_autofree char *source = NULL;
        size_t file_size = 0;
        Error *local_err = NULL;

        if (!vibtanium_blk_media_device(blk, &dev)) {
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
        vibtanium_blk_media_device_cleanup(&dev);
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
        "                       Vibtanium EFI Firmware                       ");
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
    const char *bit_hint;

    vibtanium_efi_console_set_attribute(VIBTANIUM_EFI_BOOT_MANAGER_ATTR);
    vibtanium_efi_console_enable_cursor(false);
    vibtanium_efi_console_clear();

    vibtanium_boot_manager_print_line(
        0, VIBTANIUM_EFI_BOOT_MANAGER_HILITE,
        "                       Vibtanium EFI Firmware                       ");
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

    if (!vibtanium_builtin_bit_available()) {
        bit_hint =
            "Built In Test (BIT) not compiled in (-Dvibtanium_efi=false)";
    } else if (bm->vms->built_in_test) {
        bit_hint = "B: run Built In Test (BIT)";
    } else {
        bit_hint = "Built In Test (BIT) disabled by -M built-in-test=off";
    }
    vibtanium_boot_manager_print_line(
        18, VIBTANIUM_EFI_BOOT_MANAGER_MUTED, "%s", bit_hint);
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
        "                       Vibtanium EFI Firmware                       ");
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

static void vibtanium_boot_manager_resume_guest(
    VibtaniumEfiBootManagerState *bm)
{
    VibtaniumMachineState *vms = bm->vms;

    bm->booted = true;
    timer_del(bm->timer);
    vibtanium_efi_console_enable_cursor(false);
    CPU(vms->cpu)->halted = false;
    cpu_resume(CPU(vms->cpu));
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
    vibtanium_firmware_serial_log(
        vms, "Vibtanium EFI: boot manager accepted a selection\n");
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
        VibtaniumEfiBlockDevice dev;

        if (vibtanium_blk_media_device(choice->blk, &dev)) {
            warn_report("vibtanium EFI boot manager selected media=%s path=%s",
                        dev.name, choice->loader_path);
            ok = vibtanium_try_media_efi_app(vms, machine, &dev,
                                             choice->loader_path, NULL);
            vibtanium_blk_media_device_cleanup(&dev);
        }
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

    vibtanium_boot_manager_resume_guest(bm);
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

static bool vibtanium_boot_manager_boot_bit(VibtaniumEfiBootManagerState *bm)
{
    if (!vibtanium_builtin_bit_available()) {
        vibtanium_boot_manager_set_status(
            bm, "Built In Test was not compiled into this QEMU build.");
        return false;
    }

    if (!bm->vms->built_in_test) {
        vibtanium_boot_manager_set_status(
            bm, "Built In Test is disabled by -M built-in-test=off.");
        return false;
    }

    if (!vibtanium_load_builtin_bit(bm->vms, bm->machine)) {
        vibtanium_boot_manager_set_status(bm, "Built In Test failed to load.");
        return false;
    }

    vibtanium_boot_manager_resume_guest(bm);
    return true;
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
    } else if (g_ascii_toupper(ch) == 'B') {
        vibtanium_boot_manager_boot_bit(bm);
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

bool vibtanium_efi_boot_manager_policy_valid(const char *value)
{
    return !value || !*value ||
           g_strcmp0(value, "timeout") == 0 ||
           g_strcmp0(value, "menu") == 0 ||
           g_strcmp0(value, "pause") == 0 ||
           g_strcmp0(value, "off") == 0 ||
           g_strcmp0(value, "immediate") == 0;
}

bool vibtanium_start_efi_boot_manager(VibtaniumMachineState *vms,
                                      MachineState *machine)
{
    const char *policy = vms->efi_boot_manager
                         ? vms->efi_boot_manager
                         : VIBTANIUM_EFI_BOOT_MANAGER_DEFAULT;
    VibtaniumEfiBootManagerState *bm;
    int64_t now;

    vibtanium_firmware_serial_log(
        vms, "Vibtanium EFI: preparing the project boot frontend\n");
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
    warn_report("Vibtanium EFI boot manager policy=%s entries=%u",
                policy, bm->choices ? bm->choices->len : 0);

    timer_mod(bm->timer, now + VIBTANIUM_EFI_BOOT_MANAGER_TICK_MS);
    return true;
}

void vibtanium_efi_boot_manager_destroy(VibtaniumMachineState *vms)
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
