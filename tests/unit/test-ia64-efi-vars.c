/*
 * IA-64 EFI variable store tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-vars.h"

static void append_u16(GByteArray *array, uint16_t value)
{
    uint8_t bytes[2] = {
        value,
        value >> 8,
    };

    g_byte_array_append(array, bytes, sizeof(bytes));
}

static void append_u32(GByteArray *array, uint32_t value)
{
    uint8_t bytes[4];

    for (unsigned i = 0; i < ARRAY_SIZE(bytes); i++) {
        bytes[i] = value >> (i * 8);
    }
    g_byte_array_append(array, bytes, sizeof(bytes));
}

static void append_utf16_ascii(GByteArray *array, const char *text)
{
    while (*text) {
        append_u16(array, (uint8_t)*text++);
    }
    append_u16(array, 0);
}

static GByteArray *make_boot_option(const char *description,
                                    const char *path,
                                    const uint8_t *load_options,
                                    size_t load_options_size)
{
    g_autoptr(GByteArray) file_path = g_byte_array_new();
    GByteArray *option = g_byte_array_new();
    uint8_t header[4] = { 0x04, 0x04, 0, 0 };
    uint8_t end[4] = { 0x7f, 0xff, 0x04, 0x00 };
    size_t path_node_offset;
    size_t path_node_len;

    path_node_offset = file_path->len;
    g_byte_array_append(file_path, header, sizeof(header));
    append_utf16_ascii(file_path, path);
    path_node_len = file_path->len - path_node_offset;
    g_assert_cmpuint(path_node_len, <=, UINT16_MAX);
    file_path->data[path_node_offset + 2] = path_node_len;
    file_path->data[path_node_offset + 3] = path_node_len >> 8;
    g_byte_array_append(file_path, end, sizeof(end));

    append_u32(option, VIBTANIUM_EFI_LOAD_OPTION_ACTIVE);
    append_u16(option, file_path->len);
    append_utf16_ascii(option, description);
    g_byte_array_append(option, file_path->data, file_path->len);
    if (load_options_size != 0) {
        g_byte_array_append(option, load_options, load_options_size);
    }

    return option;
}

static char *make_temp_var_path(char **dir_out)
{
    g_autoptr(GError) gerr = NULL;
    char *dir = g_dir_make_tmp("ia64-efi-vars-XXXXXX", &gerr);

    g_assert_no_error(gerr);
    g_assert_nonnull(dir);
    *dir_out = dir;
    return g_build_filename(dir, "vars.json", NULL);
}

static void cleanup_temp_var_path(char *dir, char *path)
{
    g_unlink(path);
    g_rmdir(dir);
    g_free(path);
    g_free(dir);
}

static void set_var(VibtaniumEfiVarStore *store,
                    const char *name,
                    const uint8_t *data,
                    size_t data_size)
{
    uint64_t status = vibtanium_efi_varstore_set(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, name,
        VIBTANIUM_EFI_VARIABLE_NON_VOLATILE |
        VIBTANIUM_EFI_VARIABLE_BOOTSERVICE |
        VIBTANIUM_EFI_VARIABLE_RUNTIME,
        data, data_size);

    g_assert_cmphex(status, ==, VIBTANIUM_EFI_SUCCESS);
}

static void test_status_codes_match_uefi(void)
{
    g_assert_cmphex(VIBTANIUM_EFI_SUCCESS, ==,
                    UINT64_C(0x0000000000000000));
    g_assert_cmphex(VIBTANIUM_EFI_UNSUPPORTED, ==,
                    UINT64_C(0x8000000000000003));
    g_assert_cmphex(VIBTANIUM_EFI_ACCESS_DENIED, ==,
                    UINT64_C(0x800000000000000f));
    g_assert_cmphex(VIBTANIUM_EFI_NOT_FOUND, ==,
                    UINT64_C(0x800000000000000e));
    g_assert_cmphex(VIBTANIUM_EFI_END_OF_FILE, ==,
                    UINT64_C(0x800000000000001f));
}

static void test_loads_missing_empty_and_rejects_corrupt(void)
{
    VibtaniumEfiVarStore store;
    Error *err = NULL;
    char *dir;
    char *path = make_temp_var_path(&dir);

    vibtanium_efi_varstore_init(&store);

    g_assert_true(vibtanium_efi_varstore_load(&store, path, false, &err));
    g_assert_null(err);
    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "BootOrder", NULL, NULL, NULL),
                    ==, VIBTANIUM_EFI_NOT_FOUND);

    g_assert_true(g_file_set_contents(path, "", 0, NULL));
    g_assert_true(vibtanium_efi_varstore_load(&store, path, false, &err));
    g_assert_null(err);

    g_assert_true(g_file_set_contents(path, "not json", -1, NULL));
    g_assert_false(vibtanium_efi_varstore_load(&store, path, false, &err));
    g_assert_nonnull(err);
    error_free(err);

    vibtanium_efi_varstore_destroy(&store);
    cleanup_temp_var_path(dir, path);
}

static void test_load_adds_graphical_console_variables_by_default(void)
{
    VibtaniumEfiVarStore store;
    Error *err = NULL;
    const uint8_t expected_input_path[] = {
        0x02, 0x01, 0x0c, 0x00,
        0x41, 0xd0, 0x03, 0x03,
        0x00, 0x00, 0x00, 0x00,
        0x7f, 0xff, 0x04, 0x00,
    };
    const uint8_t expected_output_path[] = {
        0x02, 0x01, 0x0c, 0x00,
        0x41, 0xd0, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x00,
        0x7f, 0xff, 0x04, 0x00,
    };
    const uint8_t *actual = NULL;
    size_t actual_size = 0;
    char *dir;
    char *path = make_temp_var_path(&dir);

    vibtanium_efi_varstore_init(&store);
    g_assert_true(vibtanium_efi_varstore_load(&store, path, false, &err));
    g_assert_null(err);

    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "ConIn", NULL, &actual, &actual_size),
                    ==, VIBTANIUM_EFI_SUCCESS);
    g_assert_cmpmem(actual, actual_size, expected_input_path,
                    sizeof(expected_input_path));
    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "ConOut", NULL, &actual, &actual_size),
                    ==, VIBTANIUM_EFI_SUCCESS);
    g_assert_cmpmem(actual, actual_size, expected_output_path,
                    sizeof(expected_output_path));
    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "ErrOut", NULL, &actual, &actual_size),
                    ==, VIBTANIUM_EFI_SUCCESS);
    g_assert_cmpmem(actual, actual_size, expected_output_path,
                    sizeof(expected_output_path));

    vibtanium_efi_varstore_destroy(&store);
    cleanup_temp_var_path(dir, path);
}

static void test_load_adds_serial_console_variables_when_requested(void)
{
    VibtaniumEfiVarStore store;
    Error *err = NULL;
    const uint8_t expected_path[] = {
        0x02, 0x01, 0x0c, 0x00,
        0x41, 0xd0, 0x00, 0x05,
        0xf8, 0x03, 0x00, 0x00,
        0x03, 0x0e, 0x13, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0xc2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x01, 0x01,
        0x7f, 0xff, 0x04, 0x00,
    };
    const uint8_t *actual = NULL;
    size_t actual_size = 0;
    uint32_t attributes = 0;
    char *dir;
    char *path = make_temp_var_path(&dir);

    vibtanium_efi_varstore_init(&store);
    g_assert_true(vibtanium_efi_varstore_load(&store, path, true, &err));
    g_assert_null(err);

    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "ConOut", &attributes, &actual, &actual_size),
                    ==, VIBTANIUM_EFI_SUCCESS);
    g_assert_cmphex(attributes, ==,
                    VIBTANIUM_EFI_VARIABLE_NON_VOLATILE |
                    VIBTANIUM_EFI_VARIABLE_BOOTSERVICE |
                    VIBTANIUM_EFI_VARIABLE_RUNTIME);
    g_assert_cmpuint(actual_size, ==, sizeof(expected_path));
    g_assert_cmpmem(actual, actual_size, expected_path,
                    sizeof(expected_path));

    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "ConIn", NULL, NULL, NULL),
                    ==, VIBTANIUM_EFI_SUCCESS);
    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "ErrOut", NULL, NULL, NULL),
                    ==, VIBTANIUM_EFI_SUCCESS);

    vibtanium_efi_varstore_destroy(&store);
    cleanup_temp_var_path(dir, path);
}

static void test_round_trips_json_variable(void)
{
    VibtaniumEfiVarStore store;
    VibtaniumEfiVarStore reloaded;
    Error *err = NULL;
    const uint8_t expected[] = { 0xde, 0xad, 0xbe, 0xef };
    const uint8_t *actual = NULL;
    size_t actual_size = 0;
    uint32_t attributes = 0;
    g_autofree char *contents = NULL;
    char *dir;
    char *path = make_temp_var_path(&dir);

    vibtanium_efi_varstore_init(&store);
    vibtanium_efi_varstore_init(&reloaded);
    g_assert_true(vibtanium_efi_varstore_load(&store, path, false, &err));
    g_assert_null(err);

    set_var(&store, "TestVar", expected, sizeof(expected));
    g_assert_true(vibtanium_efi_varstore_save(&store, &err));
    g_assert_null(err);
    g_assert_true(g_file_get_contents(path, &contents, NULL, NULL));
    g_assert_nonnull(strstr(contents, "\"version\": 2"));
    g_assert_nonnull(strstr(contents, "\"name\": \"TestVar\""));

    g_assert_true(vibtanium_efi_varstore_load(&reloaded, path, false, &err));
    g_assert_null(err);
    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &reloaded, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "TestVar", &attributes, &actual, &actual_size),
                    ==, VIBTANIUM_EFI_SUCCESS);
    g_assert_cmphex(attributes, ==,
                    VIBTANIUM_EFI_VARIABLE_NON_VOLATILE |
                    VIBTANIUM_EFI_VARIABLE_BOOTSERVICE |
                    VIBTANIUM_EFI_VARIABLE_RUNTIME);
    g_assert_cmpuint(actual_size, ==, sizeof(expected));
    g_assert_cmpmem(actual, actual_size, expected, sizeof(expected));

    vibtanium_efi_varstore_destroy(&reloaded);
    vibtanium_efi_varstore_destroy(&store);
    cleanup_temp_var_path(dir, path);
}

static void test_boot_order_yields_active_entries(void)
{
    VibtaniumEfiVarStore store;
    GPtrArray *entries = NULL;
    g_autoptr(GByteArray) boot1 =
        make_boot_option("first", "\\EFI\\debian\\elilo.efi", NULL, 0);
    g_autoptr(GByteArray) boot2 =
        make_boot_option("second", "\\EFI\\BOOT\\BOOTIA64.EFI",
                         (const uint8_t *)"opts", 4);
    uint8_t order[] = { 2, 0, 1, 0 };
    VibtaniumEfiBootEntry *first;
    VibtaniumEfiBootEntry *second;

    vibtanium_efi_varstore_init(&store);
    set_var(&store, "Boot0001", boot1->data, boot1->len);
    set_var(&store, "Boot0002", boot2->data, boot2->len);
    set_var(&store, "BootOrder", order, sizeof(order));

    g_assert_true(vibtanium_efi_varstore_boot_entries(&store, &entries,
                                                      false, &error_abort));
    g_assert_cmpuint(entries->len, ==, 2);
    first = g_ptr_array_index(entries, 0);
    second = g_ptr_array_index(entries, 1);

    g_assert_cmpuint(first->id, ==, 2);
    g_assert_cmpstr(first->description, ==, "second");
    g_assert_cmpstr(first->loader_path, ==, "/EFI/BOOT/BOOTIA64.EFI");
    g_assert_cmpuint(first->load_options->len, ==, 4);
    g_assert_cmpmem(first->load_options->data, first->load_options->len,
                    "opts", 4);
    g_assert_cmpuint(second->id, ==, 1);
    g_assert_cmpstr(second->loader_path, ==, "/EFI/debian/elilo.efi");

    g_ptr_array_unref(entries);
    vibtanium_efi_varstore_destroy(&store);
}

static void test_boot_next_is_one_shot(void)
{
    VibtaniumEfiVarStore store;
    VibtaniumEfiVarStore reloaded;
    GPtrArray *entries = NULL;
    Error *err = NULL;
    g_autoptr(GByteArray) boot1 =
        make_boot_option("next", "\\EFI\\next.efi", NULL, 0);
    g_autoptr(GByteArray) boot2 =
        make_boot_option("default", "\\EFI\\default.efi", NULL, 0);
    uint8_t boot_next[] = { 1, 0 };
    uint8_t order[] = { 2, 0 };
    char *dir;
    char *path = make_temp_var_path(&dir);
    VibtaniumEfiBootEntry *first;
    VibtaniumEfiBootEntry *second;

    vibtanium_efi_varstore_init(&store);
    vibtanium_efi_varstore_init(&reloaded);
    g_assert_true(vibtanium_efi_varstore_load(&store, path, false, &err));
    g_assert_null(err);

    set_var(&store, "Boot0001", boot1->data, boot1->len);
    set_var(&store, "Boot0002", boot2->data, boot2->len);
    set_var(&store, "BootNext", boot_next, sizeof(boot_next));
    set_var(&store, "BootOrder", order, sizeof(order));

    g_assert_true(vibtanium_efi_varstore_boot_entries(&store, &entries,
                                                      true, &err));
    g_assert_null(err);
    g_assert_cmpuint(entries->len, ==, 2);
    first = g_ptr_array_index(entries, 0);
    second = g_ptr_array_index(entries, 1);

    g_assert_cmpuint(first->id, ==, 1);
    g_assert_true(first->from_boot_next);
    g_assert_cmpuint(second->id, ==, 2);
    g_assert_false(second->from_boot_next);
    g_ptr_array_unref(entries);

    g_assert_true(vibtanium_efi_varstore_load(&reloaded, path, false, &err));
    g_assert_null(err);
    g_assert_cmphex(vibtanium_efi_varstore_get(
                        &reloaded, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID,
                        "BootNext", NULL, NULL, NULL),
                    ==, VIBTANIUM_EFI_NOT_FOUND);

    vibtanium_efi_varstore_destroy(&reloaded);
    vibtanium_efi_varstore_destroy(&store);
    cleanup_temp_var_path(dir, path);
}

static void test_driver_order_yields_active_entries(void)
{
    VibtaniumEfiVarStore store;
    GPtrArray *entries = NULL;
    g_autoptr(GByteArray) driver1 = make_boot_option(
        "first driver", "\\EFI\\Drivers\\first.efi", NULL, 0);
    g_autoptr(GByteArray) driver2 = make_boot_option(
        "floating point driver", "\\EFI\\Microsoft\\EFIDrivers\\fpswa.efi",
        (const uint8_t *)"driver-options", 14);
    uint8_t order[] = { 2, 0, 1, 0 };
    VibtaniumEfiBootEntry *first;
    VibtaniumEfiBootEntry *second;

    memset(driver2->data, 0, sizeof(uint32_t));

    vibtanium_efi_varstore_init(&store);
    set_var(&store, "Driver0001", driver1->data, driver1->len);
    set_var(&store, "Driver0002", driver2->data, driver2->len);
    set_var(&store, "DriverOrder", order, sizeof(order));

    g_assert_true(vibtanium_efi_varstore_driver_entries(
        &store, &entries, &error_abort));
    g_assert_cmpuint(entries->len, ==, 2);
    first = g_ptr_array_index(entries, 0);
    second = g_ptr_array_index(entries, 1);
    g_assert_cmpuint(first->id, ==, 2);
    g_assert_false(first->active);
    g_assert_cmpstr(first->description, ==, "floating point driver");
    g_assert_cmpstr(first->loader_path, ==,
                    "/EFI/Microsoft/EFIDrivers/fpswa.efi");
    g_assert_cmpmem(first->load_options->data, first->load_options->len,
                    "driver-options", 14);
    g_assert_cmpuint(second->id, ==, 1);
    g_assert_true(second->active);
    g_assert_cmpstr(second->loader_path, ==, "/EFI/Drivers/first.efi");

    g_ptr_array_unref(entries);
    vibtanium_efi_varstore_destroy(&store);
}

static void test_boot_entry_write_edit_and_delete(void)
{
    VibtaniumEfiVarStore store;
    GPtrArray *entries = NULL;
    VibtaniumEfiBootEntry *entry;
    const uint8_t first_opts[] = "first";
    const uint8_t second_opts[] = "second";

    vibtanium_efi_varstore_init(&store);

    g_assert_true(vibtanium_efi_varstore_write_boot_entry(
        &store, 7, "Firmware entry", "\\EFI\\BOOT\\BOOTIA64.EFI",
        first_opts, sizeof(first_opts) - 1, &error_abort));

    {
        uint16_t order[] = { 7 };
        g_assert_true(vibtanium_efi_varstore_boot_order_set(
            &store, order, G_N_ELEMENTS(order), &error_abort));
    }

    g_assert_true(vibtanium_efi_varstore_boot_entries(&store, &entries,
                                                      false, &error_abort));
    g_assert_cmpuint(entries->len, ==, 1);
    entry = g_ptr_array_index(entries, 0);
    g_assert_cmpuint(entry->id, ==, 7);
    g_assert_cmpstr(entry->description, ==, "Firmware entry");
    g_assert_cmpstr(entry->loader_path, ==, "/EFI/BOOT/BOOTIA64.EFI");
    g_assert_cmpmem(entry->load_options->data, entry->load_options->len,
                    first_opts, sizeof(first_opts) - 1);
    g_ptr_array_unref(entries);
    entries = NULL;

    g_assert_true(vibtanium_efi_varstore_write_boot_entry(
        &store, 7, "Edited entry", "/EFI/custom/loader.efi",
        second_opts, sizeof(second_opts) - 1, &error_abort));
    g_assert_true(vibtanium_efi_varstore_boot_entries(&store, &entries,
                                                      false, &error_abort));
    g_assert_cmpuint(entries->len, ==, 1);
    entry = g_ptr_array_index(entries, 0);
    g_assert_cmpstr(entry->description, ==, "Edited entry");
    g_assert_cmpstr(entry->loader_path, ==, "/EFI/custom/loader.efi");
    g_assert_cmpmem(entry->load_options->data, entry->load_options->len,
                    second_opts, sizeof(second_opts) - 1);
    g_ptr_array_unref(entries);

    g_assert_true(vibtanium_efi_varstore_delete_boot_entry(
        &store, 7, &error_abort));
    g_assert_true(vibtanium_efi_varstore_boot_entries(&store, &entries,
                                                      false, &error_abort));
    g_assert_cmpuint(entries->len, ==, 0);
    g_ptr_array_unref(entries);
    vibtanium_efi_varstore_destroy(&store);
}

static void test_boot_order_helpers_allocate_and_reorder(void)
{
    VibtaniumEfiVarStore store;
    g_autofree uint16_t *order = NULL;
    size_t order_count = 0;
    uint16_t id;

    vibtanium_efi_varstore_init(&store);

    g_assert_true(vibtanium_efi_varstore_allocate_boot_entry_id(
        &store, &id, &error_abort));
    g_assert_cmpuint(id, ==, 0);

    g_assert_true(vibtanium_efi_varstore_write_boot_entry(
        &store, 0, "zero", "\\EFI\\zero.efi", NULL, 0, &error_abort));
    g_assert_true(vibtanium_efi_varstore_write_boot_entry(
        &store, 1, "one", "\\EFI\\one.efi", NULL, 0, &error_abort));
    g_assert_true(vibtanium_efi_varstore_allocate_boot_entry_id(
        &store, &id, &error_abort));
    g_assert_cmpuint(id, ==, 2);

    {
        uint16_t new_order[] = { 1, 0 };
        g_assert_true(vibtanium_efi_varstore_boot_order_set(
            &store, new_order, G_N_ELEMENTS(new_order), &error_abort));
    }
    g_assert_true(vibtanium_efi_varstore_boot_order_get(
        &store, &order, &order_count, &error_abort));
    g_assert_cmpuint(order_count, ==, 2);
    g_assert_cmpuint(order[0], ==, 1);
    g_assert_cmpuint(order[1], ==, 0);

    vibtanium_efi_varstore_destroy(&store);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-efi-vars/status-codes-match-uefi",
                    test_status_codes_match_uefi);
    g_test_add_func("/ia64-efi-vars/load-missing-empty-corrupt",
                    test_loads_missing_empty_and_rejects_corrupt);
    g_test_add_func("/ia64-efi-vars/default-graphical-console-variables",
                    test_load_adds_graphical_console_variables_by_default);
    g_test_add_func("/ia64-efi-vars/requested-serial-console-variables",
                    test_load_adds_serial_console_variables_when_requested);
    g_test_add_func("/ia64-efi-vars/round-trip-json-variable",
                    test_round_trips_json_variable);
    g_test_add_func("/ia64-efi-vars/boot-order-yields-active-entries",
                    test_boot_order_yields_active_entries);
    g_test_add_func("/ia64-efi-vars/boot-next-is-one-shot",
                    test_boot_next_is_one_shot);
    g_test_add_func("/ia64-efi-vars/driver-order-yields-active-entries",
                    test_driver_order_yields_active_entries);
    g_test_add_func("/ia64-efi-vars/boot-entry-write-edit-delete",
                    test_boot_entry_write_edit_and_delete);
    g_test_add_func("/ia64-efi-vars/boot-order-helpers-allocate-reorder",
                    test_boot_order_helpers_allocate_and_reorder);

    return g_test_run();
}
