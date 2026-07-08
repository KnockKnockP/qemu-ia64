/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-types-uefi.h"
#include "qapi/qapi-visit-uefi.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/qobject-output-visitor.h"
#include "qapi/util.h"
#include "qapi/visitor.h"
#include "qobject/qobject.h"
#include "qobject/qjson.h"
#include "qemu/error-report.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-vars.h"

#define EFI_BOOT_ENTRY_NAME_LEN 8
#define EFI_MAX_VAR_NAME_CHARS 1024
#define EFI_CONSOLE_COM1_BASE 0x3f8
#define EFI_CONSOLE_VARIABLE_ATTRIBUTES \
    (VIBTANIUM_EFI_VARIABLE_NON_VOLATILE | \
     VIBTANIUM_EFI_VARIABLE_BOOTSERVICE | \
     VIBTANIUM_EFI_VARIABLE_RUNTIME)

typedef struct VibtaniumEfiVariable {
    char *guid;
    char *name;
    uint32_t attributes;
    GByteArray *data;
} VibtaniumEfiVariable;

static VibtaniumEfiVarStore global_varstore;
static bool global_varstore_initialized;

/*
 * ACPI(PNP0500,0x3f8)/UART(115200 8N1). EFI firmware normally exposes the
 * active console handles through ConIn/ConOut/ErrOut variables; Windows uses
 * ConOut to carry serial redirection settings when SPCR/HCDP are insufficient.
 */
static const uint8_t default_console_device_path[] = {
    0x02, 0x01, 0x0c, 0x00,             /* ACPI HID node */
    0x41, 0xd0, 0x00, 0x05,             /* EISA PNP0500 */
    EFI_CONSOLE_COM1_BASE & 0xff,
    (EFI_CONSOLE_COM1_BASE >> 8) & 0xff,
    (EFI_CONSOLE_COM1_BASE >> 16) & 0xff,
    (EFI_CONSOLE_COM1_BASE >> 24) & 0xff,
    0x03, 0x0e, 0x13, 0x00,             /* UART node */
    0x00, 0x00, 0x00, 0x00,             /* reserved */
    0x00, 0xc2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, /* 115200 */
    0x08,                               /* data bits */
    0x01,                               /* no parity */
    0x01,                               /* one stop bit */
    0x7f, 0xff, 0x04, 0x00,             /* end entire path */
};

static uint16_t rd16(const uint8_t *p)
{
    return p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const uint8_t *p)
{
    return p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void wr16(uint8_t *p, uint16_t value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static void wr32(uint8_t *p, uint32_t value)
{
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
}

static void variable_free(gpointer opaque)
{
    VibtaniumEfiVariable *var = opaque;

    if (!var) {
        return;
    }
    g_free(var->guid);
    g_free(var->name);
    g_byte_array_unref(var->data);
    g_free(var);
}

void vibtanium_efi_boot_entry_free(VibtaniumEfiBootEntry *entry)
{
    if (!entry) {
        return;
    }
    g_clear_pointer(&entry->load_options, g_byte_array_unref);
    g_free(entry);
}

void vibtanium_efi_varstore_init(VibtaniumEfiVarStore *store)
{
    memset(store, 0, sizeof(*store));
    store->variables = g_ptr_array_new_with_free_func(variable_free);
}

void vibtanium_efi_varstore_reset(VibtaniumEfiVarStore *store)
{
    if (!store->variables) {
        vibtanium_efi_varstore_init(store);
        return;
    }
    g_ptr_array_set_size(store->variables, 0);
    store->dirty = false;
}

void vibtanium_efi_varstore_destroy(VibtaniumEfiVarStore *store)
{
    if (!store) {
        return;
    }
    g_clear_pointer(&store->variables, g_ptr_array_unref);
    g_clear_pointer(&store->path, g_free);
    store->dirty = false;
}

static char *canonical_guid(const char *guid)
{
    char *canon = g_ascii_strdown(guid ? guid : "", -1);

    return canon;
}

static bool guid_is_valid(const char *guid)
{
    static const int dash[] = { 8, 13, 18, 23 };

    if (!guid || strlen(guid) != 36) {
        return false;
    }
    for (int i = 0; i < 36; i++) {
        bool is_dash = false;

        for (size_t j = 0; j < G_N_ELEMENTS(dash); j++) {
            if (i == dash[j]) {
                is_dash = true;
                break;
            }
        }
        if (is_dash) {
            if (guid[i] != '-') {
                return false;
            }
            continue;
        }
        if (!g_ascii_isxdigit(guid[i])) {
            return false;
        }
    }
    return true;
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static GByteArray *decode_hex(const char *hex, Error **errp)
{
    GByteArray *bytes;
    size_t len;

    if (!hex) {
        error_setg(errp, "missing UEFI variable data hex string");
        return NULL;
    }

    len = strlen(hex);
    if ((len & 1) != 0) {
        error_setg(errp, "UEFI variable data hex string has odd length");
        return NULL;
    }

    bytes = g_byte_array_sized_new(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        int hi = hex_value(hex[i]);
        int lo = hex_value(hex[i + 1]);
        uint8_t byte;

        if (hi < 0 || lo < 0) {
            error_setg(errp, "UEFI variable data contains non-hex byte");
            g_byte_array_unref(bytes);
            return NULL;
        }
        byte = (hi << 4) | lo;
        g_byte_array_append(bytes, &byte, 1);
    }
    return bytes;
}

static char *encode_hex(const uint8_t *data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    char *out = g_malloc(len * 2 + 1);

    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0xf];
    }
    out[len * 2] = '\0';
    return out;
}

static int variable_compare(gconstpointer a, gconstpointer b)
{
    const VibtaniumEfiVariable *va = *(VibtaniumEfiVariable **)a;
    const VibtaniumEfiVariable *vb = *(VibtaniumEfiVariable **)b;
    int cmp = g_ascii_strcasecmp(va->guid, vb->guid);

    if (cmp != 0) {
        return cmp;
    }
    return strcmp(va->name, vb->name);
}

static VibtaniumEfiVariable *find_variable(VibtaniumEfiVarStore *store,
                                           const char *guid,
                                           const char *name)
{
    g_autofree char *canon = canonical_guid(guid);

    for (size_t i = 0; i < store->variables->len; i++) {
        VibtaniumEfiVariable *var = g_ptr_array_index(store->variables, i);

        if (g_ascii_strcasecmp(var->guid, canon) == 0 &&
            strcmp(var->name, name) == 0) {
            return var;
        }
    }
    return NULL;
}

static void add_variable(VibtaniumEfiVarStore *store,
                         const char *guid,
                         const char *name,
                         uint32_t attributes,
                         GByteArray *data)
{
    VibtaniumEfiVariable *var = g_new0(VibtaniumEfiVariable, 1);

    var->guid = canonical_guid(guid);
    var->name = g_strdup(name);
    var->attributes = attributes;
    var->data = g_byte_array_ref(data);
    g_ptr_array_add(store->variables, var);
}

static void add_default_variable_if_missing(VibtaniumEfiVarStore *store,
                                            const char *name,
                                            const uint8_t *data,
                                            size_t data_size)
{
    g_autoptr(GByteArray) bytes = NULL;

    if (find_variable(store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, name)) {
        return;
    }

    bytes = g_byte_array_sized_new(data_size);
    g_byte_array_append(bytes, data, data_size);
    add_variable(store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, name,
                 EFI_CONSOLE_VARIABLE_ATTRIBUTES, bytes);
}

static void add_default_console_variables(VibtaniumEfiVarStore *store)
{
    if (!store || !store->variables) {
        return;
    }

    add_default_variable_if_missing(store, "ConIn",
                                    default_console_device_path,
                                    sizeof(default_console_device_path));
    add_default_variable_if_missing(store, "ConOut",
                                    default_console_device_path,
                                    sizeof(default_console_device_path));
    add_default_variable_if_missing(store, "ErrOut",
                                    default_console_device_path,
                                    sizeof(default_console_device_path));
}

static bool import_qapi_store(VibtaniumEfiVarStore *store,
                              UefiVarStore *vs,
                              Error **errp)
{
    UefiVariableList *item;

    if (!vs) {
        error_setg(errp, "missing UEFI variable store");
        return false;
    }
    if (vs->version != 2) {
        error_setg(errp, "unsupported UEFI variable store version %" PRId64,
                   vs->version);
        return false;
    }

    for (item = vs->variables; item; item = item->next) {
        UefiVariable *v = item->value;
        g_autoptr(GByteArray) bytes = NULL;

        if (!guid_is_valid(v->guid)) {
            error_setg(errp, "invalid UEFI variable GUID '%s'", v->guid);
            return false;
        }
        if (!v->name || !*v->name) {
            error_setg(errp, "UEFI variable with empty name");
            return false;
        }
        bytes = decode_hex(v->data, errp);
        if (!bytes) {
            return false;
        }
        add_variable(store, v->guid, v->name, v->attr, bytes);
    }
    return true;
}

bool vibtanium_efi_varstore_load(VibtaniumEfiVarStore *store,
                                 const char *path,
                                 Error **errp)
{
    g_autofree gchar *contents = NULL;
    g_autoptr(GError) gerr = NULL;
    gsize length = 0;
    QObject *qobj = NULL;
    Visitor *v = NULL;
    UefiVarStore *vs = NULL;
    bool ok = false;

    vibtanium_efi_varstore_reset(store);
    g_free(store->path);
    store->path = g_strdup(path);

    if (!path || !*path || !g_file_test(path, G_FILE_TEST_EXISTS)) {
        add_default_console_variables(store);
        store->dirty = false;
        return true;
    }

    if (!g_file_get_contents(path, &contents, &length, &gerr)) {
        error_setg(errp, "could not read NVRAM file '%s': %s",
                   path, gerr->message);
        return false;
    }
    if (length == 0) {
        add_default_console_variables(store);
        store->dirty = false;
        return true;
    }

    qobj = qobject_from_json(contents, errp);
    if (!qobj) {
        error_prepend(errp, "could not parse NVRAM file '%s': ", path);
        return false;
    }

    v = qobject_input_visitor_new(qobj);
    if (!visit_type_UefiVarStore(v, NULL, &vs, errp)) {
        error_prepend(errp, "invalid NVRAM file '%s': ", path);
        goto out;
    }

    ok = import_qapi_store(store, vs, errp);
    if (!ok) {
        error_prepend(errp, "invalid NVRAM file '%s': ", path);
    }
    if (ok) {
        add_default_console_variables(store);
    }

out:
    qapi_free_UefiVarStore(vs);
    visit_free(v);
    qobject_unref(qobj);
    store->dirty = false;
    return ok;
}

static UefiVarStore *export_qapi_store(VibtaniumEfiVarStore *store)
{
    UefiVarStore *vs = g_new0(UefiVarStore, 1);
    UefiVariableList **tail = &vs->variables;
    g_autoptr(GPtrArray) sorted = g_ptr_array_new();

    vs->version = 2;
    for (size_t i = 0; i < store->variables->len; i++) {
        g_ptr_array_add(sorted, g_ptr_array_index(store->variables, i));
    }
    g_ptr_array_sort(sorted, variable_compare);

    for (size_t i = 0; i < sorted->len; i++) {
        VibtaniumEfiVariable *var = g_ptr_array_index(sorted, i);
        UefiVariable *v;

        if ((var->attributes & VIBTANIUM_EFI_VARIABLE_NON_VOLATILE) == 0) {
            continue;
        }

        v = g_new0(UefiVariable, 1);
        v->guid = g_strdup(var->guid);
        v->name = g_strdup(var->name);
        v->attr = var->attributes;
        v->data = encode_hex(var->data->data, var->data->len);
        QAPI_LIST_APPEND(tail, v);
    }
    return vs;
}

bool vibtanium_efi_varstore_save(VibtaniumEfiVarStore *store, Error **errp)
{
    UefiVarStore *vs;
    QObject *qobj = NULL;
    Visitor *v;
    g_autoptr(GString) json = NULL;
    g_autoptr(GError) gerr = NULL;
    g_autofree char *dir = NULL;
    bool ok;

    if (!store->path || !*store->path) {
        store->dirty = false;
        return true;
    }

    dir = g_path_get_dirname(store->path);
    if (dir && strcmp(dir, ".") != 0 &&
        g_mkdir_with_parents(dir, 0777) < 0) {
        error_setg_errno(errp, errno, "could not create NVRAM directory '%s'",
                         dir);
        return false;
    }

    vs = export_qapi_store(store);
    v = qobject_output_visitor_new(&qobj);
    if (visit_type_UefiVarStore(v, NULL, &vs, errp)) {
        visit_complete(v, &qobj);
    }
    visit_free(v);
    qapi_free_UefiVarStore(vs);
    if (!qobj) {
        return false;
    }

    json = qobject_to_json_pretty(qobj, true);
    qobject_unref(qobj);
    ok = g_file_set_contents(store->path, json->str, json->len, &gerr);
    if (!ok) {
        error_setg(errp, "could not write NVRAM file '%s': %s",
                   store->path, gerr->message);
        return false;
    }

    store->dirty = false;
    return true;
}

uint64_t vibtanium_efi_varstore_get(VibtaniumEfiVarStore *store,
                                    const char *guid,
                                    const char *name,
                                    uint32_t *attributes,
                                    const uint8_t **data,
                                    size_t *data_size)
{
    VibtaniumEfiVariable *var;

    if (!store || !store->variables || !guid || !name) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    var = find_variable(store, guid, name);
    if (!var) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    if (attributes) {
        *attributes = var->attributes;
    }
    if (data) {
        *data = var->data->data;
    }
    if (data_size) {
        *data_size = var->data->len;
    }
    return VIBTANIUM_EFI_SUCCESS;
}

uint64_t vibtanium_efi_varstore_set(VibtaniumEfiVarStore *store,
                                    const char *guid,
                                    const char *name,
                                    uint32_t attributes,
                                    const uint8_t *data,
                                    size_t data_size)
{
    VibtaniumEfiVariable *old;
    g_autoptr(GByteArray) bytes = NULL;

    if (!store || !store->variables || !guid || !guid_is_valid(guid) ||
        !name || !*name || (data_size != 0 && !data)) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    old = find_variable(store, guid, name);
    if (old) {
        g_ptr_array_remove(store->variables, old);
    }

    if (data_size == 0) {
        store->dirty = true;
        return VIBTANIUM_EFI_SUCCESS;
    }

    bytes = g_byte_array_sized_new(data_size);
    g_byte_array_append(bytes, data, data_size);
    add_variable(store, guid, name, attributes, bytes);
    store->dirty = true;
    return VIBTANIUM_EFI_SUCCESS;
}

uint64_t vibtanium_efi_varstore_next_name(VibtaniumEfiVarStore *store,
                                          const char *guid,
                                          const char *name,
                                          char *next_guid,
                                          size_t next_guid_size,
                                          char **next_name)
{
    g_autoptr(GPtrArray) sorted = g_ptr_array_new();
    bool start = !name || !*name;
    bool found_current = start;

    if (!store || !store->variables || !next_guid || !next_name) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    for (size_t i = 0; i < store->variables->len; i++) {
        g_ptr_array_add(sorted, g_ptr_array_index(store->variables, i));
    }
    g_ptr_array_sort(sorted, variable_compare);

    for (size_t i = 0; i < sorted->len; i++) {
        VibtaniumEfiVariable *var = g_ptr_array_index(sorted, i);

        if (found_current) {
            g_strlcpy(next_guid, var->guid, next_guid_size);
            *next_name = g_strdup(var->name);
            return VIBTANIUM_EFI_SUCCESS;
        }
        if (guid && g_ascii_strcasecmp(var->guid, guid) == 0 &&
            strcmp(var->name, name) == 0) {
            found_current = true;
        }
    }

    return VIBTANIUM_EFI_NOT_FOUND;
}

static bool read_u16_variable(VibtaniumEfiVarStore *store,
                              const char *name,
                              uint16_t *value)
{
    const uint8_t *data;
    size_t size;
    uint64_t status;

    status = vibtanium_efi_varstore_get(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, name, NULL, &data, &size);
    if (status != VIBTANIUM_EFI_SUCCESS || size < 2) {
        return false;
    }
    *value = rd16(data);
    return true;
}

static bool read_boot_order(VibtaniumEfiVarStore *store,
                            const uint16_t **ids,
                            size_t *count)
{
    const uint8_t *data;
    size_t size;
    uint64_t status;

    status = vibtanium_efi_varstore_get(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, "BootOrder", NULL,
        &data, &size);
    if (status != VIBTANIUM_EFI_SUCCESS || (size & 1) != 0) {
        *ids = NULL;
        *count = 0;
        return false;
    }
    *ids = (const uint16_t *)data;
    *count = size / 2;
    return true;
}

static void boot_name(uint16_t id, char name[EFI_BOOT_ENTRY_NAME_LEN + 1])
{
    g_snprintf(name, EFI_BOOT_ENTRY_NAME_LEN + 1, "Boot%04X", id);
}

static bool utf16_data_to_ascii_path(const uint8_t *data,
                                     size_t size,
                                     char *out,
                                     size_t out_size)
{
    size_t n = 0;

    if (out_size == 0) {
        return false;
    }
    out[0] = '\0';
    if ((size & 1) != 0) {
        return false;
    }

    for (size_t off = 0; off + 1 < size && n + 1 < out_size; off += 2) {
        uint16_t ch = rd16(data + off);

        if (ch == 0) {
            break;
        }
        if (ch == '\\') {
            out[n++] = '/';
        } else if (ch < 0x80) {
            out[n++] = ch;
        } else {
            out[n++] = '?';
        }
    }
    out[n] = '\0';
    return n != 0;
}

static bool parse_boot_entry(uint16_t id,
                             bool from_boot_next,
                             const uint8_t *data,
                             size_t size,
                             VibtaniumEfiBootEntry **entry_out)
{
    VibtaniumEfiBootEntry *entry;
    uint32_t attributes;
    uint16_t path_list_len;
    size_t off = 6;
    size_t path_end;
    bool have_path = false;

    if (size < 6) {
        return false;
    }

    attributes = rd32(data);
    path_list_len = rd16(data + 4);
    while (off + 1 < size) {
        uint16_t ch = rd16(data + off);

        off += 2;
        if (ch == 0) {
            break;
        }
    }
    if (off > size || path_list_len > size - off) {
        return false;
    }

    entry = g_new0(VibtaniumEfiBootEntry, 1);
    entry->id = id;
    entry->active = (attributes & VIBTANIUM_EFI_LOAD_OPTION_ACTIVE) != 0;
    entry->from_boot_next = from_boot_next;
    entry->load_options = g_byte_array_new();

    utf16_data_to_ascii_path(data + 6, off - 6, entry->description,
                             sizeof(entry->description));

    path_end = off + path_list_len;
    for (size_t node = off; node + 4 <= path_end;) {
        uint8_t type = data[node];
        uint8_t subtype = data[node + 1];
        uint16_t len = rd16(data + node + 2);

        if (len < 4 || len > path_end - node) {
            vibtanium_efi_boot_entry_free(entry);
            return false;
        }
        if (type == 0x7f) {
            break;
        }
        if (type == 0x04 && subtype == 0x04 &&
            utf16_data_to_ascii_path(data + node + 4, len - 4,
                                     entry->loader_path,
                                     sizeof(entry->loader_path))) {
            have_path = true;
        }
        node += len;
    }

    if (path_end < size) {
        g_byte_array_append(entry->load_options, data + path_end,
                            size - path_end);
    }

    if (!have_path) {
        vibtanium_efi_boot_entry_free(entry);
        return false;
    }

    *entry_out = entry;
    return true;
}

static bool append_boot_entry(VibtaniumEfiVarStore *store,
                              GPtrArray *entries,
                              uint16_t id,
                              bool from_boot_next)
{
    char name[EFI_BOOT_ENTRY_NAME_LEN + 1];
    const uint8_t *data;
    size_t size;
    uint64_t status;
    VibtaniumEfiBootEntry *entry = NULL;

    boot_name(id, name);
    status = vibtanium_efi_varstore_get(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, name, NULL, &data, &size);
    if (status != VIBTANIUM_EFI_SUCCESS ||
        !parse_boot_entry(id, from_boot_next, data, size, &entry)) {
        warn_report("vibtanium EFI boot entry %s skipped: invalid or missing",
                    name);
        return false;
    }
    if (!entry->active) {
        warn_report("vibtanium EFI boot entry %s skipped: inactive", name);
        vibtanium_efi_boot_entry_free(entry);
        return false;
    }
    g_ptr_array_add(entries, entry);
    return true;
}

bool vibtanium_efi_varstore_boot_entries(VibtaniumEfiVarStore *store,
                                         GPtrArray **entries,
                                         bool consume_boot_next,
                                         Error **errp)
{
    g_autoptr(GPtrArray) result =
        g_ptr_array_new_with_free_func((GDestroyNotify)vibtanium_efi_boot_entry_free);
    uint16_t boot_next;
    const uint16_t *order;
    size_t order_count;

    if (!store || !entries) {
        error_setg(errp, "invalid EFI variable store boot-entry request");
        return false;
    }

    if (read_u16_variable(store, "BootNext", &boot_next)) {
        append_boot_entry(store, result, boot_next, true);
        if (consume_boot_next) {
            vibtanium_efi_varstore_set(
                store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, "BootNext", 0,
                NULL, 0);
            if (!vibtanium_efi_varstore_save(store, errp)) {
                return false;
            }
        }
    }

    if (read_boot_order(store, &order, &order_count)) {
        for (size_t i = 0; i < order_count; i++) {
            uint16_t id = rd16((const uint8_t *)order + i * 2);

            if (result->len > 0) {
                VibtaniumEfiBootEntry *first = g_ptr_array_index(result, 0);

                if (first->from_boot_next && first->id == id) {
                    continue;
                }
            }
            append_boot_entry(store, result, id, false);
        }
    }

    *entries = g_steal_pointer(&result);
    return true;
}

bool vibtanium_efi_varstore_set_boot_current(VibtaniumEfiVarStore *store,
                                             uint16_t id,
                                             Error **errp)
{
    uint8_t data[2];
    uint64_t status;

    wr16(data, id);
    status = vibtanium_efi_varstore_set(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, "BootCurrent",
        VIBTANIUM_EFI_VARIABLE_BOOTSERVICE |
        VIBTANIUM_EFI_VARIABLE_RUNTIME,
        data, sizeof(data));
    if (status != VIBTANIUM_EFI_SUCCESS) {
        error_setg(errp, "could not set BootCurrent");
        return false;
    }
    return true;
}

static void append_utf16_ascii(GByteArray *array, const char *text,
                               bool path)
{
    if (!text) {
        text = "";
    }

    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        uint16_t ch = *p < 0x80 ? *p : '?';
        uint8_t bytes[2];

        if (path && ch == '/') {
            ch = '\\';
        }
        wr16(bytes, ch);
        g_byte_array_append(array, bytes, sizeof(bytes));
    }

    uint8_t nul[2] = { 0, 0 };
    g_byte_array_append(array, nul, sizeof(nul));
}

static GByteArray *build_boot_option(const char *description,
                                     const char *loader_path,
                                     const uint8_t *load_options,
                                     size_t load_options_size,
                                     Error **errp)
{
    g_autoptr(GByteArray) file_path = g_byte_array_new();
    GByteArray *option = g_byte_array_new();
    uint8_t u16[2];
    uint8_t u32[4];
    uint8_t node_header[4] = { 0x04, 0x04, 0, 0 };
    uint8_t end_node[4] = { 0x7f, 0xff, 0x04, 0x00 };
    size_t node_offset;
    size_t node_len;
    size_t path_list_len;

    if (!loader_path || !*loader_path) {
        error_setg(errp, "EFI boot entry loader path is empty");
        g_byte_array_unref(option);
        return NULL;
    }
    if (load_options_size != 0 && !load_options) {
        error_setg(errp, "EFI boot entry load options are invalid");
        g_byte_array_unref(option);
        return NULL;
    }

    node_offset = file_path->len;
    g_byte_array_append(file_path, node_header, sizeof(node_header));
    append_utf16_ascii(file_path, loader_path, true);
    node_len = file_path->len - node_offset;
    if (node_len > UINT16_MAX) {
        error_setg(errp, "EFI boot entry loader path is too long");
        g_byte_array_unref(option);
        return NULL;
    }
    file_path->data[node_offset + 2] = node_len;
    file_path->data[node_offset + 3] = node_len >> 8;
    g_byte_array_append(file_path, end_node, sizeof(end_node));

    path_list_len = file_path->len;
    if (path_list_len > UINT16_MAX) {
        error_setg(errp, "EFI boot entry device path is too long");
        g_byte_array_unref(option);
        return NULL;
    }

    wr32(u32, VIBTANIUM_EFI_LOAD_OPTION_ACTIVE);
    g_byte_array_append(option, u32, sizeof(u32));
    wr16(u16, path_list_len);
    g_byte_array_append(option, u16, sizeof(u16));
    append_utf16_ascii(option, description && *description ? description
                                                           : loader_path,
                       false);
    g_byte_array_append(option, file_path->data, file_path->len);
    if (load_options_size != 0) {
        g_byte_array_append(option, load_options, load_options_size);
    }
    return option;
}

bool vibtanium_efi_varstore_write_boot_entry(VibtaniumEfiVarStore *store,
                                             uint16_t id,
                                             const char *description,
                                             const char *loader_path,
                                             const uint8_t *load_options,
                                             size_t load_options_size,
                                             Error **errp)
{
    g_autoptr(GByteArray) option = NULL;
    char name[EFI_BOOT_ENTRY_NAME_LEN + 1];
    uint64_t status;

    if (!store) {
        error_setg(errp, "invalid EFI variable store boot-entry write");
        return false;
    }

    option = build_boot_option(description, loader_path, load_options,
                               load_options_size, errp);
    if (!option) {
        return false;
    }

    boot_name(id, name);
    status = vibtanium_efi_varstore_set(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, name,
        VIBTANIUM_EFI_VARIABLE_NON_VOLATILE |
        VIBTANIUM_EFI_VARIABLE_BOOTSERVICE |
        VIBTANIUM_EFI_VARIABLE_RUNTIME,
        option->data, option->len);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        error_setg(errp, "could not write EFI boot entry %s", name);
        return false;
    }
    return vibtanium_efi_varstore_save(store, errp);
}

bool vibtanium_efi_varstore_delete_boot_entry(VibtaniumEfiVarStore *store,
                                              uint16_t id,
                                              Error **errp)
{
    char name[EFI_BOOT_ENTRY_NAME_LEN + 1];
    uint64_t status;

    if (!store) {
        error_setg(errp, "invalid EFI variable store boot-entry delete");
        return false;
    }

    boot_name(id, name);
    status = vibtanium_efi_varstore_set(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, name, 0, NULL, 0);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        error_setg(errp, "could not delete EFI boot entry %s", name);
        return false;
    }
    return vibtanium_efi_varstore_save(store, errp);
}

bool vibtanium_efi_varstore_boot_order_get(VibtaniumEfiVarStore *store,
                                           uint16_t **ids,
                                           size_t *count,
                                           Error **errp)
{
    const uint16_t *order;
    size_t order_count;

    if (!store || !ids || !count) {
        error_setg(errp, "invalid EFI variable store BootOrder request");
        return false;
    }

    *ids = NULL;
    *count = 0;
    if (!read_boot_order(store, &order, &order_count) || order_count == 0) {
        return true;
    }

    *ids = g_new0(uint16_t, order_count);
    for (size_t i = 0; i < order_count; i++) {
        (*ids)[i] = rd16((const uint8_t *)order + i * 2);
    }
    *count = order_count;
    return true;
}

bool vibtanium_efi_varstore_boot_order_set(VibtaniumEfiVarStore *store,
                                           const uint16_t *ids,
                                           size_t count,
                                           Error **errp)
{
    g_autoptr(GByteArray) data = g_byte_array_new();
    uint8_t bytes[2];
    uint64_t status;

    if (!store || (count != 0 && !ids)) {
        error_setg(errp, "invalid EFI variable store BootOrder update");
        return false;
    }

    for (size_t i = 0; i < count; i++) {
        wr16(bytes, ids[i]);
        g_byte_array_append(data, bytes, sizeof(bytes));
    }

    status = vibtanium_efi_varstore_set(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, "BootOrder",
        count == 0 ? 0 :
        VIBTANIUM_EFI_VARIABLE_NON_VOLATILE |
        VIBTANIUM_EFI_VARIABLE_BOOTSERVICE |
        VIBTANIUM_EFI_VARIABLE_RUNTIME,
        data->data, data->len);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        error_setg(errp, "could not update EFI BootOrder");
        return false;
    }
    return vibtanium_efi_varstore_save(store, errp);
}

bool vibtanium_efi_varstore_allocate_boot_entry_id(VibtaniumEfiVarStore *store,
                                                   uint16_t *id,
                                                   Error **errp)
{
    char name[EFI_BOOT_ENTRY_NAME_LEN + 1];

    if (!store || !id) {
        error_setg(errp, "invalid EFI boot-entry allocation request");
        return false;
    }

    for (uint32_t candidate = 0; candidate <= UINT16_MAX; candidate++) {
        boot_name(candidate, name);
        if (vibtanium_efi_varstore_get(
                store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, name, NULL,
                NULL, NULL) == VIBTANIUM_EFI_NOT_FOUND) {
            *id = candidate;
            return true;
        }
    }

    error_setg(errp, "no free EFI Boot#### id remains");
    return false;
}

bool vibtanium_efi_varstore_delete_boot_next(VibtaniumEfiVarStore *store,
                                             Error **errp)
{
    uint64_t status;

    if (!store) {
        error_setg(errp, "invalid EFI variable store BootNext delete");
        return false;
    }

    status = vibtanium_efi_varstore_set(
        store, VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID, "BootNext", 0, NULL, 0);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        error_setg(errp, "could not delete EFI BootNext");
        return false;
    }
    return vibtanium_efi_varstore_save(store, errp);
}

bool vibtanium_efi_vars_global_load(const char *path, Error **errp)
{
    if (!global_varstore_initialized) {
        vibtanium_efi_varstore_init(&global_varstore);
        global_varstore_initialized = true;
    }
    return vibtanium_efi_varstore_load(&global_varstore, path, errp);
}

bool vibtanium_efi_vars_global_save(Error **errp)
{
    if (!global_varstore_initialized) {
        return true;
    }
    return vibtanium_efi_varstore_save(&global_varstore, errp);
}

uint64_t vibtanium_efi_vars_get(const char *guid,
                                const char *name,
                                uint32_t *attributes,
                                const uint8_t **data,
                                size_t *data_size)
{
    if (!global_varstore_initialized) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }
    return vibtanium_efi_varstore_get(&global_varstore, guid, name,
                                      attributes, data, data_size);
}

uint64_t vibtanium_efi_vars_set(const char *guid,
                                const char *name,
                                uint32_t attributes,
                                const uint8_t *data,
                                size_t data_size,
                                Error **errp)
{
    uint64_t status;

    if (!global_varstore_initialized) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    status = vibtanium_efi_varstore_set(&global_varstore, guid, name,
                                        attributes, data, data_size);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        return status;
    }
    if (global_varstore.dirty &&
        !vibtanium_efi_varstore_save(&global_varstore, errp)) {
        return VIBTANIUM_EFI_DEVICE_ERROR;
    }
    return VIBTANIUM_EFI_SUCCESS;
}

uint64_t vibtanium_efi_vars_next_name(const char *guid,
                                      const char *name,
                                      char *next_guid,
                                      size_t next_guid_size,
                                      char **next_name)
{
    if (!global_varstore_initialized) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }
    return vibtanium_efi_varstore_next_name(&global_varstore, guid, name,
                                            next_guid, next_guid_size,
                                            next_name);
}

bool vibtanium_efi_vars_boot_entries(GPtrArray **entries,
                                     bool consume_boot_next,
                                     Error **errp)
{
    if (!global_varstore_initialized) {
        *entries = g_ptr_array_new_with_free_func(
            (GDestroyNotify)vibtanium_efi_boot_entry_free);
        return true;
    }
    return vibtanium_efi_varstore_boot_entries(&global_varstore, entries,
                                               consume_boot_next, errp);
}

bool vibtanium_efi_vars_set_boot_current(uint16_t id, Error **errp)
{
    if (!global_varstore_initialized) {
        return true;
    }
    return vibtanium_efi_varstore_set_boot_current(&global_varstore, id,
                                                   errp);
}

bool vibtanium_efi_vars_write_boot_entry(uint16_t id,
                                         const char *description,
                                         const char *loader_path,
                                         const uint8_t *load_options,
                                         size_t load_options_size,
                                         Error **errp)
{
    if (!global_varstore_initialized) {
        error_setg(errp, "EFI variable store is not initialized");
        return false;
    }
    return vibtanium_efi_varstore_write_boot_entry(
        &global_varstore, id, description, loader_path, load_options,
        load_options_size, errp);
}

bool vibtanium_efi_vars_delete_boot_entry(uint16_t id, Error **errp)
{
    if (!global_varstore_initialized) {
        error_setg(errp, "EFI variable store is not initialized");
        return false;
    }
    return vibtanium_efi_varstore_delete_boot_entry(&global_varstore, id,
                                                    errp);
}

bool vibtanium_efi_vars_boot_order_get(uint16_t **ids,
                                       size_t *count,
                                       Error **errp)
{
    if (!global_varstore_initialized) {
        *ids = NULL;
        *count = 0;
        return true;
    }
    return vibtanium_efi_varstore_boot_order_get(&global_varstore, ids,
                                                 count, errp);
}

bool vibtanium_efi_vars_boot_order_set(const uint16_t *ids,
                                       size_t count,
                                       Error **errp)
{
    if (!global_varstore_initialized) {
        error_setg(errp, "EFI variable store is not initialized");
        return false;
    }
    return vibtanium_efi_varstore_boot_order_set(&global_varstore, ids,
                                                 count, errp);
}

bool vibtanium_efi_vars_allocate_boot_entry_id(uint16_t *id, Error **errp)
{
    if (!global_varstore_initialized) {
        error_setg(errp, "EFI variable store is not initialized");
        return false;
    }
    return vibtanium_efi_varstore_allocate_boot_entry_id(&global_varstore,
                                                        id, errp);
}

bool vibtanium_efi_vars_delete_boot_next(Error **errp)
{
    if (!global_varstore_initialized) {
        return true;
    }
    return vibtanium_efi_varstore_delete_boot_next(&global_varstore, errp);
}
