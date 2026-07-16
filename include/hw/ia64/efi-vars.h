/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_EFI_VARS_H
#define HW_IA64_EFI_VARS_H

#include "qapi/error.h"

#define VIBTANIUM_EFI_GLOBAL_VARIABLE_GUID \
    "8be4df61-93ca-11d2-aa0d-00e098032b8c"

#define VIBTANIUM_EFI_VARIABLE_NON_VOLATILE      0x00000001U
#define VIBTANIUM_EFI_VARIABLE_BOOTSERVICE       0x00000002U
#define VIBTANIUM_EFI_VARIABLE_RUNTIME           0x00000004U
#define VIBTANIUM_EFI_LOAD_OPTION_ACTIVE         0x00000001U

typedef struct VibtaniumEfiVarStore {
    GPtrArray *variables;
    char *path;
    bool dirty;
} VibtaniumEfiVarStore;

typedef struct VibtaniumEfiBootEntry {
    uint16_t id;
    bool active;
    bool from_boot_next;
    char description[128];
    char loader_path[256];
    GByteArray *load_options;
} VibtaniumEfiBootEntry;

void vibtanium_efi_varstore_init(VibtaniumEfiVarStore *store);
void vibtanium_efi_varstore_reset(VibtaniumEfiVarStore *store);
void vibtanium_efi_varstore_destroy(VibtaniumEfiVarStore *store);

bool vibtanium_efi_varstore_load(VibtaniumEfiVarStore *store,
                                 const char *path,
                                 bool serial_console,
                                 Error **errp);
bool vibtanium_efi_varstore_save(VibtaniumEfiVarStore *store,
                                 Error **errp);

uint64_t vibtanium_efi_varstore_get(VibtaniumEfiVarStore *store,
                                    const char *guid,
                                    const char *name,
                                    uint32_t *attributes,
                                    const uint8_t **data,
                                    size_t *data_size);
uint64_t vibtanium_efi_varstore_set(VibtaniumEfiVarStore *store,
                                    const char *guid,
                                    const char *name,
                                    uint32_t attributes,
                                    const uint8_t *data,
                                    size_t data_size);
uint64_t vibtanium_efi_varstore_next_name(VibtaniumEfiVarStore *store,
                                          const char *guid,
                                          const char *name,
                                          char *next_guid,
                                          size_t next_guid_size,
                                          char **next_name);

bool vibtanium_efi_varstore_boot_entries(VibtaniumEfiVarStore *store,
                                         GPtrArray **entries,
                                         bool consume_boot_next,
                                         Error **errp);
bool vibtanium_efi_varstore_driver_entries(VibtaniumEfiVarStore *store,
                                           GPtrArray **entries,
                                           Error **errp);
bool vibtanium_efi_varstore_set_boot_current(VibtaniumEfiVarStore *store,
                                             uint16_t id,
                                             Error **errp);
bool vibtanium_efi_varstore_write_boot_entry(VibtaniumEfiVarStore *store,
                                             uint16_t id,
                                             const char *description,
                                             const char *loader_path,
                                             const uint8_t *load_options,
                                             size_t load_options_size,
                                             Error **errp);
bool vibtanium_efi_varstore_delete_boot_entry(VibtaniumEfiVarStore *store,
                                              uint16_t id,
                                              Error **errp);
bool vibtanium_efi_varstore_boot_order_get(VibtaniumEfiVarStore *store,
                                           uint16_t **ids,
                                           size_t *count,
                                           Error **errp);
bool vibtanium_efi_varstore_boot_order_set(VibtaniumEfiVarStore *store,
                                           const uint16_t *ids,
                                           size_t count,
                                           Error **errp);
bool vibtanium_efi_varstore_allocate_boot_entry_id(VibtaniumEfiVarStore *store,
                                                   uint16_t *id,
                                                   Error **errp);
bool vibtanium_efi_varstore_delete_boot_next(VibtaniumEfiVarStore *store,
                                             Error **errp);
void vibtanium_efi_boot_entry_free(VibtaniumEfiBootEntry *entry);

bool vibtanium_efi_vars_global_load(const char *path,
                                    bool serial_console,
                                    Error **errp);
bool vibtanium_efi_vars_global_save(Error **errp);
uint64_t vibtanium_efi_vars_get(const char *guid,
                                const char *name,
                                uint32_t *attributes,
                                const uint8_t **data,
                                size_t *data_size);
uint64_t vibtanium_efi_vars_set(const char *guid,
                                const char *name,
                                uint32_t attributes,
                                const uint8_t *data,
                                size_t data_size,
                                Error **errp);
uint64_t vibtanium_efi_vars_next_name(const char *guid,
                                      const char *name,
                                      char *next_guid,
                                      size_t next_guid_size,
                                      char **next_name);
bool vibtanium_efi_vars_boot_entries(GPtrArray **entries,
                                     bool consume_boot_next,
                                     Error **errp);
bool vibtanium_efi_vars_driver_entries(GPtrArray **entries, Error **errp);
bool vibtanium_efi_vars_set_boot_current(uint16_t id, Error **errp);
bool vibtanium_efi_vars_write_boot_entry(uint16_t id,
                                         const char *description,
                                         const char *loader_path,
                                         const uint8_t *load_options,
                                         size_t load_options_size,
                                         Error **errp);
bool vibtanium_efi_vars_delete_boot_entry(uint16_t id, Error **errp);
bool vibtanium_efi_vars_boot_order_get(uint16_t **ids,
                                       size_t *count,
                                       Error **errp);
bool vibtanium_efi_vars_boot_order_set(const uint16_t *ids,
                                       size_t count,
                                       Error **errp);
bool vibtanium_efi_vars_allocate_boot_entry_id(uint16_t *id, Error **errp);
bool vibtanium_efi_vars_delete_boot_next(Error **errp);

#endif
