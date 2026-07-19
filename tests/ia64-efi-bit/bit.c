/*
 * IA-64 in-emulator EFI BIT application.
 *
 * Boots as an EFI image under the vibtanium firmware and exercises the EFI
 * service families implemented by hw/ia64/efi-services.c from inside the
 * guest. The output is intentionally machine-greppable for run.sh.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef unsigned long size_t;
typedef int bool;

#define true 1
#define false 0
#define NULL ((void *)0)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define EFI_ERROR(code) (0x8000000000000000UL | (uint64_t)(code))
#define EFI_SUCCESS 0UL
#define EFI_INVALID_PARAMETER EFI_ERROR(2)
#define EFI_UNSUPPORTED EFI_ERROR(3)
#define EFI_BUFFER_TOO_SMALL EFI_ERROR(5)
#define EFI_NOT_READY EFI_ERROR(6)
#define EFI_WRITE_PROTECTED EFI_ERROR(8)
#define EFI_NOT_FOUND EFI_ERROR(14)
#define EFI_ACCESS_DENIED EFI_ERROR(15)
#define EFI_NO_MAPPING EFI_ERROR(17)

#define EFI_LOADER_CODE 1UL
#define EFI_LOADER_DATA 2UL
#define EFI_ALLOCATE_ANY_PAGES 0UL
#define EFI_ALLOCATE_MAX_ADDRESS 1UL
#define EFI_ALLOCATE_ADDRESS 2UL
#define EFI_TIMER_CANCEL 0UL
#define EFI_TIMER_PERIODIC 1UL
#define EFI_TIMER_RELATIVE 2UL
#define EFI_FILE_MODE_READ 1UL
#define EFI_VARIABLE_NON_VOLATILE 1UL
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 2UL
#define EFI_VARIABLE_RUNTIME_ACCESS 4UL
#define EFI_MEMORY_RUNTIME 0x8000000000000000UL
#define EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE 0x60000202UL

#define VIBTANIUM_EFI_APP_BASE 0x01000000UL
#define VIBTANIUM_EFI_LOADED_IMAGE 0x00071000UL
#define VIBTANIUM_EFI_CON_OUT 0x00081000UL
#define VIBTANIUM_FRAMEBUFFER_WIDTH 640UL
#define VIBTANIUM_FRAMEBUFFER_HEIGHT 400UL
#define BIT_MEDIA_TEXT "vibtanium-bit-ok"
#define BIT_MEDIA_TEXT_LEN (sizeof(BIT_MEDIA_TEXT) - 1)

#define BS_RAISE_TPL 0
#define BS_RESTORE_TPL 1
#define BS_ALLOCATE_PAGES 2
#define BS_FREE_PAGES 3
#define BS_GET_MEMORY_MAP 4
#define BS_ALLOCATE_POOL 5
#define BS_FREE_POOL 6
#define BS_CREATE_EVENT 7
#define BS_SET_TIMER 8
#define BS_WAIT_FOR_EVENT 9
#define BS_SIGNAL_EVENT 10
#define BS_CLOSE_EVENT 11
#define BS_CHECK_EVENT 12
#define BS_INSTALL_PROTOCOL_INTERFACE 13
#define BS_UNINSTALL_PROTOCOL_INTERFACE 15
#define BS_HANDLE_PROTOCOL 16
#define BS_LOCATE_HANDLE 19
#define BS_EXIT_BOOT_SERVICES 26
#define BS_STALL 28
#define BS_SET_WATCHDOG_TIMER 29
#define BS_OPEN_PROTOCOL 32
#define BS_CLOSE_PROTOCOL 33
#define BS_LOCATE_PROTOCOL 37
#define BS_CALCULATE_CRC32 40
#define BS_COPY_MEM 41
#define BS_SET_MEM 42

#define RT_GET_TIME 0
#define RT_SET_TIME 1
#define RT_GET_WAKEUP_TIME 2
#define RT_SET_WAKEUP_TIME 3
#define RT_SET_VIRTUAL_ADDRESS_MAP 4
#define RT_CONVERT_POINTER 5
#define RT_GET_VARIABLE 6
#define RT_GET_NEXT_VARIABLE_NAME 7
#define RT_SET_VARIABLE 8
#define RT_GET_NEXT_HIGH_MONOTONIC_COUNT 9
#define RT_RESET_SYSTEM 10

#define CONOUT_RESET 0
#define CONOUT_OUTPUT_STRING 1
#define CONOUT_TEST_STRING 2
#define CONOUT_QUERY_MODE 3
#define CONOUT_SET_MODE 4
#define CONOUT_SET_ATTRIBUTE 5
#define CONOUT_CLEAR_SCREEN 6
#define CONOUT_SET_CURSOR_POSITION 7
#define CONOUT_ENABLE_CURSOR 8

#define CONIN_RESET 0
#define CONIN_READ_KEY_STROKE 1

#define BLOCKIO_RESET 0
#define BLOCKIO_READ_BLOCKS 1
#define BLOCKIO_WRITE_BLOCKS 2
#define BLOCKIO_FLUSH_BLOCKS 3

#define SIMPLEFS_OPEN_VOLUME 0

#define FILE_OPEN 0
#define FILE_CLOSE 1
#define FILE_DELETE 2
#define FILE_READ 3
#define FILE_WRITE 4
#define FILE_GET_POSITION 5
#define FILE_SET_POSITION 6
#define FILE_GET_INFO 7
#define FILE_SET_INFO 8
#define FILE_FLUSH 9

#define GOP_QUERY_MODE 0
#define GOP_SET_MODE 1
#define GOP_BLT 2

typedef uint16_t CHAR16;

typedef struct EfiGuid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} EfiGuid;

typedef struct EfiTableHeader {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
} EfiTableHeader;

typedef struct EfiBootServices {
    EfiTableHeader hdr;
    void *fn[43];
} EfiBootServices;

typedef struct EfiRuntimeServices {
    EfiTableHeader hdr;
    void *fn[11];
} EfiRuntimeServices;

typedef struct EfiSimpleTextOutputProtocol {
    void *fn[9];
    void *mode;
} EfiSimpleTextOutputProtocol;

typedef struct EfiSimpleTextInputProtocol {
    void *fn[2];
    uint64_t wait_for_key;
} EfiSimpleTextInputProtocol;

typedef struct EfiConfigurationTable {
    EfiGuid vendor_guid;
    void *vendor_table;
} EfiConfigurationTable;

typedef struct EfiMemoryDescriptor {
    uint32_t type;
    uint32_t reserved;
    uint64_t physical_start;
    uint64_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} EfiMemoryDescriptor;

typedef struct EfiSystemTable {
    EfiTableHeader hdr;
    CHAR16 *firmware_vendor;
    uint32_t firmware_revision;
    uint32_t reserved0;
    uint64_t console_in_handle;
    EfiSimpleTextInputProtocol *con_in;
    uint64_t console_out_handle;
    EfiSimpleTextOutputProtocol *con_out;
    uint64_t standard_error_handle;
    EfiSimpleTextOutputProtocol *std_err;
    EfiRuntimeServices *runtime_services;
    EfiBootServices *boot_services;
    uint64_t number_of_table_entries;
    EfiConfigurationTable *configuration_table;
} EfiSystemTable;

typedef struct EfiLoadedImageProtocol {
    uint32_t revision;
    uint32_t reserved0;
    uint64_t parent_handle;
    EfiSystemTable *system_table;
    uint64_t device_handle;
    void *file_path;
    void *reserved;
    uint32_t load_options_size;
    uint32_t reserved1;
    void *load_options;
    void *image_base;
    uint64_t image_size;
    uint32_t image_code_type;
    uint32_t image_data_type;
    void *unload;
} EfiLoadedImageProtocol;

typedef struct EfiInputKey {
    uint16_t scan_code;
    uint16_t unicode_char;
} EfiInputKey;

typedef struct EfiTime {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t pad1;
    uint32_t nanosecond;
    int timezone;
    uint8_t daylight;
    uint8_t pad2;
} EfiTime;

typedef struct EfiTimeCapabilities {
    uint32_t resolution;
    uint32_t accuracy;
    uint8_t sets_to_zero;
} EfiTimeCapabilities;

typedef struct EfiBlockIoMedia {
    uint32_t media_id;
    uint8_t removable_media;
    uint8_t media_present;
    uint8_t logical_partition;
    uint8_t read_only;
    uint8_t write_caching;
    uint8_t pad0[3];
    uint32_t block_size;
    uint32_t io_align;
    uint32_t pad1;
    uint64_t last_block;
} EfiBlockIoMedia;

typedef struct EfiBlockIoProtocol {
    uint64_t revision;
    EfiBlockIoMedia *media;
    void *fn[4];
} EfiBlockIoProtocol;

typedef struct EfiSimpleFileSystemProtocol {
    uint64_t revision;
    void *fn[1];
} EfiSimpleFileSystemProtocol;

typedef struct EfiFileProtocol {
    uint64_t revision;
    void *fn[10];
} EfiFileProtocol;

typedef struct EfiGopModeInformation {
    uint32_t version;
    uint32_t horizontal_resolution;
    uint32_t vertical_resolution;
    uint32_t pixel_format;
    uint32_t pixel_information[4];
    uint32_t pixels_per_scan_line;
} EfiGopModeInformation;

typedef struct EfiGopMode {
    uint32_t max_mode;
    uint32_t mode;
    EfiGopModeInformation *info;
    uint64_t size_of_info;
    uint64_t frame_buffer_base;
    uint64_t frame_buffer_size;
} EfiGopMode;

typedef struct EfiGraphicsOutputProtocol {
    void *fn[3];
    EfiGopMode *mode;
} EfiGraphicsOutputProtocol;

typedef uint64_t (*EfiCall1)(uint64_t);
typedef uint64_t (*EfiCall2)(uint64_t, uint64_t);
typedef uint64_t (*EfiCall3)(uint64_t, uint64_t, uint64_t);
typedef uint64_t (*EfiCall4)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*EfiCall5)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*EfiCall6)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                             uint64_t);
typedef uint64_t (*EfiCall10)(uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t);

extern int ia64_chk_a_clr_fp_takes_branch(void);

static EfiSystemTable *g_st;
static EfiSimpleTextOutputProtocol *g_conout;
static uint64_t g_image_handle;
static uint64_t g_boot_device_handle;
static uint64_t g_pass_count;
static uint64_t g_fail_count;

static CHAR16 print_buffer[256];
static uint8_t memory_map_buffer[4096];
static uint64_t handle_buffer[8];
static uint64_t event_buffer[4];
static uint8_t copy_src[64];
static uint8_t copy_dst[64];
static uint8_t bulk_buffer[12288] __attribute__((aligned(4096)));
static uint8_t block_buffer[4096];
static uint8_t file_buffer[256];
static uint8_t file_info_buffer[256];
static uint32_t blt_pixels[16];
static uint32_t blt_readback[16];
static uint64_t custom_protocol_payload = 0xfeedfacecafebeefUL;
/* Volatile is intentional: keep the benchmark's architectural RAM traffic. */
static volatile uint64_t benchmark_words[256];
/* Volatile is intentional: make the final benchmark store observable. */
static volatile uint64_t benchmark_sink;
static volatile uint64_t virtual_address_change_context;
static volatile uint64_t virtual_address_change_seen;

static const EfiGuid loaded_image_guid = {
    0x5b1b31a1U, 0x9562U, 0x11d2U,
    { 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};
static const EfiGuid simple_text_output_guid = {
    0x387477c2U, 0x69c7U, 0x11d2U,
    { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};
static const EfiGuid simple_text_input_guid = {
    0x387477c1U, 0x69c7U, 0x11d2U,
    { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};
static const EfiGuid block_io_guid = {
    0x964e5b21U, 0x6459U, 0x11d2U,
    { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};
static const EfiGuid simple_file_system_guid = {
    0x964e5b22U, 0x6459U, 0x11d2U,
    { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};
static const EfiGuid file_info_guid = {
    0x09576e92U, 0x6d3fU, 0x11d2U,
    { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};
static const EfiGuid graphics_output_guid = {
    0x9042a9deU, 0x23dcU, 0x4a38U,
    { 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a },
};
static const EfiGuid bit_variable_guid = {
    0x8be4df61U, 0x93caU, 0x11d2U,
    { 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x99 },
};
static const EfiGuid custom_protocol_guid = {
    0x7162692aU, 0x96dfU, 0x4543U,
    { 0x9b, 0x5e, 0x76, 0x69, 0x62, 0x74, 0x65, 0x73 },
};

static CHAR16 conout_probe[] = {
    'e', 'f', 'i', ' ', 'C', 'o', 'n', 'O', 'u', 't', ' ', 'p', 'r', 'o',
    'b', 'e', '\r', '\n', 0
};
static CHAR16 empty_string[] = { 0 };
static CHAR16 bit_var_name[] = {
    'V', 'i', 'b', 'B', 'I', 'T', 'C', 0
};
static CHAR16 media_asset_path[] = {
    '\\', 'E', 'F', 'I', '\\', 'B', 'O', 'O', 'T', '\\', 'B', 'I', 'T',
    '.', 'T', 'X', 'T', 0
};
static CHAR16 media_self_path[] = {
    '\\', 'E', 'F', 'I', '\\', 'B', 'O', 'O', 'T', '\\', 'B', 'O', 'O', 'T',
    'I', 'A', '6', '4', '.', 'E', 'F', 'I', 0
};
static CHAR16 next_var_name[128];
static EfiGuid next_var_guid;

static uint64_t call1(void *fn, uint64_t a0)
{
    return ((EfiCall1)fn)(a0);
}

static void virtual_address_change_notify(uint64_t event, void *context)
{
    (void)event;
    if (context == (void *)&virtual_address_change_context) {
        virtual_address_change_seen++;
    }
}

static uint64_t call2(void *fn, uint64_t a0, uint64_t a1)
{
    return ((EfiCall2)fn)(a0, a1);
}

static uint64_t call3(void *fn, uint64_t a0, uint64_t a1, uint64_t a2)
{
    return ((EfiCall3)fn)(a0, a1, a2);
}

static uint64_t call4(void *fn, uint64_t a0, uint64_t a1, uint64_t a2,
                      uint64_t a3)
{
    return ((EfiCall4)fn)(a0, a1, a2, a3);
}

static uint64_t call5(void *fn, uint64_t a0, uint64_t a1, uint64_t a2,
                      uint64_t a3, uint64_t a4)
{
    return ((EfiCall5)fn)(a0, a1, a2, a3, a4);
}

static uint64_t call6(void *fn, uint64_t a0, uint64_t a1, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5)
{
    return ((EfiCall6)fn)(a0, a1, a2, a3, a4, a5);
}

static uint64_t call10(void *fn, uint64_t a0, uint64_t a1, uint64_t a2,
                       uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                       uint64_t a7, uint64_t a8, uint64_t a9)
{
    return ((EfiCall10)fn)(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
}

static void bytes_set(void *buffer, uint8_t value, size_t size)
{
    uint8_t *p = buffer;

    for (size_t i = 0; i < size; i++) {
        p[i] = value;
    }
}

static bool bytes_equal(const void *a, const void *b, size_t size)
{
    const uint8_t *pa = a;
    const uint8_t *pb = b;

    for (size_t i = 0; i < size; i++) {
        if (pa[i] != pb[i]) {
            return false;
        }
    }
    return true;
}

static bool ascii_prefix_equal(const uint8_t *bytes, const char *text)
{
    for (size_t i = 0; text[i] != 0; i++) {
        if (bytes[i] != (uint8_t)text[i]) {
            return false;
        }
    }
    return true;
}

static uint64_t puts_ascii(const char *s)
{
    size_t i = 0;

    if (!g_conout) {
        return EFI_INVALID_PARAMETER;
    }
    while (s[i] != 0 && i + 1 < ARRAY_SIZE(print_buffer)) {
        print_buffer[i] = (uint8_t)s[i];
        i++;
    }
    print_buffer[i] = 0;
    return call2(g_conout->fn[CONOUT_OUTPUT_STRING],
                 (uint64_t)g_conout, (uint64_t)print_buffer);
}

static bool check(const char *name, bool ok)
{
    if (ok) {
        g_pass_count++;
        puts_ascii("[PASS] ");
    } else {
        g_fail_count++;
        puts_ascii("[FAIL] ");
    }
    puts_ascii(name);
    puts_ascii("\r\n");
    return ok;
}

static bool check_status(const char *name, uint64_t got, uint64_t want)
{
    return check(name, got == want);
}

static bool utf16_eq_ascii(const CHAR16 *s, const char *ascii)
{
    size_t i = 0;

    if (!s || !ascii) {
        return false;
    }
    while (ascii[i] != 0) {
        if (s[i] != (uint8_t)ascii[i]) {
            return false;
        }
        i++;
    }
    return s[i] == 0;
}

static bool guid_nonzero(const EfiGuid *guid)
{
    const uint8_t *p = (const uint8_t *)guid;

    for (size_t i = 0; i < sizeof(*guid); i++) {
        if (p[i] != 0) {
            return true;
        }
    }
    return false;
}

static bool opcode_smoke(void)
{
    volatile uint64_t a = 3;
    volatile uint64_t b = 4;
    uint64_t sum = a + b;
    uint64_t x = 0x0123456789abcdefUL;
    uint64_t y = 0x0123456789abcdefUL;

    return sum == 7 && x == y && ia64_chk_a_clr_fp_takes_branch() == 1;
}

static EfiLoadedImageProtocol *loaded_image_protocol(void)
{
    EfiBootServices *bs = g_st->boot_services;
    uint64_t iface = 0;

    if (call3(bs->fn[BS_HANDLE_PROTOCOL], g_image_handle,
              (uint64_t)&loaded_image_guid, (uint64_t)&iface) != EFI_SUCCESS) {
        return NULL;
    }
    return (EfiLoadedImageProtocol *)iface;
}

static bool test_system_table(void)
{
    EfiLoadedImageProtocol *loaded;
    bool ok = true;

    ok &= check("efi SystemTable pointers and vendor",
                g_st != NULL &&
                g_st->hdr.header_size == 120 &&
                utf16_eq_ascii(g_st->firmware_vendor, "Vibtanium") &&
                g_st->con_out == (EfiSimpleTextOutputProtocol *)
                    VIBTANIUM_EFI_CON_OUT &&
                g_st->boot_services != NULL &&
                g_st->runtime_services != NULL &&
                g_st->number_of_table_entries >= 2 &&
                g_st->configuration_table != NULL);

    loaded = loaded_image_protocol();
    ok &= check("efi LoadedImage protocol fields",
                loaded != NULL &&
                loaded == (EfiLoadedImageProtocol *)VIBTANIUM_EFI_LOADED_IMAGE &&
                loaded->system_table == g_st &&
                loaded->device_handle != 0 &&
                loaded->image_base == (void *)VIBTANIUM_EFI_APP_BASE &&
                loaded->image_size != 0);
    if (loaded) {
        g_boot_device_handle = loaded->device_handle;
    }
    return ok;
}

static bool test_conout(void)
{
    uint64_t columns = 0;
    uint64_t rows = 0;
    bool ok = true;

    ok &= check_status("efi ConOut->OutputString",
                       call2(g_conout->fn[CONOUT_OUTPUT_STRING],
                             (uint64_t)g_conout, (uint64_t)conout_probe),
                       EFI_SUCCESS);
    ok &= check_status("efi ConOut->TestString",
                       call2(g_conout->fn[CONOUT_TEST_STRING],
                             (uint64_t)g_conout, (uint64_t)empty_string),
                       EFI_SUCCESS);
    ok &= check("efi ConOut->QueryMode 80x25",
                call4(g_conout->fn[CONOUT_QUERY_MODE],
                      (uint64_t)g_conout, 0, (uint64_t)&columns,
                      (uint64_t)&rows) == EFI_SUCCESS &&
                columns == 80 && rows == 25);
    ok &= check_status("efi ConOut->SetAttribute",
                       call2(g_conout->fn[CONOUT_SET_ATTRIBUTE],
                             (uint64_t)g_conout, 0x1f),
                       EFI_SUCCESS);
    ok &= check_status("efi ConOut->SetCursorPosition valid",
                       call3(g_conout->fn[CONOUT_SET_CURSOR_POSITION],
                             (uint64_t)g_conout, 1, 1),
                       EFI_SUCCESS);
    ok &= check_status("efi ConOut->SetCursorPosition rejects invalid",
                       call3(g_conout->fn[CONOUT_SET_CURSOR_POSITION],
                             (uint64_t)g_conout, 200, 200),
                       EFI_INVALID_PARAMETER);
    ok &= check_status("efi ConOut->EnableCursor",
                       call2(g_conout->fn[CONOUT_ENABLE_CURSOR],
                             (uint64_t)g_conout, 0),
                       EFI_SUCCESS);
    ok &= check_status("efi ConOut->SetMode mode 0",
                       call2(g_conout->fn[CONOUT_SET_MODE],
                             (uint64_t)g_conout, 0),
                       EFI_SUCCESS);
    ok &= check_status("efi ConOut->ClearScreen",
                       call1(g_conout->fn[CONOUT_CLEAR_SCREEN],
                             (uint64_t)g_conout),
                       EFI_SUCCESS);
    ok &= check_status("efi ConOut->Reset",
                       call2(g_conout->fn[CONOUT_RESET],
                             (uint64_t)g_conout, 0),
                       EFI_SUCCESS);
    return ok;
}

static bool test_boot_memory_services(void)
{
    EfiBootServices *bs = g_st->boot_services;
    uint64_t pool = 0;
    uint64_t page = 0;
    uint64_t map_size = 0;
    uint64_t map_key = 0;
    uint64_t descriptor_size = 0;
    uint32_t descriptor_version = 0;
    bool ok = true;

    ok &= check("efi BootServices Raise/RestoreTPL",
                call1(bs->fn[BS_RAISE_TPL], 8) == 4 &&
                call1(bs->fn[BS_RESTORE_TPL], 4) == EFI_SUCCESS);
    ok &= check_status("efi BootServices Stall",
                       call1(bs->fn[BS_STALL], 1), EFI_SUCCESS);
    ok &= check_status("efi BootServices SetWatchdogTimer",
                       call4(bs->fn[BS_SET_WATCHDOG_TIMER], 0, 0, 0, 0),
                       EFI_SUCCESS);

    ok &= check("efi BootServices AllocatePool/FreePool",
                call3(bs->fn[BS_ALLOCATE_POOL], EFI_LOADER_DATA, 64,
                      (uint64_t)&pool) == EFI_SUCCESS &&
                pool != 0 &&
                (((uint8_t *)pool)[0] = 0xa5, ((uint8_t *)pool)[0] == 0xa5) &&
                call1(bs->fn[BS_FREE_POOL], pool) == EFI_SUCCESS);

    ok &= check("efi BootServices AllocatePages any/free",
                call4(bs->fn[BS_ALLOCATE_PAGES], EFI_ALLOCATE_ANY_PAGES,
                      EFI_LOADER_DATA, 1, (uint64_t)&page) == EFI_SUCCESS &&
                page != 0 && (page & 0xfff) == 0 &&
                (((uint8_t *)page)[0] = 0x5a, ((uint8_t *)page)[0] == 0x5a) &&
                call2(bs->fn[BS_FREE_PAGES], page, 1) == EFI_SUCCESS &&
                call2(bs->fn[BS_FREE_PAGES], page, 1) ==
                    EFI_INVALID_PARAMETER);

    page = 0x03040000UL;
    ok &= check("efi BootServices AllocatePages exact address",
                call4(bs->fn[BS_ALLOCATE_PAGES], EFI_ALLOCATE_ADDRESS,
                      EFI_LOADER_DATA, 2, (uint64_t)&page) == EFI_SUCCESS &&
                page == 0x03040000UL &&
                call2(bs->fn[BS_FREE_PAGES], page, 2) == EFI_SUCCESS);

    ok &= check_status("efi BootServices GetMemoryMap sizes",
                       call5(bs->fn[BS_GET_MEMORY_MAP], (uint64_t)&map_size,
                             0, (uint64_t)&map_key,
                             (uint64_t)&descriptor_size,
                             (uint64_t)&descriptor_version),
                       EFI_BUFFER_TOO_SMALL);
    ok &= check("efi BootServices GetMemoryMap contents",
                map_size > 0 && map_size < sizeof(memory_map_buffer) &&
                descriptor_size == 40 && descriptor_version == 1 &&
                (map_size = sizeof(memory_map_buffer),
                 call5(bs->fn[BS_GET_MEMORY_MAP], (uint64_t)&map_size,
                       (uint64_t)memory_map_buffer, (uint64_t)&map_key,
                       (uint64_t)&descriptor_size,
                       (uint64_t)&descriptor_version) == EFI_SUCCESS) &&
                map_key != 0 && ((uint32_t *)memory_map_buffer)[0] != 0);

    ok &= check_status("efi BootServices ExitBootServices rejects bad key",
                       call2(bs->fn[BS_EXIT_BOOT_SERVICES], g_image_handle,
                             map_key + 1),
                       EFI_INVALID_PARAMETER);
    return ok;
}

static bool test_event_services(void)
{
    EfiBootServices *bs = g_st->boot_services;
    uint64_t event = 0;
    uint64_t index = 99;
    bool ok = true;

    ok &= check("efi events create/check/signal/wait/close",
                call5(bs->fn[BS_CREATE_EVENT], 0, 0, 0, 0,
                      (uint64_t)&event) == EFI_SUCCESS &&
                event != 0 &&
                call1(bs->fn[BS_CHECK_EVENT], event) == EFI_NOT_READY &&
                call1(bs->fn[BS_SIGNAL_EVENT], event) == EFI_SUCCESS &&
                call1(bs->fn[BS_CHECK_EVENT], event) == EFI_SUCCESS &&
                (event_buffer[0] = event,
                 call3(bs->fn[BS_WAIT_FOR_EVENT], 1,
                       (uint64_t)event_buffer, (uint64_t)&index) ==
                    EFI_SUCCESS) &&
                index == 0 &&
                call1(bs->fn[BS_CHECK_EVENT], event) == EFI_NOT_READY &&
                call1(bs->fn[BS_CLOSE_EVENT], event) == EFI_SUCCESS &&
                call1(bs->fn[BS_CHECK_EVENT], event) ==
                    EFI_INVALID_PARAMETER);

    event = 0;
    index = 77;
    ok &= check("efi timer event relative wait",
                call5(bs->fn[BS_CREATE_EVENT], 0, 0, 0, 0,
                      (uint64_t)&event) == EFI_SUCCESS &&
                call3(bs->fn[BS_SET_TIMER], event, EFI_TIMER_RELATIVE, 1) ==
                    EFI_SUCCESS &&
                (event_buffer[0] = event,
                 call3(bs->fn[BS_WAIT_FOR_EVENT], 1,
                       (uint64_t)event_buffer, (uint64_t)&index) ==
                    EFI_SUCCESS) &&
                index == 0 &&
                call3(bs->fn[BS_SET_TIMER], event, EFI_TIMER_CANCEL, 0) ==
                    EFI_SUCCESS &&
                call1(bs->fn[BS_CLOSE_EVENT], event) == EFI_SUCCESS);
    return ok;
}

static bool test_protocol_services(void)
{
    EfiBootServices *bs = g_st->boot_services;
    uint64_t iface = 0;
    uint64_t handle = 0;
    uint64_t handle_size = 0;
    bool ok = true;

    ok &= check("efi HandleProtocol preinstalled LoadedImage",
                call3(bs->fn[BS_HANDLE_PROTOCOL], g_image_handle,
                      (uint64_t)&loaded_image_guid, (uint64_t)&iface) ==
                    EFI_SUCCESS &&
                iface == VIBTANIUM_EFI_LOADED_IMAGE);
    iface = 0;
    ok &= check("efi HandleProtocol preinstalled ConOut",
                call3(bs->fn[BS_HANDLE_PROTOCOL], g_boot_device_handle,
                      (uint64_t)&simple_text_output_guid,
                      (uint64_t)&iface) == EFI_SUCCESS &&
                iface == (uint64_t)g_conout);
    iface = 0;
    ok &= check("efi HandleProtocol preinstalled ConIn",
                call3(bs->fn[BS_HANDLE_PROTOCOL], g_boot_device_handle,
                      (uint64_t)&simple_text_input_guid,
                      (uint64_t)&iface) == EFI_SUCCESS &&
                iface == (uint64_t)g_st->con_in);

    ok &= check_status("efi LocateHandle reports required size",
                       call5(bs->fn[BS_LOCATE_HANDLE], 2,
                             (uint64_t)&graphics_output_guid, 0,
                             (uint64_t)&handle_size, 0),
                       EFI_BUFFER_TOO_SMALL);
    ok &= check("efi LocateHandle returns boot device",
                handle_size == sizeof(uint64_t) &&
                call5(bs->fn[BS_LOCATE_HANDLE], 2,
                      (uint64_t)&graphics_output_guid, 0,
                      (uint64_t)&handle_size, (uint64_t)handle_buffer) ==
                    EFI_SUCCESS &&
                handle_buffer[0] == g_boot_device_handle);

    ok &= check("efi InstallProtocolInterface custom handle",
                call4(bs->fn[BS_INSTALL_PROTOCOL_INTERFACE],
                      (uint64_t)&handle, (uint64_t)&custom_protocol_guid, 0,
                      (uint64_t)&custom_protocol_payload) == EFI_SUCCESS &&
                handle != 0);
    ok &= check_status("efi InstallProtocolInterface rejects duplicate",
                       call4(bs->fn[BS_INSTALL_PROTOCOL_INTERFACE],
                             (uint64_t)&handle,
                             (uint64_t)&custom_protocol_guid, 0,
                             (uint64_t)&custom_protocol_payload),
                       EFI_ACCESS_DENIED);
    iface = 0;
    ok &= check("efi Open/CloseProtocol custom handle",
                call6(bs->fn[BS_OPEN_PROTOCOL], handle,
                      (uint64_t)&custom_protocol_guid, (uint64_t)&iface,
                      g_image_handle, 0, 1) == EFI_SUCCESS &&
                iface == (uint64_t)&custom_protocol_payload &&
                call4(bs->fn[BS_CLOSE_PROTOCOL], handle,
                      (uint64_t)&custom_protocol_guid, g_image_handle, 0) ==
                    EFI_SUCCESS);
    iface = 0;
    ok &= check("efi LocateProtocol custom handle",
                call3(bs->fn[BS_LOCATE_PROTOCOL],
                      (uint64_t)&custom_protocol_guid, 0,
                      (uint64_t)&iface) == EFI_SUCCESS &&
                iface == (uint64_t)&custom_protocol_payload);
    ok &= check("efi UninstallProtocolInterface custom handle",
                call3(bs->fn[BS_UNINSTALL_PROTOCOL_INTERFACE], handle,
                      (uint64_t)&custom_protocol_guid,
                      (uint64_t)&custom_protocol_payload) == EFI_SUCCESS &&
                call3(bs->fn[BS_UNINSTALL_PROTOCOL_INTERFACE], handle,
                      (uint64_t)&custom_protocol_guid,
                      (uint64_t)&custom_protocol_payload) == EFI_NOT_FOUND);
    return ok;
}

static bool test_utility_services(void)
{
    EfiBootServices *bs = g_st->boot_services;
    static const uint8_t crc_text[] = {
        '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };
    uint32_t crc = 0;
    bool ok = true;

    bytes_set(copy_src, 0x3c, sizeof(copy_src));
    bytes_set(copy_dst, 0, sizeof(copy_dst));
    ok &= check("efi CalculateCrc32 known vector",
                call3(bs->fn[BS_CALCULATE_CRC32], (uint64_t)crc_text,
                      sizeof(crc_text), (uint64_t)&crc) == EFI_SUCCESS &&
                crc == 0xcbf43926U);
    ok &= check("efi CopyMem/SetMem",
                call3(bs->fn[BS_COPY_MEM], (uint64_t)copy_dst,
                      (uint64_t)copy_src, sizeof(copy_src)) == EFI_SUCCESS &&
                bytes_equal(copy_src, copy_dst, sizeof(copy_src)) &&
                call3(bs->fn[BS_SET_MEM], (uint64_t)copy_dst,
                      sizeof(copy_dst), 0xa6) == EFI_SUCCESS &&
                copy_dst[0] == 0xa6 &&
                copy_dst[sizeof(copy_dst) - 1] == 0xa6);

    for (unsigned i = 0; i < sizeof(bulk_buffer); i++) {
        bulk_buffer[i] = i % 251;
    }
    ok &= check("efi CopyMem overlapping page-spanning move",
                call3(bs->fn[BS_COPY_MEM], (uint64_t)(bulk_buffer + 37),
                      (uint64_t)bulk_buffer, 6000) == EFI_SUCCESS);
    for (unsigned i = 0; i < 6000; i++) {
        if (bulk_buffer[37 + i] != i % 251) {
            ok &= check("efi CopyMem overlap contents", false);
            break;
        }
    }
    ok &= check("efi SetMem page-spanning fill",
                call3(bs->fn[BS_SET_MEM], (uint64_t)(bulk_buffer + 2000),
                      7000, 0x5a) == EFI_SUCCESS &&
                bulk_buffer[2000] == 0x5a &&
                bulk_buffer[8999] == 0x5a);
    return ok;
}

static bool test_runtime_services(void)
{
    EfiBootServices *bs = g_st->boot_services;
    EfiRuntimeServices *rt = g_st->runtime_services;
    EfiMemoryDescriptor virtual_map = {
        .type = 6,
        .physical_start = 0,
        .virtual_start = 0xe000000000000000UL,
        .number_of_pages = 0x1000,
        .attribute = EFI_MEMORY_RUNTIME,
    };
    EfiTime time;
    EfiTimeCapabilities caps;
    uint8_t enabled = 9;
    uint8_t pending = 9;
    uint32_t data[4] = { 0xdeadbeefU, 0x01020304U, 0x55667788U, 0xa5a55a5aU };
    uint32_t out[4] = { 0, 0, 0, 0 };
    uint64_t out_size = sizeof(out);
    uint32_t attrs = 0;
    uint64_t name_size = sizeof(next_var_name);
    uint32_t mono1 = 0;
    uint32_t mono2 = 0;
    uint64_t pointer = (uint64_t)g_st;
    uint64_t event = 0;
    bool ok = true;

    bytes_set(&time, 0, sizeof(time));
    bytes_set(&caps, 0, sizeof(caps));
    ok &= check("efi RuntimeServices GetTime",
                call2(rt->fn[RT_GET_TIME], (uint64_t)&time,
                      (uint64_t)&caps) == EFI_SUCCESS &&
                time.year == 2026 && caps.resolution == 1);
    ok &= check("efi RuntimeServices SetTime",
                call1(rt->fn[RT_SET_TIME], (uint64_t)&time) == EFI_SUCCESS &&
                call1(rt->fn[RT_SET_TIME], 0) == EFI_INVALID_PARAMETER);
    ok &= check("efi RuntimeServices Get/SetWakeupTime",
                call3(rt->fn[RT_GET_WAKEUP_TIME], (uint64_t)&enabled,
                      (uint64_t)&pending, (uint64_t)&time) == EFI_SUCCESS &&
                enabled == 0 && pending == 0 &&
                call2(rt->fn[RT_SET_WAKEUP_TIME], 0, (uint64_t)&time) ==
                    EFI_SUCCESS);

    ok &= check("efi RuntimeServices Set/GetVariable",
                call5(rt->fn[RT_SET_VARIABLE], (uint64_t)bit_var_name,
                      (uint64_t)&bit_variable_guid,
                      EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS,
                      sizeof(data), (uint64_t)data) == EFI_SUCCESS &&
                call5(rt->fn[RT_GET_VARIABLE], (uint64_t)bit_var_name,
                      (uint64_t)&bit_variable_guid, (uint64_t)&attrs,
                      (uint64_t)&out_size, (uint64_t)out) == EFI_SUCCESS &&
                attrs == (EFI_VARIABLE_NON_VOLATILE |
                          EFI_VARIABLE_BOOTSERVICE_ACCESS |
                          EFI_VARIABLE_RUNTIME_ACCESS) &&
                out_size == sizeof(data) &&
                bytes_equal(data, out, sizeof(data)));

    out_size = 4;
    ok &= check("efi RuntimeServices GetVariable buffer-too-small",
                call5(rt->fn[RT_GET_VARIABLE], (uint64_t)bit_var_name,
                      (uint64_t)&bit_variable_guid, 0,
                      (uint64_t)&out_size, (uint64_t)out) ==
                    EFI_BUFFER_TOO_SMALL &&
                out_size == sizeof(data));

    bytes_set(next_var_name, 0, sizeof(next_var_name));
    bytes_set(&next_var_guid, 0, sizeof(next_var_guid));
    name_size = sizeof(next_var_name);
    ok &= check("efi RuntimeServices GetNextVariableName",
                call3(rt->fn[RT_GET_NEXT_VARIABLE_NAME],
                      (uint64_t)&name_size, (uint64_t)next_var_name,
                      (uint64_t)&next_var_guid) == EFI_SUCCESS &&
                name_size >= 4 && next_var_name[0] != 0 &&
                guid_nonzero(&next_var_guid));

    ok &= check("efi RuntimeServices GetNextHighMonotonicCount",
                call1(rt->fn[RT_GET_NEXT_HIGH_MONOTONIC_COUNT],
                      (uint64_t)&mono1) == EFI_SUCCESS &&
                call1(rt->fn[RT_GET_NEXT_HIGH_MONOTONIC_COUNT],
                      (uint64_t)&mono2) == EFI_SUCCESS &&
                mono2 == mono1 + 1);
    ok &= check("efi RuntimeServices ConvertPointer rejects unmapped",
                call2(rt->fn[RT_CONVERT_POINTER], 0, (uint64_t)&pointer) ==
                    EFI_NOT_FOUND && pointer == (uint64_t)g_st);
    ok &= check_status("efi RuntimeServices SetVirtualAddressMap invalid",
                       call4(rt->fn[RT_SET_VIRTUAL_ADDRESS_MAP], 0, 40, 2, 0),
                       EFI_INVALID_PARAMETER);
    ok &= check_status("efi RuntimeServices SetVirtualAddressMap no mapping",
                       call4(rt->fn[RT_SET_VIRTUAL_ADDRESS_MAP], 0, 40, 1, 0),
                       EFI_NO_MAPPING);
    virtual_address_change_context = 0x5a5aa5a5UL;
    virtual_address_change_seen = 0;
    ok &= check("efi RuntimeServices physical virtual-map notification",
                call5(bs->fn[BS_CREATE_EVENT],
                      EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, 16,
                      (uint64_t)virtual_address_change_notify,
                      (uint64_t)&virtual_address_change_context,
                      (uint64_t)&event) == EFI_SUCCESS && event != 0 &&
                call4(rt->fn[RT_SET_VIRTUAL_ADDRESS_MAP],
                      sizeof(virtual_map), sizeof(virtual_map), 1,
                      (uint64_t)&virtual_map) == EFI_SUCCESS &&
                virtual_address_change_seen == 1);
    pointer = (uint64_t)g_st;
    ok &= check("efi RuntimeServices ConvertPointer mapped",
                call2(rt->fn[RT_CONVERT_POINTER], 0, (uint64_t)&pointer) ==
                    EFI_SUCCESS &&
                pointer == (0xe000000000000000UL | (uint64_t)g_st));
    call5(rt->fn[RT_SET_VARIABLE], (uint64_t)bit_var_name,
          (uint64_t)&bit_variable_guid, 0, 0, 0);
    return ok;
}

static bool test_conin_services(void)
{
    EfiBootServices *bs = g_st->boot_services;
    EfiSimpleTextInputProtocol *conin = g_st->con_in;
    EfiInputKey key;
    uint64_t index = 0;
    bool ok = true;

    bytes_set(&key, 0, sizeof(key));
    ok &= check_status("efi ConIn->Reset",
                       call2(conin->fn[CONIN_RESET], (uint64_t)conin, 0),
                       EFI_SUCCESS);
    ok &= check_status("efi ConIn->ReadKeyStroke not ready",
                       call2(conin->fn[CONIN_READ_KEY_STROKE],
                             (uint64_t)conin, (uint64_t)&key),
                       EFI_NOT_READY);
    ok &= check_status("efi ConIn WaitForKey CheckEvent not ready",
                       call1(bs->fn[BS_CHECK_EVENT], conin->wait_for_key),
                       EFI_NOT_READY);
    event_buffer[0] = conin->wait_for_key;
    ok &= check_status("efi ConIn WaitForKey WaitForEvent not ready",
                       call3(bs->fn[BS_WAIT_FOR_EVENT], 1,
                             (uint64_t)event_buffer, (uint64_t)&index),
                       EFI_NOT_READY);
    return ok;
}

static EfiGraphicsOutputProtocol *locate_gop(void)
{
    EfiBootServices *bs = g_st->boot_services;
    uint64_t iface = 0;

    if (call3(bs->fn[BS_LOCATE_PROTOCOL], (uint64_t)&graphics_output_guid,
              0, (uint64_t)&iface) != EFI_SUCCESS) {
        return NULL;
    }
    return (EfiGraphicsOutputProtocol *)iface;
}

static bool pixels_match(uint32_t value, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (blt_readback[i] != value) {
            return false;
        }
    }
    return true;
}

static bool test_gop_services(void)
{
    EfiGraphicsOutputProtocol *gop = locate_gop();
    uint64_t info_size = 0;
    EfiGopModeInformation *info = NULL;
    bool ok = true;

    ok &= check("efi GOP LocateProtocol", gop != NULL && gop->mode != NULL);
    if (!gop) {
        return false;
    }

    ok &= check("efi GOP QueryMode",
                call4(gop->fn[GOP_QUERY_MODE], (uint64_t)gop, 0,
                      (uint64_t)&info_size, (uint64_t)&info) ==
                    EFI_SUCCESS &&
                info_size == sizeof(EfiGopModeInformation) &&
                info != NULL &&
                info->horizontal_resolution == VIBTANIUM_FRAMEBUFFER_WIDTH &&
                info->vertical_resolution == VIBTANIUM_FRAMEBUFFER_HEIGHT);
    ok &= check_status("efi GOP SetMode 0",
                       call2(gop->fn[GOP_SET_MODE], (uint64_t)gop, 0),
                       EFI_SUCCESS);
    ok &= check_status("efi GOP SetMode rejects invalid",
                       call2(gop->fn[GOP_SET_MODE], (uint64_t)gop, 1),
                       EFI_UNSUPPORTED);

    blt_pixels[0] = 0x00112233U;
    ok &= check("efi GOP Blt video fill/read",
                call10(gop->fn[GOP_BLT], (uint64_t)gop,
                       (uint64_t)blt_pixels, 0, 0, 0, 8, 8, 2, 2, 0) ==
                    EFI_SUCCESS &&
                call10(gop->fn[GOP_BLT], (uint64_t)gop,
                       (uint64_t)blt_readback, 1, 8, 8, 0, 0, 2, 2, 0) ==
                    EFI_SUCCESS &&
                pixels_match(0x00112233U, 4));

    blt_pixels[0] = 0x00000011U;
    blt_pixels[1] = 0x00000022U;
    blt_pixels[2] = 0x00000033U;
    blt_pixels[3] = 0x00000044U;
    bytes_set(blt_readback, 0, sizeof(blt_readback));
    ok &= check("efi GOP Blt buffer/video/video copy",
                call10(gop->fn[GOP_BLT], (uint64_t)gop,
                       (uint64_t)blt_pixels, 2, 0, 0, 12, 8, 2, 2, 0) ==
                    EFI_SUCCESS &&
                call10(gop->fn[GOP_BLT], (uint64_t)gop, 0, 3, 12, 8, 16, 8,
                       2, 2, 0) == EFI_SUCCESS &&
                call10(gop->fn[GOP_BLT], (uint64_t)gop,
                       (uint64_t)blt_readback, 1, 16, 8, 0, 0, 2, 2, 0) ==
                    EFI_SUCCESS &&
                blt_readback[0] == 0x00000011U &&
                blt_readback[1] == 0x00000022U &&
                blt_readback[2] == 0x00000033U &&
                blt_readback[3] == 0x00000044U);
    ok &= check_status("efi GOP Blt rejects invalid rectangle",
                       call10(gop->fn[GOP_BLT], (uint64_t)gop,
                              (uint64_t)blt_pixels, 0, 0, 0,
                              VIBTANIUM_FRAMEBUFFER_WIDTH, 0, 2, 2, 0),
                       EFI_INVALID_PARAMETER);
    return ok;
}

static EfiSimpleFileSystemProtocol *locate_simplefs(void)
{
    EfiBootServices *bs = g_st->boot_services;
    uint64_t iface = 0;

    if (call3(bs->fn[BS_HANDLE_PROTOCOL], g_boot_device_handle,
              (uint64_t)&simple_file_system_guid,
              (uint64_t)&iface) != EFI_SUCCESS) {
        return NULL;
    }
    return (EfiSimpleFileSystemProtocol *)iface;
}

static EfiBlockIoProtocol *locate_blockio(void)
{
    EfiBootServices *bs = g_st->boot_services;
    uint64_t iface = 0;

    if (call3(bs->fn[BS_HANDLE_PROTOCOL], g_boot_device_handle,
              (uint64_t)&block_io_guid, (uint64_t)&iface) != EFI_SUCCESS) {
        return NULL;
    }
    return (EfiBlockIoProtocol *)iface;
}

static bool test_block_io(EfiBlockIoProtocol *block)
{
    uint32_t block_size;
    bool ok = true;

    ok &= check("efi BlockIO protocol present",
                block != NULL && block->media != NULL &&
                block->media->media_present != 0 &&
                block->media->block_size >= 512);
    if (!block || !block->media) {
        return false;
    }

    block_size = block->media->block_size;
    if (block_size > sizeof(block_buffer)) {
        block_size = sizeof(block_buffer);
    }

    ok &= check_status("efi BlockIO->Reset",
                       call2(block->fn[BLOCKIO_RESET],
                             (uint64_t)block, 0),
                       EFI_SUCCESS);
    ok &= check("efi BlockIO->ReadBlocks LBA0",
                call5(block->fn[BLOCKIO_READ_BLOCKS], (uint64_t)block,
                      block->media->media_id, 0, block_size,
                      (uint64_t)block_buffer) == EFI_SUCCESS &&
                block_buffer[510] == 0x55 && block_buffer[511] == 0xaa);
    ok &= check_status("efi BlockIO->ReadBlocks rejects odd size",
                       call5(block->fn[BLOCKIO_READ_BLOCKS],
                             (uint64_t)block, block->media->media_id, 0, 1,
                             (uint64_t)block_buffer),
                       EFI_INVALID_PARAMETER);
    ok &= check_status("efi BlockIO->WriteBlocks media policy",
                       call5(block->fn[BLOCKIO_WRITE_BLOCKS],
                             (uint64_t)block, block->media->media_id, 0,
                             block_size, (uint64_t)block_buffer),
                       block->media->read_only ? EFI_WRITE_PROTECTED :
                                                EFI_SUCCESS);
    ok &= check_status("efi BlockIO->FlushBlocks",
                       call1(block->fn[BLOCKIO_FLUSH_BLOCKS],
                             (uint64_t)block),
                       EFI_SUCCESS);
    return ok;
}

static bool test_file_protocol(EfiSimpleFileSystemProtocol *simplefs)
{
    EfiFileProtocol *root = NULL;
    EfiFileProtocol *file = NULL;
    EfiFileProtocol *self = NULL;
    uint64_t size;
    uint64_t pos = 0;
    bool ok = true;

    ok &= check("efi SimpleFS->OpenVolume",
                simplefs != NULL &&
                call2(simplefs->fn[SIMPLEFS_OPEN_VOLUME],
                      (uint64_t)simplefs, (uint64_t)&root) == EFI_SUCCESS &&
                root != NULL);
    if (!root) {
        return false;
    }

    ok &= check("efi File->Open/read test asset",
                call5(root->fn[FILE_OPEN], (uint64_t)root,
                      (uint64_t)&file, (uint64_t)media_asset_path,
                      EFI_FILE_MODE_READ, 0) == EFI_SUCCESS &&
                file != NULL &&
                (size = sizeof(file_buffer),
                 call3(file->fn[FILE_READ], (uint64_t)file,
                       (uint64_t)&size, (uint64_t)file_buffer) ==
                    EFI_SUCCESS) &&
                size >= BIT_MEDIA_TEXT_LEN &&
                ascii_prefix_equal(file_buffer, BIT_MEDIA_TEXT));

    if (file) {
        size = 0;
        ok &= check_status("efi File->GetInfo reports required size",
                           call4(file->fn[FILE_GET_INFO], (uint64_t)file,
                                 (uint64_t)&file_info_guid, (uint64_t)&size,
                                 0),
                           EFI_BUFFER_TOO_SMALL);
        ok &= check("efi File->GetInfo/GetPosition/SetPosition",
                    size > 80 && size <= sizeof(file_info_buffer) &&
                    (size = sizeof(file_info_buffer),
                     call4(file->fn[FILE_GET_INFO], (uint64_t)file,
                           (uint64_t)&file_info_guid, (uint64_t)&size,
                           (uint64_t)file_info_buffer) == EFI_SUCCESS) &&
                    (*(uint64_t *)(file_info_buffer + 8)) >=
                        BIT_MEDIA_TEXT_LEN &&
                    call2(file->fn[FILE_GET_POSITION], (uint64_t)file,
                          (uint64_t)&pos) == EFI_SUCCESS &&
                    pos >= BIT_MEDIA_TEXT_LEN &&
                    call2(file->fn[FILE_SET_POSITION], (uint64_t)file, 0) ==
                        EFI_SUCCESS &&
                    (size = 4,
                     call3(file->fn[FILE_READ], (uint64_t)file,
                           (uint64_t)&size, (uint64_t)file_buffer) ==
                        EFI_SUCCESS) &&
                    size == 4 &&
                    ascii_prefix_equal(file_buffer, "vibt"));
        ok &= check_status("efi File->Write is protected",
                           call3(file->fn[FILE_WRITE], (uint64_t)file,
                                 (uint64_t)&size, (uint64_t)file_buffer),
                           EFI_WRITE_PROTECTED);
        ok &= check_status("efi File->Flush",
                           call1(file->fn[FILE_FLUSH], (uint64_t)file),
                           EFI_SUCCESS);
        call1(file->fn[FILE_CLOSE], (uint64_t)file);
    }

    ok &= check("efi File->Open BIT image",
                call5(root->fn[FILE_OPEN], (uint64_t)root,
                      (uint64_t)&self, (uint64_t)media_self_path,
                      EFI_FILE_MODE_READ, 0) == EFI_SUCCESS &&
                self != NULL &&
                (size = 2,
                 call3(self->fn[FILE_READ], (uint64_t)self,
                       (uint64_t)&size, (uint64_t)file_buffer) ==
                    EFI_SUCCESS) &&
                size == 2 && file_buffer[0] == 'M' && file_buffer[1] == 'Z');
    if (self) {
        call1(self->fn[FILE_CLOSE], (uint64_t)self);
    }

    file = NULL;
    ok &= check_status("efi File->Open rejects write mode",
                       call5(root->fn[FILE_OPEN], (uint64_t)root,
                             (uint64_t)&file, (uint64_t)media_asset_path,
                             3, 0),
                       EFI_WRITE_PROTECTED);
    ok &= check_status("efi File directory Read unsupported",
                       (size = sizeof(file_buffer),
                        call3(root->fn[FILE_READ], (uint64_t)root,
                              (uint64_t)&size, (uint64_t)file_buffer)),
                       EFI_UNSUPPORTED);
    call1(root->fn[FILE_CLOSE], (uint64_t)root);
    return ok;
}

static bool test_media_services(void)
{
    EfiBlockIoProtocol *block = locate_blockio();
    EfiSimpleFileSystemProtocol *simplefs = locate_simplefs();
    bool ok = true;

    ok &= test_block_io(block);
    ok &= test_file_protocol(simplefs);
    return ok;
}

/*
 * Stable post-BIT workload for the host-bracketed retired-bundle benchmark.
 * It deliberately mixes dependent integer work with ordinary RAM loads and
 * stores, and never calls firmware after the ALL PASS marker.
 */
void ia64_benchmark_loop(void)
{
    uint64_t carry = 0x9e3779b97f4a7c15UL;

    for (unsigned i = 0; i < 256; i++) {
        benchmark_words[i] = carry ^ i;
    }

    for (;;) {
        for (unsigned i = 0; i < 256; i++) {
            uint64_t value = benchmark_words[i];

            value += carry + i;
            value ^= value << 13;
            value ^= value >> 7;
            benchmark_words[i] = value;
            carry += value ^ (carry >> 11);
        }
        benchmark_sink = carry;
    }
}

void efi_main(uint64_t image_handle, EfiSystemTable *system_table)
{
    g_image_handle = image_handle;
    g_st = system_table;
    g_conout = system_table ? system_table->con_out : NULL;

    puts_ascii("vibtanium efi BIT: start\r\n");
    check("ia64 opcode smoke", opcode_smoke());
    test_system_table();
    test_conout();
    test_boot_memory_services();
    test_event_services();
    test_protocol_services();
    test_utility_services();
    test_conin_services();
    test_gop_services();
    test_media_services();
    test_runtime_services();

    if (g_fail_count == 0) {
        puts_ascii("VIBTANIUM-BIT-RESULT: ALL PASS\r\n");
    } else {
        puts_ascii("VIBTANIUM-BIT-RESULT: FAILURES\r\n");
    }
}
