/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/vibtanium.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "standard-headers/linux/input-event-codes.h"
#include "system/memory.h"
#include "ui/console.h"
#include "ui/input.h"
#include "ui/surface.h"
#include "ui/vgafont.h"

#define TYPE_VIBTANIUM_EFI_DISPLAY "vibtanium-efi-display"
OBJECT_DECLARE_SIMPLE_TYPE(VibtaniumEfiDisplayState, VIBTANIUM_EFI_DISPLAY)

#define EFI_TEXT_COLUMNS \
    (VIBTANIUM_FRAMEBUFFER_WIDTH / FONT_WIDTH)
#define EFI_TEXT_ROWS \
    (VIBTANIUM_FRAMEBUFFER_HEIGHT / FONT_HEIGHT)
#define EFI_DEFAULT_ATTRIBUTE 0x07
#define VGA_CRTC_CURSOR_START 0x0a
#define VGA_CRTC_START_ADDR_HIGH 0x0c
#define VGA_CRTC_START_ADDR_LOW 0x0d
#define VGA_CRTC_CURSOR_LOC_HIGH 0x0e
#define VGA_CRTC_CURSOR_LOC_LOW 0x0f
#define VGA_TEXT_CELL_BYTES 2
#define VGA_TEXT_CELL_COUNT \
    (VIBTANIUM_VGA_TEXT_SIZE / VGA_TEXT_CELL_BYTES)

struct VibtaniumEfiDisplayState {
    SysBusDevice parent_obj;

    QemuInputHandlerState *keyboard;
    bool left_shift_down;
    bool right_shift_down;
    bool caps_lock_down;
    bool caps_lock;
};

typedef struct VibtaniumEfiConsole {
    QemuConsole *con;
    DisplaySurface *surface;
    uint32_t *fb;
    uint8_t *vga_text;
    uint8_t *vga_crtc;
    uint32_t attribute;
    uint32_t cursor_column;
    uint32_t cursor_row;
    bool cursor_visible;
    bool initialized;
    bool vga_text_active;
} VibtaniumEfiConsole;

static VibtaniumEfiConsole efi_console;
static VibtaniumEfiDisplayState *efi_display;

static const uint32_t efi_vga_palette[16] = {
    0x00000000, 0x000000aa, 0x0000aa00, 0x0000aaaa,
    0x00aa0000, 0x00aa00aa, 0x00aa5500, 0x00aaaaaa,
    0x00555555, 0x005555ff, 0x0055ff55, 0x0055ffff,
    0x00ff5555, 0x00ff55ff, 0x00ffff55, 0x00ffffff,
};

static bool efi_key_shifted(const VibtaniumEfiDisplayState *s)
{
    return s->left_shift_down || s->right_shift_down;
}

static bool efi_key_letter(uint32_t key, const VibtaniumEfiDisplayState *s,
                           uint16_t *unicode_char)
{
    bool upper;
    char ch;

    switch (key) {
    case KEY_A:
        ch = 'a';
        break;
    case KEY_B:
        ch = 'b';
        break;
    case KEY_C:
        ch = 'c';
        break;
    case KEY_D:
        ch = 'd';
        break;
    case KEY_E:
        ch = 'e';
        break;
    case KEY_F:
        ch = 'f';
        break;
    case KEY_G:
        ch = 'g';
        break;
    case KEY_H:
        ch = 'h';
        break;
    case KEY_I:
        ch = 'i';
        break;
    case KEY_J:
        ch = 'j';
        break;
    case KEY_K:
        ch = 'k';
        break;
    case KEY_L:
        ch = 'l';
        break;
    case KEY_M:
        ch = 'm';
        break;
    case KEY_N:
        ch = 'n';
        break;
    case KEY_O:
        ch = 'o';
        break;
    case KEY_P:
        ch = 'p';
        break;
    case KEY_Q:
        ch = 'q';
        break;
    case KEY_R:
        ch = 'r';
        break;
    case KEY_S:
        ch = 's';
        break;
    case KEY_T:
        ch = 't';
        break;
    case KEY_U:
        ch = 'u';
        break;
    case KEY_V:
        ch = 'v';
        break;
    case KEY_W:
        ch = 'w';
        break;
    case KEY_X:
        ch = 'x';
        break;
    case KEY_Y:
        ch = 'y';
        break;
    case KEY_Z:
        ch = 'z';
        break;
    default:
        return false;
    }

    upper = efi_key_shifted(s) ^ s->caps_lock;
    *unicode_char = upper ? g_ascii_toupper(ch) : ch;
    return true;
}

static bool efi_key_digit(uint32_t key, const VibtaniumEfiDisplayState *s,
                          uint16_t *unicode_char)
{
    static const char unshifted[] = "1234567890";
    static const char shifted[] = "!@#$%^&*()";

    if (key < KEY_1 || key > KEY_0) {
        return false;
    }

    if (key == KEY_0) {
        *unicode_char = efi_key_shifted(s) ? shifted[9] : unshifted[9];
    } else {
        size_t index = key - KEY_1;
        *unicode_char = efi_key_shifted(s) ? shifted[index] : unshifted[index];
    }
    return true;
}

static bool efi_key_symbol(uint32_t key, const VibtaniumEfiDisplayState *s,
                           uint16_t *unicode_char)
{
    bool shifted = efi_key_shifted(s);

    switch (key) {
    case KEY_SPACE:
        *unicode_char = ' ';
        return true;
    case KEY_MINUS:
        *unicode_char = shifted ? '_' : '-';
        return true;
    case KEY_EQUAL:
        *unicode_char = shifted ? '+' : '=';
        return true;
    case KEY_LEFTBRACE:
        *unicode_char = shifted ? '{' : '[';
        return true;
    case KEY_RIGHTBRACE:
        *unicode_char = shifted ? '}' : ']';
        return true;
    case KEY_SEMICOLON:
        *unicode_char = shifted ? ':' : ';';
        return true;
    case KEY_APOSTROPHE:
        *unicode_char = shifted ? '"' : '\'';
        return true;
    case KEY_GRAVE:
        *unicode_char = shifted ? '~' : '`';
        return true;
    case KEY_BACKSLASH:
        *unicode_char = shifted ? '|' : '\\';
        return true;
    case KEY_COMMA:
        *unicode_char = shifted ? '<' : ',';
        return true;
    case KEY_DOT:
        *unicode_char = shifted ? '>' : '.';
        return true;
    case KEY_SLASH:
        *unicode_char = shifted ? '?' : '/';
        return true;
    case KEY_KPASTERISK:
        *unicode_char = '*';
        return true;
    case KEY_KPMINUS:
        *unicode_char = '-';
        return true;
    case KEY_KPPLUS:
        *unicode_char = '+';
        return true;
    case KEY_KPDOT:
        *unicode_char = '.';
        return true;
    case KEY_KPSLASH:
        *unicode_char = '/';
        return true;
    default:
        return false;
    }
}

static bool efi_key_keypad_digit(uint32_t key, uint16_t *unicode_char)
{
    switch (key) {
    case KEY_KP0:
        *unicode_char = '0';
        return true;
    case KEY_KP1:
        *unicode_char = '1';
        return true;
    case KEY_KP2:
        *unicode_char = '2';
        return true;
    case KEY_KP3:
        *unicode_char = '3';
        return true;
    case KEY_KP4:
        *unicode_char = '4';
        return true;
    case KEY_KP5:
        *unicode_char = '5';
        return true;
    case KEY_KP6:
        *unicode_char = '6';
        return true;
    case KEY_KP7:
        *unicode_char = '7';
        return true;
    case KEY_KP8:
        *unicode_char = '8';
        return true;
    case KEY_KP9:
        *unicode_char = '9';
        return true;
    default:
        return false;
    }
}

static bool efi_key_to_input_key(uint32_t key,
                                 const VibtaniumEfiDisplayState *s,
                                 uint16_t *scan_code,
                                 uint16_t *unicode_char)
{
    *scan_code = 0;
    *unicode_char = 0;

    if (efi_key_letter(key, s, unicode_char) ||
        efi_key_digit(key, s, unicode_char) ||
        efi_key_symbol(key, s, unicode_char) ||
        efi_key_keypad_digit(key, unicode_char)) {
        return true;
    }

    switch (key) {
    case KEY_ENTER:
    case KEY_KPENTER:
        *unicode_char = '\r';
        return true;
    case KEY_BACKSPACE:
        *unicode_char = '\b';
        return true;
    case KEY_TAB:
        *unicode_char = '\t';
        return true;
    case KEY_UP:
        *scan_code = VIBTANIUM_EFI_SCAN_UP;
        return true;
    case KEY_DOWN:
        *scan_code = VIBTANIUM_EFI_SCAN_DOWN;
        return true;
    case KEY_RIGHT:
        *scan_code = VIBTANIUM_EFI_SCAN_RIGHT;
        return true;
    case KEY_LEFT:
        *scan_code = VIBTANIUM_EFI_SCAN_LEFT;
        return true;
    case KEY_HOME:
        *scan_code = VIBTANIUM_EFI_SCAN_HOME;
        return true;
    case KEY_END:
        *scan_code = VIBTANIUM_EFI_SCAN_END;
        return true;
    case KEY_INSERT:
        *scan_code = VIBTANIUM_EFI_SCAN_INSERT;
        return true;
    case KEY_DELETE:
        *scan_code = VIBTANIUM_EFI_SCAN_DELETE;
        return true;
    case KEY_PAGEUP:
        *scan_code = VIBTANIUM_EFI_SCAN_PAGE_UP;
        return true;
    case KEY_PAGEDOWN:
        *scan_code = VIBTANIUM_EFI_SCAN_PAGE_DOWN;
        return true;
    case KEY_F1 ... KEY_F10:
        *scan_code = VIBTANIUM_EFI_SCAN_F1 + key - KEY_F1;
        return true;
    case KEY_ESC:
        *scan_code = VIBTANIUM_EFI_SCAN_ESC;
        return true;
    default:
        return false;
    }
}

static void vibtanium_efi_keyboard_event(DeviceState *dev, QemuConsole *src,
                                         QemuInputEvent *evt)
{
    VibtaniumEfiDisplayState *s = VIBTANIUM_EFI_DISPLAY(dev);
    uint16_t scan_code;
    uint16_t unicode_char;

    if (evt->type != INPUT_EVENT_KIND_KEY) {
        return;
    }

    switch (evt->key.key) {
    case KEY_LEFTSHIFT:
        s->left_shift_down = evt->key.down;
        return;
    case KEY_RIGHTSHIFT:
        s->right_shift_down = evt->key.down;
        return;
    case KEY_CAPSLOCK:
        if (evt->key.down && !s->caps_lock_down) {
            s->caps_lock = !s->caps_lock;
        }
        s->caps_lock_down = evt->key.down;
        return;
    default:
        break;
    }

    if (!evt->key.down ||
        !efi_key_to_input_key(evt->key.key, s, &scan_code, &unicode_char)) {
        return;
    }

    vibtanium_efi_input_enqueue(scan_code, unicode_char);
}

static const QemuInputHandler vibtanium_efi_keyboard_handler = {
    .name = "vibtanium EFI keyboard",
    .mask = INPUT_EVENT_MASK_KEY,
    .event = vibtanium_efi_keyboard_event,
};

static uint32_t efi_console_fg(void)
{
    return efi_vga_palette[efi_console.attribute & 0xf];
}

static uint32_t efi_console_bg(void)
{
    return efi_vga_palette[(efi_console.attribute >> 4) & 0x7];
}

static void efi_console_update_pixels(uint32_t x, uint32_t y,
                                      uint32_t width, uint32_t height)
{
    if (!efi_console.con || width == 0 || height == 0) {
        return;
    }

    qemu_console_update(efi_console.con, x, y, width, height);
}

static void efi_console_fill_rect(uint32_t x, uint32_t y,
                                  uint32_t width, uint32_t height,
                                  uint32_t color)
{
    if (!efi_console.fb || width == 0 || height == 0 ||
        x >= VIBTANIUM_FRAMEBUFFER_WIDTH ||
        y >= VIBTANIUM_FRAMEBUFFER_HEIGHT) {
        return;
    }

    width = MIN(width, VIBTANIUM_FRAMEBUFFER_WIDTH - x);
    height = MIN(height, VIBTANIUM_FRAMEBUFFER_HEIGHT - y);

    for (uint32_t row = 0; row < height; row++) {
        uint32_t *dst = efi_console.fb +
                        (y + row) * VIBTANIUM_FRAMEBUFFER_WIDTH + x;
        for (uint32_t col = 0; col < width; col++) {
            dst[col] = color;
        }
    }
    efi_console_update_pixels(x, y, width, height);
}

static void efi_console_draw_glyph_colors(uint32_t column, uint32_t row,
                                          uint8_t ch, uint32_t fg,
                                          uint32_t bg, bool update)
{
    uint32_t x = column * FONT_WIDTH;
    uint32_t y = row * FONT_HEIGHT;

    if (!efi_console.fb || column >= EFI_TEXT_COLUMNS ||
        row >= EFI_TEXT_ROWS) {
        return;
    }

    for (uint32_t glyph_y = 0; glyph_y < FONT_HEIGHT; glyph_y++) {
        uint8_t bits = vgafont16[ch * FONT_HEIGHT + glyph_y];
        uint32_t *dst = efi_console.fb +
                        (y + glyph_y) * VIBTANIUM_FRAMEBUFFER_WIDTH + x;

        for (uint32_t glyph_x = 0; glyph_x < FONT_WIDTH; glyph_x++) {
            dst[glyph_x] = (bits & (0x80 >> glyph_x)) ? fg : bg;
        }
    }
    if (update) {
        efi_console_update_pixels(x, y, FONT_WIDTH, FONT_HEIGHT);
    }
}

static void efi_console_draw_glyph(uint32_t column, uint32_t row, uint8_t ch)
{
    efi_console_draw_glyph_colors(column, row, ch, efi_console_fg(),
                                  efi_console_bg(), true);
}

static uint16_t efi_console_vga_word(uint8_t high_reg, uint8_t low_reg)
{
    if (!efi_console.vga_crtc) {
        return 0;
    }

    return ((uint16_t)efi_console.vga_crtc[high_reg] << 8) |
           efi_console.vga_crtc[low_reg];
}

static void efi_console_draw_vga_cursor(uint16_t start_cell)
{
    uint16_t cursor;
    uint16_t relative;
    uint32_t x;
    uint32_t y;

    if (!efi_console.fb || !efi_console.vga_crtc ||
        (efi_console.vga_crtc[VGA_CRTC_CURSOR_START] & 0x20)) {
        return;
    }

    cursor = efi_console_vga_word(VGA_CRTC_CURSOR_LOC_HIGH,
                                  VGA_CRTC_CURSOR_LOC_LOW);
    relative = (cursor + VGA_TEXT_CELL_COUNT - start_cell) %
               VGA_TEXT_CELL_COUNT;
    if (relative >= VIBTANIUM_VGA_TEXT_COLUMNS * VIBTANIUM_VGA_TEXT_ROWS) {
        return;
    }

    x = (relative % VIBTANIUM_VGA_TEXT_COLUMNS) * FONT_WIDTH;
    y = (relative / VIBTANIUM_VGA_TEXT_COLUMNS) * FONT_HEIGHT +
        FONT_HEIGHT - 2;

    for (uint32_t row = 0; row < 2; row++) {
        uint32_t *dst =
            efi_console.fb + (y + row) * VIBTANIUM_FRAMEBUFFER_WIDTH + x;

        for (uint32_t column = 0; column < FONT_WIDTH; column++) {
            dst[column] = efi_vga_palette[15];
        }
    }
}

static void efi_console_render_vga_text(void)
{
    uint16_t start_cell;

    if (!efi_console.fb || !efi_console.vga_text ||
        !efi_console.vga_text_active) {
        return;
    }

    start_cell = efi_console_vga_word(VGA_CRTC_START_ADDR_HIGH,
                                      VGA_CRTC_START_ADDR_LOW) %
                 VGA_TEXT_CELL_COUNT;

    for (uint32_t row = 0; row < VIBTANIUM_VGA_TEXT_ROWS; row++) {
        for (uint32_t column = 0; column < VIBTANIUM_VGA_TEXT_COLUMNS;
             column++) {
            uint16_t cell_index =
                (start_cell + row * VIBTANIUM_VGA_TEXT_COLUMNS + column) %
                VGA_TEXT_CELL_COUNT;
            const uint8_t *cell =
                efi_console.vga_text + cell_index * VGA_TEXT_CELL_BYTES;
            uint8_t ch = cell[0] >= 0x20 ? cell[0] : ' ';
            uint8_t attribute = cell[1] ? cell[1] : EFI_DEFAULT_ATTRIBUTE;
            uint32_t fg = efi_vga_palette[attribute & 0xf];
            uint32_t bg = efi_vga_palette[(attribute >> 4) & 0x7];

            efi_console_draw_glyph_colors(column, row, ch, fg, bg, false);
        }
    }

    efi_console_draw_vga_cursor(start_cell);
}

static void efi_console_scroll(void)
{
    uint8_t *fb = (uint8_t *)efi_console.fb;
    size_t line_bytes = VIBTANIUM_FRAMEBUFFER_STRIDE * FONT_HEIGHT;
    size_t scroll_bytes = VIBTANIUM_FRAMEBUFFER_STRIDE *
                          (VIBTANIUM_FRAMEBUFFER_HEIGHT - FONT_HEIGHT);

    if (!fb) {
        return;
    }

    memmove(fb, fb + line_bytes, scroll_bytes);
    efi_console_fill_rect(0, VIBTANIUM_FRAMEBUFFER_HEIGHT - FONT_HEIGHT,
                          VIBTANIUM_FRAMEBUFFER_WIDTH, FONT_HEIGHT,
                          efi_console_bg());
    efi_console.cursor_row = EFI_TEXT_ROWS - 1;
    efi_console_update_pixels(0, 0, VIBTANIUM_FRAMEBUFFER_WIDTH,
                              VIBTANIUM_FRAMEBUFFER_HEIGHT);
}

static void efi_console_newline(void)
{
    efi_console.cursor_column = 0;
    if (efi_console.cursor_row + 1 >= EFI_TEXT_ROWS) {
        efi_console_scroll();
    } else {
        efi_console.cursor_row++;
    }
}

static bool vibtanium_efi_console_gfx_update(void *opaque)
{
    VibtaniumEfiConsole *console = opaque;

    if (console->con) {
        efi_console_render_vga_text();
        qemu_console_update_full(console->con);
    }
    return true;
}

static void vibtanium_efi_console_invalidate(void *opaque)
{
    VibtaniumEfiConsole *console = opaque;

    if (console->con) {
        efi_console_render_vga_text();
        qemu_console_update_full(console->con);
    }
}

static const GraphicHwOps vibtanium_efi_console_ops = {
    .invalidate = vibtanium_efi_console_invalidate,
    .gfx_update = vibtanium_efi_console_gfx_update,
};

static void vibtanium_efi_display_realize(DeviceState *dev, Error **errp)
{
    VibtaniumEfiDisplayState *s = VIBTANIUM_EFI_DISPLAY(dev);

    s->keyboard = qemu_input_handler_register(dev,
                                              &vibtanium_efi_keyboard_handler);
    efi_display = s;
    qemu_input_handler_activate(s->keyboard);
}

static void vibtanium_efi_display_unrealize(DeviceState *dev)
{
    VibtaniumEfiDisplayState *s = VIBTANIUM_EFI_DISPLAY(dev);

    if (efi_display == s) {
        efi_display = NULL;
    }
    g_clear_pointer(&s->keyboard, qemu_input_handler_unregister);
}

static void vibtanium_efi_display_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->desc = "vibtanium EFI framebuffer display";
    dc->realize = vibtanium_efi_display_realize;
    dc->unrealize = vibtanium_efi_display_unrealize;
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
}

static const TypeInfo vibtanium_efi_display_info = {
    .name = TYPE_VIBTANIUM_EFI_DISPLAY,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VibtaniumEfiDisplayState),
    .class_init = vibtanium_efi_display_class_init,
};

static void vibtanium_efi_display_register_types(void)
{
    type_register_static(&vibtanium_efi_display_info);
}

type_init(vibtanium_efi_display_register_types)

void vibtanium_efi_console_init(MemoryRegion *framebuffer,
                                MemoryRegion *vga_legacy,
                                uint8_t *vga_crtc)
{
    DeviceState *dev;
    uint8_t *fb;
    uint8_t *vga_legacy_ptr = NULL;

    if (!framebuffer) {
        return;
    }

    fb = memory_region_get_ram_ptr(framebuffer);
    if (!fb) {
        return;
    }
    if (vga_legacy) {
        vga_legacy_ptr = memory_region_get_ram_ptr(vga_legacy);
    }

    memset(&efi_console, 0, sizeof(efi_console));
    efi_console.fb = (uint32_t *)fb;
    if (vga_legacy_ptr) {
        efi_console.vga_text =
            vga_legacy_ptr + VIBTANIUM_VGA_TEXT_OFFSET;
    }
    efi_console.vga_crtc = vga_crtc;
    efi_console.attribute = EFI_DEFAULT_ATTRIBUTE;
    efi_console.cursor_visible = true;
    efi_console.initialized = true;

    memset(fb, 0, VIBTANIUM_FRAMEBUFFER_SIZE);
    efi_console.surface =
        qemu_create_displaysurface_from(VIBTANIUM_FRAMEBUFFER_WIDTH,
                                        VIBTANIUM_FRAMEBUFFER_HEIGHT,
                                        PIXMAN_x8r8g8b8,
                                        VIBTANIUM_FRAMEBUFFER_STRIDE,
                                        fb);
    dev = qdev_new(TYPE_VIBTANIUM_EFI_DISPLAY);
    efi_console.con =
        qemu_graphic_console_create(dev, 0, &vibtanium_efi_console_ops,
                                    &efi_console);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    qemu_console_set_surface(efi_console.con, efi_console.surface);
    qemu_console_update_full(efi_console.con);
}

void vibtanium_efi_console_set_input_active(bool active)
{
    if (!efi_display || !efi_display->keyboard) {
        return;
    }

    if (active) {
        qemu_input_handler_activate(efi_display->keyboard);
    } else {
        qemu_input_handler_deactivate(efi_display->keyboard);
    }
}

void vibtanium_efi_console_set_vga_text_active(bool active)
{
    efi_console.vga_text_active = active;
    if (active) {
        efi_console_render_vga_text();
        if (efi_console.con) {
            qemu_console_update_full(efi_console.con);
        }
    }
}

void vibtanium_efi_console_reset(void)
{
    efi_console.attribute = EFI_DEFAULT_ATTRIBUTE;
    efi_console.cursor_visible = true;
    vibtanium_efi_console_clear();
}

void vibtanium_efi_console_clear(void)
{
    efi_console.cursor_column = 0;
    efi_console.cursor_row = 0;
    efi_console_fill_rect(0, 0, VIBTANIUM_FRAMEBUFFER_WIDTH,
                          VIBTANIUM_FRAMEBUFFER_HEIGHT, efi_console_bg());
}

void vibtanium_efi_console_putchar(uint16_t ch)
{
    if (!efi_console.initialized) {
        return;
    }

    switch (ch) {
    case '\r':
        efi_console.cursor_column = 0;
        return;
    case '\n':
        efi_console_newline();
        return;
    case '\b':
        if (efi_console.cursor_column > 0) {
            efi_console.cursor_column--;
        }
        return;
    case '\t':
        do {
            vibtanium_efi_console_putchar(' ');
        } while ((efi_console.cursor_column & 7) != 0);
        return;
    default:
        break;
    }

    if (ch < 0x20) {
        return;
    }

    if (efi_console.cursor_column >= EFI_TEXT_COLUMNS) {
        efi_console_newline();
    }

    efi_console_draw_glyph(efi_console.cursor_column,
                           efi_console.cursor_row,
                           ch < 0x100 ? ch : '?');
    efi_console.cursor_column++;
    if (efi_console.cursor_column >= EFI_TEXT_COLUMNS) {
        efi_console_newline();
    }
}

void vibtanium_efi_console_set_attribute(uint64_t attribute)
{
    efi_console.attribute = attribute & 0x7f;
}

bool vibtanium_efi_console_set_cursor_position(uint64_t column, uint64_t row)
{
    if (column >= EFI_TEXT_COLUMNS || row >= EFI_TEXT_ROWS) {
        return false;
    }

    efi_console.cursor_column = column;
    efi_console.cursor_row = row;
    return true;
}

void vibtanium_efi_console_enable_cursor(bool visible)
{
    efi_console.cursor_visible = visible;
}

uint32_t vibtanium_efi_console_attribute(void)
{
    return efi_console.attribute;
}

uint32_t vibtanium_efi_console_cursor_column(void)
{
    return efi_console.cursor_column;
}

uint32_t vibtanium_efi_console_cursor_row(void)
{
    return efi_console.cursor_row;
}

bool vibtanium_efi_console_cursor_visible(void)
{
    return efi_console.cursor_visible;
}

void vibtanium_efi_console_update_rect(uint64_t x, uint64_t y,
                                       uint64_t width, uint64_t height)
{
    if (x >= VIBTANIUM_FRAMEBUFFER_WIDTH ||
        y >= VIBTANIUM_FRAMEBUFFER_HEIGHT) {
        return;
    }

    width = MIN(width, VIBTANIUM_FRAMEBUFFER_WIDTH - x);
    height = MIN(height, VIBTANIUM_FRAMEBUFFER_HEIGHT - y);
    efi_console_update_pixels(x, y, width, height);
}
