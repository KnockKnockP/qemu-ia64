/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/vibtanium.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "system/memory.h"
#include "ui/console.h"
#include "ui/surface.h"
#include "ui/vgafont.h"

#define TYPE_VIBTANIUM_EFI_DISPLAY "vibtanium-efi-display"
OBJECT_DECLARE_SIMPLE_TYPE(VibtaniumEfiDisplayState, VIBTANIUM_EFI_DISPLAY)

#define EFI_TEXT_COLUMNS \
    (VIBTANIUM_FRAMEBUFFER_WIDTH / FONT_WIDTH)
#define EFI_TEXT_ROWS \
    (VIBTANIUM_FRAMEBUFFER_HEIGHT / FONT_HEIGHT)
#define EFI_DEFAULT_ATTRIBUTE 0x07

struct VibtaniumEfiDisplayState {
    SysBusDevice parent_obj;
};

typedef struct VibtaniumEfiConsole {
    QemuConsole *con;
    DisplaySurface *surface;
    uint32_t *fb;
    uint32_t attribute;
    uint32_t cursor_column;
    uint32_t cursor_row;
    bool cursor_visible;
    bool initialized;
} VibtaniumEfiConsole;

static VibtaniumEfiConsole efi_console;

static const uint32_t efi_vga_palette[16] = {
    0x00000000, 0x000000aa, 0x0000aa00, 0x0000aaaa,
    0x00aa0000, 0x00aa00aa, 0x00aa5500, 0x00aaaaaa,
    0x00555555, 0x005555ff, 0x0055ff55, 0x0055ffff,
    0x00ff5555, 0x00ff55ff, 0x00ffff55, 0x00ffffff,
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

static void efi_console_draw_glyph(uint32_t column, uint32_t row, uint8_t ch)
{
    uint32_t x = column * FONT_WIDTH;
    uint32_t y = row * FONT_HEIGHT;
    uint32_t fg = efi_console_fg();
    uint32_t bg = efi_console_bg();

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
    efi_console_update_pixels(x, y, FONT_WIDTH, FONT_HEIGHT);
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
        qemu_console_update_full(console->con);
    }
    return true;
}

static void vibtanium_efi_console_invalidate(void *opaque)
{
    VibtaniumEfiConsole *console = opaque;

    if (console->con) {
        qemu_console_update_full(console->con);
    }
}

static const GraphicHwOps vibtanium_efi_console_ops = {
    .invalidate = vibtanium_efi_console_invalidate,
    .gfx_update = vibtanium_efi_console_gfx_update,
};

static void vibtanium_efi_display_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->desc = "vibtanium EFI framebuffer display";
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

void vibtanium_efi_console_init(MemoryRegion *framebuffer)
{
    DeviceState *dev;
    uint8_t *fb;

    if (!framebuffer) {
        return;
    }

    fb = memory_region_get_ram_ptr(framebuffer);
    if (!fb) {
        return;
    }

    memset(&efi_console, 0, sizeof(efi_console));
    efi_console.fb = (uint32_t *)fb;
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
