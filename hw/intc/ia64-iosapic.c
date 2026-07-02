/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "hw/intc/ia64-iosapic.h"
#include "hw/ia64/vibtanium.h"
#include "migration/vmstate.h"
#include "target/ia64/insn.h"

#define IA64_IOSAPIC_REG_SELECT 0x00
#define IA64_IOSAPIC_WINDOW     0x10
#define IA64_IOSAPIC_EOI        0x40
#define IA64_IOSAPIC_VERSION    0x01
#define IA64_IOSAPIC_RTE_LOW(i)  (0x10 + (i) * 2)
#define IA64_IOSAPIC_RTE_HIGH(i) (0x11 + (i) * 2)
#define IA64_IOSAPIC_RTE_MASK    (1U << 16)
#define IA64_IOSAPIC_DELIVERY_MASK (7U << 8)
#define IA64_IOSAPIC_DELIVERY_FIXED 0
#define IA64_IOSAPIC_VECTOR_MASK 0xff

struct IA64IOSAPICState {
    SysBusDevice parent_obj;

    IA64CPU *cpu;
    MemoryRegion mmio;
    uint32_t select;
    uint32_t rte_low[VIBTANIUM_IOSAPIC_REDIRECTION_COUNT];
    uint32_t rte_high[VIBTANIUM_IOSAPIC_REDIRECTION_COUNT];
    bool irq_level[VIBTANIUM_IOSAPIC_REDIRECTION_COUNT];
};

void ia64_iosapic_set_cpu(IA64IOSAPICState *s, IA64CPU *cpu)
{
    s->cpu = cpu;
}

static void ia64_iosapic_reset(DeviceState *dev)
{
    IA64IOSAPICState *s = IA64_IOSAPIC(dev);

    for (unsigned i = 0; i < VIBTANIUM_IOSAPIC_REDIRECTION_COUNT; i++) {
        s->rte_low[i] = IA64_IOSAPIC_RTE_MASK;
        s->rte_high[i] = 0;
        s->irq_level[i] = false;
    }
    s->select = 0;
}

static void ia64_iosapic_deliver_irq(IA64IOSAPICState *s, unsigned input)
{
    CPUIA64State *env;
    uint32_t low;
    uint32_t delivery_mode;
    uint64_t vector;

    if (!s->cpu || input >= VIBTANIUM_IOSAPIC_REDIRECTION_COUNT) {
        return;
    }

    env = &s->cpu->env;
    low = s->rte_low[input];
    delivery_mode = low & IA64_IOSAPIC_DELIVERY_MASK;
    vector = low & IA64_IOSAPIC_VECTOR_MASK;

    if ((low & IA64_IOSAPIC_RTE_MASK) ||
        delivery_mode != IA64_IOSAPIC_DELIVERY_FIXED) {
        return;
    }

    if (ia64_queue_external_interrupt(env, vector)) {
        cpu_interrupt(CPU(s->cpu), CPU_INTERRUPT_HARD);
    }
}

static void ia64_iosapic_set_irq(void *opaque, int n, int level)
{
    IA64IOSAPICState *s = opaque;
    unsigned input = n;
    bool old_level;

    if (input >= VIBTANIUM_IOSAPIC_REDIRECTION_COUNT) {
        return;
    }

    old_level = s->irq_level[input];
    s->irq_level[input] = level != 0;

    if (level && !old_level) {
        ia64_iosapic_deliver_irq(s, input);
    }
}

static bool ia64_iosapic_register_index(uint32_t reg, unsigned *index,
                                        bool *high)
{
    if (reg < IA64_IOSAPIC_RTE_LOW(0)) {
        return false;
    }
    reg -= IA64_IOSAPIC_RTE_LOW(0);
    if ((reg >> 1) >= VIBTANIUM_IOSAPIC_REDIRECTION_COUNT) {
        return false;
    }

    *index = reg >> 1;
    *high = (reg & 1) != 0;
    return true;
}

static uint64_t ia64_iosapic_read(void *opaque, hwaddr offset, unsigned size)
{
    IA64IOSAPICState *s = opaque;
    unsigned index;
    bool high;

    if (size != 4) {
        return UINT32_MAX;
    }

    switch (offset) {
    case IA64_IOSAPIC_REG_SELECT:
        return s->select;
    case IA64_IOSAPIC_WINDOW:
        if (s->select == IA64_IOSAPIC_VERSION) {
            return ((VIBTANIUM_IOSAPIC_REDIRECTION_COUNT - 1) << 16) | 0x11;
        }
        if (ia64_iosapic_register_index(s->select, &index, &high)) {
            return high ? s->rte_high[index] : s->rte_low[index];
        }
        return 0;
    case IA64_IOSAPIC_EOI:
        return 0;
    default:
        return 0;
    }
}

static void ia64_iosapic_write(void *opaque, hwaddr offset,
                               uint64_t value, unsigned size)
{
    IA64IOSAPICState *s = opaque;
    uint32_t old_low;
    unsigned index;
    bool high;

    if (size != 4) {
        return;
    }

    switch (offset) {
    case IA64_IOSAPIC_REG_SELECT:
        s->select = value;
        break;
    case IA64_IOSAPIC_WINDOW:
        if (ia64_iosapic_register_index(s->select, &index, &high)) {
            if (high) {
                s->rte_high[index] = value;
            } else {
                old_low = s->rte_low[index];
                s->rte_low[index] = value;
                if ((old_low & IA64_IOSAPIC_RTE_MASK) &&
                    !(s->rte_low[index] & IA64_IOSAPIC_RTE_MASK) &&
                    s->irq_level[index]) {
                    ia64_iosapic_deliver_irq(s, index);
                }
            }
        }
        break;
    case IA64_IOSAPIC_EOI:
        break;
    default:
        break;
    }
}

static const MemoryRegionOps ia64_iosapic_ops = {
    .read = ia64_iosapic_read,
    .write = ia64_iosapic_write,
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

static void ia64_iosapic_init(Object *obj)
{
    IA64IOSAPICState *s = IA64_IOSAPIC(obj);
    DeviceState *dev = DEVICE(obj);

    memory_region_init_io(&s->mmio, obj, &ia64_iosapic_ops, s,
                          "vibtanium.iosapic", VIBTANIUM_IOSAPIC_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);
    qdev_init_gpio_in(dev, ia64_iosapic_set_irq,
                      VIBTANIUM_IOSAPIC_REDIRECTION_COUNT);
}

static const VMStateDescription vmstate_ia64_iosapic = {
    .name = "vibtanium-iosapic",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(select, IA64IOSAPICState),
        VMSTATE_UINT32_ARRAY(rte_low, IA64IOSAPICState,
                             VIBTANIUM_IOSAPIC_REDIRECTION_COUNT),
        VMSTATE_UINT32_ARRAY(rte_high, IA64IOSAPICState,
                             VIBTANIUM_IOSAPIC_REDIRECTION_COUNT),
        VMSTATE_BOOL_ARRAY(irq_level, IA64IOSAPICState,
                           VIBTANIUM_IOSAPIC_REDIRECTION_COUNT),
        VMSTATE_END_OF_LIST()
    }
};

static void ia64_iosapic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, ia64_iosapic_reset);
    dc->desc = "IA-64 IOSAPIC";
    dc->vmsd = &vmstate_ia64_iosapic;
}

static const TypeInfo ia64_iosapic_info = {
    .name = TYPE_IA64_IOSAPIC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(IA64IOSAPICState),
    .instance_init = ia64_iosapic_init,
    .class_init = ia64_iosapic_class_init,
};

static void ia64_iosapic_register_types(void)
{
    type_register_static(&ia64_iosapic_info);
}

type_init(ia64_iosapic_register_types)
