/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-ldst.h"
#include "bundle.h"
#include "cpu.h"
#include "exec-smoke.h"
#include "exec/helper-proto.h"
#include "hw/ia64/efi.h"

static void abort_unsupported_slot(CPUIA64State *env,
                                   const IA64DecodedBundle *decoded,
                                   int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": unsupported instruction %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

static void abort_zero_branch(CPUIA64State *env,
                              const IA64DecodedBundle *decoded,
                              int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": branch target became zero in %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

enum {
    EFI_BOOT_SERVICE_BASE = 0,
    EFI_RUNTIME_SERVICE_BASE =
        EFI_BOOT_SERVICE_BASE + VIBATNIUM_EFI_BOOT_SERVICE_COUNT,
    EFI_CON_OUT_SERVICE_BASE =
        EFI_RUNTIME_SERVICE_BASE + VIBATNIUM_EFI_RUNTIME_SERVICE_COUNT,
    EFI_CON_IN_SERVICE_BASE =
        EFI_CON_OUT_SERVICE_BASE + VIBATNIUM_EFI_CON_OUT_SERVICE_COUNT,
    EFI_SERVICE_DESCRIPTOR_COUNT =
        EFI_CON_IN_SERVICE_BASE + VIBATNIUM_EFI_CON_IN_SERVICE_COUNT,
};

static const uint8_t efi_loaded_image_guid[16] = {
    0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11,
    0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_simple_text_output_guid[16] = {
    0xc2, 0x77, 0x74, 0x38, 0xc7, 0x69, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_device_path_guid[16] = {
    0x91, 0x6e, 0x57, 0x09, 0x3f, 0x6d, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_block_io_guid[16] = {
    0x21, 0x5b, 0x4e, 0x96, 0x59, 0x64, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_simple_file_system_guid[16] = {
    0x22, 0x5b, 0x4e, 0x96, 0x59, 0x64, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static bool efi_gate_service_index(uint64_t gate_ip, unsigned *index)
{
    uint64_t offset;

    if (gate_ip < VIBATNIUM_EFI_CALL_GATE_BASE) {
        return false;
    }

    offset = gate_ip - VIBATNIUM_EFI_CALL_GATE_BASE;
    if ((offset & (IA64_BUNDLE_SIZE - 1)) != 0) {
        return false;
    }
    offset /= IA64_BUNDLE_SIZE;
    if (offset >= EFI_SERVICE_DESCRIPTOR_COUNT) {
        return false;
    }

    *index = offset;
    return true;
}

static bool efi_guest_guid_equals(CPUIA64State *env, uint64_t address,
                                  const uint8_t guid[16])
{
    if (address == 0) {
        return false;
    }

    for (int i = 0; i < 16; i++) {
        if (cpu_ldub_data_ra(env, address + i, GETPC()) != guid[i]) {
            return false;
        }
    }
    return true;
}

static void efi_guest_stq(CPUIA64State *env, uint64_t address, uint64_t value)
{
    cpu_stq_le_data_ra(env, address, value, GETPC());
}

static uint64_t efi_guest_ldq(CPUIA64State *env, uint64_t address)
{
    return cpu_ldq_le_data_ra(env, address, GETPC());
}

static bool efi_guest_guid_is_known_media(CPUIA64State *env, uint64_t guid)
{
    return efi_guest_guid_equals(env, guid, efi_device_path_guid) ||
           efi_guest_guid_equals(env, guid, efi_block_io_guid) ||
           efi_guest_guid_equals(env, guid, efi_simple_file_system_guid);
}

static uint64_t efi_handle_protocol(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t interface = ia64_read_gr(env, 34);

    if (protocol == 0 || interface == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    if (handle == VIBATNIUM_EFI_IMAGE_HANDLE &&
        efi_guest_guid_equals(env, protocol, efi_loaded_image_guid)) {
        efi_guest_stq(env, interface, VIBATNIUM_EFI_LOADED_IMAGE);
        return VIBATNIUM_EFI_SUCCESS;
    }

    if (handle == VIBATNIUM_EFI_BOOT_DEVICE_HANDLE &&
        efi_guest_guid_equals(env, protocol, efi_simple_text_output_guid)) {
        efi_guest_stq(env, interface, VIBATNIUM_EFI_CON_OUT);
        return VIBATNIUM_EFI_SUCCESS;
    }

    if (handle == VIBATNIUM_EFI_BOOT_DEVICE_HANDLE &&
        efi_guest_guid_is_known_media(env, protocol)) {
        efi_guest_stq(env, interface, 0);
        return VIBATNIUM_EFI_UNSUPPORTED;
    }

    efi_guest_stq(env, interface, 0);
    return VIBATNIUM_EFI_NOT_FOUND;
}

static unsigned efi_locate_handles_for_protocol(CPUIA64State *env,
                                                uint64_t protocol,
                                                uint64_t *handles,
                                                unsigned capacity)
{
    if (efi_guest_guid_equals(env, protocol, efi_loaded_image_guid)) {
        if (capacity > 0) {
            handles[0] = VIBATNIUM_EFI_IMAGE_HANDLE;
        }
        return 1;
    }

    if (efi_guest_guid_equals(env, protocol, efi_simple_text_output_guid) ||
        efi_guest_guid_is_known_media(env, protocol)) {
        if (capacity > 0) {
            handles[0] = VIBATNIUM_EFI_BOOT_DEVICE_HANDLE;
        }
        return 1;
    }

    return 0;
}

static uint64_t efi_locate_handle(CPUIA64State *env)
{
    uint64_t search_type = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t size_ptr = ia64_read_gr(env, 35);
    uint64_t buffer = ia64_read_gr(env, 36);
    uint64_t handles[4];
    unsigned count;
    uint64_t required;
    uint64_t provided;

    if (search_type != 2 || protocol == 0 || size_ptr == 0) {
        return VIBATNIUM_EFI_UNSUPPORTED;
    }

    count = efi_locate_handles_for_protocol(env, protocol, handles,
                                            ARRAY_SIZE(handles));
    required = count * sizeof(uint64_t);
    provided = efi_guest_ldq(env, size_ptr);
    efi_guest_stq(env, size_ptr, required);
    if (count == 0) {
        return VIBATNIUM_EFI_NOT_FOUND;
    }

    if (buffer == 0 || provided < required) {
        return VIBATNIUM_EFI_BUFFER_TOO_SMALL;
    }

    for (unsigned i = 0; i < count; i++) {
        efi_guest_stq(env, buffer + i * sizeof(uint64_t), handles[i]);
    }
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_allocate_pool(CPUIA64State *env)
{
    static uint64_t pool_next = VIBATNIUM_EFI_POOL_BASE;
    uint64_t size = ia64_read_gr(env, 33);
    uint64_t buffer = ia64_read_gr(env, 34);
    uint64_t address;
    uint64_t next;

    if (buffer == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    address = QEMU_ALIGN_UP(pool_next, 16);
    next = QEMU_ALIGN_UP(address + MAX(size, UINT64_C(1)), 16);
    if (next < address ||
        next > VIBATNIUM_EFI_POOL_BASE + VIBATNIUM_EFI_POOL_SIZE) {
        efi_guest_stq(env, buffer, 0);
        return VIBATNIUM_EFI_OUT_OF_RESOURCES;
    }

    pool_next = next;
    efi_guest_stq(env, buffer, address);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_dispatch_boot_service(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0:
        return 4; /* RaiseTPL returns the previous TPL, not EFI_STATUS. */
    case 1:
    case 6:
    case 7:
    case 8:
    case 10:
    case 11:
    case 12:
    case VIBATNIUM_EFI_BOOT_SET_WATCHDOG_INDEX:
        return VIBATNIUM_EFI_SUCCESS;
    case 5:
        return efi_allocate_pool(env);
    case VIBATNIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX:
        return efi_handle_protocol(env);
    case 19:
        return efi_locate_handle(env);
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_runtime_service(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 6: /* GetVariable */
    case 7: /* GetNextVariableName */
        return VIBATNIUM_EFI_NOT_FOUND;
    case 8: /* SetVariable */
        return VIBATNIUM_EFI_SUCCESS;
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

static void efi_console_output_string(CPUIA64State *env)
{
    uint64_t text = ia64_read_gr(env, 33);
    GString *line;

    if (text == 0) {
        return;
    }

    line = g_string_new(NULL);
    for (unsigned i = 0; i < 4096; i++) {
        uint16_t ch = cpu_lduw_le_data_ra(env, text + i * 2, GETPC());

        if (ch == 0) {
            break;
        }
        if (ch == '\r') {
            continue;
        }
        g_string_append_c(line, ch < 0x80 ? (char)ch : '?');
    }
    if (line->len != 0) {
        fprintf(stderr, "%s", line->str);
    }
    g_string_free(line, true);
}

static uint64_t efi_dispatch_console_out(CPUIA64State *env, unsigned index)
{
    uint64_t columns = ia64_read_gr(env, 33);
    uint64_t rows = ia64_read_gr(env, 34);

    switch (index) {
    case 0:
    case 1:
    case 2:
    case 5:
    case 6:
    case 7:
    case 8:
        return VIBATNIUM_EFI_SUCCESS;
    case 4:
        efi_console_output_string(env);
        return VIBATNIUM_EFI_SUCCESS;
    case 3:
        if (columns == 0 || rows == 0) {
            return VIBATNIUM_EFI_INVALID_PARAMETER;
        }
        efi_guest_stq(env, columns, 80);
        efi_guest_stq(env, rows, 25);
        return VIBATNIUM_EFI_SUCCESS;
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

bool vibatnium_efi_dispatch_gate(CPUIA64State *env, uint64_t gate_ip)
{
    unsigned service_index;
    uint64_t result = VIBATNIUM_EFI_UNSUPPORTED;

    if (!env || !efi_gate_service_index(gate_ip, &service_index)) {
        return false;
    }

    if (service_index < EFI_RUNTIME_SERVICE_BASE) {
        result = efi_dispatch_boot_service(env,
                                           service_index -
                                           EFI_BOOT_SERVICE_BASE);
    } else if (service_index < EFI_CON_OUT_SERVICE_BASE) {
        result = efi_dispatch_runtime_service(env,
                                              service_index -
                                              EFI_RUNTIME_SERVICE_BASE);
    } else if (service_index >= EFI_CON_OUT_SERVICE_BASE &&
               service_index < EFI_CON_IN_SERVICE_BASE) {
        result = efi_dispatch_console_out(env,
                                          service_index -
                                          EFI_CON_OUT_SERVICE_BASE);
    }

    ia64_write_gr(env, 8, result);
    ia64_return_from_call_frame(env, env->br[0]);
    return true;
}

static uint64_t ia64_ldst_read(CPUIA64State *env, uint64_t address,
                               uint8_t width)
{
    switch (width) {
    case 1:
        return cpu_ldub_data_ra(env, address, GETPC());
    case 2:
        return cpu_lduw_le_data_ra(env, address, GETPC());
    case 4:
        return cpu_ldl_le_data_ra(env, address, GETPC());
    case 8:
        return cpu_ldq_le_data_ra(env, address, GETPC());
    default:
        g_assert_not_reached();
    }
}

static void ia64_ldst_write(CPUIA64State *env, uint64_t address,
                            uint8_t width, uint64_t value)
{
    switch (width) {
    case 1:
        cpu_stb_data_ra(env, address, value, GETPC());
        break;
    case 2:
        cpu_stw_le_data_ra(env, address, value, GETPC());
        break;
    case 4:
        cpu_stl_le_data_ra(env, address, value, GETPC());
        break;
    case 8:
        cpu_stq_le_data_ra(env, address, value, GETPC());
        break;
    default:
        g_assert_not_reached();
    }
}

static bool exec_ldst_immediate(CPUIA64State *env,
                                const IA64LdstImmediate *decoded)
{
    uint64_t address = ia64_read_gr(env, decoded->base);
    uint64_t update;

    if (decoded->width > 1 && (address & (decoded->width - 1)) != 0) {
        return false;
    }

    switch (decoded->kind) {
    case IA64_LDST_IMM_LOAD:
        if (decoded->target != 0) {
            ia64_write_gr(env, decoded->target,
                          ia64_ldst_read(env, address, decoded->width));
        }
        break;
    case IA64_LDST_IMM_STORE:
        ia64_ldst_write(env, address, decoded->width,
                        ia64_read_gr(env, decoded->source));
        break;
    case IA64_LDST_IMM_PREFETCH:
        break;
    default:
        g_assert_not_reached();
    }

    if (decoded->base_update) {
        update = decoded->update_from_register
            ? ia64_read_gr(env, decoded->update_source)
            : (uint64_t)decoded->immediate;
        ia64_write_gr(env, decoded->base, address + update);
    }
    env->gr[0] = 0;
    return true;
}

static uint32_t helper_map_fr(CPUIA64State *env, uint32_t reg)
{
    if (reg < 32) {
        return reg;
    }
    return 32 + ((reg - 32 + env->rse.rrb_fr) % (IA64_FR_COUNT - 32));
}

static void helper_write_fr_raw(CPUIA64State *env, uint32_t reg,
                                uint64_t low, uint64_t high)
{
    uint32_t mapped;

    if (reg >= IA64_FR_COUNT || reg < 2) {
        return;
    }

    mapped = helper_map_fr(env, reg);
    env->fr[mapped].raw[0] = low;
    env->fr[mapped].raw[1] = high;
}

static void exec_floating_load(CPUIA64State *env,
                               const IA64FloatingMemoryInstruction *decoded,
                               uint64_t address)
{
    switch (decoded->format) {
    case IA64_FLOAT_FMT_SINGLE:
        helper_write_fr_raw(env, decoded->freg,
                            cpu_ldl_le_data_ra(env, address, GETPC()),
                            0x1003e);
        break;
    case IA64_FLOAT_FMT_DOUBLE:
    case IA64_FLOAT_FMT_SIGNIFICAND:
        helper_write_fr_raw(env, decoded->freg,
                            cpu_ldq_le_data_ra(env, address, GETPC()),
                            0x1003e);
        break;
    case IA64_FLOAT_FMT_EXTENDED:
    case IA64_FLOAT_FMT_SPILL_FILL:
        helper_write_fr_raw(env, decoded->freg,
                            cpu_ldq_le_data_ra(env, address, GETPC()),
                            cpu_ldq_le_data_ra(env, address + 8, GETPC()));
        break;
    default:
        g_assert_not_reached();
    }
}

static void exec_floating_store(CPUIA64State *env,
                                const IA64FloatingMemoryInstruction *decoded,
                                uint64_t address)
{
    uint32_t mapped = helper_map_fr(env, decoded->freg);
    uint64_t low = env->fr[mapped].raw[0];
    uint64_t high = env->fr[mapped].raw[1];

    switch (decoded->format) {
    case IA64_FLOAT_FMT_SINGLE:
        cpu_stl_le_data_ra(env, address, low, GETPC());
        break;
    case IA64_FLOAT_FMT_DOUBLE:
    case IA64_FLOAT_FMT_SIGNIFICAND:
        cpu_stq_le_data_ra(env, address, low, GETPC());
        break;
    case IA64_FLOAT_FMT_EXTENDED:
    case IA64_FLOAT_FMT_SPILL_FILL:
        cpu_stq_le_data_ra(env, address, low, GETPC());
        cpu_stq_le_data_ra(env, address + 8, high, GETPC());
        break;
    default:
        g_assert_not_reached();
    }
}

static bool exec_floating_memory(CPUIA64State *env,
                                 const IA64FloatingMemoryInstruction *decoded)
{
    uint64_t address = ia64_read_gr(env, decoded->base);
    uint64_t update;

    if (decoded->width > 1 && (address & (decoded->width - 1)) != 0) {
        return false;
    }

    switch (decoded->kind) {
    case IA64_FLOAT_MEM_LOAD:
        exec_floating_load(env, decoded, address);
        break;
    case IA64_FLOAT_MEM_STORE:
        exec_floating_store(env, decoded, address);
        break;
    default:
        g_assert_not_reached();
    }

    if (decoded->base_update) {
        update = decoded->update_from_register
            ? ia64_read_gr(env, decoded->update_source)
            : (uint64_t)decoded->immediate;
        ia64_write_gr(env, decoded->base, address + update);
    }
    return true;
}

void HELPER(exec_bundle)(CPUIA64State *env,
                         uint32_t tmpl,
                         uint64_t slot0,
                         uint64_t slot1,
                         uint64_t slot2)
{
    IA64DecodedBundle decoded;
    uint64_t next_ip = env->ip + IA64_BUNDLE_SIZE;

    decoded.tmpl = tmpl & 0x1f;
    decoded.slot[0] = slot0 & IA64_SLOT_MASK;
    decoded.slot[1] = slot1 & IA64_SLOT_MASK;
    decoded.slot[2] = slot2 & IA64_SLOT_MASK;
    decoded.info = ia64_template_info(decoded.tmpl);
    decoded.valid = decoded.info->valid;

    if (!decoded.valid) {
        abort_unsupported_slot(env, &decoded, 0);
    }

    if (vibatnium_efi_dispatch_gate(env, env->ip)) {
        return;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = decoded.info->slot_type[slot];
        uint64_t raw = decoded.slot[slot];
        uint8_t qp = ia64_slot_predicate(raw);
        IA64LdstImmediate ldst;
        IA64FloatingMemoryInstruction fldst;
        IA64CompareInstruction cmp;
        IA64ExtractInstruction extract;
        IA64IntegerExtendInstruction int_ext;

        if (decoded.info->long_immediate && slot == 1) {
            uint8_t x_qp = ia64_slot_predicate(decoded.slot[2]);

            if (x_qp == 0 || (env->pr & (1ULL << x_qp)) != 0) {
                if (!ia64_exec_lx_movl(env, decoded.slot[1],
                                       decoded.slot[2])) {
                    abort_unsupported_slot(env, &decoded, 1);
                }
            }
            slot++;
            continue;
        }

        if (qp != 0 && ((env->pr & (1ULL << qp)) == 0) &&
            !(type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x4 &&
              (((raw >> 6) & 0x7) == 2 || ((raw >> 6) & 0x7) == 3))) {
            continue;
        }
        if (ia64_exec_smoke_slot_supported(type, raw)) {
            continue;
        }
        if (ia64_slot_is_i_nop(type, raw)) {
            continue;
        }
        if (ia64_slot_is_m34_alloc(type, raw)) {
            ia64_exec_m34_alloc(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_ip(type, raw)) {
            ia64_exec_i_mov_ip(env, raw, env->ip);
            continue;
        }
        if (ia64_slot_is_i_mov_from_branch(type, raw)) {
            ia64_exec_i_mov_from_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_branch(type, raw)) {
            ia64_exec_i_mov_to_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_from_predicate(type, raw)) {
            ia64_exec_i_mov_from_predicate(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_predicate(type, raw)) {
            ia64_exec_i_mov_to_predicate(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_rotating_predicate_immediate(type, raw)) {
            ia64_exec_i_mov_to_rotating_predicate_immediate(env, raw);
            continue;
        }
        if (ia64_slot_is_mov_to_application(type, raw)) {
            ia64_exec_mov_to_application(env, type, raw);
            continue;
        }
        if (ia64_slot_is_mov_from_application(type, raw)) {
            ia64_exec_mov_from_application(env, type, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_application_immediate(type, raw)) {
            ia64_exec_i_mov_to_application_immediate(env, raw);
            continue;
        }
        if (ia64_slot_is_m_check_advanced(type, raw)) {
            ia64_exec_m_check_advanced(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            continue;
        }
        if (ia64_slot_is_m_system_noop(type, raw)) {
            continue;
        }
        if (ia64_slot_is_m_setf(type, raw) && ia64_exec_m_setf(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_getf(type, raw) && ia64_exec_m_getf(env, raw)) {
            continue;
        }
        if (ia64_decode_extract(type, raw, &extract) &&
            ia64_exec_extract(env, &extract)) {
            continue;
        }
        if (ia64_decode_integer_extend(type, raw, &int_ext) &&
            ia64_exec_integer_extend(env, &int_ext)) {
            continue;
        }
        if (ia64_slot_is_f_reciprocal_approx(type, raw) &&
            ia64_exec_f_reciprocal_approx(env, raw)) {
            continue;
        }
        if (ia64_slot_is_f_misc(type, raw) &&
            ia64_exec_f_misc(env, raw)) {
            continue;
        }
        if (ia64_slot_is_f_multiply_add(type, raw) &&
            ia64_exec_f_multiply_add(env, raw)) {
            continue;
        }
        if (ia64_slot_is_f_select_or_xma(type, raw) &&
            ia64_exec_f_select_or_xma(env, raw)) {
            continue;
        }
        if (ia64_decode_floating_memory(type, raw, &fldst) &&
            exec_floating_memory(env, &fldst)) {
            continue;
        }
        if (ia64_decode_ldst_immediate(type, raw, &ldst) &&
            exec_ldst_immediate(env, &ldst)) {
            continue;
        }
        if (ia64_decode_compare(type, raw, &cmp) &&
            ia64_exec_compare(env, &cmp)) {
            continue;
        }
        if (ia64_slot_is_alu_add(type, raw)) {
            ia64_exec_alu_add(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_sub(type, raw)) {
            ia64_exec_alu_sub(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_logic(type, raw)) {
            ia64_exec_alu_logic(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_addp4(type, raw)) {
            ia64_exec_alu_addp4(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_shladd(type, raw)) {
            ia64_exec_alu_shladd(env, raw);
            continue;
        }
        if (ia64_slot_is_addl(type, raw)) {
            ia64_exec_addl(env, raw);
            continue;
        }
        if (ia64_slot_is_b_branch_relative(type, raw)) {
            ia64_exec_b_branch_relative(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            continue;
        }
        if (ia64_slot_is_b_call_relative(type, raw)) {
            ia64_exec_b_call_relative(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            continue;
        }
        if (ia64_slot_is_b_indirect_branch(type, raw)) {
            ia64_exec_b_indirect_branch(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            continue;
        }
        if (ia64_slot_is_b_predict_or_nop(type, raw)) {
            continue;
        }
        if (decoded.info->long_immediate && type == IA64_SLOT_TYPE_X) {
            abort_unsupported_slot(env, &decoded, 1);
        }

        abort_unsupported_slot(env, &decoded, slot);
    }

    env->ip = next_ip;
    env->cr[IA64_CR_IIP] = env->ip;
}
