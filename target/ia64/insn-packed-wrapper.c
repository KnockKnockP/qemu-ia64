/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Temporary bridge for packed A-unit work.
 *
 * insn.c currently owns the scalar major-0x8 ALU entry points used by the
 * interpreter dispatch.  Rename only those two symbols while compiling insn.c,
 * then packed-compare.c provides the public names and falls through to these
 * scalar implementations when the slot is not a packed compare.
 *
 * This keeps the hook local to target/ia64 sources and avoids global linker
 * --wrap arguments.  Once the packed ALU family is folded directly into
 * insn.c, this wrapper can disappear and meson.build can list insn.c again.
 */
#define ia64_slot_is_alu_add ia64_slot_is_alu_add_scalar
#define ia64_exec_alu_add ia64_exec_alu_add_scalar
#include "insn.c"
