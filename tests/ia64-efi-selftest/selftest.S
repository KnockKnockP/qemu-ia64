/*
 * IA-64 in-emulator EFI self-test application.
 *
 * Boots as an EFI image under the vibtanium firmware (loaded via -kernel or an
 * ESP). It runs a small battery of opcode and EFI-service checks, reports each
 * one via ConOut->OutputString (routed to the host serial/stderr), and ends
 * with a sentinel line the harness greps for:
 *
 *   VIBTANIUM-SELFTEST-RESULT: ALL PASS      (every check passed)
 *   VIBTANIUM-SELFTEST-RESULT: FAILURES      (at least one check failed)
 *
 * Entry state (see hw/ia64/efi.c vibtanium_efi_prepare_cpu):
 *   r32 = ImageHandle, r33 = SystemTable, r1 = gp, r12 = sp, PSR.bn = 1.
 *
 * Register conventions used here:
 *   r4 = pass count, r5 = fail count      (preserved statics)
 *   r6 = ConOut, r7 = RuntimeServices     (preserved statics)
 * Helpers (puts/report) take arguments in the standard IA-64 way: the caller
 * places them in its output registers and issues br.call, which rotates the
 * frame so the callee sees them as r32, r33, ...
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

	/* --- IA-64 EFI entry descriptor (plabel): {code_entry, gp} -------- */
	.section .head,"ax"
	.global _image_start
_image_start:
	data8	_start
	data8	_image_start

	.text
	.align 16
	.global _start
_start:
	alloc	r34 = ar.pfs, 2, 14, 8, 0
	mov	r4 = r0			/* pass count = 0                */
	mov	r5 = r0			/* fail count = 0               */
	adds	r14 = 64, r33 ;;	/* &SystemTable->ConOut          */
	ld8	r6 = [r14] ;;		/* r6 = ConOut                   */
	adds	r15 = 88, r33 ;;	/* &SystemTable->RuntimeServices */
	ld8	r7 = [r15] ;;		/* r7 = RuntimeServices          */

	movl	r48 = s_banner ;;
	br.call.sptk.many b0 = puts ;;

	/* ---- test 1: integer add (3 + 4 == 7) --------------------------- */
	mov	r14 = 3 ;;
	adds	r15 = 4, r14 ;;
	cmp.eq	p8, p9 = 7, r15 ;;
	mov	r48 = 0
(p8)	mov	r48 = 1 ;;
	movl	r49 = t_add ;;
	br.call.sptk.many b0 = report ;;

	/* ---- test 2: movl 64-bit immediate + cmp.eq --------------------- */
	movl	r14 = 0x0123456789abcdef ;;
	movl	r15 = 0x0123456789abcdef ;;
	cmp.eq	p8, p9 = r14, r15 ;;
	mov	r48 = 0
(p8)	mov	r48 = 1 ;;
	movl	r49 = t_movl ;;
	br.call.sptk.many b0 = report ;;

	/* ---- test 3: chk.a.clr fp must take the recovery branch --------- *
	 * With no preceding ldf.a, the ALAT has no matching entry, so the
	 * advanced-load check is required to branch to recovery code.       */
	mov	r14 = 0 ;;
	chk.a.clr f8, .Lrecover3
	mov	r14 = 9			/* fall-through: unexpected      */
	br.cond.sptk.many .Ldone3 ;;
.Lrecover3:
	mov	r14 = 1			/* branched: expected            */
.Ldone3:
	cmp.eq	p8, p9 = 1, r14 ;;
	mov	r48 = 0
(p8)	mov	r48 = 1 ;;
	movl	r49 = t_chka ;;
	br.call.sptk.many b0 = report ;;

	/* ---- test 4: ConOut->OutputString returns EFI_SUCCESS ----------- */
	movl	r48 = s_crlf ;;		/* harmless probe write          */
	br.call.sptk.many b0 = puts ;;
	mov	r35 = r8 ;;		/* capture status before report  */
	cmp.eq	p8, p9 = 0, r35 ;;
	mov	r48 = 0
(p8)	mov	r48 = 1 ;;
	movl	r49 = t_conout ;;
	br.call.sptk.many b0 = report ;;

	/* ---- test 5: SetVariable then GetVariable round-trip ------------ */
	/* SetVariable(Name, Guid, attr=7, size=4, &set_data)               */
	adds	r14 = 88, r7 ;;		/* &RT->SetVariable              */
	ld8	r15 = [r14] ;;
	ld8	r16 = [r15] ;;
	mov	b6 = r16
	movl	r48 = var_name
	movl	r49 = var_guid ;;
	mov	r50 = 7
	mov	r51 = 4
	movl	r52 = set_data ;;
	br.call.sptk.many b0 = b6 ;;
	mov	r35 = r8 ;;		/* set status                    */

	/* GetVariable(Name, Guid, NULL, &get_size, &get_data)             */
	movl	r14 = get_size ;;
	mov	r17 = 8 ;;
	st8	[r14] = r17 ;;		/* reset buffer size = 8         */
	adds	r14 = 72, r7 ;;		/* &RT->GetVariable              */
	ld8	r15 = [r14] ;;
	ld8	r16 = [r15] ;;
	mov	b6 = r16
	movl	r48 = var_name
	movl	r49 = var_guid ;;
	mov	r50 = 0
	movl	r51 = get_size ;;
	movl	r52 = get_data ;;
	br.call.sptk.many b0 = b6 ;;
	mov	r36 = r8 ;;		/* get status                    */
	movl	r14 = get_data ;;
	ld4	r37 = [r14] ;;		/* read back low 32 bits         */

	/* ok = set==0 && get==0 && data==0xdeadbeef                        */
	movl	r18 = 0xdeadbeef ;;
	cmp.eq	p6, p0 = 0, r35
	cmp.eq	p7, p0 = 0, r36 ;;
	cmp.eq	p8, p0 = r37, r18 ;;
	/* combine: r48 = 1 iff p6 & p7 & p8 (all three sub-conditions) */
	mov	r19 = 0 ;;
(p6)	mov	r19 = 1 ;;
(p7)	adds	r19 = 1, r19 ;;
(p8)	adds	r19 = 1, r19 ;;
	cmp.eq	p8, p9 = 3, r19 ;;
	mov	r48 = 0
(p8)	mov	r48 = 1 ;;
	movl	r49 = t_setget ;;
	br.call.sptk.many b0 = report ;;

	/* ---- final verdict --------------------------------------------- */
	cmp.eq	p8, p9 = 0, r5 ;;	/* fail count == 0 ?             */
(p8)	movl	r48 = s_result_pass
(p9)	movl	r48 = s_result_fail ;;
	br.call.sptk.many b0 = puts ;;

.Lspin:
	br.sptk.many .Lspin ;;

/*
 * puts(CHAR16 *str) -- in0 (r32) = string; prints via ConOut in r6.
 * Returns the OutputString status in r8. Preserves the caller's b0 and r4-r7.
 */
	.align 16
	.global puts
puts:
	alloc	r34 = ar.pfs, 1, 3, 2, 0	/* in:r32 loc:r33-35 out:r36-37 */
	mov	r33 = b0
	adds	r14 = 8, r6 ;;			/* &ConOut->OutputString        */
	ld8	r15 = [r14] ;;			/* plabel pointer               */
	ld8	r16 = [r15] ;;			/* entry point                  */
	mov	b6 = r16
	mov	r36 = r6			/* out0 = This = ConOut         */
	mov	r37 = r32 ;;			/* out1 = str                   */
	br.call.sptk.many b0 = b6 ;;
	mov	b0 = r33
	mov	ar.pfs = r34 ;;
	br.ret.sptk.many b0 ;;

/*
 * report(ok, CHAR16 *name) -- in0 (r32) = pass flag (0/1), in1 (r33) = name.
 * Prints "[PASS] <name>\r\n" or "[FAIL] <name>\r\n" and bumps r4/r5.
 */
	.align 16
	.global report
report:
	alloc	r34 = ar.pfs, 2, 5, 2, 0	/* in:r32-33 loc:r34-38 out:r39-40 */
	mov	r35 = b0
	cmp.ne	p6, p7 = 0, r32 ;;		/* p6 = pass                    */
(p6)	adds	r4 = 1, r4
(p7)	adds	r5 = 1, r5
(p6)	movl	r36 = s_pass
	;;
(p7)	movl	r36 = s_fail ;;
	mov	r39 = r36 ;;			/* out0 = prefix                */
	br.call.sptk.many b0 = puts ;;
	mov	r39 = r33 ;;			/* out0 = name                  */
	br.call.sptk.many b0 = puts ;;
	movl	r39 = s_crlf ;;			/* out0 = CRLF                  */
	br.call.sptk.many b0 = puts ;;
	mov	b0 = r35
	mov	ar.pfs = r34 ;;
	br.ret.sptk.many b0 ;;

	/* --- writable scratch data (initialized so it lands in the image) */
	.section .data,"aw"
	.align 16
var_guid:
	.byte 0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11
	.byte 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x99
	.align 8
set_data:
	.4byte 0xdeadbeef
	.align 8
get_size:
	.8byte 8
get_data:
	.8byte 0

	.include "strings.S"
