/*
 * IA-64 EFI self-test entry shim.
 *
 * The real test lives in selftest.c. This file only provides the IA-64 EFI
 * entry descriptor, transfers the firmware handoff registers to efi_main(),
 * and keeps one instruction-level helper that C cannot express.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

        .section .head,"ax"
        .global _image_start
_image_start:
        data8   _start
        data8   __gp

        .text
        .explicit
        .align 16
        .global _start
_start:
        alloc   r38 = ar.pfs, 2, 0, 2, 0
        mov     out0 = in0
        mov     out1 = in1 ;;
        br.call.sptk.many b0 = efi_main ;;

.Lspin:
        br.sptk.many .Lspin ;;

        .align 16
        .global ia64_chk_a_clr_fp_takes_branch
ia64_chk_a_clr_fp_takes_branch:
        alloc   r34 = ar.pfs, 0, 1, 0, 0
        mov     r8 = r0 ;;
        chk.a.clr f8, .Lchk_recovery
        mov     ar.pfs = r34 ;;
        br.ret.sptk.many b0 ;;

.Lchk_recovery:
        mov     r8 = 1
        mov     ar.pfs = r34 ;;
        br.ret.sptk.many b0 ;;
