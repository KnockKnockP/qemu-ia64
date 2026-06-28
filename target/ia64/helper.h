/* SPDX-License-Identifier: GPL-2.0-or-later */
DEF_HELPER_5(exec_bundle, void, env, i32, i64, i64, i64)
DEF_HELPER_3(start_fast_bundle, void, env, i32, i32)
DEF_HELPER_3(finish_fast_bundle, void, env, i64, i64)
DEF_HELPER_0(perf_tb_exec, void)
