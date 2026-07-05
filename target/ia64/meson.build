ia64_ss = ss.source_set()
ia64_ss.add(files(
  'bundle.c',
  'cpu.c',
  'debug-trace.c',
  'exception.c',
  'firmware-hook.c',
  'insn.c',
  'interp.c',
  'machine.c',
  'mem.c',
  'packed-compare.c',
  'perf.c',
  'tcg-classify.c',
  'translate.c',
))

# Extend the existing scalar-ALU dispatch point with packed compare support
# without carrying a large insn.c rewrite in this branch.
add_project_link_arguments(
  '-Wl,--wrap=ia64_slot_is_alu_add',
  '-Wl,--wrap=ia64_exec_alu_add',
  language: 'c',
)

target_arch += {'ia64': ia64_ss}
