========================
IA-64 production engine
========================

IA-64 has one execution engine: the typed full-TCG translator.  The target
link contains the typed decoder, opcode traits, translator, and bounded
architectural support.  It does not contain the former generic bundle/slot
interpreter, its staged classifier, or a runtime engine selector.

The old in-process ``dual-oracle`` role was removed at production cutover.  It
was only link separation, not an independently reachable runtime path, and
therefore could not provide a trustworthy differential result.  Runtime tests
now execute the production binary once and compare its architectural state to
independent goldens derived from the IA-64 manuals.  A future differential
oracle must be a separate test executable or process and may not share the
``qemu-system-ia64`` dispatch path.

Build and verification
======================

For example, in an MSYS2 MINGW64 shell from the source directory::

  mkdir -p build-ia64-full-tcg
  cd build-ia64-full-tcg
  ../configure --target-list=ia64-softmmu --enable-debug
  ninja qemu-system-ia64.exe
  meson test test-ia64-engine-role test-ia64-production-cutover

The same commands work on POSIX hosts without the ``.exe`` suffix.

``test-ia64-engine-role`` checks the source boundary and the final
executable's symbol table.  A manual production-link check is::

  nm -a qemu-system-ia64.exe | \
      grep -E 'helper_exec_bundle|helper_exec_slot|ia64_insn_exec_bundle|exec_predecoded_slot'

The command must print nothing.  ``target/ia64/meson.build`` owns this
physical boundary.  The former interpreter sources may only be used by a
standalone test oracle; adding them to the system emulator is forbidden.
