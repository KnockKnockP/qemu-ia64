# Local IA-64 manuals

This directory is the QEMU repository's local input cache for conformance
citation validation. PDF and extracted text files are ignored by Git.

From MSYS2 MINGW64, run:

```sh
./scripts/ia64-fetch-conformance-manuals.sh
```

The script downloads the three public Intel Itanium Architecture Software
Developer's Manual volumes currently cited by the catalogue and extracts text
with `pdftotext`. No Vibtanium checkout is required.
