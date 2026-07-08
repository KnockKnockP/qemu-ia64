ia64_hw_ss = ss.source_set()
vibtanium_sources = files('efi.c',
                         'efi-boot-manager.c',
                         'efi-console.c',
                         'efi-services.c',
                         'efi-vars.c',
                         'efi-storage.c',
                         'firmware.c',
                         'sparse-io.c',
                         'vibtanium.c')
if get_option('vibtanium_bit')
  vibtanium_sources += files('efi-bit.c',
                             'efi-bit-blob.c')
endif
ia64_hw_ss.add(when: 'CONFIG_VIBTANIUM', if_true: vibtanium_sources)

hw_arch += {'ia64': ia64_hw_ss}
