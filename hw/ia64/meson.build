ia64_hw_ss = ss.source_set()
ia64_hw_ss.add(when: 'CONFIG_VIBATNIUM', if_true: files('efi.c',
                                                        'vibatnium.c'))

hw_arch += {'ia64': ia64_hw_ss}
