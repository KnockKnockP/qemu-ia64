ia64_hw_ss = ss.source_set()
ia64_hw_ss.add(when: 'CONFIG_VIBTANIUM', if_true: files('efi.c',
                                                        'efi-console.c',
                                                        'efi-vars.c',
                                                        'efi-storage.c',
                                                        'vibtanium.c'))

hw_arch += {'ia64': ia64_hw_ss}
