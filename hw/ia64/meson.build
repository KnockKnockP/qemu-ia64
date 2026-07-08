ia64_hw_ss = ss.source_set()
ia64_hw_ss.add(when: 'CONFIG_VIBTANIUM', if_true: files('efi.c',
                                                        'efi-bit.c',
                                                        'efi-bit-blob.c',
                                                        'efi-boot-manager.c',
                                                        'efi-console.c',
                                                        'efi-services.c',
                                                        'efi-vars.c',
                                                        'efi-storage.c',
                                                        'firmware.c',
                                                        'sparse-io.c',
                                                        'vibtanium.c'))

hw_arch += {'ia64': ia64_hw_ss}
