ia64_hw_ss = ss.source_set()
vibtanium_sources = files('firmware.c',
                         'sparse-io.c',
                         'vibtanium.c')
ia64_hw_ss.add(when: 'CONFIG_VIBTANIUM', if_true: vibtanium_sources)

hw_arch += {'ia64': ia64_hw_ss}
