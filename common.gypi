{
  'variables': {
    'visibility%': 'hidden',
    'target_arch%': 'x64',
    'host_arch%': 'x64',
    'msvs_multi_core_compile': '1',
    'enable_shared%': 'false',
    'runtime_library%': 'default',
    'with_ssl%': 'false',
  },

  'target_defaults': {
    'default_configuration': 'Debug',
    'target_conditions': [
      ['with_ssl != "false" and with_ssl != "true"', {
        'include_dirs': [ '<(with_ssl)/include' ],
        'target_conditions': [
          ['OS != "win"', {
            'library_dirs': [ '<(with_ssl)/lib' ],
          }],
        ],
      }],
      ['OS != "win" and with_ssl != "false"', {
        'libraries': [ '-lcrypto', '-lssl' ],
      }],
    ],
    'configurations': {
      'Debug': {
        'defines': [ 'DEBUG', '_DEBUG' ],
        'cflags': [ '-g', '-O0', '-fwrapv' ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'target_conditions': [
              ['runtime_library == "default" and enable_shared == "false"', {
                'RuntimeLibrary': 1, # /MTd
              }],
              ['runtime_library == "default" and enable_shared == "true"', {
                'RuntimeLibrary': 3, # /MDd
              }],
              ['runtime_library == "mt"', {
                'RuntimeLibrary': 1, # /MTd
              }],
              ['runtime_library == "md"', {
                'RuntimeLibrary': 3, # /MDd
              }],
            ],
            'Optimization': 0, # /Od, no optimization
            'MinimalRebuild': 'false',
            'OmitFramePointers': 'false',
            'BasicRuntimeChecks': 3, # /RTC1
          },
          'VCLinkerTool': {
            'LinkIncremental': 2, # enable incremental linking
            'target_conditions': [
              ['with_ssl != "false"', {
                'target_conditions': [
                  ['runtime_library == "default" and enable_shared == "false"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC\static' ],
                    'AdditionalDependencies': [ 'ssleay32MTd.lib', 'libeay32MTd.lib' ],
                  }],
                  ['runtime_library == "default" and enable_shared == "true"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC' ],
                    'AdditionalDependencies': [ 'ssleay32MDd.lib', 'libeay32MDd.lib' ],
                  }],

                  ['runtime_library == "mt" and enable_shared == "false"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC\static' ],
                    'AdditionalDependencies': [ 'ssleay32MTd.lib', 'libeay32MTd.lib' ],
                  }],
                  ['runtime_library == "mt" and enable_shared == "true"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC' ],
                    'AdditionalDependencies': [ 'ssleay32MTd.lib', 'libeay32MTd.lib' ],
                  }],

                  ['runtime_library == "md" and enable_shared == "false"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC\static' ],
                    'AdditionalDependencies': [ 'ssleay32MDd.lib', 'libeay32MDd.lib' ],
                  }],
                  ['runtime_library == "md" and enable_shared == "true"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC' ],
                    'AdditionalDependencies': [ 'ssleay32MDd.lib', 'libeay32MDd.lib' ],
                  }],
                ],
              }],
            ],
          },
        },
        'xcode_settings': {
          'GCC_OPTIMIZATION_LEVEL': '0',
          'OTHER_CFLAGS': [ '-g', '-Wno-strict-aliasing' ],
        },
      },
      'Release': {
        'defines': [ 'NDEBUG' ],
        'cflags': [
          '-O3',
          '-fstrict-aliasing',
          '-fomit-frame-pointer',
          '-fdata-sections',
          '-ffunction-sections',
        ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'target_conditions': [
              ['runtime_library == "default" and enable_shared == "false"', {
                'RuntimeLibrary': 0, # /MT
              }],
              ['runtime_library == "default" and enable_shared == "true"', {
                'RuntimeLibrary': 2, # /MD
              }],
              ['runtime_library == "mt"', {
                'RuntimeLibrary': 0, # /MT
              }],
              ['runtime_library == "md"', {
                'RuntimeLibrary': 2, # /MD
              }],
            ],
            'Optimization': 3, # /Ox, full optimization
            'FavorSizeOrSpeed': 1, # /Ot, favour speed over size
            'InlineFunctionExpansion': 2, # /Ob2, inline anything eligible
            'WholeProgramOptimization': 'true', # /GL, whole program optimization, needed for LTCG
            'OmitFramePointers': 'true',
            'EnableFunctionLevelLinking': 'true',
            'EnableIntrinsicFunctions': 'true',
          },
          'VCLibrarianTool': {
            'AdditionalOptions': [
              '/LTCG', # link time code generation
            ],
          },
          'VCLinkerTool': {
            'LinkTimeCodeGeneration': 1, # link-time code generation
            'OptimizeReferences': 2, # /OPT:REF
            'EnableCOMDATFolding': 2, # /OPT:ICF
            'LinkIncremental': 1, # disable incremental linking
            'target_conditions': [
              ['with_ssl != "false"', {
                'target_conditions': [
                  ['runtime_library == "default" and enable_shared == "false"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC\static' ],
                    'AdditionalDependencies': [ 'ssleay32MT.lib', 'libeay32MT.lib' ],
                  }],
                  ['runtime_library == "default" and enable_shared == "true"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC' ],
                    'AdditionalDependencies': [ 'ssleay32MD.lib', 'libeay32MD.lib' ],
                  }],

                  ['runtime_library == "mt" and enable_shared == "false"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC\static' ],
                    'AdditionalDependencies': [ 'ssleay32MT.lib', 'libeay32MT.lib' ],
                  }],
                  ['runtime_library == "mt" and enable_shared == "true"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC' ],
                    'AdditionalDependencies': [ 'ssleay32MT.lib', 'libeay32MT.lib' ],
                  }],

                  ['runtime_library == "md" and enable_shared == "false"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC\static' ],
                    'AdditionalDependencies': [ 'ssleay32MD.lib', 'libeay32MD.lib' ],
                  }],
                  ['runtime_library == "md" and enable_shared == "true"', {
                    'AdditionalLibraryDirectories': [ '<(with_ssl)\lib\VC' ],
                    'AdditionalDependencies': [ 'ssleay32MD.lib', 'libeay32MD.lib' ],
                  }],
                ],
              }],
            ],
          },
        },
      }
    },
    'msvs_settings': {
      'VCCLCompilerTool': {
        'StringPooling': 'true', # pool string literals
        'DebugInformationFormat': 3, # Generate a PDB
        'WarningLevel': 3,
        'BufferSecurityCheck': 'true',
        'ExceptionHandling': 1, # /EHsc
        'SuppressStartupBanner': 'true',
        'WarnAsError': 'false',
        'AdditionalOptions': [
          '/MP', # compile across multiple CPUs
         ],
      },
      'VCLibrarianTool': {
      },
      'VCLinkerTool': {
        'GenerateDebugInformation': 'true',
        'RandomizedBaseAddress': 2, # enable ASLR
        'DataExecutionPrevention': 2, # enable DEP
        'AllowIsolation': 'true',
        'SuppressStartupBanner': 'true',
        'target_conditions': [
          ['_type == "executable"', {
            'SubSystem': 1, # console executable
          }],
        ],
      },
    },
    'conditions': [
      ['OS == "win"', {
        'msvs_cygwin_shell': 0, # prevent actions from trying to use cygwin
        'defines': [
          'WIN32',
          # we don't really want VC++ warning us about
          # how dangerous C functions are...
          '_CRT_SECURE_NO_DEPRECATE',
          # ... or that C implementations shouldn't use
          # POSIX names
          '_CRT_NONSTDC_NO_DEPRECATE',
        ],
        'target_conditions': [
          ['target_arch == "x64"', {
            'msvs_configuration_platform': 'x64'
          }],
        ]
      }],
      ['OS in "freebsd linux openbsd solaris android"', {
        'cflags': [ '-Wall' ],
        'cflags_cc': [ '-fno-rtti', '-fno-exceptions' ],
        'target_conditions': [
          ['_type == "static_library"', {
            'standalone_static_library': 1, # disable thin archive which needs binutils >= 2.19
          }],
        ],
        'conditions': [
          [ 'host_arch != target_arch and target_arch == "ia32"', {
            'cflags': [ '-m32' ],
            'ldflags': [ '-m32' ],
          }],
          [ 'target_arch == "x32"', {
            'cflags': [ '-mx32' ],
            'ldflags': [ '-mx32' ],
          }],
          [ 'OS == "linux"', {
            'cflags': [ '-ansi' ],
          }],
          [ 'OS == "solaris"', {
            'cflags': [ '-pthreads' ],
            'ldflags': [ '-pthreads' ],
          }],
          [ 'OS not in "solaris android"', {
            'cflags': [ '-pthread' ],
            'ldflags': [ '-pthread' ],
          }],
          [ 'visibility == "hidden"', {
            'cflags': [ '-fvisibility=hidden' ],
          }],
        ],
      }],
      ['OS == "mac"', {
        'xcode_settings': {
          'ALWAYS_SEARCH_USER_PATHS': 'NO',
          'GCC_CW_ASM_SYNTAX': 'NO',                # No -fasm-blocks
          'GCC_DYNAMIC_NO_PIC': 'NO',               # No -mdynamic-no-pic
                                                    # (Equivalent to -fPIC)
          'GCC_ENABLE_CPP_EXCEPTIONS': 'NO',        # -fno-exceptions
          'GCC_ENABLE_CPP_RTTI': 'NO',              # -fno-rtti
          'GCC_ENABLE_PASCAL_STRINGS': 'NO',        # No -mpascal-strings
          # GCC_INLINES_ARE_PRIVATE_EXTERN maps to -fvisibility-inlines-hidden
          'GCC_INLINES_ARE_PRIVATE_EXTERN': 'YES',
          'GCC_SYMBOLS_PRIVATE_EXTERN': 'YES',      # -fvisibility=hidden
          'GCC_THREADSAFE_STATICS': 'NO',           # -fno-threadsafe-statics
          'PREBINDING': 'NO',                       # No -Wl,-prebind
          'USE_HEADERMAP': 'NO',
          'OTHER_CFLAGS': [
            '-fstrict-aliasing',
          ],
          'WARNING_CFLAGS': [
            '-Wall',
            '-Wextra',
            '-Wendif-labels',
            '-W',
            '-Wno-unused-parameter',
          ],
        },
        'conditions': [
          ['target_arch == "ia32"', {
            'xcode_settings': {'ARCHS': ['i386']},
          }],
          ['target_arch == "x64"', {
            'xcode_settings': {'ARCHS': ['x86_64']},
          }],
        ],
        'target_conditions': [
          ['_type != "static_library"', {
            'xcode_settings': {'OTHER_LDFLAGS': ['-Wl,-search_paths_first']},
          }],
        ],
      }],
     ['OS == "solaris"', {
       'cflags': [ '-fno-omit-frame-pointer' ],
       # pull in V8's postmortem metadata
       'ldflags': [ '-Wl,-z,allextract' ]
     }],
    ],
  },
}
