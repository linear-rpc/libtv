{
  'variables': {
    'tv_library%': 'static_library',
    'warning_cflags%': [
      '-Wall -Wextra',
      '-Werror',
      '-Wcast-align',
      # '-Wcast-qual',
      # '-Wconversion',
      '-Wdisabled-optimization',
      '-Wfloat-equal -Wformat=2',
      '-Winit-self -Winvalid-pch',
      # '-Wmissing-format-attribute',
      '-Wmissing-include-dirs -Wmissing-noreturn',
      '-Wpacked -Wpointer-arith',
      #'-Wswitch-default',
      # '-Wswitch-enum',
      '-Wvolatile-register-var',
      '-Wwrite-strings',
      # '-Wlogical-op -Woverlength-strings -Wstrict-overflow=5 -Wvla',
      # '-Waggregate-return -Winline -Wpadded -Wunreachable-code -Wunsafe-loop-optimizations',
      # '-Wlarger-than-XXXXXX',
      '-Wno-unused-parameter',
    ],
    'warning_cflags_c%': [
      '-Wbad-function-cast',
      # '-Wmissing-declarations -Wmissing-prototypes',
      '-Wnested-externs',
      '-Wold-style-definition',
      '-Wstrict-prototypes',
      '-Wno-sign-compare',
      '-Wno-strict-aliasing',
    ],
    'other_cflags%': [
      '-ftrapv',
      '-fstack-protector-all -Wstack-protector',
      # '-fmudflapth -lmudflapth',
      '-fno-strict-aliasing',
      # '-Wstrict-aliasing=2',
      '-fno-omit-frame-pointer',
      '-std=gnu99',
      '-pedantic',
    ],
    'other_cflags_c%': [ ],
  },
  'target_defaults': {
    'defines': [ '_GNU_SOURCE' ],
    'cflags': [ '<@(warning_cflags)', '<@(other_cflags)' ],
    'cflags_c': [ '<@(warning_cflags_c)', '<@(other_cflags_c)' ],
    'xcode_settings': {
      'GCC_GENERATE_DEBUGGING_SYMBOLS': 'NO',
      'GCC_OPTIMIZATION_LEVEL': '0',
      'WARNING_CFLAGS': [ '<@(warning_cflags)', '<@(warning_cflags_c)' ],
      'OTHER_CFLAGS': [ '<@(other_cflags)', '<@(other_cflags_c)' ],
    },
    'msbuild_settings': {
      'ClCompile': {
        'CompileAs': 'CompileAsCpp',
      },
    },
  },
  'targets': [
    {
      'target_name': 'libtv',
      'type': '<(tv_library)',
      'include_dirs': [
        'deps/http-parser',
        'include',
      ],
      'dependencies': [
        'deps/libuv/uv.gyp:libuv',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'include',
          'deps/http-parser',
        ],
      },
      'sources': [
        'deps/http-parser/http_parser.c',
        'src/md5.h',
        'src/md5.c',
        'src/buffer.c',
        'src/handle.c',
        'src/internal.h',
        'src/loop.c',
        'src/pipe.c',
        'src/queue.h',
        'src/stream.c',
        'src/tcp.c',
        'src/timer.c',
        'src/ws.c',
        'src/ws_frame.c',
        'src/ws_handshake.c',
      ],
      'conditions': [
        ['with_ssl != "false"', {
          'defines': [
            'WITH_SSL',
          ],
          'sources': [
            'src/ssl.c',
            'src/wss.c',
          ],
        }, {
          'sources': [
            'src/sha1.h',
            'src/sha1.c',
          ]
        }],
        ['OS == "win"', {
          'defines': [
            # https://msdn.microsoft.com/en-US/library/windows/desktop/aa383745(v=vs.85).aspx
            '_WIN32_WINNT=0x0600', # supports after Windows Vista
          ],
        }, { # Not Windows i.e. POSIX
          'conditions': [
            ['_type == "shared_library" and OS != "mac"', {
              # This will cause gyp to set soname
              'product_extension': 'so.1',
            }],
          ],
        }],
        ['_type == "shared_library"', {
          'defines': [
            'BUILDING_TV_SHARED=1',
            'BUILDING_WS_SHARED=1',
            'USING_UV_SHARED=1',
          ]
        }],
      ]
    },
  ],
}
