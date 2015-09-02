{
  'target_defaults': {
    'conditions': [
      ['OS != "win"', {
        'defines': [
          '_LARGEFILE_SOURCE',
          '_FILE_OFFSET_BITS=64',
        ],
      }],
    ],
    # TODO: Select CharacterSet
    # 'msvs_configuration_attributes': {
    #   'CharacterSet': '1', # Use Unicode Character Set
    #   'CharacterSet': '2', # Use Multi-Byte Character Set
    # },
    'xcode_settings': {
      'OTHER_CFLAGS': [ '--std=gnu99', '-pedantic' ],
    }
  },

  'targets': [
    {
      'target_name': 'libtv',
      'type': '<(tv_library)',
      'include_dirs': [
        'deps/http-parser',
        'include',
        'src',
      ],
      'dependencies': [
        'deps/libuv/uv.gyp:libuv',
      ],
      'direct_dependent_settings': {
        'include_dirs': [ 'include', 'deps/http-parser' ],
      },
      'sources': [
        'common.gypi',
        'deps/http-parser/http_parser.h',
        'deps/http-parser/http_parser.c',
        'include/tv.h',
        'include/websocket/buffer.h',
        'include/websocket/slist.h',
        'include/websocket/ws_frame.h',
        'include/websocket/ws_handshake.h',
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
          'sources': [
            'src/ssl.c',
            'src/wss.c',
          ],
          'defines': [
            'WITH_SSL',
          ],
        }, {
          'sources': [
            'src/sha1.h',
            'src/sha1.c',
          ]
        }],
        ['OS == "win"', {
          'defines': [
            '_WIN32_WINNT=0x0600',
            '_GNU_SOURCE',
          ],
        }, { # Not Windows i.e. POSIX
          'cflags': [
            '-g',
            '--std=gnu99',
            '-pedantic',
            '-Wall',
            '-Wextra',
            '-Wno-unused-parameter',
          ],
          'conditions': [
            ['_type == "shared_library"', {
              'cflags': [ '-fPIC' ],
            }],
            ['_type == "shared_library" and OS != "mac"', {
              # This will cause gyp to set soname
              # Must correspond with TV_VERSION_MAJOR
              # in include/tv.h
              'product_extension': 'so.1',
            }],
          ],
        }],
        ['OS in "mac ios"', {
          'defines': [
            '_DARWIN_USE_64_BIT_INODE=1',
            '_DARWIN_UNLIMITED_SELECT=1',
          ]
        }],
        ['OS != "mac"', {
          # Enable on all platforms except OS X. The antique gcc/clang that
          # ships with Xcode emits waaaay too many false positives.
          'cflags': [ '-Wstrict-aliasing' ],
        }],
        ['OS == "linux"', {
          'defines': [ '_GNU_SOURCE' ],
        }],
        ['OS == "solaris"', {
          'defines': [
            '__EXTENSIONS__',
            '_XOPEN_SOURCE=500',
          ],
        }],
        ['OS == "aix"', {
          'defines': [
            '_ALL_SOURCE',
            '_XOPEN_SOURCE=500',
            '_LINUX_SOURCE_COMPAT',
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
