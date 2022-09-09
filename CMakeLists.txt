cmake_minimum_required(VERSION 3.4)
project(libtv LANGUAGES C)

cmake_policy(SET CMP0057 NEW) # Enable IN_LIST operator
cmake_policy(SET CMP0064 NEW) # Support if (TEST) operator

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckCCompilerFlag)
include(GNUInstallDirs)
include(CTest)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_C_STANDARD 90)


# Compiler check
string(CONCAT is-msvc $<OR:
  $<C_COMPILER_ID:MSVC>,
  $<STREQUAL:${CMAKE_C_COMPILER_FRONTEND_VARIANT},MSVC>
>)

check_c_compiler_flag(/W4 TV_LINT_W4)
check_c_compiler_flag(/wd4100 TV_LINT_NO_UNUSED_PARAMETER_MSVC)
check_c_compiler_flag(/wd4127 TV_LINT_NO_CONDITIONAL_CONSTANT_MSVC)
check_c_compiler_flag(/wd4201 TV_LINT_NO_NONSTANDARD_MSVC)
check_c_compiler_flag(/wd4206 TV_LINT_NO_NONSTANDARD_EMPTY_TU_MSVC)
check_c_compiler_flag(/wd4210 TV_LINT_NO_NONSTANDARD_FILE_SCOPE_MSVC)
check_c_compiler_flag(/wd4232 TV_LINT_NO_NONSTANDARD_NONSTATIC_DLIMPORT_MSVC)
check_c_compiler_flag(/wd4456 TV_LINT_NO_HIDES_LOCAL)
check_c_compiler_flag(/wd4457 TV_LINT_NO_HIDES_PARAM)
check_c_compiler_flag(/wd4459 TV_LINT_NO_HIDES_GLOBAL)
check_c_compiler_flag(/wd4706 TV_LINT_NO_CONDITIONAL_ASSIGNMENT_MSVC)
check_c_compiler_flag(/wd4996 TV_LINT_NO_UNSAFE_MSVC)
check_c_compiler_flag(-Wall TV_LINT_WALL) # DO NOT use this under MSVC
check_c_compiler_flag(-Werror TV_LINT_WERROR)

# TODO: Place these into its own function
check_c_compiler_flag(-Wno-unused-parameter TV_LINT_NO_UNUSED_PARAMETER)
check_c_compiler_flag(-Wstrict-prototypes TV_LINT_STRICT_PROTOTYPES)
check_c_compiler_flag(-Wextra TV_LINT_EXTRA)

check_c_compiler_flag(/utf-8 TV_LINT_UTF8_MSVC)

set(lint-no-unused-parameter $<$<BOOL:${TV_LINT_NO_UNUSED_PARAMETER}>:-Wno-unused-parameter>)
set(lint-strict-prototypes $<$<BOOL:${TV_LINT_STRICT_PROTOTYPES}>:-Wstrict-prototypes>)
set(lint-extra $<$<BOOL:${TV_LINT_EXTRA}>:-Wextra>)
set(lint-w4 $<$<BOOL:${TV_LINT_W4}>:/W4>)
set(lint-no-unused-parameter-msvc $<$<BOOL:${TV_LINT_NO_UNUSED_PARAMETER_MSVC}>:/wd4100>)
set(lint-no-conditional-constant-msvc $<$<BOOL:${TV_LINT_NO_CONDITIONAL_CONSTANT_MSVC}>:/wd4127>)
set(lint-no-nonstandard-msvc $<$<BOOL:${TV_LINT_NO_NONSTANDARD_MSVC}>:/wd4201>)
set(lint-no-nonstandard-empty-tu-msvc $<$<BOOL:${TV_LINT_NO_NONSTANDARD_EMPTY_TU_MSVC}>:/wd4206>)
set(lint-no-nonstandard-file-scope-msvc $<$<BOOL:${TV_LINT_NO_NONSTANDARD_FILE_SCOPE_MSVC}>:/wd4210>)
set(lint-no-nonstandard-nonstatic-dlimport-msvc $<$<BOOL:${TV_LINT_NO_NONSTANDARD_NONSTATIC_DLIMPORT_MSVC}>:/wd4232>)
set(lint-no-hides-local-msvc $<$<BOOL:${TV_LINT_NO_HIDES_LOCAL}>:/wd4456>)
set(lint-no-hides-param-msvc $<$<BOOL:${TV_LINT_NO_HIDES_PARAM}>:/wd4457>)
set(lint-no-hides-global-msvc $<$<BOOL:${TV_LINT_NO_HIDES_GLOBAL}>:/wd4459>)
set(lint-no-conditional-assignment-msvc $<$<BOOL:${TV_LINT_NO_CONDITIONAL_ASSIGNMENT_MSVC}>:/wd4706>)
set(lint-no-unsafe-msvc $<$<BOOL:${TV_LINT_NO_UNSAFE_MSVC}>:/wd4996>)
# Unfortunately, this one is complicated because MSVC and clang-cl support -Wall
# but using it is like calling -Weverything
string(CONCAT lint-default $<
  $<AND:$<BOOL:${TV_LINT_WALL}>,$<NOT:${is-msvc}>>:-Wall
>)

set(lint-utf8-msvc $<$<BOOL:${TV_LINT_UTF8_MSVC}>:/utf-8>)

list(APPEND tv_cflags ${lint-strict-prototypes} ${lint-extra} ${lint-default} ${lint-w4})
list(APPEND tv_cflags ${lint-no-unused-parameter})
list(APPEND tv_cflags ${lint-no-unused-parameter-msvc})
list(APPEND tv_cflags ${lint-no-conditional-constant-msvc})
list(APPEND tv_cflags ${lint-no-nonstandard-msvc})
list(APPEND tv_cflags ${lint-no-nonstandard-empty-tu-msvc})
list(APPEND tv_cflags ${lint-no-nonstandard-file-scope-msvc})
list(APPEND tv_cflags ${lint-no-nonstandard-nonstatic-dlimport-msvc})
list(APPEND tv_cflags ${lint-no-hides-local-msvc})
list(APPEND tv_cflags ${lint-no-hides-param-msvc})
list(APPEND tv_cflags ${lint-no-hides-global-msvc})
list(APPEND tv_cflags ${lint-no-conditional-assignment-msvc})
list(APPEND tv_cflags ${lint-no-unsafe-msvc})
list(APPEND tv_cflags ${lint-utf8-msvc} )

check_c_compiler_flag(-fno-strict-aliasing TV_F_STRICT_ALIASING)
list(APPEND tv_cflags $<$<BOOL:${TV_LINT_WERROR}>:-Werror>)
list(APPEND tv_cflags $<$<BOOL:${TV_F_STRICT_ALIASING}>:-fno-strict-aliasing>)

set(tv_sources
  deps/http-parser/http_parser.c
  src/buffer.c
  src/handle.c
  src/loop.c
  src/md5.c
  src/pipe.c
  src/stream.c
  src/tcp.c
  src/timer.c
  src/ws.c
  src/ws_frame.c
  src/ws_handshake.c
  src/ssl.c
  src/wss.c)

add_definitions(-DWITH_SSL)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(tv_libraries ${tv_libraries} ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})

add_subdirectory(deps/libuv)
include_directories(deps/libuv/include)
include_directories(deps/http-parser)
set(tv_libraries ${tv_libraries} uv_a)

add_library(tv STATIC ${tv_sources})
target_compile_definitions(tv PRIVATE ${tv_defines})
target_compile_options(tv PRIVATE ${tv_cflags})
target_include_directories(tv
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)
if(CMAKE_SYSTEM_NAME STREQUAL "OS390")
  target_include_directories(tv PUBLIC $<BUILD_INTERFACE:${ZOSLIB_DIR}/include>)
  set_target_properties(tv PROPERTIES LINKER_LANGUAGE CXX)
endif()
target_link_libraries(tv ${tv_libraries})



install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES ${PROJECT_BINARY_DIR}/libtv.pc ${PROJECT_BINARY_DIR}/libtv-static.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(TARGETS tv EXPORT libtvConfig
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(EXPORT libtvConfig DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libtv)

if(MSVC)
  set(CMAKE_DEBUG_POSTFIX d)
endif()

message(STATUS "summary of build options:
    Install prefix:  ${CMAKE_INSTALL_PREFIX}
    Target system:   ${CMAKE_SYSTEM_NAME}
    Compiler:
      C compiler:    ${CMAKE_C_COMPILER} (${CMAKE_C_COMPILER_ID})
      CFLAGS:        ${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
")
