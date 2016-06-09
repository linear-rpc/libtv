AC_INIT([libtv], [0.3.2], [https://github.com/linear-rpc/libtv])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/loop.c])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([config.h])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CANONICAL_HOST
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT

AC_PROG_CC
AC_CHECK_PROGS([DOXYGEN], [doxygen])
AC_SUBST(DOXYGEN)

AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([rt], [timer_create])
LIBUV_DIR=`pwd`/deps/libuv
AC_SUBST(LIBUV_DIR)

AC_MSG_CHECKING(for necessity of -Wno-enum-compare)
AC_TRY_COMPILE([
        typedef enum {
                A = 0
        } enum_a_t;
        typedef enum {
                B = 0
        } enum_b_t;
        ],
        [enum_a_t a = A; enum_b_t b = B; if (a != b) {return -1;}],
        [no_enum_compare="no"], [no_enum_compare="yes"])
AC_MSG_RESULT($no_enum_compare)
if test "x$no_enum_compare" = "xyes"; then
   ENUM_CFLAGS="-Wno-enum-compare"
else
   ENUM_CFLAGS=
fi

# Checks for --enable-debug
AC_ARG_ENABLE([debug],
              AC_HELP_STRING([--enable-debug], [enable debug@<:@default=yes@:>@]),
              [enable_debug="$enableval"], [enable_debug=yes])
if test "x${enable_debug}" = "xyes"; then
   DEBUG_CFLAGS="-O0 -g"
else
   DEBUG_CFLAGS="-O3 -DNDEBUG -D_FORTIFY_SOURCE=2"
fi

AS_IF([test "x${ac_cv_env_CFLAGS_set}" = "x"],
      [CFLAGS="-Wall -Werror -fno-strict-aliasing --std=gnu89 ${ENUM_CFLAGS} ${DEBUG_CFLAGS} -I${LIBUV_DIR}/include"],
      [CFLAGS="$CFLAGS -fno-strict-aliasing ${ENUM_CFLAGS} -I${LIBUV_DIR}/include"])

# Checks for --with-ssl
AC_ARG_WITH([ssl],
            [AC_HELP_STRING([--with-ssl], [use OpenSSL library@<:@default=no@:>@])],
            [with_ssl=$withval], [with_ssl=no])
if test "x$with_ssl" = "xyes"; then
   CFLAGS="$CFLAGS -DWITH_SSL"
   LIBS="$LIBS -lssl -lcrypto"
elif test "x${with_ssl}" != "xno"; then
   CFLAGS="$CFLAGS -DWITH_SSL -I$with_ssl/include"
   LDFLAGS="-L$with_ssl/lib $LDFLAGS"
   LIBS="$LIBS -lssl -lcrypto"
fi
AM_CONDITIONAL([WITH_SSL], [test "x$with_ssl" != "xno"])
if test "x$with_ssl" != "xno"; then
   AC_MSG_CHECKING(for TLSv1_1_method in -lssl)
   AC_TRY_LINK([#include "openssl/ssl.h"],
               [TLSv1_1_method();], [AC_MSG_RESULT(yes)],
               [AC_MSG_RESULT(no); AC_MSG_ERROR(openssl v1.0.1 or newer required)])
   AC_SUBST(WITH_SSL, true)
fi

# Checks for --with-test
AC_ARG_WITH([test],
            AC_HELP_STRING([--with-test], [make tests@<:@default=no@:>@]),
            [with_test=$withval], [with_test=no])
AM_CONDITIONAL([WITH_TEST], [test "x${with_test}" != "xno"])
if test "x${with_test}" != "xno"; then
   AC_SUBST(WITH_TEST, true)
fi

# Checks for --with-sample
AC_ARG_WITH([sample],
            AC_HELP_STRING([--with-sample], [make samples@<:@default=no@:>@]),
            [with_sample=$withval], [with_sample=no])
AM_CONDITIONAL([WITH_SAMPLE], [test "x${with_sample}" != "xno"])
if test "x${with_sample}" != "xno"; then
   AC_SUBST(WITH_SAMPLE, true)
fi

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 doc/Makefile
                 sample/Makefile])
AC_CONFIG_SUBDIRS([deps/libuv])
AC_CHECK_PROG(PKG_CONFIG, pkg-config, yes)
AM_CONDITIONAL([HAVE_PKG_CONFIG], [test "x$PKG_CONFIG" != "x"])
AS_IF([test "x$PKG_CONFIG" != "x"], [
    AC_CONFIG_FILES([libtv.pc])
])
AC_OUTPUT
