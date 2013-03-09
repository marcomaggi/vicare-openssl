dnl @configure_input@
dnl

AC_PREREQ([2.68])
AC_INIT([Vicare/OpenSSL],[0.1d0],[marco.maggi-ipsu@poste.it],
  [vicare-openssl],[http://marcomaggi.github.com/vicare.html])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([autotools])
AC_CONFIG_AUX_DIR([autotools])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([-Wall foreign dist-xz no-dist-gzip])
AM_MAINTAINER_MODE

VICARE_OPTION_DEBUGGING_MODE
VICARE_OPTION_NAUSICAA([no])

#page
#### compiler

AC_PROG_CC
AC_PROG_CC_C_O

AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

LT_PREREQ([2.4])
LT_INIT([shared disable-static])

dnl AC_LANG([C])
dnl AC_DEFINE([_GNU_SOURCE],[1],[enable everything GNU])

#page
#### vicare configuration

AC_CHECK_HEADERS([vicare.h],,[AC_MSG_FAILURE([missing vicare.h header],[2])])
AC_CHECK_PROG([VICARE],[vicare],[vicare],[:])

#page
#### openssl configuration

AC_ARG_WITH([openssl],
  [AS_HELP_STRING([--with-openssl],[the path to the OpenSSL files])],
  [OPENSSL_DIR=${withval}],
  [OPENSSL_DIR=])

if test "z$OPENSSL_DIR" != z
then
  CFLAGS="$CFLAGS -I $OPENSSL_DIR/include"
  CPPFLAGS="$CPPFLAGS -I $OPENSSL_DIR/include"
  LIBS="$LIBS -L$OPENSSL_DIR/lib"
fi

AC_CHECK_HEADERS([openssl/ssl.h],,
  [AC_MSG_FAILURE([missing openssl/ssl.h header],[2])])
AC_CHECK_LIB([crypto],[MD5_Init],,
  [AC_MSG_FAILURE([missing OpenSSL crypto library],[2])])
AC_CHECK_LIB([ssl],[SSL_library_init],,
  [AC_MSG_FAILURE([missing OpenSSL ssl library],[2])])

VICARE_EXTENSION_LIBRARY_VERSION([openssl],[0],[0],[0])

#page
#### C language preprocessor symbols from the file "libesmtp.h"

m4_define([VICARE_INCLUDES],[
AC_INCLUDES_DEFAULT
#ifdef HAVE_VICARE_H
#  include <vicare.h>
#endif
#ifdef HAVE_OPENSSL_SSL_H
#  include <openssl/ssl.h>
#endif
])

dnl Stuff
dnl VICARE_CONSTANT_TESTS([XML_TRUE XML_FALSE])

#page
#### C language functions from the header file "libesmtp.h"

dnl AC_CHECK_FUNCS([openssl_version])

#page
#### finish

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile]
        [src/Makefile]
        [doc/Makefile]
        [tests/Makefile]
        [lib/Makefile]
        [lib/vicare/crypto/openssl/constants.sls]
        [meta/slackware/doinst.sh])
AC_OUTPUT

### end of file
# Local Variables:
# mode: autoconf
# page-delimiter: "^#page"
# End:
