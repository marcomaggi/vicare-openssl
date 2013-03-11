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

dnl This must come first.
AC_CHECK_HEADERS([openssl/ssl.h],,
  [AC_MSG_FAILURE([missing openssl/ssl.h header],[2])])

dnl Message digests.
AC_CHECK_HEADERS([openssl/md4.h],,
  [AC_MSG_FAILURE([missing openssl/md4.h header],[2])])
AC_CHECK_HEADERS([openssl/md5.h],,
  [AC_MSG_FAILURE([missing openssl/md5.h header],[2])])
AC_CHECK_HEADERS([openssl/mdc2.h],,
  [AC_MSG_FAILURE([missing openssl/mdc2.h header],[2])])
AC_CHECK_HEADERS([openssl/sha.h],,
  [AC_MSG_FAILURE([missing openssl/sha.h header],[2])])
AC_CHECK_HEADERS([openssl/ripemd.h],,
  [AC_MSG_FAILURE([missing openssl/ripemd.h header],[2])])

AC_CHECK_LIB([crypto],[MD5_Init],,
  [AC_MSG_FAILURE([missing OpenSSL crypto library],[2])])
AC_CHECK_LIB([ssl],[SSL_library_init],,
  [AC_MSG_FAILURE([missing OpenSSL ssl library],[2])])

VICARE_EXTENSION_LIBRARY_VERSION([openssl],[0],[0],[0])

m4_define([VICARE_INCLUDES],[
AC_INCLUDES_DEFAULT
#ifdef HAVE_VICARE_H
#  include <vicare.h>
#endif

#ifdef HAVE_OPENSSL_SSL_H
#  include <openssl/ssl.h>
#endif

#ifdef HAVE_OPENSSL_MD4_H
#  include <openssl/md4.h>
#endif
#ifdef HAVE_OPENSSL_MD5_H
#  include <openssl/md5.h>
#endif
#ifdef HAVE_OPENSSL_MDC2_H
#  include <openssl/mdc2.h>
#endif
#ifdef HAVE_OPENSSL_SHA_H
#  include <openssl/sha.h>
#endif
#ifdef HAVE_OPENSSL_RIPEMD_H
#  include <openssl/ripemd.h>
#endif

])

#page
#### C language stuff from the files "openssl/md4.h", "openssl/md5.h"

dnl Message Digest 4
VICARE_CONSTANT_TESTS([MD4_DIGEST_LENGTH])
AC_CHECK_FUNCS([MD4_Init MD4_Update MD4_Final MD4])

dnl Message Digest 5
VICARE_CONSTANT_TESTS([MD5_DIGEST_LENGTH])
AC_CHECK_FUNCS([MD5_Init MD5_Update MD5_Final MD5])

dnl MDC2
VICARE_CONSTANT_TESTS([MDC2_DIGEST_LENGTH])
AC_CHECK_FUNCS([MDC2_Init MDC2_Update MDC2_Final MDC2])

dnl SHA1
VICARE_CONSTANT_TESTS([SHA_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA1_Init SHA1_Update SHA1_Final SHA1])

dnl SHA224
VICARE_CONSTANT_TESTS([SHA224_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA224_Init SHA224_Update SHA224_Final SHA224])

dnl SHA256
VICARE_CONSTANT_TESTS([SHA256_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA256_Init SHA256_Update SHA256_Final SHA256])

dnl SHA384
VICARE_CONSTANT_TESTS([SHA384_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA384_Init SHA384_Update SHA384_Final SHA384])

dnl SHA512
VICARE_CONSTANT_TESTS([SHA512_DIGEST_LENGTH])
AC_CHECK_FUNCS([SHA512_Init SHA512_Update SHA512_Final SHA512])

dnl RIPEMD 160
VICARE_CONSTANT_TESTS([RIPEMD160_DIGEST_LENGTH])
AC_CHECK_FUNCS([RIPEMD160_Init RIPEMD160_Update RIPEMD160_Final RIPEMD160])

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
