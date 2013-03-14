## Process this file with automake to produce Makefile.in

vicare_openssl_CURRENT	= @vicare_openssl_VERSION_INTERFACE_CURRENT@
vicare_openssl_REVISION	= @vicare_openssl_VERSION_INTERFACE_REVISION@
vicare_openssl_AGE	= @vicare_openssl_VERSION_INTERFACE_AGE@
vicare_openssl_VERSION	= $(vicare_openssl_CURRENT):$(vicare_openssl_REVISION):$(vicare_openssl_AGE)

lib_LTLIBRARIES			= libvicare-openssl.la
libvicare_openssl_la_LDFLAGS	= -version-info $(vicare_openssl_VERSION)
libvicare_openssl_la_SOURCES	= \
	vicare-openssl-version.c		\
	vicare-openssl-core.c			\
	\
	vicare-openssl-hash-checksums.c		\
	vicare-openssl-hmac.c			\
	\
	vicare-openssl-crypto-aes.c		\
	\
	vicare-openssl-evp-hash.c		\
	\
	vicare-openssl-internals.h

### end of file
