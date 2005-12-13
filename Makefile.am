lib_LTLIBRARIES=libibmca.la

libibmca_la_LIBADD=@OPENSSL_LIB_DIR@/libcrypto.a
libibmca_la_LDFLAGS=-lc
libibmca_la_CFLAGS=-I@OPENSSL_INCLUDE_DIR@
CFLAGS=-I@OPENSSL_INCLUDE_DIR@
libibmca_la_SOURCES=e_ibmca.c e_ibmca.h e_ibmca_err.c
