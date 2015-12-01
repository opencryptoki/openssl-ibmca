lib_LTLIBRARIES=libibmca.la

libibmca_la_SOURCES=e_ibmca.c e_ibmca_err.c
libibmca_la_LDFLAGS=-module -version-info 0:2:0 -shared -no-undefined -avoid-version

dist_libibmca_la_SOURCES=e_ibmca_err.h e_os.h cryptlib.h
EXTRA_DIST = openssl.cnf.sample

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = doc
