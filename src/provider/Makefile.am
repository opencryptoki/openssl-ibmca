VERSION = 1:1:0

lib_LTLIBRARIES=ibmca-provider.la

ibmca_provider_la_SOURCES=p_ibmca.c

ibmca_provider_la_LIBADD=-ldl
ibmca_provider_la_LDFLAGS=-module -version-number ${VERSION} -shared -no-undefined \
		  -avoid-version -Wl,--version-script=${srcdir}/ibmca-provider.map

EXTRA_DIST = openssl.cnf.provider.sample ibmca-provider-opensslconfig

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = doc

noinst_SCRIPTS = ibmca-provider-opensslconfig
