TESTS_PERL = \
tls.pl		\
ecsign.pl	\
ecderive.pl	\
dhderive.pl	\
rsa512.pl	\
rsa1k.pl	\
rsa2k.pl	\
rsa4k.pl	\
rsa8k.pl
#rsa16k.pl

if OPENSSL_IMPLICIT_REJECTION
TESTS_PERL += rsaimplrej.pl
endif

TESTS = \
	rsakey		\
	eckey		\
	dhkey		\
	threadtest	\
	${TESTS_PERL}

check_PROGRAMS = rsakey eckey dhkey threadtest

dhkey_SOURCES = dhkey.c
if PROVIDER_FULL_LIBICA
dhkey_LDADD = -lcrypto -lica
else
dhkey_LDADD = -lcrypto -lica-cex
endif

eckey_SOURCES = eckey.c
if PROVIDER_FULL_LIBICA
eckey_LDADD = -lcrypto -lica
else
eckey_LDADD = -lcrypto -lica-cex
endif

rsakey_SOURCES = rsakey.c
if PROVIDER_FULL_LIBICA
rsakey_LDADD = -lcrypto -lica
else
rsakey_LDADD = -lcrypto -lica-cex
endif

threadtest_SOURCES = threadtest.c
threadtest_LDADD = -lcrypto -lpthread

AM_TESTS_ENVIRONMENT = export IBMCA_TEST_PATH=${top_builddir}/src/provider/.libs/ IBMCA_OPENSSL_TEST_CONF=${srcdir}/openssl-test.cnf PERL5LIB=${srcdir};
EXTRA_DIST = ${TESTS_PERL} test.pm openssl-test.cnf server-cert-rsa.pem	\
	server-key-rsa.pem server-cert-ec.pem server-key-ec.pem		\
	rsa-implrej-bad-empty-in.bin rsa-implrej-bad-empty-out.bin	\
	rsa-implrej-bad-max-in.bin rsa-implrej-bad-max-out.bin		\
	rsa-implrej-bad-prf-in.bin rsa-implrej-bad-prf-out.bin		\
	rsa-implrej-good-in.bin rsa-implrej-good-out.bin		\
	rsa-implrej-key.pem rsa16k.pl

CLEANFILES = *.out *.dec *.pub *.key
