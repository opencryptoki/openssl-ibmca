TESTS_CIPHERS = \
des-ecb-test.pl \
des-cbc-test.pl \
des-cfb-test.pl \
des-ofb-test.pl \
3des-ecb-test.pl \
3des-cbc-test.pl \
3des-cfb-test.pl \
3des-ofb-test.pl \
aes-128-ecb-test.pl \
aes-128-cbc-test.pl \
aes-128-cfb-test.pl \
aes-128-ofb-test.pl \
aes-192-ecb-test.pl \
aes-192-cbc-test.pl \
aes-192-cfb-test.pl \
aes-192-ofb-test.pl \
aes-256-ecb-test.pl \
aes-256-cbc-test.pl \
aes-256-cfb-test.pl \
aes-256-ofb-test.pl

if FULL_LIBICA
TESTS_CIPHERS_EXEC=${TESTS_CIPHERS}
endif

TESTS_PERL = \
rsa2k.pl 	\
rsa4k.pl 	\
rsa8k.pl	\
rsa16k.pl	\
dsa2k.pl	\
dsa4k.pl	\
dsa8k.pl	\
dsamax.pl

TESTS = ${TESTS_PERL} \
${TESTS_CIPHERS_EXEC} \
loadtest \
loadtest-ec \
threadtest \
libica-link.sh \
eckey \
enginectrl

check_PROGRAMS = loadtest loadtest-ec threadtest eckey enginectrl
check_SCRIPTS = libica-link.sh

loadtest_SOURCES = loadtest.c
loadtest_LDADD = -lssl -lcrypto

loadtest_ec_SOURCES = loadtest-ec.c
loadtest_ec_LDADD = -lssl -lcrypto

threadtest_SOURCES = threadtest.c
threadtest_LDADD = -lcrypto -lpthread

eckey_SOURCES = eckey.c
eckey_LDADD = -lcrypto

enginectrl_SOURCES = enginectrl.c
enginectrl_LDADD = -lcrypto -ldl

AM_TESTS_ENVIRONMENT = export IBMCA_TEST_PATH=${top_builddir}/src/engine/.libs/ibmca.so IBMCA_OPENSSL_TEST_CONF=${srcdir}/openssl-test.cnf IBMCA_OPENSSL_TEST_NOINIT_CONF=${srcdir}/openssl-test-noinit.cnf PERL5LIB=${srcdir};
EXTRA_DIST = ${TESTS_PERL} ${TESTS_CIPHERS} test.pm openssl-test.cnf 	\
	openssl-test-noinit.cnf dsa2k.key dsa2k_pub.key dsa4k.key	\
	dsa4k_pub.key dsa8k.key dsa8k_pub.key dsamax.key dsamax_pub.key	\
	rsa2k.key rsa4k.key rsa8k.key rsa16k.key dsaparam2k.key		\
	dsaparam4k.key dsaparam8k.key dsaparammax.key

libica-link.sh:
	@echo '#!/bin/bash' > libica-link.sh
	@echo "IBMCA_SO=\"${abs_top_builddir}/src/engine/.libs/ibmca.so\"" > libica-link.sh
	@echo "if ldd \"\$${IBMCA_SO}\" | grep -q libica; then" >> libica-link.sh
	@echo "    echo \"Linking against libica detected\"" >> libica-link.sh
	@echo "    echo \"Check these ica symbols:\"" >> libica-link.sh
	@echo "    nm --undefined-only \"\$${IBMCA_SO}\" | grep 'ica_'" >> libica-link.sh
	@echo "    exit 99" >> libica-link.sh
	@echo "fi" >> libica-link.sh
	@echo "exit 0" >> libica-link.sh
	@chmod u+x libica-link.sh

CLEANFILES = *.out *.dec libica-link.sh
