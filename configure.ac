#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# See autoconf and autoscan online documentation for details.

AC_INIT([openssl-ibmca], [2.2.3], [opencryptoki-users@lists.sf.net])
AC_CONFIG_SRCDIR([src/engine/e_ibmca.c]) # sanity check
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign])

AC_PATH_PROG([CHMOD], [chmod], [/bin/chmod])

# Cmdline arguments.
AC_ARG_ENABLE([debug],
		[AS_HELP_STRING([--enable-debug], [turn on debugging flags (default is off)])],
		[enable_debug="yes"],)

if test "x$enable_debug" == "xyes"; then
	CFLAGS="$CFLAGS -O0 -g -DDEBUG -Wall"
	AC_MSG_RESULT([*** Enabling debugging at user request ***])
else
	CFLAGS="$CFLAGS -O2 -Wall"
fi

AC_ARG_ENABLE([engine],
		[AS_HELP_STRING([--enable-engine], [build IBMCA engine (OpenSSL 1.1.1, default is yes)])],
		[if test "x$enableval" = "xyes" ; then
			enable_engine="yes"
		 else
		 	enable_engine="no"
		 fi],
		[enable_engine="yes"])

AC_ARG_ENABLE([provider],
		[AS_HELP_STRING([--enable-provider], [build IBMCA provider (OpenSSL >= 3.0, default is yes if built against OpenSSL 3.0 or later, else the default is false)])],
		[if test "x$enableval" = "xyes" ; then
			enable_provider="yes"
		 else
		 	enable_provider="no"
		 fi],
		[enable_provider="check"])

# Checks for programs.
AC_DISABLE_STATIC
AC_PROG_CC
LT_INIT

# Checks for libraries.
AC_CHECK_LIB([crypto], [RAND_add], [], AC_MSG_ERROR([*** openssl >= 1.1.1 is required ***]))
AC_CHECK_LIB([crypto], [OSSL_LIB_CTX_new], [openssl_3_0="yes"], [openssl_3_0="no"])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h netinet/in.h stddef.h stdlib.h \
                 string.h strings.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADER([ica_api.h], [], AC_MSG_ERROR([*** libica-devel >= 3.6.0 is required ***]))


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostbyaddr gethostbyname memset strcasecmp strncasecmp strstr malloc])
AC_CHECK_DECLS([ICA_FLAG_DHW,DES_ECB], [],
		AC_MSG_ERROR([*** libica-devel >= 3.6.0 are required ***]),
		[#include <ica_api.h>])

AC_ARG_WITH([libica-cex],
	[AS_HELP_STRING([--with-libica-cex],[Use libica-cex as default library for the IBMCA engine])],
	[usecexonly=${withval}],
	[])

AC_ARG_WITH([libica-version],
	[AS_HELP_STRING([--with-libica-version],[Use specified libica major version (defaults to 4)])],
	[libicaversion=${withval}],
	[libicaversion=4])

if test "x$usecexonly" = xyes; then
	defaultlib="libica-cex.so.$libicaversion"
	ica="ica-cex"
else
	defaultlib="libica.so.$libicaversion"
	ica="ica"
fi
# In cex-only mode, testing the ciphers does not make any sense since
# they will fall back to OpenSSL without the engine.  So remove these
# tests from that build.
AM_CONDITIONAL([FULL_LIBICA], [test "x$usecexonly" != xyes])

# If compiled against OpenSSL 3.0 or later, build the provider unless
# explicitely disabled. 
# If build against OpenSSL 1.1.1, we can not build the provider.
if test "x$openssl_3_0" = xyes; then
	if test "x$enable_provider" != xno; then
		enable_provider=yes
	fi
else
	if test "x$enable_provider" = xyes; then
		AC_MSG_ERROR([*** openssl >= 3.0 is required to build the IBMCA provider ***]);
	fi
	enable_provider=no
fi

AM_CONDITIONAL([IBMCA_ENGINE], [test "x$enable_engine" == xyes])
AM_CONDITIONAL([IBMCA_PROVIDER], [test "x$enable_provider" == xyes])


AC_DEFINE_UNQUOTED([LIBICA_SHARED_LIB],["$defaultlib"])
AC_SUBST([ICA],["$ica"])

AC_CHECK_PROG([openssl_var],[openssl],[yes],[no])
if test "x$openssl_var" != xyes; then
        AC_MSG_ERROR([openssl binary required]);
fi

if test "x$enable_provider" = xyes; then
	AC_CHECK_DECLS([ica_fips_status], [],
		AC_MSG_ERROR([*** libica >= 4.0 is required to build the IBMCA provider ***]),
		[#include <ica_api.h>])
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/engine/Makefile
	src/engine/test/Makefile.linux
	src/engine/doc/Makefile
	src/provider/Makefile
	src/provider/doc/Makefile
	test/Makefile
	test/engine/Makefile])

AC_OUTPUT

echo "CFLAGS=$CFLAGS"
echo "IBMCA engine:      $enable_engine"
echo "  default library: $defaultlib"
echo "IBMCA provider:    $enable_provider"
