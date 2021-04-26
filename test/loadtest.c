#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

int setup()
{
    const SSL_METHOD *req_method;
    SSL_CTX *ctx;

    /* Start code copy from libcurl 7.61.1 Curl_ossl_init function */
    OPENSSL_load_builtin_modules();

    /* MOD start */
#ifdef HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    //ENGINE_load_builtin_engines();
#endif
    ENGINE_load_builtin_engines();
    /* MOD end */

    /* OPENSSL_config(NULL); is "strongly recommended" to use but unfortunately
       that function makes an exit() call on wrongly formatted config files
       which makes it hard to use in some situations. OPENSSL_config() itself
       calls CONF_modules_load_file() and we use that instead and we ignore
       its return code! */

    /* CONF_MFLAGS_DEFAULT_SECTION introduced some time between 0.9.8b and
       0.9.8e */
#ifndef CONF_MFLAGS_DEFAULT_SECTION
#define CONF_MFLAGS_DEFAULT_SECTION 0x0
#endif

    CONF_modules_load_file(NULL, NULL,
                           CONF_MFLAGS_DEFAULT_SECTION|
                           CONF_MFLAGS_IGNORE_MISSING_FILE);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) &&  \
    !defined(LIBRESSL_VERSION_NUMBER)
    /* OpenSSL 1.1.0+ takes care of initialization itself */
#else
    /* Lets get nice error messages */
    SSL_load_error_strings();

    /* Init the global ciphers and digests */
    if(!SSLeay_add_ssl_algorithms())
        return 0;

    OpenSSL_add_all_algorithms();
#endif
    /* End code copy from libcurl 7.61.1 Curl_ossl_init function */
    
    /* Start extraction from libcurl 7.61.1 ossl_connect_step1 */
    req_method = TLS_client_method();
    /* This initializes libssl which initializes libcrypto for the
       second time. */
    ctx = SSL_CTX_new(req_method);
    SSL_CTX_free(ctx);
    return 1;
}

int check_globals()
{
    int            ret = 0;
    EVP_PKEY      *eckey = NULL;
    ENGINE        *engine;
    EVP_PKEY_CTX  *pctx = NULL;

    engine = ENGINE_by_id("ibmca");
    if (engine == NULL) {
        fprintf(stderr, "Failed to retrieve ibmca engine\n");
        goto out;
    }
    pctx = EVP_PKEY_CTX_new_id(NID_X25519, engine);
    if (pctx == NULL) {
        fprintf(stderr, "Failed to create PKEY_CTX\n");
        return 0;
    }
    if (EVP_PKEY_keygen_init(pctx) != 1 ||
        EVP_PKEY_keygen(pctx, &eckey) != 1) {
        fprintf(stderr, "keygen initialization failed\n");
        goto out;
    }
    if (eckey == NULL) {
        /* error */
        fprintf(stderr, "Failed to create ec key for X25519\n");
        goto out;
    }
    ret = 1;
 out:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (eckey)
        EVP_PKEY_free(eckey);
    return ret;
}

int main(int argc, char **argv)
{
    /* First fix the environment */
    char *testcnf = getenv("IBMCA_OPENSSL_TEST_CONF");

    /* Do not overwrite a user-provided OPENSSL_CONF in the
       environment.  This allows us to execute this test also on an
       installation with a user-provided engine configuration. */
    if (testcnf && setenv("OPENSSL_CONF", testcnf, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_CONF environment variable!\n");
        return 77;
    }
    
    if (!setup()) {
        fprintf(stderr, "Setup failed!\n");
        return 99;
    }
    if (!check_globals()) {
        fprintf(stderr, "Check for global variables failed!\n");
        return 99;
    }
    return 0;
}
