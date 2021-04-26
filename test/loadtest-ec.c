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
    ECDSA_SIG     *sig = NULL;
    EC_KEY        *eckey = NULL;
    unsigned char  digest[20];

    memset(digest, 0, sizeof(digest));
    
    eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
    if (eckey == NULL) {
        /* error */
        fprintf(stderr, "Failed to create EC_KEY for secp384r1\n");
        goto out;
    }
    if (!EC_KEY_generate_key(eckey)) {
        /* error */
        fprintf(stderr, "Failed to generate EC_KEY\n");
        goto out;
    }
    sig = ECDSA_do_sign(digest, sizeof(digest), eckey);
    if (sig == NULL) {
        /* error */
        fprintf(stderr, "Failed to sign\n");
        goto out;
    }
    ret = ECDSA_do_verify(digest, sizeof(digest), sig, eckey);
    if (ret == -1) {
        /* error */
        fprintf(stderr, "Failed to verify signature\n");
        goto out;
    } else if (ret == 0) {
        /* incorrect signature */
        fprintf(stderr, "Signature incorrect\n");
        goto out;
    } else {
        /* signature ok */
        ret = 1;
    }
 out:
    if (sig)
        ECDSA_SIG_free(sig);
    if (eckey)
        EC_KEY_free(eckey);
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
