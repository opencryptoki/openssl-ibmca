#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/engine.h>

void setup(void)
{
    OPENSSL_load_builtin_modules();

    ENGINE_load_builtin_engines();

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
    OpenSSL_add_all_algorithms();
#endif
}

int check_eckey(int nid, const char *name)
{
    int            ret = 0;
    ECDSA_SIG     *sig = NULL;
    EC_KEY        *eckey = NULL;
    unsigned char  digest[20];
    ENGINE        *engine = NULL;

    memset(digest, 0, sizeof(digest));

    engine = ENGINE_by_id("ibmca");
    if (engine == NULL) {
        fprintf(stderr, "ibmca engine not loaded\n");
        goto out;
    }
    if (ENGINE_get_EC(engine) == NULL) {
        fprintf(stderr, "ibmca does not support EC_KEY.  Skipping...\n");
        exit(77);
    }
    eckey = EC_KEY_new_by_curve_name(nid);
    if (eckey == NULL) {
        /* curve not supported => test passed */
        fprintf(stderr, "Curve %s not supported by OpenSSL\n", name);
        ret = 1;
        goto out;
    }
    if (EC_KEY_get0_engine(eckey) != engine) {
        fprintf(stderr, "EC_KEY for %s does not use ibmca engine\n", name);
        goto out;
    }
    if (!EC_KEY_generate_key(eckey)) {
        /* error */
        fprintf(stderr, "Failed to generate EC_KEY for %s\n", name);
        goto out;
    }
    sig = ECDSA_do_sign(digest, sizeof(digest), eckey);
    if (sig == NULL) {
        /* error */
        fprintf(stderr, "Failed to sign with %s\n", name);
        goto out;
    }
    ret = ECDSA_do_verify(digest, sizeof(digest), sig, eckey);
    if (ret == -1) {
        /* error */
        fprintf(stderr, "Failed to verify signature with %s\n", name);
        goto out;
    } else if (ret == 0) {
        /* incorrect signature */
        fprintf(stderr, "Signature incorrect with %s\n", name);
        goto out;
    } else {
        /* signature ok */
        ret = 1;
    }
 out:
    if (engine)
        ENGINE_free(engine);
    if (sig)
        ECDSA_SIG_free(sig);
    if (eckey)
        EC_KEY_free(eckey);
    return ret;
}

int main(int argc, char **argv)
{
    static const struct testparams {
        int         nid;
        const char *name;
    } params[] = {
                {NID_X9_62_prime192v1, "NID_X9_62_prime192v1"},
                {NID_secp224r1,        "NID_secp224r1"},
                {NID_X9_62_prime256v1, "NID_X9_62_prime256v1"},
                {NID_secp384r1,        "NID_secp384r1"},
                {NID_secp521r1,        "NID_secp521r1"},
                {NID_brainpoolP160r1,  "NID_brainpoolP160r1"},
                {NID_brainpoolP192r1,  "NID_brainpoolP192r1"},
                {NID_brainpoolP224r1,  "NID_brainpoolP224r1"},
                {NID_brainpoolP256r1,  "NID_brainpoolP256r1"},
                {NID_brainpoolP320r1,  "NID_brainpoolP320r1"},
                {NID_brainpoolP384r1,  "NID_brainpoolP384r1"},
                {NID_brainpoolP512r1,  "NID_brainpoolP512r1"}
    };
            
    int ret = 0, i;
    /* First fix the environment */
    char *testcnf = getenv("IBMCA_OPENSSL_TEST_CONF");

    /* Do not overwrite a user-provided OPENSSL_CONF in the
       environment.  This allows us to execute this test also on an
       installation with a user-provided engine configuration. */
    if (testcnf && setenv("OPENSSL_CONF", testcnf, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_CONF environment variable!\n");
        return 77;
    }
    
    setup();
    for (i = 0; i < sizeof(params) / sizeof(struct testparams); ++i) {
        if (!check_eckey(params[i].nid, params[i].name)) {
            fprintf(stderr, "Failure for %s\n", params[i].name);
            ret = 99;
        }
    }
    return ret;
}
