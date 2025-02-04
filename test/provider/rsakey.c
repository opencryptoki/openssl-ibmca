/*
 * Copyright [2021-2022] International Business Machines Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include <ica_api.h>

#define UNUSED(var)                             ((void)(var))

static void setup(void)
{
    OPENSSL_load_builtin_modules();

    CONF_modules_load_file(NULL, NULL,
                           CONF_MFLAGS_DEFAULT_SECTION|
                           CONF_MFLAGS_IGNORE_MISSING_FILE);
}

static int check_provider(EVP_PKEY_CTX *ctx, const char *expected_provider)
{
    const OSSL_PROVIDER *provider;
    const char *provname;

    if (expected_provider == NULL)
        expected_provider = "default";

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        return 0;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, expected_provider) != 0) {
        fprintf(stderr, "Context is not using the %s provider, but '%s'\n",
                expected_provider, provname);
        return 0;
    }

    return 1;
}

static int set_rsa_pss_keygen_params(EVP_PKEY_CTX *ctx, const char *pss_md,
                                     const char *pss_mgf1_md, int pss_saltlen)
{
    if (pss_md != NULL) {
        if (EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, pss_md, NULL) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_keygen_md_name failed\n");
            return 0;
        }
    }

    if (pss_mgf1_md != NULL) {
        if (EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, pss_mgf1_md) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name failed\n");
            return 0;
        }
    }

    if (pss_saltlen != 0) {
        if (EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, pss_saltlen) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen failed\n");
            return 0;
        }
    }

    return 1;
}

static int set_rsa_pss_params(EVP_PKEY_CTX *ctx, int padding,
                              const char *pss_mgf1_md, int pss_saltlen)
{
    if (padding != 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            return 0;
        }
    }

    if (pss_mgf1_md != NULL) {
        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, pss_mgf1_md, NULL) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            return 0;
        }
    }

    if (pss_saltlen != 0) {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, pss_saltlen) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            return 0;
        }
    }

    return 1;
}

static int generate_key(const char* provider, const char *algo, int bits,
                        const char *pss_md, const char *pss_mgf1_md,
                        int pss_saltlen, const OSSL_PARAM *params,
                        EVP_PKEY **rsa_pkey)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
        goto out;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits failed\n");
        goto out;
    }

    if (!set_rsa_pss_keygen_params(ctx, pss_md, pss_mgf1_md, pss_saltlen))
        goto out;

    if (params != NULL) {
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_params failed\n");
            goto out;
        }
    }

    if (EVP_PKEY_keygen(ctx, rsa_pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed\n");
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

static int sign_single(const char* provider, EVP_PKEY *rsa_pkey,
                       int pss_padding, const char *pss_mgf1_md,
                       int pss_saltlen, const unsigned char *tbs,
                       size_t tbs_len, unsigned char *sig, size_t *sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (!set_rsa_pss_params(ctx, pss_padding, pss_mgf1_md, pss_saltlen))
        goto out;

    if (EVP_PKEY_sign(ctx, sig, sig_len, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign failed\n");
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

static int verify_single(const char* provider, const char *algo,
                         EVP_PKEY *rsa_pkey, int pss_padding,
                         const char *pss_mgf1_md, int pss_saltlen,
                         const unsigned char *tbs, size_t tbs_len,
                         const unsigned char *sig, size_t sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (!set_rsa_pss_params(ctx, pss_padding, pss_mgf1_md, pss_saltlen))
        goto out;

    ok = EVP_PKEY_verify(ctx, sig, sig_len, tbs, tbs_len);
    if (ok == -1) {
        /* error */
        fprintf(stderr, "Failed to verify signature with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Signature incorrect with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Signature correct with %s (%s provider)\n", algo,
                provider != NULL ? provider : "default");
        ok = 1;
    }

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

static int sign_digest(const char* provider, EVP_PKEY *rsa_pkey,
                       const char *md_name, int pss_padding,
                       const char *pss_mgf1_md, int pss_saltlen,
                       const unsigned char *tbs, size_t tbs_len,
                       unsigned char *sig, size_t *sig_len)
{
    char props[200];
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto out;
    }

    if (EVP_DigestSignInit_ex(md_ctx, &ctx, md_name, NULL,
                              props, rsa_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (!set_rsa_pss_params(ctx, pss_padding, pss_mgf1_md, pss_saltlen))
        goto out;

    if (EVP_DigestSignUpdate(md_ctx, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_DigestSignUpdate (1) failed\n");
        goto out;
    }

    if (EVP_DigestSignUpdate(md_ctx, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_DigestSignUpdate (2) failed\n");
        goto out;
    }

    if (EVP_DigestSignFinal(md_ctx, sig, sig_len) <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal failed\n");
        goto out;
    }

    ok = 1;

out:
    if (md_ctx != NULL)
        EVP_MD_CTX_free(md_ctx);

    return ok;
}

static int verify_digest(const char* provider, const char *algo,
                         EVP_PKEY *rsa_pkey, const char *md_name,
                         int pss_padding, const char *pss_mgf1_md,
                         int pss_saltlen, const unsigned char *tbs,
                         size_t tbs_len, unsigned char *sig, size_t sig_len)
{
    char props[200];
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto out;
    }

    if (EVP_DigestVerifyInit_ex(md_ctx, &ctx, md_name, NULL,
                                props, rsa_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (!set_rsa_pss_params(ctx, pss_padding, pss_mgf1_md, pss_saltlen))
        goto out;

    if (EVP_DigestVerifyUpdate(md_ctx, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (1) failed\n");
        goto out;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (2) failed\n");
        goto out;
    }

    ok = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
    if (ok == -1) {
        /* error */
        fprintf(stderr, "Failed to digest-verify signature with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Digest-Signature incorrect with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Digest-Signature correct with %s (%s provider)\n", algo,
                provider != NULL ? provider : "default");
        ok = 1;
    }

out:
    if (md_ctx != NULL)
        EVP_MD_CTX_free(md_ctx);

    return ok;
}

#ifdef EVP_PKEY_OP_SIGNMSG
static int sign_message(const char* provider, EVP_PKEY *rsa_pkey,
                        const char *alg_name, const unsigned char *tbs,
                        size_t tbs_len, unsigned char *sig, size_t *sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    alg = EVP_SIGNATURE_fetch(NULL, alg_name, props);
    if (alg == NULL) {
        fprintf(stderr, "EVP_SIGNATURE_fetch for %s failed\n", alg_name);
        goto out;
    }

    if (EVP_PKEY_sign_message_init(ctx, alg, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (EVP_PKEY_sign_message_update(ctx, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_update (1) failed\n");
        goto out;
    }

    if (EVP_PKEY_sign_message_update(ctx, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_update (2) failed\n");
        goto out;
    }

    if (EVP_PKEY_sign_message_final(ctx, sig, sig_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_final failed\n");
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (alg != NULL)
        EVP_SIGNATURE_free(alg);

    return ok;
}

static int verify_message(const char* provider, const char *algo,
                          EVP_PKEY *rsa_pkey, const char *alg_name,
                          const unsigned char *tbs, size_t tbs_len,
                          unsigned char *sig, size_t sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    alg = EVP_SIGNATURE_fetch(NULL, alg_name, props);
    if (alg == NULL) {
        fprintf(stderr, "EVP_SIGNATURE_fetch for %s failed\n", alg_name);
        goto out;
    }

    if (EVP_PKEY_verify_message_init(ctx, alg, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (EVP_PKEY_CTX_set_signature(ctx, sig, sig_len) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_signature failed\n");
        goto out;
    }

    if (EVP_PKEY_verify_message_update(ctx, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_update (1) failed\n");
        goto out;
    }

    if (EVP_PKEY_verify_message_update(ctx, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_update (2) failed\n");
        goto out;
    }

    ok = EVP_PKEY_verify_message_final(ctx);
    if (ok == -1) {
        /* error */
        fprintf(stderr, "Failed to verify-message signature with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Message-Signature incorrect with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Message-Signature correct with %s (%s provider)\n", algo,
                provider != NULL ? provider : "default");
        ok = 1;
    }

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (alg != NULL)
        EVP_SIGNATURE_free(alg);

    return ok;
}

static int sign_message_single(const char* provider, EVP_PKEY *rsa_pkey,
                               const char *alg_name, const unsigned char *tbs,
                               size_t tbs_len, unsigned char *sig,
                               size_t *sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    alg = EVP_SIGNATURE_fetch(NULL, alg_name, props);
    if (alg == NULL) {
        fprintf(stderr, "EVP_SIGNATURE_fetch for %s failed\n", alg_name);
        goto out;
    }

    if (EVP_PKEY_sign_message_init(ctx, alg, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (EVP_PKEY_sign(ctx, sig, sig_len, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign failed\n");
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (alg != NULL)
        EVP_SIGNATURE_free(alg);

    return ok;
}

static int verify_message_single(const char* provider, const char *algo,
                                 EVP_PKEY *rsa_pkey, const char *alg_name,
                                 const unsigned char *tbs, size_t tbs_len,
                                 unsigned char *sig, size_t sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    alg = EVP_SIGNATURE_fetch(NULL, alg_name, props);
    if (alg == NULL) {
        fprintf(stderr, "EVP_SIGNATURE_fetch for %s failed\n", alg_name);
        goto out;
    }

    if (EVP_PKEY_verify_message_init(ctx, alg, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_message_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;


    ok = EVP_PKEY_verify(ctx, sig, sig_len, tbs, tbs_len);
    if (ok == -1) {
        /* error */
        fprintf(stderr, "Failed to verify-message-single signature with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Message-Signature single incorrect with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Message-Signature single correct with %s (%s provider)\n", algo,
                provider != NULL ? provider : "default");
        ok = 1;
    }

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (alg != NULL)
        EVP_SIGNATURE_free(alg);

    return ok;
}

static int sign_message_prehashed(const char* provider, EVP_PKEY *rsa_pkey,
                                  const char *alg_name,
                                  const unsigned char *tbs, size_t tbs_len,
                                  unsigned char *sig, size_t *sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    alg = EVP_SIGNATURE_fetch(NULL, alg_name, props);
    if (alg == NULL) {
        fprintf(stderr, "EVP_SIGNATURE_fetch for %s failed\n", alg_name);
        goto out;
    }

    if (EVP_PKEY_sign_init_ex2(ctx, alg, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_init_ex2 failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (EVP_PKEY_sign(ctx, sig, sig_len, tbs, tbs_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign failed\n");
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (alg != NULL)
        EVP_SIGNATURE_free(alg);

    return ok;
}

static int verify_message_prehashed(const char* provider, const char *algo,
                                    EVP_PKEY *rsa_pkey, const char *alg_name,
                                    const unsigned char *tbs, size_t tbs_len,
                                    unsigned char *sig, size_t sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    alg = EVP_SIGNATURE_fetch(NULL, alg_name, props);
    if (alg == NULL) {
        fprintf(stderr, "EVP_SIGNATURE_fetch for %s failed\n", alg_name);
        goto out;
    }

    if (EVP_PKEY_verify_init_ex2(ctx, alg, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_init_ex2 failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;


    ok = EVP_PKEY_verify(ctx, sig, sig_len, tbs, tbs_len);
    if (ok == -1) {
        /* error */
        fprintf(stderr, "Failed to verify-message-prehashed signature with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Message-Signature prehashed incorrect with %s (%s provider)\n",
                algo, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Message-Signature prehashed correct with %s (%s provider)\n", algo,
                provider != NULL ? provider : "default");
        ok = 1;
    }

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (alg != NULL)
        EVP_SIGNATURE_free(alg);

    return ok;
}
#endif

static int check_rsakey(int bits, const char *algo, const char *name)
{
    int            ok = 0;
    size_t         siglen;
    unsigned char  sigbuf[1024];
    EVP_PKEY       *rsa_pkey = NULL;
    unsigned char  digest[32];
    const char *pss_md = NULL;
    const char *pss_mgf1_md = NULL;
    int pss_saltlen = 0;
    int pss_padding = 0;

    memset(digest, 0, sizeof(digest));

    if (strcmp(algo, "RSA-PSS") == 0) {
        pss_md = "SHA256";
        pss_mgf1_md = "SHA256";
        pss_saltlen = 24;
        pss_padding = RSA_PKCS1_PSS_PADDING;
    }

    /* Keygen with IBMCA provider */
    if (!generate_key("ibmca", algo, bits, pss_md, pss_mgf1_md, pss_saltlen,
                      NULL, &rsa_pkey))
        goto out;

    /* Sign with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_single("ibmca", rsa_pkey, pss_padding, pss_mgf1_md, pss_saltlen,
                     digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* Verify with default provider */
    if (!verify_single(NULL, name, rsa_pkey, pss_padding, pss_mgf1_md, pss_saltlen,
                     digest, sizeof(digest), sigbuf, siglen))
        goto out;


    /* Verify with IBMCA provider */
    if (!verify_single("ibmca", name, rsa_pkey, pss_padding, pss_mgf1_md, pss_saltlen,
                     digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Digest-Sign with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_digest("ibmca", rsa_pkey, "SHA256",
                     pss_padding, pss_mgf1_md, pss_saltlen,
                     digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* Digest-Verify with default provider */
    if (!verify_digest(NULL, name, rsa_pkey, "SHA256",
                       pss_padding, pss_mgf1_md, pss_saltlen,
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Digest-Verify with IBMCA provider */
    if (!verify_digest("ibmca", name, rsa_pkey, "SHA256",
                       pss_padding, pss_mgf1_md, pss_saltlen,
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Digest-Sign with default provider */
    siglen = sizeof(sigbuf);
    if (!sign_digest(NULL, rsa_pkey, "SHA256",
                     pss_padding, pss_mgf1_md, pss_saltlen,
                     digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* Digest-Verify with default provider */
    if (!verify_digest(NULL, name, rsa_pkey, "SHA256",
                       pss_padding, pss_mgf1_md, pss_saltlen,
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Digest-Verify with IBMCA provider */
    if (!verify_digest("ibmca", name, rsa_pkey, "SHA256",
                       pss_padding, pss_mgf1_md, pss_saltlen,
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

#ifdef EVP_PKEY_OP_SIGNMSG
    if (strcmp(algo, "RSA-PSS") == 0)
        goto skip;

    /* SignMessage with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_message("ibmca", rsa_pkey, "RSA-SHA256",
                      digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* VerifyMessage with default provider */
    if (!verify_message(NULL, name, rsa_pkey, "RSA-SHA256",
                        digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* VerifyMessage with IBMCA provider */
    if (!verify_message("ibmca", name, rsa_pkey, "RSA-SHA256",
                        digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* SignMessage one-shot with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_message_single("ibmca", rsa_pkey, "RSA-SHA256",
                             digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* VerifyMessage one-shot with default provider */
    if (!verify_message_single(NULL, name, rsa_pkey, "RSA-SHA256",
                               digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* VerifyMessage one-shot with IBMCA provider */
    if (!verify_message_single("ibmca", name, rsa_pkey, "RSA-SHA256",
                               digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Sign pre-hashed message with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_message_prehashed("ibmca", rsa_pkey, "RSA-SHA256",
                                digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* Verify pre-hashed message with default provider */
    if (!verify_message_prehashed(NULL, name, rsa_pkey, "RSA-SHA256",
                                  digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Verify pre-hashed message with IBMCA provider */
    if (!verify_message_prehashed("ibmca", name, rsa_pkey, "RSA-SHA256",
                                  digest, sizeof(digest), sigbuf, siglen))
        goto out;

skip:
#endif

    ok = 1;

 out:
    if (rsa_pkey)
       EVP_PKEY_free(rsa_pkey);

    ERR_print_errors_fp(stderr);

    return ok;
}

static const unsigned int required_ica_mechs[] = { RSA_ME,  RSA_CRT };
static const unsigned int required_ica_mechs_len =
                        sizeof(required_ica_mechs) / sizeof(unsigned int);

typedef unsigned int (*ica_get_functionlist_t)(libica_func_list_element *,
                                               unsigned int *);

static int check_libica()
{
    unsigned int mech_len, i, k, found = 0;
    libica_func_list_element *mech_list = NULL;
    void *ibmca_dso;
    ica_get_functionlist_t p_ica_get_functionlist;
    int rc;

    ibmca_dso = dlopen(LIBICA_NAME, RTLD_NOW);
    if (ibmca_dso == NULL) {
        fprintf(stderr, "Failed to load libica '%s'!\n", LIBICA_NAME);
        return 77;
    }

    p_ica_get_functionlist =
            (ica_get_functionlist_t)dlsym(ibmca_dso, "ica_get_functionlist");
    if (p_ica_get_functionlist == NULL) {
        fprintf(stderr, "Failed to get ica_get_functionlist from '%s'!\n",
                LIBICA_NAME);
        return 77;
    }

    rc = p_ica_get_functionlist(NULL, &mech_len);
    if (rc != 0) {
        fprintf(stderr, "Failed to get function list from libica!\n");
        return 77;
    }

    mech_list = calloc(sizeof(libica_func_list_element), mech_len);
    if (mech_list == NULL) {
        fprintf(stderr, "Failed to allocate memory for function list!\n");
        return 77;
    }

    rc = p_ica_get_functionlist(mech_list, &mech_len);
    if (rc != 0) {
        fprintf(stderr, "Failed to get function list from libica!\n");
        free(mech_list);
        return 77;
    }

    for (i = 0; i < mech_len; i++) {
        for (k = 0; k < required_ica_mechs_len; k++) {
            if (mech_list[i].mech_mode_id == required_ica_mechs[k]) {
                if (mech_list[i].flags &
                    (ICA_FLAG_SW | ICA_FLAG_SHW | ICA_FLAG_DHW))
                    found++;
            }
        }
    }

    free(mech_list);

    if (found < required_ica_mechs_len) {
        fprintf(stderr,
               "Libica does not support the required algorithms, skipping.\n");
        return 77;
    }

    return 0;
}

int main(int argc, char **argv)
{
    static const struct testparams {
        int         bits;
        const char *algo;
        const char *name;
    } params[] = {
                {512, "RSA", "RSA-512"},
                {1024, "RSA", "RSA-1024"},
                {2048, "RSA", "RSA-2048"},
                {4096, "RSA", "RSA-4096"},
                {512, "RSA-PSS", "RSA-PSS-512"},
                {1024, "RSA-PSS", "RSA-PSS-1024"},
                {2048, "RSA-PSS", "RSA-PSS-2048"},
                {4096, "RSA-PSS", "RSA-PSS-4096"},
    };

    UNUSED(argc);
    UNUSED(argv);

    int ret = 0, i;
    /* First fix the environment */
    char *testcnf = getenv("IBMCA_OPENSSL_TEST_CONF");
    char *testpath = getenv("IBMCA_TEST_PATH");

    /* Do not overwrite a user-provided OPENSSL_CONF in the
       environment.  This allows us to execute this test also on an
       installation with a user-provided engine configuration. */
    if (testcnf && setenv("OPENSSL_CONF", testcnf, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_CONF environment variable!\n");
        return 77;
    }
    
    if (testpath && setenv("OPENSSL_MODULES", testpath, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_MODULES environment variable!\n");
        return 77;
    }

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    ret = check_libica();
    if (ret != 0)
        return ret;

    setup();
    for (i = 0; i < (int)(sizeof(params) / sizeof(struct testparams)); ++i) {
        if (!check_rsakey(params[i].bits, params[i].algo, params[i].name)) {
            fprintf(stderr, "Failure for %s\n", params[i].name);
            ret = 99;
        }
    }
    return ret;
}
