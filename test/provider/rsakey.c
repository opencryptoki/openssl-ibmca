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
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

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

/*
 * Verify that the private exponent d of a key is correct: e * d = 1 mod (p-1)
 * and mod (q-1) (thus also mod lcm(p-1, q-1)), and 0 < d < phi(n).
 */
static int check_private_exponent(EVP_PKEY *rsa_pkey)
{
    BIGNUM *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *p1 = NULL, *q1 = NULL, *t = NULL;
    BN_CTX *bn_ctx = NULL;
    int ok = 0;

    if (EVP_PKEY_get_bn_param(rsa_pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1 ||
        EVP_PKEY_get_bn_param(rsa_pkey, OSSL_PKEY_PARAM_RSA_D, &d) != 1 ||
        EVP_PKEY_get_bn_param(rsa_pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) != 1 ||
        EVP_PKEY_get_bn_param(rsa_pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) != 1) {
        fprintf(stderr, "EVP_PKEY_get_bn_param failed\n");
        goto out;
    }

    bn_ctx = BN_CTX_new();
    p1 = BN_dup(p);
    q1 = BN_dup(q);
    t = BN_new();
    if (bn_ctx == NULL || p1 == NULL || q1 == NULL || t == NULL ||
        !BN_sub_word(p1, 1) || !BN_sub_word(q1, 1)) {
        fprintf(stderr, "BN allocation failed\n");
        goto out;
    }

    if (!BN_mod_mul(t, e, d, p1, bn_ctx) || !BN_is_one(t) ||
        !BN_mod_mul(t, e, d, q1, bn_ctx) || !BN_is_one(t)) {
        fprintf(stderr, "d is not the inverse of e\n");
        goto out;
    }

    /* phi(n) = (p-1)(q-1) */
    if (!BN_mul(t, p1, q1, bn_ctx)) {
        fprintf(stderr, "BN_mul failed\n");
        goto out;
    }
    if (BN_is_zero(d) || BN_is_negative(d) || BN_cmp(d, t) >= 0) {
        fprintf(stderr, "d is not in the range (0, phi(n))\n");
        goto out;
    }

    ok = 1;

out:
    BN_free(e);
    BN_clear_free(d);
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(p1);
    BN_clear_free(q1);
    BN_free(t);
    BN_CTX_free(bn_ctx);

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

#ifdef OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ
static int export_import_key_from_pq(const char* provider, EVP_PKEY *rsa_pkey)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM *export_params = NULL;
    OSSL_PARAM import_params[7];
    OSSL_PARAM *export_params2 = NULL;
    EVP_PKEY *rsa_pkey2 = NULL;
    int ok = 0, i, k, derive_from_pq = 1;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
        goto out;
    }

    if (EVP_PKEY_todata(rsa_pkey, EVP_PKEY_KEYPAIR, &export_params) != 1) {
        fprintf(stderr, "EVP_PKEY_todata failed\n");
        goto out;
    }

    for (i = 0, k = 0; export_params[i].key != NULL && k < 5; i++) {
        if (strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_N) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_E) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_D) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_FACTOR1) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_FACTOR2) == 0) {
            import_params[k] = export_params[i];
            k++;
        }
    }
    import_params[k++] =
            OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ,
                                     &derive_from_pq);
    import_params[k++] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_fromdata_init failed\n");
        goto out;
    }

    if (EVP_PKEY_fromdata(ctx, &rsa_pkey2, EVP_PKEY_KEYPAIR,
                          import_params) != 1) {
        fprintf(stderr, "EVP_PKEY_fromdata failed\n");
        goto out;
    }

    /*
     * Export the new key again to compare the key components. EVP_PKEY_eq()
     * would only compare the public key components, but not the private
     * components.
     */
    if (EVP_PKEY_todata(rsa_pkey2, EVP_PKEY_KEYPAIR, &export_params2) != 1) {
        fprintf(stderr, "EVP_PKEY_todata failed\n");
        goto out;
    }

    ok = 1;

    for (i = 0; export_params[i].key != NULL; i++) {
        for (k = 0; export_params2[k].key != NULL; k++) {
            if (strcmp(export_params[i].key, export_params2[k].key) == 0) {
                if (export_params[i].data_size != export_params2[k].data_size ||
                    memcmp(export_params[i].data, export_params2[k].data,
                           export_params[i].data_size) != 0) {
                    fprintf(stderr, "Key component '%s' is different\n",
                            export_params[i].key);
                    ok = 0;
                }
                break;
            }
        }
    }

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (export_params != NULL)
        OSSL_PARAM_free(export_params);
    if (export_params2 != NULL)
        OSSL_PARAM_free(export_params2);
    if (rsa_pkey2 != NULL)
        EVP_PKEY_free(rsa_pkey2);

    return ok;
}
#endif

#ifdef OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION
static int decrypt_implicit_rejection(const char *provider, EVP_PKEY *rsa_pkey,
                                      const unsigned char *in, size_t inlen,
                                      unsigned char *out, size_t *outlen)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned int implicit_rejection = 1;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
        goto out;
    }

    params[0] = OSSL_PARAM_construct_uint(
                                OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION,
                                &implicit_rejection);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(ctx, params) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_params failed\n");
        goto out;
    }

    if (EVP_PKEY_decrypt(ctx, out, outlen, in, inlen) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt failed\n");
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

#ifdef OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ
/*
 * Import only n, e, p and q (no d, no CRT components) with DERIVE_FROM_PQ into
 * the IBMCA provider.
 */
static int import_key_from_pq_only(EVP_PKEY *rsa_pkey, EVP_PKEY **new_pkey)
{
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM *export_params = NULL;
    OSSL_PARAM import_params[6];
    int ok = 0, i, k, derive_from_pq = 1;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
        goto out;
    }

    if (EVP_PKEY_todata(rsa_pkey, EVP_PKEY_KEYPAIR, &export_params) != 1) {
        fprintf(stderr, "EVP_PKEY_todata failed\n");
        goto out;
    }

    for (i = 0, k = 0; export_params[i].key != NULL && k < 4; i++) {
        if (strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_N) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_E) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_FACTOR1) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_FACTOR2) == 0) {
            import_params[k] = export_params[i];
            k++;
        }
    }
    import_params[k++] =
            OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ,
                                     &derive_from_pq);
    import_params[k++] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, new_pkey, EVP_PKEY_KEYPAIR,
                          import_params) != 1) {
        fprintf(stderr, "EVP_PKEY_fromdata failed\n");
        goto out;
    }

    ok = 1;

out:
    if (export_params != NULL)
        OSSL_PARAM_free(export_params);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}
#endif

/*
 * Decrypt (nearly certainly) invalid PKCS#1 v1.5 ciphertexts with implicit
 * rejection. In this case, a pseudo-random message is returned that is derived
 * from the private exponent d of the key. The result is thus the same for
 * all providers and for all copies of the key, only if they all use the
 * correct d.
 *
 * Use the default provider as reference and compare it with the IBMCA
 * provider using the original key, a duplicate of the key, and a key that was
 * imported with only n, e, p and q (thus has no d imported).
 */
static int check_implicit_rejection(EVP_PKEY *rsa_pkey)
{
    EVP_PKEY *pkey_dup = NULL, *pkey_pq = NULL;
    unsigned char in[1024], ref[1024], out[1024];
    size_t keylen, inlen, reflen, outlen;
    int ok = 0, i;
    size_t k;

    keylen = EVP_PKEY_get_size(rsa_pkey);
    if (keylen < 11 + 8 || keylen > sizeof(in)) {
        fprintf(stderr, "Unexpected key size %lu\n", (unsigned long)keylen);
        goto out;
    }

    pkey_dup = EVP_PKEY_dup(rsa_pkey);
    if (pkey_dup == NULL) {
        fprintf(stderr, "EVP_PKEY_dup failed\n");
        goto out;
    }

#ifdef OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ
    if (!import_key_from_pq_only(rsa_pkey, &pkey_pq))
        goto out;
#endif

    for (i = 0; i < 3; i++) {
        /* Deterministic ciphertext, always smaller than the modulus */
        inlen = keylen;
        in[0] = 0;
        for (k = 1; k < inlen; k++)
            in[k] = (unsigned char)(k * 131 + i * 17 + 7);

        reflen = sizeof(ref);
        if (!decrypt_implicit_rejection(NULL, rsa_pkey, in, inlen,
                                        ref, &reflen))
            goto out;

        outlen = sizeof(out);
        if (!decrypt_implicit_rejection("ibmca", rsa_pkey, in, inlen,
                                        out, &outlen))
            goto out;
        if (outlen != reflen || memcmp(out, ref, reflen) != 0) {
            fprintf(stderr, "Implicit rejection result differs for the "
                    "original key (ciphertext %d)\n", i);
            goto out;
        }

        outlen = sizeof(out);
        if (!decrypt_implicit_rejection("ibmca", pkey_dup, in, inlen,
                                        out, &outlen))
            goto out;
        if (outlen != reflen || memcmp(out, ref, reflen) != 0) {
            fprintf(stderr, "Implicit rejection result differs for the "
                    "duplicated key (ciphertext %d)\n", i);
            goto out;
        }

        if (pkey_pq != NULL) {
            outlen = sizeof(out);
            if (!decrypt_implicit_rejection("ibmca", pkey_pq, in, inlen,
                                            out, &outlen))
                goto out;
            if (outlen != reflen || memcmp(out, ref, reflen) != 0) {
                fprintf(stderr, "Implicit rejection result differs for the "
                        "key imported from p and q (ciphertext %d)\n", i);
                goto out;
            }
        }
    }

    ok = 1;

out:
    if (pkey_dup != NULL)
        EVP_PKEY_free(pkey_dup);
    if (pkey_pq != NULL)
        EVP_PKEY_free(pkey_pq);

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

    /* Check the private exponent d of the generated key */
    if (!check_private_exponent(rsa_pkey))
        goto out;
    printf("Private exponent d correct with %s (ibmca provider)\n", name);

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

#ifdef OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ
    if (!export_import_key_from_pq("ibmca", rsa_pkey))
        goto out;

    if (!export_import_key_from_pq(NULL, rsa_pkey))
        goto out;
#endif

#ifdef OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION
    /* RSA-PSS keys can not be used for encryption/decryption */
    if (strcmp(algo, "RSA") == 0) {
        if (!check_implicit_rejection(rsa_pkey))
            goto out;
        printf("Implicit rejection correct with %s (ibmca provider)\n", name);
    }
#endif

    ok = 1;

 out:
    if (rsa_pkey)
       EVP_PKEY_free(rsa_pkey);

    ERR_print_errors_fp(stderr);

    return ok;
}

#ifdef OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ
/*
 * Import only n, e, p and q (no d, no CRT components) with DERIVE_FROM_PQ into
 * the IBMCA provider, and verify that the derived private key components are
 * correct: d, dP and dQ must be inverses of e modulo phi(n), p-1 and q-1, and
 * qInv must be the inverse of q modulo p.
 */
static int import_from_pq_check_components(EVP_PKEY *rsa_pkey)
{
    char props[] = "?provider=ibmca";
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM *export_params = NULL;
    OSSL_PARAM import_params[6];
    EVP_PKEY *pkey2 = NULL;
    BIGNUM *e = NULL, *d = NULL, *p = NULL, *q = NULL, *dp = NULL, *dq = NULL;
    BIGNUM *qinv = NULL, *p1 = NULL, *q1 = NULL, *t = NULL;
    BN_CTX *bn_ctx = NULL;
    int ok = 0, i, k, derive_from_pq = 1;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
        goto out;
    }

    if (EVP_PKEY_todata(rsa_pkey, EVP_PKEY_KEYPAIR, &export_params) != 1) {
        fprintf(stderr, "EVP_PKEY_todata failed\n");
        goto out;
    }

    for (i = 0, k = 0; export_params[i].key != NULL && k < 4; i++) {
        if (strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_N) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_E) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_FACTOR1) == 0 ||
            strcmp(export_params[i].key, OSSL_PKEY_PARAM_RSA_FACTOR2) == 0) {
            import_params[k] = export_params[i];
            k++;
        }
    }
    import_params[k++] =
            OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ,
                                     &derive_from_pq);
    import_params[k++] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey2, EVP_PKEY_KEYPAIR, import_params) != 1) {
        fprintf(stderr, "EVP_PKEY_fromdata failed\n");
        goto out;
    }

    if (EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_E, &e) != 1 ||
        EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_D, &d) != 1 ||
        EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) != 1 ||
        EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) != 1 ||
        EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dp) != 1 ||
        EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dq) != 1 ||
        EVP_PKEY_get_bn_param(pkey2, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                              &qinv) != 1) {
        fprintf(stderr, "EVP_PKEY_get_bn_param failed\n");
        goto out;
    }

    bn_ctx = BN_CTX_new();
    p1 = BN_dup(p);
    q1 = BN_dup(q);
    t = BN_new();
    if (bn_ctx == NULL || p1 == NULL || q1 == NULL || t == NULL ||
        !BN_sub_word(p1, 1) || !BN_sub_word(q1, 1)) {
        fprintf(stderr, "BN allocation failed\n");
        goto out;
    }

    /* e * dP = 1 mod (p-1), e * dQ = 1 mod (q-1) */
    if (!BN_mod_mul(t, e, dp, p1, bn_ctx) || !BN_is_one(t)) {
        fprintf(stderr, "dP is not the inverse of e mod (p-1)\n");
        goto out;
    }
    if (!BN_mod_mul(t, e, dq, q1, bn_ctx) || !BN_is_one(t)) {
        fprintf(stderr, "dQ is not the inverse of e mod (q-1)\n");
        goto out;
    }

    /* e * d = 1 mod (p-1) and mod (q-1), thus also mod lcm(p-1, q-1) */
    if (!BN_mod_mul(t, e, d, p1, bn_ctx) || !BN_is_one(t) ||
        !BN_mod_mul(t, e, d, q1, bn_ctx) || !BN_is_one(t)) {
        fprintf(stderr, "d is not the inverse of e\n");
        goto out;
    }

    /* qInv * q = 1 mod p */
    if (!BN_mod_mul(t, qinv, q, p, bn_ctx) || !BN_is_one(t)) {
        fprintf(stderr, "qInv is not the inverse of q mod p\n");
        goto out;
    }

    /* The components must also be properly reduced: 0 < x < modulus */
    if (BN_is_zero(dp) || BN_is_negative(dp) || BN_cmp(dp, p1) >= 0) {
        fprintf(stderr, "dP is not in the range (0, p-1)\n");
        goto out;
    }
    if (BN_is_zero(dq) || BN_is_negative(dq) || BN_cmp(dq, q1) >= 0) {
        fprintf(stderr, "dQ is not in the range (0, q-1)\n");
        goto out;
    }
    if (BN_is_zero(qinv) || BN_is_negative(qinv) || BN_cmp(qinv, p) >= 0) {
        fprintf(stderr, "qInv is not in the range (0, p)\n");
        goto out;
    }
    /* d = e^-1 mod phi(n), phi(n) = (p-1)(q-1) */
    if (!BN_mul(t, p1, q1, bn_ctx)) {
        fprintf(stderr, "BN_mul failed\n");
        goto out;
    }
    if (BN_is_zero(d) || BN_is_negative(d) || BN_cmp(d, t) >= 0) {
        fprintf(stderr, "d is not in the range (0, phi(n))\n");
        goto out;
    }

    ok = 1;

out:
    BN_free(e);
    BN_clear_free(d);
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(dp);
    BN_clear_free(dq);
    BN_clear_free(qinv);
    BN_clear_free(p1);
    BN_clear_free(q1);
    BN_free(t);
    BN_CTX_free(bn_ctx);
    if (export_params != NULL)
        OSSL_PARAM_free(export_params);
    if (pkey2 != NULL)
        EVP_PKEY_free(pkey2);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

/*
 * Generate a key with a non-default public exponent using the default
 * provider, and derive the private key components from p and q in the IBMCA
 * provider. This covers the single-word prime, single-word composite and
 * multi-word public exponent branches of the CRT derivation.
 *
 * Returns 1 on success, 0 on failure, and -1 if the subtest was skipped
 * because the default provider could not generate a key with this exponent.
 */
static int check_rsakey_pub_exp(int bits, const char *e_hex)
{
    BIGNUM *e = NULL;
    EVP_PKEY *rsa_pkey = NULL;
    unsigned char e_buf[16];
    OSSL_PARAM params[2];
    int ok = 0;

    if (BN_hex2bn(&e, e_hex) == 0 ||
        BN_bn2nativepad(e, e_buf, sizeof(e_buf)) < 0) {
        fprintf(stderr, "Failed to convert public exponent\n");
        goto out;
    }

    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, e_buf,
                                        sizeof(e_buf));
    params[1] = OSSL_PARAM_construct_end();

    if (!generate_key(NULL, "RSA", bits, NULL, NULL, 0, params, &rsa_pkey)) {
        /* The default provider may not support this exponent */
        fprintf(stderr, "Skipping public exponent 0x%s: keygen failed\n",
                e_hex);
        ERR_clear_error();
        ok = -1;
        goto out;
    }

    if (!export_import_key_from_pq("ibmca", rsa_pkey))
        goto out;

    if (!import_from_pq_check_components(rsa_pkey))
        goto out;

    printf("Key components derived from p and q correct for e=0x%s "
           "(ibmca provider)\n", e_hex);
    ok = 1;

out:
    BN_free(e);
    if (rsa_pkey != NULL)
        EVP_PKEY_free(rsa_pkey);

    ERR_print_errors_fp(stderr);

    return ok;
}
#endif

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

#ifdef OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ
    {
        /* 3, 17, 65537 (prime), 15, 4097 (composite), 65-bit (multi-word) */
        static const char *pub_exps[] = {
            "3", "11", "10001", "0F", "1001", "1000000000000000D"
        };
        int num_exps = (int)(sizeof(pub_exps) / sizeof(pub_exps[0]));
        int rc, skipped = 0;

        for (i = 0; i < num_exps; ++i) {
            rc = check_rsakey_pub_exp(1024, pub_exps[i]);
            if (rc == 0) {
                fprintf(stderr, "Failure for public exponent 0x%s\n",
                        pub_exps[i]);
                ret = 99;
            } else if (rc < 0) {
                skipped++;
            }
        }

        if (skipped > 0)
            fprintf(stderr, "WARNING: %d of %d public exponent subtests were "
                    "skipped\n", skipped, num_exps);
        if (skipped == num_exps) {
            fprintf(stderr, "Failure: no public exponent subtest was run\n");
            ret = 99;
        }
    }
#endif

    return ret;
}
