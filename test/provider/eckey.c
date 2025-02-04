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
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
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

static int generate_key(const char* provider, int nid, const char *curvename,
                        const OSSL_PARAM *params, EVP_PKEY *template,
                        EVP_PKEY **ec_pkey)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    if (template != NULL) {
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, template, props);
        if (ctx == NULL) {
            fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
            goto out;
        }
    } else {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", props);
        if (ctx == NULL) {
            fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
            goto out;
        }
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (template == NULL) {
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
            if (ERR_GET_REASON(ERR_peek_last_error()) == 7) {
                /* curve not supported => test passed */
                fprintf(stderr, "Curve %s not supported by OpenSSL\n", curvename);
                ok = 1;
            } else {
                fprintf(stderr, "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed\n");
            }
            goto out;
        }
    }

    if (params != NULL) {
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_params failed\n");
            goto out;
        }
    }

    if (EVP_PKEY_keygen(ctx, ec_pkey) <= 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == 7) {
            /* curve not supported => test passed */
            fprintf(stderr, "Curve %s not supported by OpenSSL\n", curvename);
            ok = 1;
        } else {
            fprintf(stderr, "EVP_PKEY_keygen failed\n");
        }
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

static int sign_single(const char* provider, EVP_PKEY *ec_pkey,
                       const unsigned char *tbs, size_t tbs_len,
                       unsigned char *sig, size_t *sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
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

static int verify_single(const char* provider, const char *curvename,
                         EVP_PKEY *ec_pkey, const unsigned char *tbs,
                         size_t tbs_len, const unsigned char *sig,
                         size_t sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
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

    ok = EVP_PKEY_verify(ctx, sig, sig_len, tbs, tbs_len);
    if (ok == -1) {
        /* error */
        fprintf(stderr, "Failed to verify signature with %s (%s provider)\n",
                curvename, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Signature incorrect with %s (%s provider)\n",
                curvename, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Signature correct with %s (%s provider)\n", curvename,
                provider != NULL ? provider : "default");
        ok = 1;
    }

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

static int sign_digest(const char* provider, EVP_PKEY *ec_pkey,
                       const char *md_name, const OSSL_PARAM *params,
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
                              props, ec_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (params != NULL) {
        if (EVP_PKEY_CTX_set_params(ctx, params) == 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_params failed\n");
            goto out;
        }
    }

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

static int verify_digest(const char* provider, const char *curvename,
                         EVP_PKEY *ec_pkey, const char *md_name,
                         const unsigned char *tbs, size_t tbs_len,
                         unsigned char *sig, size_t sig_len)
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
                                props, ec_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
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
                curvename, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Digest-Signature incorrect with %s (%s provider)\n",
                curvename, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Digest-Signature correct with %s (%s provider)\n", curvename,
                provider != NULL ? provider : "default");
        ok = 1;
    }

out:
    if (md_ctx != NULL)
        EVP_MD_CTX_free(md_ctx);

    return ok;
}

#ifdef EVP_PKEY_OP_SIGNMSG
static int sign_message(const char* provider, EVP_PKEY *ec_pkey,
                        const char *alg_name, const unsigned char *tbs,
                        size_t tbs_len, unsigned char *sig, size_t *sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
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
        ctx = NULL;
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

static int verify_message(const char* provider, const char *curvename,
                          EVP_PKEY *ec_pkey, const char *alg_name,
                          const unsigned char *tbs, size_t tbs_len,
                          unsigned char *sig, size_t sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
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
                curvename, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Message-Signature incorrect with %s (%s provider)\n",
                curvename, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Message-Signature correct with %s (%s provider)\n", curvename,
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

static int sign_message_single(const char* provider, EVP_PKEY *ec_pkey,
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

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
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

static int verify_message_single(const char* provider, const char *curvename,
                                 EVP_PKEY *ec_pkey, const char *alg_name,
                                 const unsigned char *tbs, size_t tbs_len,
                                 unsigned char *sig, size_t sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
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
                curvename, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Message-Signature single incorrect with %s (%s provider)\n",
                curvename, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Message-Signature single correct with %s (%s provider)\n", curvename,
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

static int sign_message_prehashed(const char* provider, EVP_PKEY *ec_pkey,
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

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
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

static int verify_message_prehashed(const char* provider, const char *curvename,
                                    EVP_PKEY *ec_pkey, const char *alg_name,
                                    const unsigned char *tbs, size_t tbs_len,
                                    unsigned char *sig, size_t sig_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
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
                curvename, provider != NULL ? provider : "default");
        ok = 0;
        goto out;
    } else if (ok == 0) {
        /* incorrect signature */
        fprintf(stderr, "Message-Signature prehashed incorrect with %s (%s provider)\n",
                curvename, provider != NULL ? provider : "default");
        goto out;
    } else {
        /* signature ok */
        printf("Message-Signature prehashed correct with %s (%s provider)\n", curvename,
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

static int derive_key(const char* provider, EVP_PKEY *ec_pkey,
                      EVP_PKEY *peer_pkey, int kdf, const char *kdf_md,
                      size_t kdf_outlen, unsigned char *derived_key,
                      size_t *derived_key_len)
{
    char props[200];
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    sprintf(props, "%sprovider=%s", provider != NULL ? "?" : "",
            provider != NULL ? provider : "default");

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, props);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed\n");
        goto out;
    }

    if (!check_provider(ctx, provider))
        goto out;

    if (kdf != 0 && kdf_md != NULL && kdf_outlen != 0) {
        if (EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, kdf) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_type failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_ecdh_kdf_md(ctx,
                                         EVP_get_digestbyname(kdf_md)) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_md failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, kdf_outlen) != 1) {
            fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_outlen failed\n");
            goto out;
        }
    }

    if (EVP_PKEY_derive_set_peer_ex(ctx, peer_pkey, 1) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer_ex failed\n");
        goto out;
    }

    if (EVP_PKEY_derive(ctx, derived_key, derived_key_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed\n");
        goto out;
    }

    ok = 1;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ok;
}

static int check_eckey(int nid, const char *curvename)
{
    int            ok = 0;
    size_t         siglen;
    unsigned char  sigbuf[1024];
    EVP_PKEY      *ec_pkey = NULL;
    EVP_PKEY      *peer_pkey = NULL;
    size_t         keylen1, keylen2;
    unsigned char  keybuf1[512], keybuf2[512];
    unsigned char  digest[32];
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    size_t         siglen2;
    unsigned char  sigbuf2[1024];
    OSSL_PARAM params[2];
    unsigned int   nonce_type;
#endif
#ifdef OSSL_PKEY_PARAM_DHKEM_IKM
    EVP_PKEY      *ec_pkey1 = NULL, *ec_pkey2 = NULL;
    const char     dhkem_ikm[100] = { 0 };
#endif

    memset(digest, 0, sizeof(digest));

    /* Keygen with IBMCA provider */
    if (!generate_key("ibmca", nid, curvename, NULL, NULL, &ec_pkey))
        goto out;
    if (ec_pkey == NULL) {
        ok = 1; /* Curve not supported, skip */
        goto out;
    }

#ifdef OSSL_PKEY_PARAM_DHKEM_IKM
    /* Test DHKEM keygen */
    switch (nid) {
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
    case NID_secp521r1:
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM,
                                                      (void *)dhkem_ikm,
                                                      sizeof(dhkem_ikm));
        params[1] = OSSL_PARAM_construct_end();

        /* Keygen using DHKEM with IBMCA provider */
        if (!generate_key("ibmca", nid, curvename, params, NULL, &ec_pkey1))
            goto out;

        /* Keygen using DHKEM with default provider */
        if (!generate_key(NULL, nid, curvename, params, NULL, &ec_pkey2))
            goto out;

        /* Compare key from IBMCA with key from default provider */
        if (!EVP_PKEY_eq(ec_pkey1, ec_pkey2)) {
            fprintf(stderr, "EC keys generated via DHKEM do not match\n");
            ok = 1;
            goto out;
        }

        EVP_PKEY_free(ec_pkey1);
        ec_pkey1 = NULL;
        EVP_PKEY_free(ec_pkey2);
        ec_pkey2 = NULL;
        break;
    }
#endif

    /* Sign with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_single("ibmca", ec_pkey, digest, sizeof(digest),
                     sigbuf, &siglen))
        goto out;

    /* Verify with default provider */
    if (!verify_single(NULL, curvename, ec_pkey,
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Verify with IBMCA provider */
    if (!verify_single("ibmca", curvename, ec_pkey,
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;


    /* Digest-Sign with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_digest("ibmca", ec_pkey, "SHA256", NULL,
                     digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* Digest-Verify with default provider */
    if (!verify_digest(NULL, curvename, ec_pkey, "SHA256",
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Digest-Verify with IBMCA provider */
    if (!verify_digest("ibmca", curvename, ec_pkey, "SHA256",
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Digest-Sign with default provider */
    siglen = sizeof(sigbuf);
    if (!sign_digest(NULL, ec_pkey, "SHA256", NULL,
                     digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* Digest-Verify with default provider */
    if (!verify_digest(NULL, curvename, ec_pkey, "SHA256",
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Digest-Verify with IBMCA provider */
    if (!verify_digest("ibmca", curvename, ec_pkey, "SHA256",
                       digest, sizeof(digest), sigbuf, siglen))
        goto out;

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    nonce_type = 1;
    params[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE,
                                          &nonce_type);
    params[1] = OSSL_PARAM_construct_end();

    /* Digest-Sign using deterministic signature with default provider */
    siglen = sizeof(sigbuf);
    if (!sign_digest(NULL, ec_pkey, "SHA256", params,
                     digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* Digest-Sign using deterministic signature with IBMCA provider */
    siglen2 = sizeof(sigbuf2);
    if (!sign_digest("ibmca", ec_pkey, "SHA256", params,
                     digest, sizeof(digest), sigbuf2, &siglen2))
        goto out;

    if (siglen != siglen2 ||
        memcmp(sigbuf, sigbuf2, siglen) != 0) {
        fprintf(stderr, "Deterministic signatures do not match\n");
        ok = 0;
        goto out;
    } else {
        printf("Deterministic signature is correct\n");
    }
#endif

#ifdef EVP_PKEY_OP_SIGNMSG
    /* SignMessage with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_message("ibmca", ec_pkey, "ECDSA-SHA256",
                      digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* VerifyMessage with default provider */
    if (!verify_message(NULL, curvename, ec_pkey, "ECDSA-SHA256",
                        digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* VerifyMessage with IBMCA provider */
    if (!verify_message("ibmca", curvename, ec_pkey, "ECDSA-SHA256",
                        digest, sizeof(digest), sigbuf, siglen))
        goto out;


    /* SignMessage one-shot with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_message_single("ibmca", ec_pkey, "ECDSA-SHA256",
                             digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* VerifyMessage one-shot with default provider */
    if (!verify_message_single(NULL, curvename, ec_pkey, "ECDSA-SHA256",
                               digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* VerifyMessage one-shot with IBMCA provider */
    if (!verify_message_single("ibmca", curvename, ec_pkey, "ECDSA-SHA256",
                               digest, sizeof(digest), sigbuf, siglen))
        goto out;


    /* Sign pre-hashed message with IBMCA provider */
    siglen = sizeof(sigbuf);
    if (!sign_message_prehashed("ibmca", ec_pkey, "ECDSA-SHA256",
                                digest, sizeof(digest), sigbuf, &siglen))
        goto out;

    /* Verify pre-hashed message with default provider */
    if (!verify_message_prehashed(NULL, curvename, ec_pkey, "ECDSA-SHA256",
                                  digest, sizeof(digest), sigbuf, siglen))
        goto out;

    /* Verify pre-hashed message with IBMCA provider */
    if (!verify_message_prehashed("ibmca", curvename, ec_pkey, "ECDSA-SHA256",
                                  digest, sizeof(digest), sigbuf, siglen))
        goto out;
#endif

    /* Keygen with IBMCA provider (using ec_pkey as template) */
    if (!generate_key("ibmca", nid, curvename, NULL, ec_pkey, &peer_pkey))
        goto out;

    /* Derive with IBMCA provider (no KDF) */
    keylen1 = sizeof(keybuf1);
    if (!derive_key("ibmca", ec_pkey, peer_pkey, 0, NULL, 0, keybuf1, &keylen1))
        goto out;

    /* Derive with default provider (no KDF) */
    keylen2 = sizeof(keybuf2);
    if (!derive_key(NULL, ec_pkey, peer_pkey, 0, NULL, 0, keybuf2, &keylen2))
        goto out;

    if (keylen1 != keylen2 || memcmp(keybuf1, keybuf2, keylen1) != 0) {
        fprintf(stderr, "Derived keys are not equal\n");
        goto out;
    }

    /* Derive with IBMCA provider (X9_63 KDF) */
    keylen1 = sizeof(keybuf1);
    if (!derive_key("ibmca", ec_pkey, peer_pkey,
                    EVP_PKEY_ECDH_KDF_X9_63, "SHA256", keylen1,
                    keybuf1, &keylen1))
        goto out;

    /* Derive with default provider (X9_63 KDF) */
    keylen2 = sizeof(keybuf2);
    if (!derive_key(NULL, ec_pkey, peer_pkey,
                    EVP_PKEY_ECDH_KDF_X9_63, "SHA256", keylen2,
                    keybuf2, &keylen2))
        goto out;

    if (keylen1 != keylen2 || memcmp(keybuf1, keybuf2, keylen1) != 0) {
        fprintf(stderr, "Derived keys are not equal\n");
        goto out;
    }

    ok = 1;

 out:
    if (peer_pkey)
       EVP_PKEY_free(peer_pkey);
    if (ec_pkey)
       EVP_PKEY_free(ec_pkey);
#ifdef OSSL_PKEY_PARAM_DHKEM_IKM
    if (ec_pkey1)
       EVP_PKEY_free(ec_pkey1);
    if (ec_pkey2)
       EVP_PKEY_free(ec_pkey2);
#endif

    ERR_print_errors_fp(stderr);

    return ok;
}

static const unsigned int required_ica_mechs[] = { EC_DH, EC_DSA_SIGN,
                                                   EC_DSA_VERIFY, EC_KGEN, };
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
        if (!check_eckey(params[i].nid, params[i].name)) {
            fprintf(stderr, "Failure for %s\n", params[i].name);
            ret = 99;
        }
    }
    return ret;
}
