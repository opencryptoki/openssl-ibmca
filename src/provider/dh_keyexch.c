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
#include <stdarg.h>
#include <stddef.h>
#include <err.h>
#include <strings.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/kdf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

#include "p_ibmca.h"

static OSSL_FUNC_keyexch_newctx_fn ibmca_keyexch_dh_newctx;
static OSSL_FUNC_keyexch_init_fn ibmca_keyexch_dh_init;
static OSSL_FUNC_keyexch_set_peer_fn ibmca_keyexch_dh_set_peer;
static OSSL_FUNC_keyexch_derive_fn ibmca_keyexch_dh_derive;
static OSSL_FUNC_keyexch_set_ctx_params_fn ibmca_keyexch_dh_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn
                                        ibmca_keyexch_dh_settable_ctx_params;
static OSSL_FUNC_keyexch_get_ctx_params_fn ibmca_keyexch_dh_get_ctx_params;
static OSSL_FUNC_keyexch_gettable_ctx_params_fn
                                       ibmca_keyexch_dh_gettable_ctx_params;

static void ibmca_keyexch_dh_free_cb(struct ibmca_op_ctx *ctx);
static int ibmca_keyexch_dh_dup_cb(const struct ibmca_op_ctx *ctx,
                                   struct ibmca_op_ctx *new_ctx);
static int ibmca_keyexch_dh_set_ctx_params(void *vctx,
                                           const OSSL_PARAM params[]);

static void *ibmca_keyexch_dh_newctx(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    struct ibmca_op_ctx *opctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    opctx = ibmca_op_newctx(provctx, NULL, EVP_PKEY_DH,
                            ibmca_keyexch_dh_free_cb,
                            ibmca_keyexch_dh_dup_cb);
    if (opctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_op_newctx failed");
        return NULL;
    }

    ibmca_debug_ctx(provctx, "opctx: %p", opctx);

    return opctx;
}

static void ibmca_keyexch_dh_free_cb(struct ibmca_op_ctx *ctx)
{
    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->dh.derive.peer_key != NULL)
        ibmca_keymgmt_free(ctx->dh.derive.peer_key);
    ctx->dh.derive.peer_key = NULL;

    ctx->dh.derive.pad = false;

    ctx->dh.derive.kdf_type = EVP_PKEY_DH_KDF_NONE;

    if (ctx->dh.derive.kdf_md != NULL)
        EVP_MD_free(ctx->dh.derive.kdf_md);
    ctx->dh.derive.kdf_md = NULL;

    ctx->dh.derive.kdf_outlen = 0;

    if (ctx->dh.derive.kdf_ukm != NULL)
        P_CLEAR_FREE(ctx->provctx, ctx->dh.derive.kdf_ukm,
                     ctx->dh.derive.kdf_ukmlen);
    ctx->dh.derive.kdf_ukm = NULL;
    ctx->dh.derive.kdf_ukmlen = 0;

    if (ctx->dh.derive.kdf_cekalg != NULL)
        P_FREE(ctx->provctx, ctx->dh.derive.kdf_cekalg);
    ctx->dh.derive.kdf_cekalg = NULL;
}

static int ibmca_keyexch_dh_dup_cb(const struct ibmca_op_ctx *ctx,
                                   struct ibmca_op_ctx *new_ctx)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p new_ctx: %p", ctx, new_ctx);

    if (ctx->dh.derive.peer_key != NULL) {
        new_ctx->dh.derive.peer_key = ctx->dh.derive.peer_key;
        ibmca_keymgmt_upref(new_ctx->dh.derive.peer_key);
    }

    new_ctx->dh.derive.pad = ctx->dh.derive.pad;

    new_ctx->dh.derive.kdf_type = ctx->dh.derive.kdf_type;

    new_ctx->dh.derive.kdf_md = ctx->dh.derive.kdf_md;
    if (new_ctx->dh.derive.kdf_md != NULL) {
        if (EVP_MD_up_ref(new_ctx->dh.derive.kdf_md) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_up_ref failed");
            return 0;
        }
    }

    new_ctx->dh.derive.kdf_outlen = ctx->dh.derive.kdf_outlen;

    if (ctx->dh.derive.kdf_ukm != NULL && ctx->dh.derive.kdf_ukmlen > 0) {
        new_ctx->dh.derive.kdf_ukm = P_MEMDUP(ctx->provctx,
                                              ctx->dh.derive.kdf_ukm,
                                              ctx->dh.derive.kdf_ukmlen);
        if (new_ctx->dh.derive.kdf_ukm == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED, "P_MEMDUP failed");
            return 0;
        }
        new_ctx->dh.derive.kdf_ukmlen = ctx->dh.derive.kdf_ukmlen;
    }

    if (ctx->dh.derive.kdf_cekalg != NULL) {
        new_ctx->dh.derive.kdf_cekalg = P_STRDUP(ctx->provctx,
                                                 ctx->dh.derive.kdf_cekalg);
        if (new_ctx->dh.derive.kdf_cekalg == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED, "P_STRDUP failed");
            return 0;
        }
    }

    return 1;
}

static int ibmca_keyexch_dh_init(void *vctx, void *vkey,
                                 const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;
    const OSSL_PARAM *p;

    if (ctx == NULL || key == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    if (ibmca_op_init(ctx, key, EVP_PKEY_OP_DERIVE) == 0) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_init failed");
        return 0;
    }

    /* Set up defaults for this context */
    ibmca_keyexch_dh_free_cb(ctx);

    if (params != NULL) {
        if (ibmca_keyexch_dh_set_ctx_params(ctx, params) == 0) {
            ibmca_debug_op_ctx(ctx,
                    "ERROR: ibmca_keyexch_dh_set_ctx_params failed");
            return 0;
        }
    }

    return 1;
}

static int ibmca_keyexch_dh_set_peer(void *vctx, void *vkey)
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);

    if (key->type != ctx->key->type) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Peer key is not an DH or DHX key");
        return 0;
    }

    if (ctx->key->match(ctx->key, key,
                        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Peer key uses a different DH parameters");
        return 0;
    }

    if (key->has(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Peer key does not contain a public DH key");
        return 0;
    }

    if (ctx->dh.derive.peer_key != NULL)
        ibmca_keymgmt_free(ctx->dh.derive.peer_key);

    ctx->dh.derive.peer_key = key;
    ibmca_keymgmt_upref(key);

    return 1;
}

static int ibmca_keyexch_dh_derive_plain_fallback(struct ibmca_op_ctx *ctx,
                                                  unsigned char *secret,
                                                  size_t outlen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t keylen;
    int rc = 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p secret: %p outlen: %lu", ctx, secret,
                       outlen);

    pkey = ibmca_new_fallback_pkey(ctx->key);
    if (pkey == NULL) {
        ibmca_debug_op_ctx(ctx,"ERROR: ibmca_new_fallback_pkey failed");
        goto out;
    }

    peer = ibmca_new_fallback_pkey(ctx->dh.derive.peer_key);
    if (peer == NULL) {
        ibmca_debug_op_ctx(ctx,"ERROR: ibmca_new_fallback_pkey failed");
        goto out;
    }

    pctx = ibmca_new_fallback_pkey_ctx(ctx->provctx, pkey, NULL);
    if (pctx == NULL) {
        ibmca_debug_op_ctx(ctx,"ERROR: ibmca_new_fallback_pkey_ctx failed");
        goto out;
    }

    if (EVP_PKEY_derive_init(pctx) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_derive_init failed");
        goto out;
    }

    if (ibmca_check_fallback_provider(ctx->provctx, pctx) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_check_fallback_provider failed");
        goto out;
    }

    if (EVP_PKEY_derive_set_peer(pctx, peer) != 1 ||
        EVP_PKEY_CTX_set_dh_pad(pctx, 1) != 1 ||
        EVP_PKEY_CTX_set_dh_kdf_type(pctx, EVP_PKEY_DH_KDF_NONE) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_derive_set_peer/EVP_PKEY_CTX_set_dh_pad/EVP_PKEY_CTX_set_dh_kdf_type failed");
        goto out;
    }

    keylen = outlen;
    if (EVP_PKEY_derive(pctx, secret, &keylen) != 1 ||
        keylen != outlen) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_derive failed");
        goto out;
    }

    rc = 1;

out:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (peer != NULL)
        EVP_PKEY_free(peer);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return rc;
}

static int ibmca_keyexch_dh_derive_plain(struct ibmca_op_ctx *ctx,
                                         unsigned char *secret,
                                         size_t *secretlen, size_t outlen,
                                         bool pad)
{
    int rc = 0;
    unsigned char *buf, *pub;
    bool use_tbuf = false;
    size_t prime_size, i;
    ica_rsa_key_mod_expo_t mod_exp;
    BIGNUM *z = NULL, *pminus1 = NULL;

    ibmca_debug_op_ctx(ctx, "ctx: %p secret: %p outlen: %lu pad: %d", ctx,
                       secret, outlen, pad);

    prime_size = ctx->key->get_max_param_size(ctx->key);
    if (secret == NULL) {
        *secretlen = prime_size;
        rc = 1;
        goto out;
    }

    *secretlen = outlen < prime_size ? outlen : prime_size;

    if (ibmca_op_alloc_tbuf(ctx, 4 * prime_size) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
        goto out;
    }

    if (*secretlen == prime_size) {
        buf = secret;
    } else {
        buf = ctx->tbuf;
        use_tbuf = true;
    }

    /* Z = pub_key^priv_key mod p */
    mod_exp.key_length = prime_size;
    mod_exp.modulus = ctx->tbuf + prime_size;
    mod_exp.exponent = ctx->tbuf + 2 * prime_size;
    pub = ctx->tbuf + 3 * prime_size;

    if (BN_bn2binpad(ctx->key->dh.ffc_params.p, mod_exp.modulus,
                     prime_size) <= 0 ||
        BN_bn2binpad(ctx->key->dh.priv, mod_exp.exponent, prime_size) <= 0 ||
        BN_bn2binpad(ctx->dh.derive.peer_key->dh.pub, pub, prime_size) <= 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR, "BN_bn2binpad failed");
        goto out;
    }

    rc = ica_rsa_mod_expo(ctx->provctx->ica_adapter, pub, &mod_exp, buf);
    if (rc == 0) {
        z = BN_secure_new();
        if (z == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED,
                             "BN_secure_new failed");
            goto out;
        }
        z = BN_bin2bn(buf, prime_size, z);
        pminus1 = BN_new();
        if (z == NULL || pminus1 == NULL ||
            BN_copy(pminus1, ctx->key->dh.ffc_params.p) == NULL ||
            BN_sub_word(pminus1, 1) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "BN_bin2bn/BN_copy/BN_sub_word failed");
            goto out;
        }
        /* Error if z <= 1 or z = p - 1 */
        if (BN_cmp(z, BN_value_one()) <= 0 ||
            BN_cmp(z, pminus1) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM, "invalid secret");
            goto out;
        }
    } else {
        ibmca_debug_op_ctx(ctx, "ica_rsa_mod_expo failed with: %s",
                           strerror(rc));

        rc = ibmca_keyexch_dh_derive_plain_fallback(ctx, buf, prime_size);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_keyexch_dh_derive_plain_fallback failed");
            rc = 0;
            goto out;
        }
    }

    if (use_tbuf)
        memcpy(secret, ctx->tbuf, *secretlen);

    if (pad == false) {
        for (i = 0; i < *secretlen && secret[i] == 0; i++)
            ;
        if (i > 0 && i < *secretlen) {
            memmove(secret, secret + i, *secretlen - i);
            P_CLEANSE(ctx->provctx, secret + *secretlen - i, i);
            *secretlen = *secretlen - i;
        }
    }

    rc = 1;

out:
    if (rc != 1)
        *secretlen = 0;
    if (use_tbuf && ctx->tbuf != NULL)
        P_CLEANSE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);
    if (z != NULL)
        BN_clear_free(z);
    if (pminus1 != NULL)
        BN_free(pminus1);

    ibmca_debug_op_ctx(ctx, "secretlen: %lu", *secretlen);

    return rc;
}

static int ibmca_keyexch_dh_kdf_x942(const struct ibmca_prov_ctx *provctx,
                                     const unsigned char *z, size_t z_len,
                                     EVP_MD *md, const unsigned char *ukm,
                                     size_t ukm_len, const char *cek_alg,
                                     unsigned char *out, size_t outlen)
{
    int rc = 0;
    OSSL_PARAM params[5];
    OSSL_PARAM *p;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(provctx->libctx, OSSL_KDF_NAME_X942KDF_ASN1, NULL);
    if (kdf == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to fetch KDF '%s'", OSSL_KDF_NAME_X942KDF_ASN1);
        goto out;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_KDF_CTX_new failed");
        goto out;
    }

    p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)EVP_MD_get0_name(md), 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (void *)z, z_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                             (void *)ukm, ukm_len);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG,
                                            (char *)cek_alg, 0);
    *p = OSSL_PARAM_construct_end();

    rc = EVP_KDF_derive(kctx, out, outlen, params);
    if (rc <= 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_KDF_derive failed");
        goto out;
    }

    rc = 1;

out:
    if (kctx != NULL)
        EVP_KDF_CTX_free(kctx);
    if (kdf != NULL)
        EVP_KDF_free(kdf);

    return rc;

}

static int ibmca_keyexch_dh_derive_x942_kdf(struct ibmca_op_ctx *ctx,
                                            unsigned char *secret,
                                            size_t *secretlen, size_t outlen)
{
    int rc = 0;
    size_t len, prime_size;

    ibmca_debug_op_ctx(ctx, "ctx: %p secret: %p outlen: %lu", ctx, secret,
                       outlen);

    *secretlen = ctx->dh.derive.kdf_outlen;

    if (secret == NULL) {
        rc = 1;
        goto out;
    }

    if (outlen < *secretlen) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Output buffer too small");
        goto out;
    }

    prime_size = ctx->key->get_max_param_size(ctx->key);

    if (ibmca_op_alloc_tbuf(ctx, prime_size * 4) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
        goto out;
    }

    rc = ibmca_keyexch_dh_derive_plain(ctx, ctx->tbuf, &len, prime_size, true);
    if (rc != 1) {
        ibmca_debug_op_ctx(ctx,
                           "ERROR: ibmca_keyexch_dh_derive_plain failed");
        goto out;
    }

    rc = ibmca_keyexch_dh_kdf_x942(ctx->provctx, ctx->tbuf, len,
                                   ctx->dh.derive.kdf_md,
                                   ctx->dh.derive.kdf_ukm,
                                   ctx->dh.derive.kdf_ukmlen,
                                   ctx->dh.derive.kdf_cekalg,
                                   secret, ctx->dh.derive.kdf_outlen);
    if (rc != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_keyexch_dh_kdf_x942 failed");
        goto out;
    }

    rc = 1;

out:
    if (rc != 1)
        *secretlen = 0;

    ibmca_debug_op_ctx(ctx, "secretlen: %lu", *secretlen);

    if (ctx->tbuf != NULL)
        P_CLEANSE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);

    return rc;
}

static int ibmca_keyexch_dh_derive(void *vctx,  unsigned char *secret,
                                   size_t *secretlen, size_t outlen)
{
    struct ibmca_op_ctx *ctx = vctx;

    if (ctx == NULL || secretlen == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p secret: %p outlen: %lu", ctx, secret,
                       outlen);

    switch (ctx->dh.derive.kdf_type) {
    case EVP_PKEY_DH_KDF_X9_42:
        return ibmca_keyexch_dh_derive_x942_kdf(ctx, secret, secretlen, outlen);
    case EVP_PKEY_DH_KDF_NONE:
    default:
        return ibmca_keyexch_dh_derive_plain(ctx, secret, secretlen, outlen,
                                             ctx->dh.derive.pad);
    }

    return 0;
}

static int ibmca_keyexch_dh_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    OSSL_PARAM *p;
    const char *name;
    int rc;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    /* OSSL_EXCHANGE_PARAM_KDF_TYPE */
    switch (ctx->dh.derive.kdf_type) {
    case EVP_PKEY_DH_KDF_X9_42:
        name = OSSL_KDF_NAME_X942KDF_ASN1;
        break;
    case EVP_PKEY_DH_KDF_NONE:
    default:
        name = "";
        break;
    }
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_EXCHANGE_PARAM_KDF_TYPE, name);
    if (rc == 0)
       return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_DIGEST */
    if (ctx->dh.derive.kdf_md != NULL)
        name = EVP_MD_get0_name(ctx->dh.derive.kdf_md);
    else
        name = "";
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_EXCHANGE_PARAM_KDF_DIGEST, name);
    if (rc == 0)
       return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_OUTLEN */
    rc = ibmca_param_build_set_size_t(ctx->provctx, NULL, params,
                                      OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                      ctx->dh.derive.kdf_outlen);
    if (rc == 0)
       return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_UKM */
    rc = ibmca_param_build_set_octet_ptr(ctx->provctx, NULL, params,
                                         OSSL_EXCHANGE_PARAM_KDF_UKM,
                                         ctx->dh.derive.kdf_ukm,
                                         ctx->dh.derive.kdf_ukmlen);
    if (rc == 0)
       return 0;

    /* OSSL_KDF_PARAM_CEK_ALG */
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_KDF_PARAM_CEK_ALG,
                                    ctx->dh.derive.kdf_cekalg);
    if (rc == 0)
       return 0;

    return 1;
}

static int ibmca_keyexch_dh_set_ctx_params(void *vctx,
                                           const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    const OSSL_PARAM *p;
    const char *name, *props = NULL;
    unsigned int value;
    int rc;
    void *ukm = NULL;
    size_t ukmlen;
    EVP_MD *md;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    /* OSSL_EXCHANGE_PARAM_PAD */
    rc = ibmca_param_get_uint(ctx->provctx, params,
                              OSSL_EXCHANGE_PARAM_PAD, &value);
    if (rc == 0)
        return 0;
    if (rc > 0)
        ctx->dh.derive.pad = (value != 0);

    /* OSSL_EXCHANGE_PARAM_KDF_TYPE */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_EXCHANGE_PARAM_KDF_TYPE, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (name[0] == '\0') {
            ctx->dh.derive.kdf_type = EVP_PKEY_DH_KDF_NONE;
        } else if (strcmp(name, OSSL_KDF_NAME_X942KDF_ASN1) == 0) {
            ctx->dh.derive.kdf_type = EVP_PKEY_DH_KDF_X9_42;
        } else {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "DH '%s': '%s' is not supported",
                             OSSL_EXCHANGE_PARAM_KDF_TYPE, name);
            return 0;
        }
    }

    /* OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, &props);
    if (rc == 0)
        return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_DIGEST */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                             OSSL_EXCHANGE_PARAM_KDF_DIGEST, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        md = EVP_MD_fetch(ctx->provctx->libctx, name,
                          props != NULL ? props : ctx->propq);
        if (md == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                              "DH '%s': '%s' could not be fetched",
                              OSSL_EXCHANGE_PARAM_KDF_DIGEST, name);
            return 0;
        }

        if (ctx->dh.derive.kdf_md != NULL)
            EVP_MD_free(ctx->dh.derive.kdf_md);
        ctx->dh.derive.kdf_md = md;
    }

    /* OSSL_EXCHANGE_PARAM_KDF_OUTLEN */
    rc = ibmca_param_get_size_t(ctx->provctx, params,
                                OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                &ctx->dh.derive.kdf_outlen);
    if (rc == 0)
        return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_UKM */
    rc = ibmca_param_get_octet_string(ctx->provctx, params,
                                      OSSL_EXCHANGE_PARAM_KDF_UKM,
                                      &ukm, &ukmlen);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (ctx->dh.derive.kdf_ukm != NULL)
            P_CLEAR_FREE(ctx->provctx, ctx->dh.derive.kdf_ukm,
                         ctx->dh.derive.kdf_ukmlen);
        ctx->dh.derive.kdf_ukm = ukm;
        ctx->dh.derive.kdf_ukmlen = ukmlen;
    }

    /* OSSL_KDF_PARAM_CEK_ALG */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_KDF_PARAM_CEK_ALG, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        ctx->dh.derive.kdf_cekalg = P_STRDUP(ctx->provctx, name);
        if (ctx->dh.derive.kdf_cekalg == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED, "P_STRDUP failed");
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM ibmca_keyexch_dh_gettable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keyexch_dh_gettable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    for (p = ibmca_keyexch_dh_gettable_params;
                                    p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_keyexch_dh_gettable_params;
}

static const OSSL_PARAM ibmca_keyexch_dh_settable_params[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keyexch_dh_settable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    for (p = ibmca_keyexch_dh_settable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_keyexch_dh_settable_params;
}

static const OSSL_DISPATCH ibmca_dh_keyexch_functions[] = {
    /* Context management */
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))ibmca_keyexch_dh_newctx },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))ibmca_op_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))ibmca_op_dupctx },

    /* Shared secret derivation */
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))ibmca_keyexch_dh_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))ibmca_keyexch_dh_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))ibmca_keyexch_dh_derive },

    /* Key Exchange parameters */
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        (void (*)(void))ibmca_keyexch_dh_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        (void (*)(void))ibmca_keyexch_dh_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
            (void (*)(void))ibmca_keyexch_dh_get_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        (void (*)(void))ibmca_keyexch_dh_gettable_ctx_params },

    { 0, NULL }
};

const OSSL_ALGORITHM ibmca_dh_keyexch[] = {
    { "DH:dhKeyAgreement:1.2.840.113549.1.3.1", NULL,
      ibmca_dh_keyexch_functions, "IBMCA DH key exchange implementation" },
    { NULL, NULL, NULL, NULL }
};
