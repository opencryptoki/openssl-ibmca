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
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

#include "p_ibmca.h"

static OSSL_FUNC_keyexch_newctx_fn ibmca_keyexch_ec_newctx;
static OSSL_FUNC_keyexch_init_fn ibmca_keyexch_ec_init;
static OSSL_FUNC_keyexch_set_peer_fn ibmca_keyexch_ec_set_peer;
static OSSL_FUNC_keyexch_derive_fn ibmca_keyexch_ec_derive;
static OSSL_FUNC_keyexch_set_ctx_params_fn ibmca_keyexch_ec_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn
                                        ibmca_keyexch_ec_settable_ctx_params;
static OSSL_FUNC_keyexch_get_ctx_params_fn ibmca_keyexch_ec_get_ctx_params;
static OSSL_FUNC_keyexch_gettable_ctx_params_fn
                                       ibmca_keyexch_ec_gettable_ctx_params;

static void ibmca_keyexch_ec_free_cb(struct ibmca_op_ctx *ctx);
static int ibmca_keyexch_ec_dup_cb(const struct ibmca_op_ctx *ctx,
                                   struct ibmca_op_ctx *new_ctx);
static int ibmca_keyexch_ec_set_ctx_params(void *vctx,
                                           const OSSL_PARAM params[]);

static void *ibmca_keyexch_ec_newctx(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    struct ibmca_op_ctx *opctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    opctx = ibmca_op_newctx(provctx, NULL, EVP_PKEY_EC,
                            ibmca_keyexch_ec_free_cb,
                            ibmca_keyexch_ec_dup_cb);
    if (opctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_op_newctx failed");
        return NULL;
    }

    ibmca_debug_ctx(provctx, "opctx: %p", opctx);

    return opctx;
}

static void ibmca_keyexch_ec_free_cb(struct ibmca_op_ctx *ctx)
{
    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->ec.derive.peer_key != NULL)
        ibmca_keymgmt_free(ctx->ec.derive.peer_key);
    ctx->ec.derive.peer_key = NULL;

    ctx->ec.derive.kdf_type = EVP_PKEY_ECDH_KDF_NONE;

    if (ctx->ec.derive.kdf_md != NULL)
        EVP_MD_free(ctx->ec.derive.kdf_md);
    ctx->ec.derive.kdf_md = NULL;

    ctx->ec.derive.kdf_outlen = 0;

    if (ctx->ec.derive.kdf_ukm != NULL)
        P_CLEAR_FREE(ctx->provctx, ctx->ec.derive.kdf_ukm,
                     ctx->ec.derive.kdf_ukmlen);
    ctx->ec.derive.kdf_ukm = NULL;
    ctx->ec.derive.kdf_ukmlen = 0;
}

static int ibmca_keyexch_ec_dup_cb(const struct ibmca_op_ctx *ctx,
                                   struct ibmca_op_ctx *new_ctx)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p new_ctx: %p", ctx, new_ctx);

    if (ctx->ec.derive.peer_key != NULL) {
        new_ctx->ec.derive.peer_key = ctx->ec.derive.peer_key;
        ibmca_keymgmt_upref(new_ctx->ec.derive.peer_key);
    }

    new_ctx->ec.derive.kdf_type = ctx->ec.derive.kdf_type;

    new_ctx->ec.derive.kdf_md = ctx->ec.derive.kdf_md;
    if (new_ctx->ec.derive.kdf_md != NULL) {
        if (EVP_MD_up_ref(new_ctx->ec.derive.kdf_md) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_up_ref failed");
            return 0;
        }
    }

    new_ctx->ec.derive.kdf_outlen = ctx->ec.derive.kdf_outlen;

    if (ctx->ec.derive.kdf_ukm != NULL && ctx->ec.derive.kdf_ukmlen > 0) {
        new_ctx->ec.derive.kdf_ukm = P_MEMDUP(ctx->provctx,
                                              ctx->ec.derive.kdf_ukm,
                                              ctx->ec.derive.kdf_ukmlen);
        if (new_ctx->ec.derive.kdf_ukm == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED, "P_MEMDUP failed");
            return 0;
        }
        new_ctx->ec.derive.kdf_ukmlen = ctx->ec.derive.kdf_ukmlen;
    }

    return 1;
}

static int ibmca_keyexch_ec_init(void *vctx, void *vkey,
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

    /* Setup defaults for this context */
    ibmca_keyexch_ec_free_cb(ctx);

    if (params != NULL) {
        if (ibmca_keyexch_ec_set_ctx_params(ctx, params) == 0) {
            ibmca_debug_op_ctx(ctx,
                    "ERROR: ibmca_keyexch_ec_set_ctx_params failed");
            return 0;
        }
    }

    return 1;
}

static int ibmca_keyexch_ec_set_peer(void *vctx, void *vkey)
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p", ctx, key);

    if (key->type != EVP_PKEY_EC) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Peer key is not an EC key");
        return 0;
    }

    if (ctx->key->match(ctx->key, key,
                        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Peer key uses a different EC curve");
        return 0;
    }

    if (key->has(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Peer key does not contain a public EC key");
        return 0;
    }

    ibmca_keymgmt_upref(key);

    if (ctx->ec.derive.peer_key != NULL)
        ibmca_keymgmt_free(ctx->ec.derive.peer_key);

    ctx->ec.derive.peer_key = key;

    return 1;
}

static int ibmca_keyexch_ec_derive_plain_fallback(struct ibmca_op_ctx *ctx,
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

    peer = ibmca_new_fallback_pkey(ctx->ec.derive.peer_key);
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
        EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_NONE) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_derive_set_peer/EVP_PKEY_CTX_set_ecdh_kdf_type failed");
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

static int ibmca_keyexch_ec_derive_plain(struct ibmca_op_ctx *ctx,
                                         unsigned char *secret,
                                         size_t *secretlen, size_t outlen)
{
    int rc = 0;
    unsigned char *buf;
    bool use_tbuf = false;

    ibmca_debug_op_ctx(ctx, "ctx: %p secret: %p outlen: %lu", ctx, secret,
                       outlen);

    if (secret == NULL) {
        *secretlen = ctx->key->ec.prime_size;
        rc = 1;
        goto out;
    }

    *secretlen = outlen < ctx->key->ec.prime_size ?
                                            outlen : ctx->key->ec.prime_size;

    if (*secretlen == ctx->key->ec.prime_size) {
        buf = secret;
    } else {
        if (ibmca_op_alloc_tbuf(ctx, ctx->key->ec.prime_size) != 1) {
            ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
            goto out;
        }

        buf = ctx->tbuf;
        use_tbuf = true;
    }

    if (ctx->key->ec.fallback.d != NULL ||
        (ctx->ec.derive.peer_key->ec.fallback.x != NULL &&
         ctx->ec.derive.peer_key->ec.fallback.y != NULL)) {
        rc = ibmca_keyexch_ec_derive_plain_fallback(ctx, buf,
                                                    ctx->key->ec.prime_size);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_keyexch_ec_derive_plain_fallback failed");
            rc = 0;
            goto out;
        }

        goto copy;
    }

    rc = ica_ecdh_derive_secret(ctx->provctx->ica_adapter, ctx->key->ec.key,
                                ctx->ec.derive.peer_key->ec.key,
                                buf, ctx->key->ec.prime_size);

    if (rc != 0) {
        ibmca_debug_op_ctx(ctx, "ica_ecdh_derive_secret failed with: %s",
                           strerror(rc));

        rc = ibmca_keyexch_ec_derive_plain_fallback(ctx, buf,
                                                    ctx->key->ec.prime_size);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_keyexch_ec_derive_plain_fallback failed");
            rc = 0;
            goto out;
        }
    }

copy:
    if (use_tbuf)
        memcpy(secret, ctx->tbuf, *secretlen);

    rc = 1;

out:
    if (rc != 1)
        *secretlen = 0;
    if (use_tbuf && ctx->tbuf != NULL)
        P_CLEANSE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);

    ibmca_debug_op_ctx(ctx, "secretlen: %lu", *secretlen);

    return rc;
}

static int ibmca_keyexch_ec_kdf_x963(const struct ibmca_prov_ctx *provctx,
                                     const unsigned char *z, size_t z_len,
                                     EVP_MD *md, const unsigned char *ukm,
                                     size_t ukm_len, unsigned char *out,
                                     size_t outlen)
{
    int rc = 0;
    OSSL_PARAM params[4];
    OSSL_PARAM *p;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(provctx->libctx, OSSL_KDF_NAME_X963KDF, NULL);
    if (kdf == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to fetch KDF '%s'", OSSL_KDF_NAME_X963KDF);
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

static int ibmca_keyexch_ec_derive_x963_kdf(struct ibmca_op_ctx *ctx,
                                            unsigned char *secret,
                                            size_t *secretlen, size_t outlen)
{
    int rc = 0;
    size_t len;

    ibmca_debug_op_ctx(ctx, "ctx: %p secret: %p outlen: %lu", ctx, secret,
                       outlen);

    *secretlen = ctx->ec.derive.kdf_outlen;

    if (secret == NULL) {
        rc = 1;
        goto out;
    }

    if (outlen < *secretlen) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Output buffer too small");
        goto out;
    }

    if (ibmca_op_alloc_tbuf(ctx, ctx->key->ec.prime_size) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
        goto out;
    }

    rc = ibmca_keyexch_ec_derive_plain(ctx, ctx->tbuf,
                                       &len, ctx->key->ec.prime_size);
    if (rc != 1) {
        ibmca_debug_op_ctx(ctx,
                           "ERROR: ibmca_keyexch_ec_derive_plain failed");
        goto out;
    }

    rc = ibmca_keyexch_ec_kdf_x963(ctx->provctx, ctx->tbuf,
                                   ctx->key->ec.prime_size,
                                   ctx->ec.derive.kdf_md,
                                   ctx->ec.derive.kdf_ukm,
                                   ctx->ec.derive.kdf_ukmlen,
                                   secret, ctx->ec.derive.kdf_outlen);
    if (rc != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_keyexch_ec_alloc_tbuf failed");
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

static int ibmca_keyexch_ec_derive(void *vctx,  unsigned char *secret,
                                   size_t *secretlen, size_t outlen)
{
    struct ibmca_op_ctx *ctx = vctx;

    if (ctx == NULL || secretlen == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p secret: %p outlen: %lu", ctx, secret,
                       outlen);

    switch (ctx->ec.derive.kdf_type) {
    case EVP_PKEY_ECDH_KDF_X9_63:
        return ibmca_keyexch_ec_derive_x963_kdf(ctx, secret, secretlen, outlen);
    case EVP_PKEY_ECDH_KDF_NONE:
    default:
        return ibmca_keyexch_ec_derive_plain(ctx, secret, secretlen, outlen);
    }

    return 0;
}

static int ibmca_keyexch_ec_get_ctx_params(void *vctx, OSSL_PARAM params[])
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

    /* OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE */
    rc = ibmca_param_build_set_int(ctx->provctx, NULL, params,
                                   OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
                                   0);
    if (rc == 0)
       return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_TYPE */
    switch (ctx->ec.derive.kdf_type) {
    case EVP_PKEY_ECDH_KDF_X9_63:
        name = OSSL_KDF_NAME_X963KDF;
        break;
    case EVP_PKEY_ECDH_KDF_NONE:
    default:
        name = "";
        break;
    }
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_EXCHANGE_PARAM_KDF_TYPE, name);
    if (rc == 0)
       return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_DIGEST */
    if (ctx->ec.derive.kdf_md != NULL)
        name = EVP_MD_get0_name(ctx->ec.derive.kdf_md);
    else
        name = "";
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_EXCHANGE_PARAM_KDF_DIGEST, name);
    if (rc == 0)
       return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_OUTLEN */
    rc = ibmca_param_build_set_size_t(ctx->provctx, NULL, params,
                                      OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                      ctx->ec.derive.kdf_outlen);
    if (rc == 0)
       return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_UKM */
    rc = ibmca_param_build_set_octet_ptr(ctx->provctx, NULL, params,
                                         OSSL_EXCHANGE_PARAM_KDF_UKM,
                                         ctx->ec.derive.kdf_ukm,
                                         ctx->ec.derive.kdf_ukmlen);
    if (rc == 0)
       return 0;

    return 1;
}

static int ibmca_keyexch_ec_set_ctx_params(void *vctx,
                                           const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    const OSSL_PARAM *p;
    const char *name, *props = NULL;
    int rc, value;
    void *ukm = NULL;
    size_t ukmlen;
    EVP_MD *md;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    /* OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE */
    rc = ibmca_param_get_int(ctx->provctx, params,
                             OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, &value);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        /* We do not support Cofactor DH (ECC CDH) */
        if (value != 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "EC '%s': %d is not supported",
                             OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, value);
            return 0;
        }
    }

    /* OSSL_EXCHANGE_PARAM_KDF_TYPE */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_EXCHANGE_PARAM_KDF_TYPE, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (name[0] == '\0') {
            ctx->ec.derive.kdf_type = EVP_PKEY_ECDH_KDF_NONE;
        } else if (strcmp(name, OSSL_KDF_NAME_X963KDF) == 0) {
            ctx->ec.derive.kdf_type = EVP_PKEY_ECDH_KDF_X9_62;
        } else {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "EC '%s': '%s' is not supported",
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
                              "EC '%s': '%s' could not be fetched",
                              OSSL_EXCHANGE_PARAM_KDF_DIGEST, name);
            return 0;
        }

        if (ctx->ec.derive.kdf_md != NULL)
            EVP_MD_free(ctx->ec.derive.kdf_md);
        ctx->ec.derive.kdf_md = md;
    }

    /* OSSL_EXCHANGE_PARAM_KDF_OUTLEN */
    rc = ibmca_param_get_size_t(ctx->provctx, params,
                                OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                &ctx->ec.derive.kdf_outlen);
    if (rc == 0)
        return 0;

    /* OSSL_EXCHANGE_PARAM_KDF_UKM */
    rc = ibmca_param_get_octet_string(ctx->provctx, params,
                                      OSSL_EXCHANGE_PARAM_KDF_UKM,
                                      &ukm, &ukmlen);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (ctx->ec.derive.kdf_ukm != NULL)
            P_CLEAR_FREE(ctx->provctx, ctx->ec.derive.kdf_ukm,
                         ctx->ec.derive.kdf_ukmlen);
        ctx->ec.derive.kdf_ukm = ukm;
        ctx->ec.derive.kdf_ukmlen = ukmlen;
    }

    return 1;
}

static const OSSL_PARAM ibmca_keyexch_ec_gettable_params[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keyexch_ec_gettable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    for (p = ibmca_keyexch_ec_gettable_params;
                                    p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_keyexch_ec_gettable_params;
}

static const OSSL_PARAM ibmca_keyexch_ec_settable_params[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keyexch_ec_settable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    for (p = ibmca_keyexch_ec_settable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_keyexch_ec_settable_params;
}

static const OSSL_DISPATCH ibmca_ec_keyexch_functions[] = {
    /* Context management */
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))ibmca_keyexch_ec_newctx },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))ibmca_op_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))ibmca_op_dupctx },

    /* Shared secret derivation */
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))ibmca_keyexch_ec_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))ibmca_keyexch_ec_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))ibmca_keyexch_ec_derive },

    /* Key Exchange parameters */
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        (void (*)(void))ibmca_keyexch_ec_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        (void (*)(void))ibmca_keyexch_ec_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
            (void (*)(void))ibmca_keyexch_ec_get_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        (void (*)(void))ibmca_keyexch_ec_gettable_ctx_params },

    { 0, NULL }
};

const OSSL_ALGORITHM ibmca_ec_keyexch[] = {
    { "ECDH", NULL, ibmca_ec_keyexch_functions, "IBMCA ECDH implementation" },
    { NULL, NULL, NULL, NULL }
};
