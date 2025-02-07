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
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

#include "p_ibmca.h"

static OSSL_FUNC_signature_newctx_fn ibmca_signature_ec_newctx;
static OSSL_FUNC_signature_sign_init_fn ibmca_signature_ec_sign_init;
static OSSL_FUNC_signature_sign_fn ibmca_signature_ec_sign;
static OSSL_FUNC_signature_verify_init_fn ibmca_signature_ec_verify_init;
static OSSL_FUNC_signature_verify_fn ibmca_signature_ec_verify;
static OSSL_FUNC_signature_digest_sign_init_fn
                                ibmca_signature_ec_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn
                                ibmca_signature_ec_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn
                                ibmca_signature_ec_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn
                                ibmca_signature_ec_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_final_fn
                                ibmca_signature_ec_digest_verify_final;
static OSSL_FUNC_signature_get_ctx_params_fn ibmca_signature_ec_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn
                                ibmca_signature_ec_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn ibmca_signature_ec_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn
                                ibmca_signature_ec_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn
                                ibmca_signature_ec_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn
                                ibmca_signature_ec_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn
                               ibmca_signature_ec_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn
                                ibmca_signature_ec_settable_ctx_md_params;
#ifdef EVP_PKEY_OP_SIGNMSG
static OSSL_FUNC_signature_sign_message_update_fn
                                ibmca_signature_ec_signverify_message_update;
static OSSL_FUNC_signature_sign_message_final_fn
                                ibmca_signature_ec_sign_message_final;
static OSSL_FUNC_signature_verify_message_final_fn
                                ibmca_signature_ec_verify_message_final;
static OSSL_FUNC_signature_query_key_types_fn
                                ibmca_signature_ec_query_key_types;
#endif

static void ibmca_signature_ec_free_cb(struct ibmca_op_ctx *ctx);
static int ibmca_signature_ec_dup_cb(const struct ibmca_op_ctx *ctx,
                                     struct ibmca_op_ctx *new_ctx);

#ifdef EVP_PKEY_OP_SIGNMSG
static const char *ibmca_signature_ec_keytypes[] = { "EC", NULL };

static const char **ibmca_signature_ec_query_key_types(void)
{
    return ibmca_signature_ec_keytypes;
}
#endif

static void*ibmca_signature_ec_newctx(void *vprovctx, const char *propq)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    struct ibmca_op_ctx *opctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    opctx = ibmca_op_newctx(provctx, propq, EVP_PKEY_EC,
                            ibmca_signature_ec_free_cb,
                            ibmca_signature_ec_dup_cb);
    if (opctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_op_newctx failed");
        return NULL;
    }

    ibmca_debug_ctx(provctx, "opctx: %p", opctx);

    return opctx;
}

static void ibmca_signature_ec_free_cb(struct ibmca_op_ctx *ctx)
{
    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->ec.signature.md != NULL)
        EVP_MD_free(ctx->ec.signature.md);
    ctx->ec.signature.md = NULL;
    ctx->ec.signature.set_md_allowed = true;

    ctx->ec.signature.md_size = 0;

    if (ctx->ec.signature.md_ctx != NULL)
        EVP_MD_CTX_free(ctx->ec.signature.md_ctx);
    ctx->ec.signature.md_ctx = NULL;

    ctx->ec.signature.nonce_type = 0;

    if (ctx->ec.signature.signature != NULL)
        P_FREE(ctx->provctx, ctx->ec.signature.signature);
    ctx->ec.signature.signature = NULL;
    ctx->ec.signature.signature_len = 0;
}

static int ibmca_signature_ec_dup_cb(const struct ibmca_op_ctx *ctx,
                                     struct ibmca_op_ctx *new_ctx)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p new_ctx: %p", ctx, new_ctx);

    new_ctx->ec.signature.md = ctx->ec.signature.md;
    if (new_ctx->ec.signature.md != NULL) {
        if (EVP_MD_up_ref(new_ctx->ec.signature.md) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_up_ref failed");
            return 0;
        }
    }

    new_ctx->ec.signature.set_md_allowed = ctx->ec.signature.set_md_allowed;
    new_ctx->ec.signature.md_size = ctx->ec.signature.md_size;

    if (ctx->ec.signature.md_ctx != NULL) {
        new_ctx->ec.signature.md_ctx = EVP_MD_CTX_new();
        if (new_ctx->ec.signature.md_ctx == NULL ||
            EVP_MD_CTX_copy(new_ctx->ec.signature.md_ctx,
                            ctx->ec.signature.md_ctx) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_CTX_copy failed");
            return 0;
        }
    }

    new_ctx->ec.signature.nonce_type = ctx->ec.signature.nonce_type;

    new_ctx->ec.signature.signature_len = 0;
    new_ctx->ec.signature.signature = NULL;
    if (ctx->ec.signature.signature != NULL) {
        new_ctx->ec.signature.signature = P_MEMDUP(ctx->provctx,
                                               ctx->ec.signature.signature,
                                               ctx->ec.signature.signature_len);
        if (new_ctx->ec.signature.signature == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED,
                             "P_MEMDUP failed");
            return 0;
        }
        new_ctx->ec.signature.signature_len = ctx->ec.signature.signature_len;
    }

    return 1;
}

static int ibmca_signature_ec_set_md(struct ibmca_op_ctx *ctx,
                                     const char *mdname, int md_nid,
                                     const char *props)
{
    EVP_MD *md;

    if (mdname == NULL)
        mdname = OBJ_nid2sn(md_nid);

    ibmca_debug_op_ctx(ctx, "ctx: %p mdname: '%s'", ctx, mdname);

    if (!ctx->ec.signature.set_md_allowed) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Digest not allowed to be set in the current state");
        return 0;
    }

    md = EVP_MD_fetch(ctx->provctx->libctx, mdname,
                      props != NULL ? props : ctx->propq);
    if (md == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Digest '%s' could not be fetched", mdname);
        return 0;
    }

    if ((EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) != 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "XOF Digest '%s' is not allowed", mdname);
        EVP_MD_free(md);
        return 0;
    }

    if (ctx->ec.signature.md != NULL)
        EVP_MD_free(ctx->ec.signature.md);

    ctx->ec.signature.md = md;
    ctx->ec.signature.md_size = EVP_MD_get_size(md);

    return 1;
}

static int ibmca_signature_ec_op_init(struct ibmca_op_ctx *ctx,
                                      struct ibmca_key *key,
                                      const OSSL_PARAM params[],
                                      int operation, const char *mdname)
{
    const OSSL_PARAM *p;

    if (ctx == NULL || key == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p operation: %d mdname: %s", ctx,
                       key, operation, mdname != NULL ? mdname : "(null)");
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    if (ibmca_op_init(ctx, key, operation) == 0) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_init failed");
        return 0;
    }

    /* Setup defaults for this context */
    ibmca_signature_ec_free_cb(ctx);

    ctx->ec.signature.set_md_allowed = true;

    if (mdname != NULL) {
        if (ibmca_signature_ec_set_md(ctx, mdname, 0, NULL) == 0)
            return 0;
    }

    if (params != NULL) {
        if (ibmca_signature_ec_set_ctx_params(ctx, params) == 0) {
            ibmca_debug_op_ctx(ctx,
                    "ERROR: ibmca_signature_ec_set_ctx_params failed");
            return 0;
        }
    }

    switch (operation) {
    case EVP_PKEY_OP_SIGNCTX:
    case EVP_PKEY_OP_VERIFYCTX:
#ifdef EVP_PKEY_OP_SIGNMSG
    case EVP_PKEY_OP_SIGNMSG:
    case EVP_PKEY_OP_VERIFYMSG:
#endif
        ctx->ec.signature.md_ctx = EVP_MD_CTX_new();
        if (ctx->ec.signature.md_ctx == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_CTX_new failed");
            return 0;
        }

        if (EVP_DigestInit_ex2(ctx->ec.signature.md_ctx,
                               ctx->ec.signature.md, params) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_DigestInit_ex2 failed");
            return 0;
        }

        ctx->ec.signature.set_md_allowed = false;
        break;
    }

    return 1;
}

static int ibmca_signature_ec_sign_init(void *vctx, void *vkey,
                                        const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_ec_op_init(ctx, key, params,
                                      EVP_PKEY_OP_SIGN, NULL);
}

static int ibmca_signature_ec_verify_init(void *vctx, void *vkey,
                                          const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_ec_op_init(ctx, key, params,
                                      EVP_PKEY_OP_VERIFY, NULL);
}

static int ibmca_signature_ec_sign_fallback(struct ibmca_op_ctx *ctx,
                                            unsigned char *sig, size_t *siglen,
                                            const unsigned char *tbs,
                                            size_t tbslen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    OSSL_PARAM params[3];
    const char *md_name;
#endif
    int rc = 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu sig: %p siglen: %lu",
                       ctx, ctx->key, tbslen, sig, *siglen);

    pkey = ibmca_new_fallback_pkey(ctx->key);
    if (pkey == NULL) {
        ibmca_debug_op_ctx(ctx,"ERROR: ibmca_new_fallback_pkey failed");
        goto out;
    }

    pctx = ibmca_new_fallback_pkey_ctx(ctx->provctx, pkey, NULL);
    if (pctx == NULL) {
        ibmca_debug_op_ctx(ctx,"ERROR: ibmca_new_fallback_pkey_ctx failed");
        goto out;
    }

    if (EVP_PKEY_sign_init(pctx) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_sign_init failed");
        goto out;
    }

    if (ibmca_check_fallback_provider(ctx->provctx, pctx) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_check_fallback_provider failed");
        goto out;
    }

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    ibmca_debug_op_ctx(ctx, "nonce_type: %u", ctx->ec.signature.nonce_type);

    if (ctx->ec.signature.nonce_type != 0) {
        md_name = EVP_MD_get0_name(ctx->ec.signature.md);
        if (md_name == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Digest must be set when using deterministic "
                             "signatures");
            goto out;
        }

        ibmca_debug_op_ctx(ctx, "md_name: %s", md_name);

        params[0] = OSSL_PARAM_construct_utf8_string(
                                              OSSL_SIGNATURE_PARAM_DIGEST,
                                              (char *)md_name, strlen(md_name));
        params[1] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE,
                                              &ctx->ec.signature.nonce_type);
        params[2] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_PKEY_CTX_set_params failed");
            goto out;
        }
    }
#endif

    if (EVP_PKEY_sign(pctx, sig, siglen, tbs, tbslen) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_sign failed");
        goto out;
    }

    rc = 1;

out:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return rc;
}

static int ibmca_signature_ec_sign(void *vctx,
                                   unsigned char *sig, size_t *siglen,
                                   size_t sigsize, const unsigned char *tbs,
                                   size_t tbslen)
{
    struct ibmca_op_ctx *ctx = vctx;
    ECDSA_SIG *ecdsa_sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    unsigned char *p;
    int rc = 0;

    if (ctx == NULL || siglen == NULL || tbs == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu sigsize: %lu",
                       ctx, ctx->key, tbslen, sigsize);

    if (ctx->key == NULL ||
        (ctx->operation != EVP_PKEY_OP_SIGN &&
#ifdef EVP_PKEY_OP_SIGNMSG
         ctx->operation != EVP_PKEY_OP_SIGNCTX &&
         ctx->operation != EVP_PKEY_OP_SIGNMSG)) {
#else
         ctx->operation != EVP_PKEY_OP_SIGNCTX)) {
#endif
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "sign operation not initialized");
        return 0;
    }

#ifdef EVP_PKEY_OP_SIGNMSG
     if (ctx->operation == EVP_PKEY_OP_SIGNMSG) {
         rc = ibmca_signature_ec_signverify_message_update(ctx, tbs, tbslen);
         if (rc != 1)
             goto out;

         rc = ibmca_signature_ec_sign_message_final(ctx, sig, siglen, sigsize);
         goto out;
     }
#endif

    *siglen = ctx->key->get_max_param_size(ctx->key);

    if (sig == NULL) { /* size query */
        rc = 1;
        goto out;
    }

    if (sigsize < *siglen) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Output buffer too small");
        goto out;
    }

    if (ctx->ec.signature.md_size != 0) {
        if (tbslen != ctx->ec.signature.md_size) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid input data size: %lu expected: %d",
                             tbslen, ctx->ec.signature.md_size);
            goto out;
        }
    }

    if (ibmca_op_alloc_tbuf(ctx, ctx->key->ec.prime_size * 2) == 0) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
        goto out;
    }

    if (ctx->key->ec.fallback.d != NULL || ctx->ec.signature.nonce_type != 0) {
        rc = ibmca_signature_ec_sign_fallback(ctx, sig, siglen, tbs, tbslen);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_signature_ec_sign_fallback failed");
            rc = 0;
        }
        goto out;
    }

    rc = ica_ecdsa_sign(ctx->provctx->ica_adapter, ctx->key->ec.key,
                        tbs, tbslen, ctx->tbuf, ctx->tbuf_len);
    if (rc != 0) {
        ibmca_debug_op_ctx(ctx, "ica_ecdsa_sign failed with: %s", strerror(rc));

        rc = ibmca_signature_ec_sign_fallback(ctx, sig, siglen, tbs, tbslen);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_signature_ec_sign_fallback failed");
            rc = 0;
        }
        goto out;
    }

    r = BN_bin2bn(ctx->tbuf, ctx->key->ec.prime_size, NULL);
    s = BN_bin2bn(ctx->tbuf + ctx->key->ec.prime_size,
                  ctx->key->ec.prime_size, NULL);
    if (r == NULL || s == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR, "BN_bin2bn failed");
        goto out;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL ||
        ECDSA_SIG_set0(ecdsa_sig, r, s) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "ECDSA_SIG_new/ECDSA_SIG_set0 failed");
        goto out;
    }
    r = NULL;
    s = NULL;

    p = sig;
    *siglen = i2d_ECDSA_SIG(ecdsa_sig, &p);
    if (*siglen <= 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR, "i2d_ECDSA_SIG failed");
        goto out;
    }

    rc = 1;

 out:
     if (ecdsa_sig != NULL)
         ECDSA_SIG_free(ecdsa_sig);
     if (r != NULL)
         BN_free(r);
     if (s != NULL)
         BN_free(s);

    ibmca_debug_op_ctx(ctx, "siglen: %lu rc: %d", *siglen, rc);

    return rc;
}

static int ibmca_signature_ec_verify_fallback(struct ibmca_op_ctx *ctx,
                                              const unsigned char *sig,
                                              size_t siglen,
                                              const unsigned char *tbs,
                                              size_t tbslen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc = 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu sig: %p siglen: %lu",
                       ctx, ctx->key, tbslen, sig, siglen);

    pkey = ibmca_new_fallback_pkey(ctx->key);
    if (pkey == NULL) {
        ibmca_debug_op_ctx(ctx,"ERROR: ibmca_new_fallback_pkey failed");
        goto out;
    }

    pctx = ibmca_new_fallback_pkey_ctx(ctx->provctx, pkey, NULL);
    if (pctx == NULL) {
        ibmca_debug_op_ctx(ctx,"ERROR: ibmca_new_fallback_pkey_ctx failed");
        goto out;
    }

    if (EVP_PKEY_verify_init(pctx) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_verify_init failed");
        goto out;
    }

    if (ibmca_check_fallback_provider(ctx->provctx, pctx) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_check_fallback_provider failed");
        goto out;
    }

    rc = EVP_PKEY_verify(pctx, sig, siglen, tbs, tbslen);
    if (rc < 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_verify failed with %d", rc);
        goto out;
    }
    if (rc == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_SIGNATURE_BAD, "Signature bad");
        goto out;
    }

    rc = 1;

out:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return rc;
}

static int ibmca_signature_ec_verify(void *vctx,
                                     const unsigned char *sig, size_t siglen,
                                     const unsigned char *tbs, size_t tbslen)
{
    struct ibmca_op_ctx *ctx = vctx;
    ECDSA_SIG *ecdsa_sig = NULL;
    const BIGNUM *r, *s;
    const unsigned char *p;
    unsigned char *der = NULL;
    int derlen = -1;
#ifdef EVP_PKEY_OP_SIGNMSG
    OSSL_PARAM params[2];
#endif
    int rc = -1;

    if (ctx == NULL || sig == NULL || tbs == NULL)
        return -1;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu siglen: %lu",
                       ctx, ctx->key, tbslen, siglen);

    if (ctx->key == NULL ||
        (ctx->operation != EVP_PKEY_OP_VERIFY &&
#ifdef EVP_PKEY_OP_SIGNMSG
         ctx->operation != EVP_PKEY_OP_VERIFYCTX &&
         ctx->operation != EVP_PKEY_OP_VERIFYMSG)) {
#else
         ctx->operation != EVP_PKEY_OP_VERIFYCTX)) {
#endif
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "verify operation not initialized");
        return -1;
    }

#ifdef EVP_PKEY_OP_SIGNMSG
    if (ctx->operation == EVP_PKEY_OP_VERIFYMSG) {
        params[0] = OSSL_PARAM_construct_octet_string(
                                          OSSL_SIGNATURE_PARAM_SIGNATURE,
                                          (unsigned char *)sig, siglen);
        params[1] = OSSL_PARAM_construct_end();

        rc = ibmca_signature_ec_set_ctx_params(ctx, params);
        if (rc != 1)
            goto out;

        rc = ibmca_signature_ec_signverify_message_update(ctx, tbs, tbslen);
        if (rc != 1)
            goto out;

        rc = ibmca_signature_ec_verify_message_final(ctx);
        goto out;
    }
#endif

    if (ctx->ec.signature.md_size != 0) {
        if (tbslen != ctx->ec.signature.md_size) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid input data size: %lu expected: %d",
                             tbslen, ctx->ec.signature.md_size);
            goto out;
        }
    }

    if (ibmca_op_alloc_tbuf(ctx, ctx->key->ec.prime_size * 2) == 0) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
        goto out;
    }

    if (ctx->key->ec.fallback.x != NULL && ctx->key->ec.fallback.y) {
        rc = ibmca_signature_ec_verify_fallback(ctx, sig, siglen, tbs, tbslen);
        goto out;
    }

    p = sig;
    if (d2i_ECDSA_SIG(&ecdsa_sig, &p, siglen) == NULL ||
        ecdsa_sig == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_SIGNATURE_BAD, "d2i_ECDSA_SIG failed");
        goto out;
    }

    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(ecdsa_sig, &der);
    if ((size_t)derlen != siglen || memcmp(sig, der, derlen) != 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_SIGNATURE_BAD,
                         "Signature encoding wrong");
        goto out;
    }

    r = ECDSA_SIG_get0_r(ecdsa_sig);
    s = ECDSA_SIG_get0_s(ecdsa_sig);
    if (r == NULL || s == NULL ||
        BN_bn2binpad(r, ctx->tbuf, ctx->key->ec.prime_size) <= 0 ||
        BN_bn2binpad(s, ctx->tbuf + ctx->key->ec.prime_size,
                     ctx->key->ec.prime_size) <= 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "BN_bn2binpad failed");
        goto out;
    }

    rc = ica_ecdsa_verify(ctx->provctx->ica_adapter, ctx->key->ec.key,
                          tbs, tbslen, ctx->tbuf, ctx->tbuf_len);
    if (rc == EFAULT) {
        put_error_op_ctx(ctx, IBMCA_ERR_SIGNATURE_BAD, "Bad signature");
        rc = 0;
        goto out;
    }
    if (rc != 0) {
        ibmca_debug_op_ctx(ctx, "ica_ecdsa_verify failed with: %s",
                           strerror(rc));

        rc = ibmca_signature_ec_verify_fallback(ctx, sig, siglen, tbs, tbslen);
        goto out;
    }

    rc = 1;

out:
    if (ecdsa_sig != NULL)
        ECDSA_SIG_free(ecdsa_sig);
    if (der != NULL)
        P_FREE(ctx->provctx, der);

    ibmca_debug_op_ctx(ctx, "rc: %d", rc);

    return rc;
}

static int ibmca_signature_ec_get_algid(struct ibmca_op_ctx *ctx,
                                        OSSL_PARAM *p)
{
    ASN1_OBJECT *oid = NULL;
    X509_ALGOR * algid = NULL;
    unsigned char *aid_buf = NULL;
    size_t aid_len;

    if (ctx->ec.signature.md == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM, "No digest is set");
        return 0;
    }

    switch (EVP_MD_get_type(ctx->ec.signature.md)) {
    case NID_sha1:
        oid = OBJ_nid2obj(NID_ecdsa_with_SHA1);
        break;
    case NID_sha224:
         oid = OBJ_nid2obj(NID_ecdsa_with_SHA224);
         break;
    case NID_sha256:
         oid = OBJ_nid2obj(NID_ecdsa_with_SHA256);
         break;
    case NID_sha384:
         oid = OBJ_nid2obj(NID_ecdsa_with_SHA384);
         break;
    case NID_sha512:
         oid = OBJ_nid2obj(NID_ecdsa_with_SHA512);
         break;
    case NID_sha3_224:
         oid = OBJ_nid2obj(NID_ecdsa_with_SHA3_224);
         break;
    case NID_sha3_256:
         oid = OBJ_nid2obj(NID_ecdsa_with_SHA3_256);
         break;
    case NID_sha3_384:
         oid = OBJ_nid2obj(NID_ecdsa_with_SHA3_384);
         break;
    case NID_sha3_512:
         oid = OBJ_nid2obj(NID_ecdsa_with_SHA3_512);
         break;
    default:
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "AlgorithmID not supported for digest '%s'",
                         EVP_MD_get0_name(ctx->ec.signature.md));
        return 0;
    }

    algid = X509_ALGOR_new();
    if (algid == NULL ||
        X509_ALGOR_set0(algid, oid, V_ASN1_UNDEF, NULL) == 0 ||
        (aid_len = i2d_X509_ALGOR(algid, &aid_buf)) <= 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "X509_ALGOR_new/X509_ALGOR_set0/i2d_X509_ALGOR failed");
        X509_ALGOR_free(algid);
        return 0;
    }

    if (OSSL_PARAM_set_octet_string(p, aid_buf, aid_len) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "Failed to return param '%s'",
                         OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        P_FREE(ctx->provctx, aid_buf);
        X509_ALGOR_free(algid);
        return 0;
    }
    P_FREE(ctx->provctx, aid_buf);
    X509_ALGOR_free(algid);

    ibmca_debug_op_ctx(ctx, "param '%s': [octet string] (%lu bytes)",
                       OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid_len);

    return 1;
}

static int ibmca_signature_ec_get_ctx_params(void *vctx,
                                             OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    OSSL_PARAM *p;
    const char *name = NULL;
    int rc;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    /* OSSL_SIGNATURE_PARAM_ALGORITHM_ID */
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && ibmca_signature_ec_get_algid(ctx, p) == 0)
        return 0;

    /* OSSL_SIGNATURE_PARAM_DIGEST */
    if (ctx->ec.signature.md != NULL)
        name = EVP_MD_get0_name(ctx->ec.signature.md);
    else
        name = "";
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_SIGNATURE_PARAM_DIGEST, name);
    if (rc == 0)
       return 0;

    /* OSSL_SIGNATURE_PARAM_DIGEST_SIZE */
    rc = ibmca_param_build_set_size_t(ctx->provctx, NULL, params,
                                      OSSL_SIGNATURE_PARAM_DIGEST,
                                      ctx->ec.signature.md_size);
    if (rc == 0)
       return 0;

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    /* OSSL_SIGNATURE_PARAM_NONCE_TYPE */
    rc = ibmca_param_build_set_uint(ctx->provctx, NULL, params,
                                    OSSL_SIGNATURE_PARAM_NONCE_TYPE,
                                    ctx->ec.signature.nonce_type);
    if (rc == 0)
       return 0;
#endif

    return 1;
}

static int ibmca_signature_ec_set_ctx_params(void *vctx,
                                             const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    const OSSL_PARAM *p;
    const char *name, *props = NULL;
    size_t md_size;
#ifdef EVP_PKEY_OP_SIGNMSG
    size_t len;
    unsigned char *ptr = NULL;
#endif
    int rc;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    switch (ctx->operation) {
    case EVP_PKEY_OP_SIGN:
    case EVP_PKEY_OP_VERIFY:
    case EVP_PKEY_OP_VERIFYRECOVER:
    case EVP_PKEY_OP_SIGNCTX:
    case EVP_PKEY_OP_VERIFYCTX:
        /* OSSL_SIGNATURE_PARAM_PROPERTIES */
        rc = ibmca_param_get_utf8(ctx->provctx, params,
                                  OSSL_SIGNATURE_PARAM_PROPERTIES, &props);
        if (rc == 0)
            return 0;

        /* OSSL_SIGNATURE_PARAM_DIGEST */
        rc = ibmca_param_get_utf8(ctx->provctx, params,
                                  OSSL_SIGNATURE_PARAM_DIGEST, &name);
        if (rc == 0)
            return 0;
        if (rc > 0 &&
            ibmca_signature_ec_set_md(ctx, name, 0, props) == 0)
            return 0;

        /* OSSL_SIGNATURE_PARAM_DIGEST_SIZE */
        rc = ibmca_param_get_size_t(ctx->provctx, params,
                                    OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &md_size);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            if (!ctx->ec.signature.set_md_allowed) {
                put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                 "Digest size not allowed to be set in the "
                                 "current state");
                return 0;
            }
            ctx->ec.signature.md_size = md_size;
        }
        break;

#ifdef EVP_PKEY_OP_SIGNMSG
    case EVP_PKEY_OP_SIGNMSG:
    case EVP_PKEY_OP_VERIFYMSG:
        /* OSSL_SIGNATURE_PARAM_SIGNATURE */
        rc = ibmca_param_get_octet_string(ctx->provctx, params,
                                          OSSL_SIGNATURE_PARAM_SIGNATURE,
                                          (void **)&ptr, &len);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            if (ctx->ec.signature.signature != NULL)
                P_CLEAR_FREE(ctx->provctx, ctx->ec.signature.signature,
                        ctx->ec.signature.signature_len);
            ctx->ec.signature.signature = ptr;
            ctx->ec.signature.signature_len = len;
        }
        break;
#endif
    }

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    /* OSSL_SIGNATURE_PARAM_NONCE_TYPE */
    rc = ibmca_param_get_uint(ctx->provctx, params,
                              OSSL_SIGNATURE_PARAM_NONCE_TYPE,
                              &ctx->ec.signature.nonce_type);
    if (rc == 0)
        return 0;
#endif

    return 1;
}

static const OSSL_PARAM ibmca_signature_ec_gettable_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, NULL),
#endif
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_signature_ec_gettable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    for (p = ibmca_signature_ec_gettable_params;
                                    p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_signature_ec_gettable_params;
}

static const OSSL_PARAM ibmca_signature_ec_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, NULL),
#endif
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_signature_ec_settable_params_no_digest[] = {
    OSSL_PARAM_END
};

#ifdef EVP_PKEY_OP_SIGNMSG
static const OSSL_PARAM ibmca_signature_ec_sigalg_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, NULL),
#endif
    OSSL_PARAM_END
};
#endif

static const OSSL_PARAM *ibmca_signature_ec_settable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p, *params;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

#ifdef EVP_PKEY_OP_SIGNMSG
    if (ctx != NULL && ctx->operation == EVP_PKEY_OP_VERIFYMSG)
        params = ibmca_signature_ec_sigalg_settable_params;
    else if (ctx != NULL && ctx->operation == EVP_PKEY_OP_SIGNMSG)
        params = NULL;
    else if (ctx == NULL || ctx->ec.signature.set_md_allowed)
#else
    if (ctx == NULL || ctx->ec.signature.set_md_allowed)
#endif
        params = ibmca_signature_ec_settable_params;
    else
        params = ibmca_signature_ec_settable_params_no_digest;

    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return params;
}

#ifdef EVP_PKEY_OP_SIGNMSG
static int ibmca_signature_ec_signverify_message_update(void *vctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_digest_signverify_update(ctx, ctx->ec.signature.md_ctx,
                                          data, datalen);
}

static int ibmca_signature_ec_sign_message_final(void *vctx,
                                                 unsigned char *sig,
                                                 size_t *siglen,
                                                 size_t sigsize)
{
    struct ibmca_op_ctx *ctx = vctx;
    int rc;

    ctx->operation = EVP_PKEY_OP_SIGNCTX;
    rc = ibmca_digest_sign_final(ctx, ctx->ec.signature.md_ctx,
                                 ibmca_signature_ec_sign,
                                sig, siglen, sigsize);
    ctx->operation = EVP_PKEY_OP_SIGNMSG;

    return rc;
}

static int ibmca_signature_ec_verify_message_final(void *vctx)
{
    struct ibmca_op_ctx *ctx = vctx;
    int rc;

    ctx->operation = EVP_PKEY_OP_VERIFYCTX;
    rc = ibmca_digest_verify_final(ctx, ctx->ec.signature.md_ctx,
                                   ibmca_signature_ec_verify,
                                   ctx->ec.signature.signature,
                                   ctx->ec.signature.signature_len);
    ctx->operation = EVP_PKEY_OP_VERIFYMSG;

    return rc;
}
#endif

static int ibmca_signature_ec_digest_sign_init(void *vctx, const char *mdname,
                                               void *vkey,
                                               const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_ec_op_init(ctx, key, params,
                                      EVP_PKEY_OP_SIGNCTX, mdname);
}

static int ibmca_signature_ec_digest_verify_init(void *vctx, const char *mdname,
                                                 void *vkey,
                                                 const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_ec_op_init(ctx, key, params,
                                      EVP_PKEY_OP_VERIFYCTX, mdname);
}

static int ibmca_signature_ec_digest_signverify_update(void *vctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_digest_signverify_update(ctx, ctx->ec.signature.md_ctx,
                                          data, datalen);
}

static int ibmca_signature_ec_digest_sign_final(void *vctx,
                                                unsigned char *sig,
                                                size_t *siglen,
                                                size_t sigsize)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_digest_sign_final(ctx, ctx->ec.signature.md_ctx,
                                   ibmca_signature_ec_sign,
                                   sig, siglen, sigsize);
}

static int ibmca_signature_ec_digest_verify_final(void *vctx,
                                                  const unsigned char *sig,
                                                  size_t siglen)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_digest_verify_final(ctx, ctx->ec.signature.md_ctx,
                                     ibmca_signature_ec_verify,
                                     sig, siglen);
}

static int ibmca_signature_ec_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_get_ctx_md_params(ctx, ctx->ec.signature.md_ctx, params);
}

static int ibmca_signature_ec_set_ctx_md_params(void *vctx,
                                                const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_set_ctx_md_params(ctx, ctx->ec.signature.md_ctx, params);
}

static const OSSL_PARAM *ibmca_signature_ec_gettable_ctx_md_params(void *vctx)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_gettable_ctx_md_params(ctx, ctx->ec.signature.md);
}

static const OSSL_PARAM *ibmca_signature_ec_settable_ctx_md_params(void *vctx)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_settable_ctx_md_params(ctx, ctx->ec.signature.md);
}

static const OSSL_DISPATCH ibmca_ecdsa_signature_functions[] = {
    /* Signature context constructor, destructor */
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ibmca_signature_ec_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ibmca_op_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ibmca_op_dupctx },
    /* Signing */
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,
            (void (*)(void))ibmca_signature_ec_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ibmca_signature_ec_sign },
    /* Verifying */
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
            (void (*)(void))ibmca_signature_ec_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ibmca_signature_ec_verify },
    /* Digest Sign */
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
            (void (*)(void))ibmca_signature_ec_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
            (void (*)(void))ibmca_signature_ec_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
            (void (*)(void))ibmca_signature_ec_digest_sign_final },
    /* Digest Verify */
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
            (void (*)(void))ibmca_signature_ec_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
            (void (*)(void))ibmca_signature_ec_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
            (void (*)(void))ibmca_signature_ec_digest_verify_final },
    /* Signature parameters */
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
            (void (*)(void))ibmca_signature_ec_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
            (void (*)(void))ibmca_signature_ec_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void
            (*)(void))ibmca_signature_ec_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
            (void (*)(void))ibmca_signature_ec_settable_ctx_params },
    /* MD parameters */
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
            (void (*)(void))ibmca_signature_ec_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        (void (*)(void))ibmca_signature_ec_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
            (void (*)(void))ibmca_signature_ec_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        (void (*)(void))ibmca_signature_ec_settable_ctx_md_params },
    { 0, NULL }
};

#ifdef EVP_PKEY_OP_SIGNMSG
#define IBMCA_IMPL_ECDSA_SIGALG(md, MD)                                        \
    static OSSL_FUNC_signature_sign_init_fn                                    \
                     ibmca_signature_ec_##md##_sign_init;                      \
    static OSSL_FUNC_signature_verify_init_fn                                  \
                     ibmca_signature_ec_##md##_verify_init;                    \
    static OSSL_FUNC_signature_sign_message_init_fn                            \
                     ibmca_signature_ec_##md##_sign_message_init;              \
    static OSSL_FUNC_signature_verify_message_init_fn                          \
                     ibmca_signature_ec_##md##_verify_message_init;            \
                                                                               \
    static int ibmca_signature_ec_##md##_sign_init(void *vctx, void *vkey,     \
                                                   const OSSL_PARAM params[])  \
    {                                                                          \
        struct ibmca_op_ctx *ctx = vctx;                                       \
        struct ibmca_key *key = vkey;                                          \
                                                                               \
        return ibmca_signature_ec_op_init(ctx, key, params,                    \
                                          EVP_PKEY_OP_SIGN, #MD);              \
    }                                                                          \
                                                                               \
    static int ibmca_signature_ec_##md##_verify_init(void *vctx, void *vkey,   \
                                                     const OSSL_PARAM params[])\
    {                                                                          \
        struct ibmca_op_ctx *ctx = vctx;                                       \
        struct ibmca_key *key = vkey;                                          \
                                                                               \
        return ibmca_signature_ec_op_init(ctx, key, params,                    \
                                          EVP_PKEY_OP_VERIFY, #MD);            \
    }                                                                          \
                                                                               \
    static int ibmca_signature_ec_##md##_sign_message_init(                    \
                                                    void *vctx, void *vkey,    \
                                                    const OSSL_PARAM params[]) \
    {                                                                          \
        struct ibmca_op_ctx *ctx = vctx;                                       \
        struct ibmca_key *key = vkey;                                          \
                                                                               \
        return ibmca_signature_ec_op_init(ctx, key, params,                    \
                                          EVP_PKEY_OP_SIGNMSG, #MD);           \
    }                                                                          \
                                                                               \
       static int ibmca_signature_ec_##md##_verify_message_init(               \
                                                    void *vctx, void *vkey,    \
                                                    const OSSL_PARAM params[]) \
       {                                                                       \
           struct ibmca_op_ctx *ctx = vctx;                                    \
           struct ibmca_key *key = vkey;                                       \
                                                                               \
           return ibmca_signature_ec_op_init(ctx, key, params,                 \
                                             EVP_PKEY_OP_VERIFYMSG, #MD);      \
       }                                                                       \
                                                                               \
    static const OSSL_DISPATCH ibmca_ecdsa_##md##_signature_functions[] = {    \
        /* Signature context constructor, destructor */                        \
        { OSSL_FUNC_SIGNATURE_NEWCTX,                                          \
                (void (*)(void))ibmca_signature_ec_newctx },                   \
        { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ibmca_op_freectx },     \
        { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ibmca_op_dupctx },       \
        { OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,                                 \
                (void (*)(void))ibmca_signature_ec_query_key_types },          \
        /* Signing */                                                          \
        { OSSL_FUNC_SIGNATURE_SIGN_INIT,                                       \
                (void (*)(void))ibmca_signature_ec_##md##_sign_init },         \
        { OSSL_FUNC_SIGNATURE_SIGN,                                            \
                (void (*)(void))ibmca_signature_ec_sign },                     \
        /* Verifying */                                                        \
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT,                                     \
                (void (*)(void))ibmca_signature_ec_##md##_verify_init },       \
        { OSSL_FUNC_SIGNATURE_VERIFY,                                          \
                (void (*)(void))ibmca_signature_ec_verify },                   \
        /* Sign Message */                                                     \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,                               \
                (void (*)(void))ibmca_signature_ec_##md##_sign_message_init }, \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,                             \
                (void (*)(void))ibmca_signature_ec_signverify_message_update },\
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,                              \
                (void (*)(void))ibmca_signature_ec_sign_message_final },       \
        /* Verify Message */                                                   \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,                             \
               (void (*)(void))ibmca_signature_ec_##md##_verify_message_init },\
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,                           \
                (void (*)(void))ibmca_signature_ec_signverify_message_update },\
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,                            \
                (void (*)(void))ibmca_signature_ec_verify_message_final },     \
        /* Signature parameters */                                             \
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                                  \
                (void (*)(void))ibmca_signature_ec_get_ctx_params },           \
        { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                             \
                (void (*)(void))ibmca_signature_ec_gettable_ctx_params },      \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                  \
                (void (*)(void))ibmca_signature_ec_set_ctx_params },           \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                             \
               (void (*)(void))ibmca_signature_ec_settable_ctx_params },       \
        { 0, NULL }                                                            \
    }

#define IBMCA_DEF_ECDSA_SIGALG(md, MD, names)                                  \
    { names, NULL, ibmca_ecdsa_##md##_signature_functions,                     \
      "IBMCA ECDSA " #MD " implementation" }

IBMCA_IMPL_ECDSA_SIGALG(sha1, SHA1);
IBMCA_IMPL_ECDSA_SIGALG(sha224, SHA2-224);
IBMCA_IMPL_ECDSA_SIGALG(sha256, SHA2-256);
IBMCA_IMPL_ECDSA_SIGALG(sha384, SHA2-384);
IBMCA_IMPL_ECDSA_SIGALG(sha512, SHA2-512);
IBMCA_IMPL_ECDSA_SIGALG(sha3_224, SHA3-224);
IBMCA_IMPL_ECDSA_SIGALG(sha3_256, SHA3-256);
IBMCA_IMPL_ECDSA_SIGALG(sha3_384, SHA3-384);
IBMCA_IMPL_ECDSA_SIGALG(sha3_512, SHA3-512);

#endif

const OSSL_ALGORITHM ibmca_ec_signature[] = {
    { "ECDSA", NULL, ibmca_ecdsa_signature_functions,
      "IBMCA ECDSA implementation" },
#ifdef EVP_PKEY_OP_SIGNMSG
    IBMCA_DEF_ECDSA_SIGALG(sha1, SHA1,
                           "ECDSA-SHA1:ECDSA-SHA-1:ecdsa-with-SHA1:"
                           "1.2.840.10045.4.1"),
    IBMCA_DEF_ECDSA_SIGALG(sha224, SHA2-224,
                           "ECDSA-SHA2-224:ECDSA-SHA224:ecdsa-with-SHA224:"
                           "1.2.840.10045.4.3.1"),
    IBMCA_DEF_ECDSA_SIGALG(sha256, SHA2-256,
                           "ECDSA-SHA2-256:ECDSA-SHA256:ecdsa-with-SHA256:"
                           "1.2.840.10045.4.3.2"),
    IBMCA_DEF_ECDSA_SIGALG(sha384, SHA2-384,
                           "ECDSA-SHA2-384:ECDSA-SHA384:ecdsa-with-SHA384:"
                           "1.2.840.10045.4.3.3"),
    IBMCA_DEF_ECDSA_SIGALG(sha512, SHA2-512,
                           "ECDSA-SHA2-512:ECDSA-SHA512:ecdsa-with-SHA512:"
                           "1.2.840.10045.4.3.4"),
    IBMCA_DEF_ECDSA_SIGALG(sha3_224, SHA3-224,
                           "ECDSA-SHA3-224:ecdsa_with_SHA3-224:"
                           "id-ecdsa-with-sha3-224:2.16.840.1.101.3.4.3.9"),
    IBMCA_DEF_ECDSA_SIGALG(sha3_256, SHA3-256,
                           "ECDSA-SHA3-256:ecdsa_with_SHA3-256:"
                           "id-ecdsa-with-sha3-256:2.16.840.1.101.3.4.3.10"),
    IBMCA_DEF_ECDSA_SIGALG(sha3_384, SHA3-384,
                           "ECDSA-SHA3-384:ecdsa_with_SHA3-384:"
                           "id-ecdsa-with-sha3-384:2.16.840.1.101.3.4.3.11"),
    IBMCA_DEF_ECDSA_SIGALG(sha3_512, SHA3-512,
                           "ECDSA-SHA3-512:ecdsa_with_SHA3-512:"
                           "id-ecdsa-with-sha3-512:2.16.840.1.101.3.4.3.12"),
#endif
    { NULL, NULL, NULL, NULL }
};
