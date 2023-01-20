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

static void ibmca_signature_ec_free_cb(struct ibmca_op_ctx *ctx);
static int ibmca_signature_ec_dup_cb(const struct ibmca_op_ctx *ctx,
                                     struct ibmca_op_ctx *new_ctx);

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
         ctx->operation != EVP_PKEY_OP_SIGNCTX)) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "sign operation not initialized");
        return 0;
    }

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

    if (ctx->key->ec.fallback.d != NULL) {
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
    int rc = -1;

    if (ctx == NULL || sig == NULL || tbs == NULL)
        return -1;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu siglen: %lu",
                       ctx, ctx->key, tbslen, siglen);

    if (ctx->key == NULL ||
        (ctx->operation != EVP_PKEY_OP_VERIFY &&
         ctx->operation != EVP_PKEY_OP_VERIFYCTX)) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "verify operation not initialized");
        return -1;
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
                                    OSSL_SIGNATURE_PARAM_NONCE_TYPE, 0);
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
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    unsigned int nonce_type;
#endif
    int rc;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

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
                             "Digest size not allowed to be set in the current state");
            return 0;
        }
        ctx->ec.signature.md_size = md_size;
    }

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
    /* OSSL_SIGNATURE_PARAM_NONCE_TYPE */
    rc = ibmca_param_get_uint(ctx->provctx, params,
                              OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type);
    if (rc == 0)
        return 0;
    /* Only allow nonce_type = 0 = random K */
    if (nonce_type != 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Deterministic signature is not supported");
        return 0;
    }
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

static const OSSL_PARAM *ibmca_signature_ec_settable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p, *params;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    if (ctx->ec.signature.set_md_allowed)
        params = ibmca_signature_ec_settable_params;
    else
        params = ibmca_signature_ec_settable_params_no_digest;

    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return params;
}

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

const OSSL_ALGORITHM ibmca_ec_signature[] = {
    { "ECDSA", NULL, ibmca_ecdsa_signature_functions,
      "IBMCA ECDSA implementation" },
    { NULL, NULL, NULL, NULL }
};
