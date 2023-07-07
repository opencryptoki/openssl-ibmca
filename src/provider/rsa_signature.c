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
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "p_ibmca.h"

static OSSL_FUNC_signature_newctx_fn ibmca_signature_rsa_newctx;
static OSSL_FUNC_signature_sign_init_fn ibmca_signature_rsa_sign_init;
static OSSL_FUNC_signature_sign_fn ibmca_signature_rsa_sign;
static OSSL_FUNC_signature_verify_init_fn ibmca_signature_rsa_verify_init;
static OSSL_FUNC_signature_verify_fn ibmca_signature_rsa_verify;
static OSSL_FUNC_signature_verify_recover_init_fn
                                ibmca_signature_rsa_verifyrecover_init;
static OSSL_FUNC_signature_verify_recover_fn ibmca_signature_rsa_verify_recover;
static OSSL_FUNC_signature_digest_sign_init_fn
                                ibmca_signature_rsa_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn
                                ibmca_signature_rsa_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn
                                ibmca_signature_rsa_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn
                                ibmca_signature_rsa_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_final_fn
                                ibmca_signature_rsa_digest_verify_final;
static OSSL_FUNC_signature_get_ctx_params_fn ibmca_signature_rsa_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn
                                ibmca_signature_rsa_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn ibmca_signature_rsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn
                                ibmca_signature_rsa_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn
                                ibmca_signature_rsa_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn
                                ibmca_signature_rsa_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn
                               ibmca_signature_rsa_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn
                                ibmca_signature_rsa_settable_ctx_md_params;

static void ibmca_signature_rsa_free_cb(struct ibmca_op_ctx *ctx);
static int ibmca_signature_rsa_dup_cb(const struct ibmca_op_ctx *ctx,
                                      struct ibmca_op_ctx *new_ctx);

static const struct ibmca_pss_params ibmca_rsa_pss_defaults =
                                            IBMCA_RSA_PSS_DEFAULTS;

static void *ibmca_signature_rsa_newctx(void *vprovctx, const char *propq)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    struct ibmca_op_ctx *opctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    opctx = ibmca_op_newctx(provctx, propq, EVP_PKEY_RSA,
                            ibmca_signature_rsa_free_cb,
                            ibmca_signature_rsa_dup_cb);
    if (opctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_op_newctx failed");
        return NULL;
    }

    ibmca_debug_ctx(provctx, "opctx: %p", opctx);

    return opctx;
}

static void ibmca_signature_rsa_free_cb(struct ibmca_op_ctx *ctx)
{
    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->rsa.signature.md != NULL)
        EVP_MD_free(ctx->rsa.signature.md);
    ctx->rsa.signature.md = NULL;
    ctx->rsa.signature.set_md_allowed = true;

    if (ctx->rsa.signature.mgf1_md != NULL)
        EVP_MD_free(ctx->rsa.signature.mgf1_md);
    ctx->rsa.signature.mgf1_md = NULL;

    if (ctx->rsa.signature.md_ctx != NULL)
        EVP_MD_CTX_free(ctx->rsa.signature.md_ctx);
    ctx->rsa.signature.md_ctx = NULL;
}

static int ibmca_signature_rsa_dup_cb(const struct ibmca_op_ctx *ctx,
                                      struct ibmca_op_ctx *new_ctx)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p new_ctx: %p", ctx, new_ctx);

    new_ctx->rsa.signature.pad_mode = ctx->rsa.signature.pad_mode;

    new_ctx->rsa.signature.md = ctx->rsa.signature.md;
    if (new_ctx->rsa.signature.md != NULL) {
        if (EVP_MD_up_ref(new_ctx->rsa.signature.md) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_up_ref failed");
            return 0;
        }

    }
    new_ctx->rsa.signature.set_md_allowed = ctx->rsa.signature.set_md_allowed;

    new_ctx->rsa.signature.mgf1_md = ctx->rsa.signature.mgf1_md;
    if (new_ctx->rsa.signature.mgf1_md != NULL) {
        if (EVP_MD_up_ref(new_ctx->rsa.signature.mgf1_md) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_up_ref failed");
            return 0;
        }
    }

    new_ctx->rsa.signature.saltlen = ctx->rsa.signature.saltlen;
    new_ctx->rsa.signature.pss = ctx->rsa.signature.pss;

    if (ctx->rsa.signature.md_ctx != NULL) {
        new_ctx->rsa.signature.md_ctx = EVP_MD_CTX_new();
        if (new_ctx->rsa.signature.md_ctx == NULL ||
            EVP_MD_CTX_copy(new_ctx->rsa.signature.md_ctx,
                            ctx->rsa.signature.md_ctx) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_CTX_copy failed");
            return 0;
        }
    }

    return 1;
}

static int ibmca_signature_rsa_set_md(struct ibmca_op_ctx *ctx,
                                      const char *mdname, int md_nid,
                                      const char *props)
{
    EVP_MD *md;

    if (mdname == NULL)
        mdname = OBJ_nid2sn(md_nid);

    ibmca_debug_op_ctx(ctx, "ctx: %p mdname: '%s'", ctx, mdname);

    if (!ctx->rsa.signature.set_md_allowed) {
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

    if (ctx->key->type == EVP_PKEY_RSA_PSS &&
        ctx->rsa.signature.pss.restricted &&
        EVP_MD_get_type(md) != ctx->rsa.signature.pss.digest_nid) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "RSA-PSS key is restricted, digest not allowed");
        EVP_MD_free(md);
        return 0;
    }

    if (ctx->rsa.signature.md != NULL)
        EVP_MD_free(ctx->rsa.signature.md);

    ctx->rsa.signature.md = md;

    return 1;
}

static int ibmca_signature_rsa_set_mgf1_md(struct ibmca_op_ctx *ctx,
                                           const char *mdname, int md_nid,
                                           const char *props)
{
    EVP_MD *md;

    if (mdname == NULL)
        mdname = OBJ_nid2sn(md_nid);

    ibmca_debug_op_ctx(ctx, "ctx: %p mdname: '%s'", ctx, mdname);

    md = EVP_MD_fetch(ctx->provctx->libctx, mdname,
                      props != NULL ? props : ctx->propq);
    if (md == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Digest '%s' could not be fetched", mdname);
        return 0;
    }

    if (ctx->key->type == EVP_PKEY_RSA_PSS &&
        ctx->rsa.signature.pss.restricted &&
        EVP_MD_get_type(md) != ctx->rsa.signature.pss.mgf_digest_nid) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "RSA-PSS key is restricted, mgf1 digest not allowed");
        EVP_MD_free(md);
        return 0;
    }

    if (ctx->rsa.signature.mgf1_md != NULL)
        EVP_MD_free(ctx->rsa.signature.mgf1_md);

    ctx->rsa.signature.mgf1_md = md;

    return 1;
}

static int ibmca_signature_rsa_pss_check_params(struct ibmca_op_ctx *ctx)
{
    int saltlen;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->rsa.signature.pss.restricted == false)
        return 1;

    if (EVP_MD_get_type(ctx->rsa.signature.md) !=
                                    ctx->rsa.signature.pss.digest_nid) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "RSA-PSS key is restricted, digest not allowed");
        return 0;
    }

    if (EVP_MD_get_type(ctx->rsa.signature.mgf1_md != NULL ?
                                ctx->rsa.signature.mgf1_md :
                                ctx->rsa.signature.md) !=
                                    ctx->rsa.signature.pss.mgf_digest_nid) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "RSA-PSS key is restricted, mgf1 digest not allowed");
        return 0;
    }

    switch (ctx->rsa.signature.saltlen) {
    case RSA_PSS_SALTLEN_DIGEST:
        if (EVP_MD_get_size(ctx->rsa.signature.md) <
                              ctx->rsa.signature.pss.saltlen) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Saltlen should be >= %d, but digest size is %d",
                             ctx->rsa.signature.pss.saltlen,
                             EVP_MD_get_size(
                                     ctx->rsa.signature.md));
            return 0;
        }
        break;
    case RSA_PSS_SALTLEN_MAX_SIGN:
    case RSA_PSS_SALTLEN_MAX:
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
#endif
        saltlen = ctx->key->get_max_param_size(ctx->key) -
                    EVP_MD_get_size(ctx->rsa.signature.md) - 2;
        if ((ctx->key->rsa.bits & 0x7) == 1)
            saltlen--;
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
        if (ctx->rsa.signature.saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX &&
            saltlen > EVP_MD_get_size(ctx->rsa.signature.md))
            saltlen = EVP_MD_get_size(ctx->rsa.signature.md);
#endif
        if (saltlen < ctx->rsa.signature.pss.saltlen) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Saltlen should be >= %d, but max salt len is %d",
                             ctx->rsa.signature.pss.saltlen, saltlen);
            return 0;
        }
        break;
    default:
        if (ctx->rsa.signature.saltlen < ctx->rsa.signature.pss.saltlen) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Saltlen should be >= %d, but salt len is %d",
                             ctx->rsa.signature.pss.saltlen,
                             ctx->rsa.signature.saltlen);
            return 0;
        }
        break;
    }

    return 1;
}

static int ibmca_signature_rsa_op_init(struct ibmca_op_ctx *ctx,
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
    ibmca_signature_rsa_free_cb(ctx);

    ctx->rsa.signature.pss = ibmca_rsa_pss_defaults;
    /* Max for sign, auto for verify */
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    ctx->rsa.signature.pss.saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
#else
    ctx->rsa.signature.pss.saltlen = RSA_PSS_SALTLEN_AUTO;
#endif

    if (key->type == EVP_PKEY_RSA_PSS) {
        ctx->rsa.signature.pad_mode = RSA_PKCS1_PSS_PADDING;

        ibmca_debug_op_ctx(ctx,"RSA-PSS restricted: %d",
                           key->rsa.pss.restricted);

        if (key->rsa.pss.restricted)
            ctx->rsa.signature.pss = key->rsa.pss;

        if (ibmca_signature_rsa_set_md(ctx, NULL,
                                       ctx->rsa.signature.pss.digest_nid,
                                       NULL) == 0)
            return 0;
        if (ctx->rsa.signature.pss.mgf_digest_nid !=
                                 ctx->rsa.signature.pss.digest_nid &&
            ibmca_signature_rsa_set_mgf1_md(ctx, NULL,
                                        ctx->rsa.signature.pss.mgf_digest_nid,
                                        NULL) == 0)
            return 0;
    } else {
        ctx->rsa.signature.pad_mode = RSA_PKCS1_PADDING;
    }

    ctx->rsa.signature.set_md_allowed = true;

    if (mdname != NULL) {
        if (ibmca_signature_rsa_set_md(ctx, mdname, 0, NULL) == 0)
            return 0;
    }

    ctx->rsa.signature.saltlen = ctx->rsa.signature.pss.saltlen;

    if (params != NULL) {
        if (ibmca_signature_rsa_set_ctx_params(ctx, params) == 0) {
            ibmca_debug_op_ctx(ctx,
                    "ERROR: ibmca_signature_rsa_set_ctx_params failed");
            return 0;
        }
    }

    switch (operation) {
    case EVP_PKEY_OP_SIGNCTX:
    case EVP_PKEY_OP_VERIFYCTX:
        ctx->rsa.signature.md_ctx = EVP_MD_CTX_new();
        if (ctx->rsa.signature.md_ctx == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_MD_CTX_new failed");
            return 0;
        }

        if (EVP_DigestInit_ex2(ctx->rsa.signature.md_ctx,
                               ctx->rsa.signature.md, params) == 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_DigestInit_ex2 failed");
            return 0;
        }

        ctx->rsa.signature.set_md_allowed = false;
        break;
    }

    return 1;

}

static int ibmca_signature_rsa_sign_init(void *vctx, void *vkey,
                                         const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_rsa_op_init(ctx, key, params,
                                       EVP_PKEY_OP_SIGN, NULL);
}

static int ibmca_signature_rsa_verify_init(void *vctx, void *vkey,
                                           const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_rsa_op_init(ctx, key, params,
                                       EVP_PKEY_OP_VERIFY, NULL);
}

static int ibmca_signature_rsa_verifyrecover_init(void *vctx, void *vkey,
                                                  const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_rsa_op_init(ctx, key, params,
                                       EVP_PKEY_OP_VERIFYRECOVER, NULL);
}

static int ibmca_signature_rsa_sign_x931_post_process(struct ibmca_op_ctx *ctx,
                                                      unsigned char *data,
                                                      size_t data_len)
{
    BIGNUM *bn_n = NULL, *bn_new_data = NULL, *bn_data = NULL;
    int rc = 0;

    /* Special handling for X.931 */
    bn_n = BN_bin2bn(ctx->key->rsa.public.modulus,
                     ctx->key->rsa.public.key_length, NULL);
    bn_data = BN_bin2bn(data, data_len, NULL);
    bn_new_data = BN_new();
    if(bn_n == NULL || bn_new_data == NULL || bn_data == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "BN_bin2bn/BN_new failed");
        rc = 0;
        goto out;
    }

    if (BN_sub(bn_new_data, bn_n, bn_data) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR, "BN_bin2bn failed");
        rc = 0;
        goto out;
    }

    if (BN_cmp(bn_data, bn_new_data) > 0) {
        if (BN_bn2binpad(bn_new_data, data, data_len)<= 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "BN_bn2binpad failed");
            rc = 0;
            goto out;
        }
    }

    rc = 1;

out:
    if (bn_n != NULL)
        BN_free(bn_n);
    if (bn_data != NULL)
        BN_free(bn_data);
    if (bn_new_data != NULL)
        BN_free(bn_new_data);

    return rc;
}

static int ibmca_signature_rsa_verify_x931_post_process(
                                        struct ibmca_op_ctx *ctx,
                                        unsigned char *data, size_t data_len)
{
    int rc = 0;
    BIGNUM *bn_n = NULL, *bn_sig = NULL;

    if ((data[data_len - 1] & 0xf) != 12) {
        bn_n = BN_bin2bn(ctx->key->rsa.public.modulus,
                         ctx->key->rsa.public.key_length, NULL);
        bn_sig = BN_bin2bn(data, data_len, NULL);

        if (bn_n == NULL || bn_sig == NULL ||
            BN_sub(bn_sig, bn_n, bn_sig) == 0 ||
            BN_bn2binpad(bn_sig, data, data_len) <= 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "BN_bin2bn/BN_sub/BN_bn2binpad failed");
            goto out;
        }
    }

    rc = 1;

out:
    if (bn_n != NULL)
        BN_free(bn_n);
    if (bn_sig != NULL)
        BN_free(bn_sig);

    return rc;
}

static int ibmca_signature_rsa_sign_fallback(struct ibmca_op_ctx *ctx,
                                             unsigned char *sig, size_t sigsize,
                                             const unsigned char *tbs,
                                             size_t tbslen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t siglen;
    int rc = 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu sig: %p sigsize: %lu",
                       ctx, ctx->key, tbslen, sig, sigsize);

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

    if (EVP_PKEY_sign_init(pctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_sign_init/EVP_PKEY_CTX_set_rsa_padding failed");
        goto out;
    }

    if (ibmca_check_fallback_provider(ctx->provctx, pctx) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_check_fallback_provider failed");
        goto out;
    }

    siglen = sigsize;
    if (EVP_PKEY_sign(pctx, sig, &siglen, tbs, tbslen) != 1 ||
        siglen != sigsize) {
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

static int ibmca_signature_rsa_sign(void *vctx,
                                    unsigned char *sig, size_t *siglen,
                                    size_t sigsize, const unsigned char *tbs,
                                    size_t tbslen)
{
    struct ibmca_op_ctx *ctx = vctx;
    unsigned char diginfo[MAX_DIGINFO_SIZE + EVP_MAX_MD_SIZE];
    unsigned char *enc_data;
    size_t enc_data_len, diginfo_len, rsa_size;
    int rc = 1;

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

    rsa_size = ctx->key->get_max_param_size(ctx->key);
    *siglen = rsa_size;

    if (sig == NULL) /* size query */
        goto out;

    if (sigsize < *siglen) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Output buffer too small");
        return 0;
    }

    if (ctx->rsa.signature.md != NULL) {
        if (tbslen != (size_t)EVP_MD_get_size(ctx->rsa.signature.md)) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid input data size: %lu expected: %d",
                             tbslen,
                             EVP_MD_get_size(ctx->rsa.signature.md));
            return 0;
        }
    }

    ibmca_debug_op_ctx(ctx, "pad_mode: %d", ctx->rsa.signature.pad_mode);

    /* Allocate padding buffer, if required by padding mode */
    switch (ctx->rsa.signature.pad_mode) {
    case RSA_NO_PADDING:
        if (tbslen != rsa_size) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid input length");
            return 0;
        }
        enc_data = (unsigned char *)tbs;
        enc_data_len = tbslen;
        break;

    case RSA_PKCS1_PADDING:
    case RSA_PKCS1_PSS_PADDING:
    case RSA_X931_PADDING:
        if (ibmca_op_alloc_tbuf(ctx, rsa_size) == 0) {
            ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
            return 0;
        }

        enc_data_len = ctx->tbuf_len;
        enc_data = ctx->tbuf;
        break;

    case RSA_PKCS1_OAEP_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING:
    default:
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Invalid padding mode: %d",
                         ctx->rsa.signature.pad_mode);
        return 0;
    }

    /* Perform padding */
    switch (ctx->rsa.signature.pad_mode) {
    case RSA_NO_PADDING:
        rc = 1;
        break;

    case RSA_PKCS1_PADDING:
        if (ctx->rsa.signature.md != NULL) {
            rc = ibmca_rsa_build_digest_info(ctx->key->provctx,
                                             ctx->rsa.signature.md,
                                             tbs, tbslen,
                                             diginfo, sizeof(diginfo),
                                             &diginfo_len);
            if (rc == 0)
                break;

            rc = ibmca_rsa_add_pkcs1_padding(ctx->key->provctx, 1,
                                             diginfo, diginfo_len,
                                             enc_data, enc_data_len);
        } else {
            rc = ibmca_rsa_add_pkcs1_padding(ctx->key->provctx, 1,
                                             tbs, tbslen,
                                             enc_data, enc_data_len);
        }
        break;

    case RSA_X931_PADDING:
        if (ctx->rsa.signature.md == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "X.931 padding requires a digest");
            rc = 0;
            break;
        }

        rc = ibmca_rsa_add_x931_padding(ctx->key->provctx, tbs, tbslen,
                                        enc_data, enc_data_len,
                                        EVP_MD_get_type(
                                            ctx->rsa.signature.md));
        break;

    case RSA_PKCS1_PSS_PADDING:
        rc = ibmca_signature_rsa_pss_check_params(ctx);
        if (rc == 0)
           break;

        rc = ibmca_rsa_add_pss_mgf1_padding(ctx->key->provctx, tbs, tbslen,
                                           enc_data, enc_data_len,
                                           ctx->rsa.signature.md,
                                           ctx->rsa.signature.mgf1_md,
                                           ctx->rsa.signature.saltlen);
        break;

    case RSA_PKCS1_OAEP_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING:
    default:
        rc = 0;
        goto out;
    }
    if (rc == 0)
        goto out;

    /* Perform private key encrypt */
    rc = ibmca_rsa_priv_with_blinding(ctx->key, enc_data, sig, rsa_size);
    if (rc != 1) {
        ibmca_debug_op_ctx(ctx, "ibmca_asym_cipher_rsa_with_blinding failed");

        rc = ibmca_signature_rsa_sign_fallback(ctx, sig, *siglen,
                                               enc_data, enc_data_len);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_signature_rsa_sign_fallback failed");
            rc = 0;
            goto out;
        }
    }

    if (ctx->rsa.signature.pad_mode == RSA_X931_PADDING &&
        ibmca_signature_rsa_sign_x931_post_process(ctx, sig, *siglen) == 0) {
        rc = 0;
        goto out;
    }

    rc = 1;

 out:
    if (ctx->tbuf != NULL)
        P_CLEANSE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);

    ibmca_debug_op_ctx(ctx, "siglen: %lu rc: %d", *siglen, rc);

    return rc;
}

static int ibmca_signature_rsa_verify_fallback(struct ibmca_op_ctx *ctx,
                                               unsigned char *out,
                                               size_t outsize,
                                               const unsigned char *tbs,
                                               size_t tbslen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen;
    int rc = 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p tbslen: %lu out: %p outsize: %lu",
                       ctx, ctx->key, tbslen, out, outsize);

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

    if (EVP_PKEY_verify_recover_init(pctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_verify_recover_init/EVP_PKEY_CTX_set_rsa_padding failed");
        goto out;
    }

    if (ibmca_check_fallback_provider(ctx->provctx, pctx) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_check_fallback_provider failed");
        goto out;
    }

    outlen = outsize;
    if (EVP_PKEY_verify_recover(pctx, out, &outlen, tbs, tbslen) != 1 ||
        outlen != outsize) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_verify_recover failed");
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

static int ibmca_signature_rsa_verify(void *vctx,
                                      const unsigned char *sig, size_t siglen,
                                      const unsigned char *tbs, size_t tbslen)
{
    struct ibmca_op_ctx *ctx = vctx;
    unsigned char diginfo[MAX_DIGINFO_SIZE + EVP_MAX_MD_SIZE];
    unsigned char *dec_data, *data = NULL;
    size_t dec_data_len, data_len = 0, diginfo_len, rsa_size;
    int rc = 1;

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

    rsa_size = ctx->key->get_max_param_size(ctx->key);
    if (siglen != rsa_size) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Invalid signature length");
        return -1;
    }

    ibmca_debug_op_ctx(ctx, "pad_mode: %d", ctx->rsa.signature.pad_mode);

    /* Allocate decryption buffer */
    if (ibmca_op_alloc_tbuf(ctx, rsa_size) == 0) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
        return -1;
    }

    dec_data_len = ctx->tbuf_len;
    dec_data = ctx->tbuf;

    /* Perform public key decrypt */
    rc = ica_rsa_mod_expo(ctx->provctx->ica_adapter, sig,
                          &ctx->key->rsa.public, dec_data);
    if (rc != 0) {
        ibmca_debug_op_ctx(ctx, "ica_rsa_mod_expo failed with: %s",
                           strerror(rc));

        rc = ibmca_signature_rsa_verify_fallback(ctx, dec_data, dec_data_len,
                                                 sig, siglen);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_signature_rsa_verify_fallback failed");
            rc = -1;
            goto out;
        }
    }

    /* Perform padding check */
    switch (ctx->rsa.signature.pad_mode) {
    case RSA_NO_PADDING:
        data = dec_data;
        data_len = dec_data_len;
        rc = 1;
        break;

    case RSA_PKCS1_PADDING:
        if (ctx->rsa.signature.md != NULL) {
            rc = ibmca_rsa_build_digest_info(ctx->key->provctx,
                                             ctx->rsa.signature.md,
                                             tbs, tbslen,
                                             diginfo, sizeof(diginfo),
                                             &diginfo_len);
            if (rc == 0)
                break;

            tbs = diginfo;
            tbslen = diginfo_len;
        }

        rc = ibmca_rsa_check_pkcs1_padding_type1(ctx->key->provctx,
                                                 dec_data, dec_data_len, NULL,
                                                 dec_data_len, &data,
                                                 &data_len);
        break;

    case RSA_X931_PADDING:
        if (ctx->rsa.signature.md == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "X.931 padding requires a digest");
            rc = 0;
            break;
        }

        rc = ibmca_signature_rsa_verify_x931_post_process(ctx, dec_data,
                                                          dec_data_len);
        if (rc == 0)
            break;

        rc = ibmca_rsa_check_X931_padding(ctx->key->provctx,
                                          dec_data, dec_data_len, NULL,
                                          dec_data_len, &data, &data_len,
                                          EVP_MD_get_type(
                                            ctx->rsa.signature.md));
        break;

    case RSA_PKCS1_PSS_PADDING:
        rc = ibmca_signature_rsa_pss_check_params(ctx);
        if (rc == 0)
           break;

        rc = ibmca_rsa_check_pss_mgf1_padding(ctx->key->provctx,
                                              dec_data, dec_data_len,
                                              tbs, tbslen,
                                              ctx->rsa.signature.md,
                                              ctx->rsa.signature.mgf1_md,
                                              ctx->rsa.signature.saltlen);
        break;

    case RSA_PKCS1_OAEP_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING:
    default:
        rc = -1;
        break;
    }
    if (rc == 0)
        goto out;

    /* If data is NULL, padding check has already verified the signature */
    if (data != NULL && data_len > 0) {
        if (data_len != tbslen ||
            memcmp(data, tbs, tbslen) != 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_SIGNATURE_BAD, "Bad signature");
            rc = 0;
            goto out;
        }
    }

    rc = 1;

out:
    P_CLEANSE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);

    ibmca_debug_op_ctx(ctx, "rc: %d", rc);

    return rc;
}

static int ibmca_signature_rsa_verify_recover(void *vctx,
                                              unsigned char *rout,
                                              size_t *routlen,
                                              size_t routsize,
                                              const unsigned char *sig,
                                              size_t siglen)
{
    struct ibmca_op_ctx *ctx = vctx;
    unsigned char diginfo[MAX_DIGINFO_SIZE + EVP_MAX_MD_SIZE];
    unsigned char *dec_data, *msg;
    size_t dec_data_len, diginfo_len, msg_len, md_len, rsa_size;
    int rc = 1;

    if (ctx == NULL || routlen == NULL || sig == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p routsize: %lu siglen: %lu",
                       ctx, ctx->key, routsize, siglen);

    if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_VERIFYRECOVER) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "verify recover operation not initialized");
        return 0;
    }

    rsa_size = ctx->key->get_max_param_size(ctx->key);
    *routlen = rsa_size;

    if (rout == NULL) /* size query */
        goto out;

    if (routsize < *routlen) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM, "Output buffer too small");
        return 0;
    }

    if (siglen != rsa_size) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Invalid signature length");
        return 0;
    }

    ibmca_debug_op_ctx(ctx, "pad_mode: %d", ctx->rsa.signature.pad_mode);

    /* Allocate padding buffer, if required by padding mode */
    switch (ctx->rsa.signature.pad_mode) {
    case RSA_NO_PADDING:
        dec_data = rout;
        dec_data_len = *routlen;
        break;

    case RSA_PKCS1_PADDING:
    case RSA_X931_PADDING:
        if (ibmca_op_alloc_tbuf(ctx, rsa_size) == 0) {
            ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
            return 0;
        }

        dec_data_len = ctx->tbuf_len;
        dec_data = ctx->tbuf;
        break;

    case RSA_PKCS1_PSS_PADDING:
    case RSA_PKCS1_OAEP_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING:
    default:
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Invalid padding mode: %d", ctx->rsa.signature.pad_mode);
        return 0;
    }

    /* Perform public key decrypt */
    rc = ica_rsa_mod_expo(ctx->provctx->ica_adapter, sig,
                          &ctx->key->rsa.public, dec_data);
    if (rc != 0) {
        ibmca_debug_op_ctx(ctx, "ica_rsa_mod_expo failed with: %s",
                           strerror(rc));

        rc = ibmca_signature_rsa_verify_fallback(ctx, dec_data, dec_data_len,
                                                 sig, siglen);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_signature_rsa_verify_fallback failed");
            rc = 0;
            goto out;
        }
    }

    /* Perform padding check */
    switch (ctx->rsa.signature.pad_mode) {
    case RSA_NO_PADDING:
        rc = 1;
        break;

    case RSA_PKCS1_PADDING:
        if (ctx->rsa.signature.md != NULL) {
            rc = ibmca_rsa_check_pkcs1_padding_type1(ctx->key->provctx,
                                                     dec_data, dec_data_len,
                                                     NULL, *routlen, &msg,
                                                     &msg_len);
            if (rc == 0)
                break;

            md_len = EVP_MD_get_size(ctx->rsa.signature.md);
            if (md_len <= 0) {
                put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                              "EVP_MD_get_size failed");
                break;
            }

            /* Rightmost md_len bytes of msg is the hash */
            rc = ibmca_rsa_build_digest_info(ctx->key->provctx,
                                             ctx->rsa.signature.md,
                                             msg + msg_len - md_len, md_len,
                                             diginfo, sizeof(diginfo),
                                             &diginfo_len);
            if (rc == 0)
                break;

            if (diginfo_len != dec_data_len ||
                memcmp(diginfo, dec_data, diginfo_len) != 0) {
                put_error_op_ctx(ctx, IBMCA_ERR_SIGNATURE_BAD, "Bad signature");
                break;
            }

            if (routsize < md_len) {
                put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                 "Output buffer size too small");
                break;
            }

            memcpy(rout, msg + msg_len - md_len, md_len);
            *routlen = md_len;
        } else {
            rc = ibmca_rsa_check_pkcs1_padding_type1(ctx->key->provctx,
                                                     dec_data, dec_data_len,
                                                     rout, *routlen, NULL,
                                                     routlen);
        }
        break;

    case RSA_X931_PADDING:
        if (ctx->rsa.signature.md == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "X.931 padding requires a digest");
            rc = 0;
            break;
        }

        rc = ibmca_signature_rsa_verify_x931_post_process(ctx, dec_data,
                                                          dec_data_len);
        if (rc == 0)
            break;

        rc = ibmca_rsa_check_X931_padding(ctx->key->provctx,
                                          dec_data, dec_data_len, rout,
                                          *routlen, NULL, routlen,
                                          EVP_MD_get_type(
                                            ctx->rsa.signature.md));
        break;

    case RSA_PKCS1_PSS_PADDING:
    case RSA_PKCS1_OAEP_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING:
    default:
        rc = 0;
        break;
    }
    if (rc == 0)
        goto out;

    rc = 1;

out:
    P_CLEANSE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);

    ibmca_debug_op_ctx(ctx, "routlen: %lu rc: %d", *routlen, rc);

    return rc;
}

static int ibmca_signature_rsa_digest_sign_init(void *vctx, const char *mdname,
                                                void *vkey,
                                                const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_rsa_op_init(ctx, key, params,
                                       EVP_PKEY_OP_SIGNCTX, mdname);
}

static int ibmca_signature_rsa_digest_verify_init(void *vctx,
                                                  const char *mdname,
                                                  void *vkey,
                                                  const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_signature_rsa_op_init(ctx, key, params,
                                       EVP_PKEY_OP_VERIFYCTX, mdname);
}

static int ibmca_signature_rsa_digest_signverify_update(void *vctx,
                                                    const unsigned char *data,
                                                    size_t datalen)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_digest_signverify_update(ctx, ctx->rsa.signature.md_ctx,
                                          data, datalen);
}

static int ibmca_signature_rsa_digest_sign_final(void *vctx,
                                                 unsigned char *sig,
                                                 size_t *siglen,
                                                 size_t sigsize)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_digest_sign_final(ctx, ctx->rsa.signature.md_ctx,
                                   ibmca_signature_rsa_sign,
                                   sig, siglen, sigsize);
}

static int ibmca_signature_rsa_digest_verify_final(void *vctx,
                                                   const unsigned char *sig,
                                                   size_t siglen)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_digest_verify_final(ctx, ctx->rsa.signature.md_ctx,
                                     ibmca_signature_rsa_verify,
                                     sig, siglen);
}

static int ibmca_signature_rsa_get_algid_pss_parms(struct ibmca_op_ctx *ctx,
                                                   int *ptype, void **param)
{
    RSA_PSS_PARAMS *pss = NULL;
    X509_ALGOR *mgf_md_algo = NULL;
    ASN1_STRING *mgf_md_alfo_str = NULL;
    int rc = 0, saltlen;

    pss = RSA_PSS_PARAMS_new();
    if (pss == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED,
                         "RSA_PSS_PARAMS_new failed");
        goto done;
    }

    switch (ctx->rsa.signature.saltlen) {
    case RSA_PSS_SALTLEN_DIGEST:
        saltlen = EVP_MD_get_size(ctx->rsa.signature.md);
        break;

    case RSA_PSS_SALTLEN_AUTO:
    case RSA_PSS_SALTLEN_MAX:
        saltlen = ctx->key->get_max_param_size(ctx->key) -
                    EVP_MD_get_size(ctx->rsa.signature.md) - 2;
        if ((ctx->key->rsa.bits & 0x7) == 1)
            saltlen--;
        break;

    default:
        saltlen = ctx->rsa.signature.saltlen;
        if (saltlen < 0) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "Invalid saltlen value");
            goto done;
        }
    }

    pss->saltLength = ASN1_INTEGER_new();
    if (pss->saltLength == NULL ||
        ASN1_INTEGER_set(pss->saltLength, saltlen) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "ASN1_INTEGER_new/ASN1_INTEGER_set failed");
        goto done;
    }

    pss->hashAlgorithm = X509_ALGOR_new();
    if (pss->hashAlgorithm == NULL ||
        X509_ALGOR_set0(pss->hashAlgorithm,
                        OBJ_nid2obj(EVP_MD_get_type(ctx->rsa.signature.md)),
                        V_ASN1_NULL, NULL) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "X509_ALGOR_new/X509_ALGOR_set0 failed");
        goto done;
    }

    mgf_md_algo = X509_ALGOR_new();
    if (mgf_md_algo == NULL ||
        X509_ALGOR_set0(mgf_md_algo,
                        OBJ_nid2obj(EVP_MD_get_type(
                                    ctx->rsa.signature.mgf1_md != NULL ?
                                            ctx->rsa.signature.mgf1_md :
                                            ctx->rsa.signature.md)),
                        V_ASN1_NULL, NULL) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "X509_ALGOR_new/X509_ALGOR_set0 failed");
        goto done;
    }

    if (ASN1_item_pack(mgf_md_algo, ASN1_ITEM_rptr(X509_ALGOR),
                       &mgf_md_alfo_str) == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "ASN1_item_pack failed");
        goto done;
    }

    pss->maskGenAlgorithm = X509_ALGOR_new();
    if (pss->maskGenAlgorithm == NULL ||
        X509_ALGOR_set0(pss->maskGenAlgorithm, OBJ_nid2obj(NID_mgf1),
                         V_ASN1_SEQUENCE, mgf_md_alfo_str) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "X509_ALGOR_new/X509_ALGOR_set0 failed");
        goto done;
    }
    mgf_md_alfo_str = NULL;

    pss->maskHash = X509_ALGOR_new();
    if (pss->maskHash == NULL ||
        X509_ALGOR_set0(pss->maskHash,
                        OBJ_nid2obj(EVP_MD_get_type(
                                    ctx->rsa.signature.mgf1_md != NULL ?
                                            ctx->rsa.signature.mgf1_md :
                                            ctx->rsa.signature.md)),
                        V_ASN1_NULL, NULL) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "X509_ALGOR_new/X509_ALGOR_set0 failed");
        goto done;
    }

    /* We always use the default trailer field, so we can omit it */

    *ptype = V_ASN1_SEQUENCE;
    *param = ASN1_item_pack(pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), NULL);
    if (*param == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "ASN1_item_pack failed");
        goto done;
    }

    rc = 1;

done:
    if (mgf_md_alfo_str != NULL)
        ASN1_STRING_free(mgf_md_alfo_str);
    if (mgf_md_algo != NULL)
        X509_ALGOR_free(mgf_md_algo);
    RSA_PSS_PARAMS_free(pss);

    return rc;
}

static int ibmca_signature_rsa_get_algid(struct ibmca_op_ctx *ctx,
                                         OSSL_PARAM *p)
{
    ASN1_OBJECT *oid = NULL;
    X509_ALGOR * algid = NULL;
    void *alg_param = NULL;
    int alg_ptype = V_ASN1_NULL;
    unsigned char *aid_buf = NULL;
    size_t aid_len;

    if (ctx->rsa.signature.md == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM, "No digest is set");
        return 0;
    }

    switch (ctx->rsa.signature.pad_mode) {
    case RSA_PKCS1_PADDING:
        switch (EVP_MD_get_type(ctx->rsa.signature.md)) {
        case NID_sha1:
            oid = OBJ_nid2obj(NID_sha1WithRSAEncryption);
            break;
        case NID_sha224:
             oid = OBJ_nid2obj(NID_sha224WithRSAEncryption);
             break;
        case NID_sha256:
             oid = OBJ_nid2obj(NID_sha256WithRSAEncryption);
             break;
        case NID_sha384:
             oid = OBJ_nid2obj(NID_sha384WithRSAEncryption);
             break;
        case NID_sha512:
             oid = OBJ_nid2obj(NID_sha512WithRSAEncryption);
             break;
        case NID_sha512_224:
             oid = OBJ_nid2obj(NID_sha512_224WithRSAEncryption);
             break;
        case NID_sha512_256:
             oid = OBJ_nid2obj(NID_sha512_256WithRSAEncryption);
             break;
        case NID_sha3_224:
             oid = OBJ_nid2obj(NID_RSA_SHA3_224);
             break;
        case NID_sha3_256:
             oid = OBJ_nid2obj(NID_RSA_SHA3_256);
             break;
        case NID_sha3_384:
             oid = OBJ_nid2obj(NID_RSA_SHA3_384);
             break;
        case NID_sha3_512:
             oid = OBJ_nid2obj(NID_RSA_SHA3_512);
             break;
        default:
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "AlgorithmID not supported for digest '%s'",
                             EVP_MD_get0_name(ctx->rsa.signature.md));
            return 0;
        }
        break;

    case RSA_PKCS1_PSS_PADDING:
        if (ctx->key->type == EVP_PKEY_RSA_PSS) {
            oid = OBJ_nid2obj(NID_rsassaPss);

            if (ibmca_signature_rsa_get_algid_pss_parms(ctx, &alg_ptype,
                                                        &alg_param) == 0)
                return 0;
        } else {
            oid = OBJ_nid2obj(NID_rsaEncryption);
        }
        break;

    default:
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "AlgorithmID not supported for pad mode %d",
                         ctx->rsa.signature.pad_mode);
        return 0;
    }

    algid = X509_ALGOR_new();
    if (algid == NULL ||
        X509_ALGOR_set0(algid, oid, alg_ptype, alg_param) == 0 ||
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

static int ibmca_signature_rsa_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    OSSL_PARAM *p;
    const char *name = NULL;
    int i, rc;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    /* OSSL_SIGNATURE_PARAM_ALGORITHM_ID */
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && ibmca_signature_rsa_get_algid(ctx, p) == 0)
        return 0;

    /* OSSL_SIGNATURE_PARAM_PAD_MODE */
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            rc = ibmca_param_build_set_int(ctx->provctx, NULL, params,
                                           OSSL_SIGNATURE_PARAM_PAD_MODE,
                                           ctx->rsa.signature.pad_mode);
            if (rc == 0)
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            for (i = 0; ibmca_rsa_padding_table[i].id != 0; i++) {
                if ((int)ibmca_rsa_padding_table[i].id ==
                                                ctx->rsa.signature.pad_mode) {
                    name = ibmca_rsa_padding_table[i].ptr;
                    break;
                }
            }
            if (name == NULL) {
                put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                                 "Invalid RSA padding mode: %d",
                                 ctx->rsa.signature.pad_mode);
                return 0;
            }

            rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                            OSSL_SIGNATURE_PARAM_PAD_MODE,
                                            name);
             if (rc == 0)
                 return 0;
            break;
        default:
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid param type for: '%s'",
                             OSSL_SIGNATURE_PARAM_PAD_MODE);
            return 0;
        }
    }

    /* OSSL_SIGNATURE_PARAM_DIGEST */
    if (ctx->rsa.signature.md != NULL)
        name = EVP_MD_get0_name(ctx->rsa.signature.md);
    else name = "";
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_SIGNATURE_PARAM_DIGEST, name);
    if (rc == 0)
       return 0;

    /* OSSL_SIGNATURE_PARAM_MGF1_DIGEST */
    if (ctx->rsa.signature.mgf1_md != NULL)
        name = EVP_MD_get0_name(ctx->rsa.signature.mgf1_md);
    else if (ctx->rsa.signature.md != NULL)
        name = EVP_MD_get0_name(ctx->rsa.signature.md);
    else name = "";
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_SIGNATURE_PARAM_MGF1_DIGEST, name);
    if (rc == 0)
       return 0;

    /* OSSL_SIGNATURE_PARAM_PSS_SALTLEN */
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_INTEGER) {
            rc = ibmca_param_build_set_int(ctx->provctx, NULL, params,
                                           OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                           ctx->rsa.signature.saltlen);
            if (rc == 0)
               return 0;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            switch (ctx->rsa.signature.saltlen) {
            case RSA_PSS_SALTLEN_DIGEST:
                rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                            OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                            OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST);
                break;
            case RSA_PSS_SALTLEN_MAX:
                rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                            OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                            OSSL_PKEY_RSA_PSS_SALT_LEN_MAX);
                break;
            case RSA_PSS_SALTLEN_AUTO:
                rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                            OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                            OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO);
                break;
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
            case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
                rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                            OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                            OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX);
                break;
#endif
            default:
                rc = snprintf(p->data, p->data_size, "%d",
                              ctx->rsa.signature.saltlen);
                if (rc <= 0) {
                    put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                     "Failed to return param '%s'",
                                     OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
                    return 0;
                }
                p->return_size = rc;
                ibmca_debug_op_ctx(ctx, "param '%s': '%s'",
                                   OSSL_SIGNATURE_PARAM_PSS_SALTLEN, p->data);
                break;
            }
            if (rc <= 0)
                return 0;
        }
    }

    return 1;
}

static int ibmca_signature_rsa_set_ctx_params(void *vctx,
                                              const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    const OSSL_PARAM *p;
    const char *name, *props = NULL;
    int i, rc, saltlen;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    /* OSSL_SIGNATURE_PARAM_PAD_MODE */
    p = OSSL_PARAM_locate_const((OSSL_PARAM *)params,
                                OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            rc = ibmca_param_get_int(ctx->provctx, params,
                                     OSSL_SIGNATURE_PARAM_PAD_MODE,
                                     &ctx->rsa.signature.pad_mode);
            if (rc == 0)
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            rc = ibmca_param_get_utf8(ctx->provctx, params,
                                      OSSL_SIGNATURE_PARAM_PAD_MODE, &name);
            if (rc == 1) {
                ctx->rsa.signature.pad_mode = 0;
                for (i = 0; ibmca_rsa_padding_table[i].id != 0; i++) {
                    if (strcmp(name, ibmca_rsa_padding_table[i].ptr) == 0) {
                        ctx->rsa.signature.pad_mode =
                                            ibmca_rsa_padding_table[i].id;
                        break;
                    }
                }
            }
            break;
        default:
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid param type for: '%s'",
                             OSSL_SIGNATURE_PARAM_PAD_MODE);
            return 0;
        }

        switch (ctx->rsa.signature.pad_mode) {
        case RSA_NO_PADDING:
        case RSA_PKCS1_PADDING:
        case RSA_X931_PADDING:
            if (ctx->key->type == EVP_PKEY_RSA_PSS) {
                put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                 "Padding mode %d not allowed with RSA-PSS",
                                 ctx->rsa.signature.pad_mode);
                return 0;
            }
            break;

        case RSA_PKCS1_PSS_PADDING:
            if (ctx->operation != EVP_PKEY_OP_SIGN &&
                ctx->operation != EVP_PKEY_OP_SIGNCTX &&
                ctx->operation != EVP_PKEY_OP_VERIFY &&
                ctx->operation != EVP_PKEY_OP_VERIFYCTX) {
                put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                 "PSS padding only allowed for sign and verify operations");
                return 0;
            }

            /* Setup md defaults if not already set */
            if (ctx->rsa.signature.md == NULL &&
                ibmca_signature_rsa_set_md(ctx, NULL,
                                           ctx->rsa.signature.pss.digest_nid,
                                           NULL) == 0)
                return 0;
            if (ctx->rsa.signature.mgf1_md == NULL &&
                 ctx->rsa.signature.pss.mgf_digest_nid !=
                                     ctx->rsa.signature.pss.digest_nid &&
                ibmca_signature_rsa_set_mgf1_md(ctx, NULL,
                                     ctx->rsa.signature.pss.mgf_digest_nid,
                                     NULL) == 0)
                return 0;
            break;

        case RSA_PKCS1_OAEP_PADDING: /* OAEP is for encrypt/decrypt only */
        case RSA_PKCS1_WITH_TLS_PADDING: /* TLS is for decrypt only */
        default:
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                      "Invalid RSA padding mode: %d",
                                      ctx->rsa.signature.pad_mode);
            return 0;
        }
    }

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
        ibmca_signature_rsa_set_md(ctx, name, 0, props) == 0)
        return 0;

    /* OSSL_SIGNATURE_PARAM_PSS_SALTLEN */
    p = OSSL_PARAM_locate_const((OSSL_PARAM *)params,
                                OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            rc = ibmca_param_get_int(ctx->provctx, params,
                                     OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                     &saltlen);
            if (rc == 0)
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
                saltlen = RSA_PSS_SALTLEN_DIGEST;
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
                saltlen = RSA_PSS_SALTLEN_MAX;
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
                saltlen = RSA_PSS_SALTLEN_AUTO;
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX) == 0)
                saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
#endif
            else
                saltlen = atoi(p->data);

            ibmca_debug_op_ctx(ctx, "param '%s': '%s'",
                               OSSL_SIGNATURE_PARAM_PSS_SALTLEN, p->data);
            break;
        default:
            return 0;
        }

#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
        if (saltlen < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
#else
        if (saltlen < RSA_PSS_SALTLEN_MAX) {
#endif
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid salt length: %d", saltlen);
            return 0;
        }

        if (ctx->key->type == EVP_PKEY_RSA_PSS &&
            ctx->rsa.signature.pss.restricted) {
            switch (saltlen) {
            case RSA_PSS_SALTLEN_AUTO:
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
            case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
#endif
                if (ctx->operation == EVP_PKEY_OP_VERIFY) {
                    put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                     "Cannot use auto-detected salt length");
                    return 0;
                }
                break;
            case RSA_PSS_SALTLEN_DIGEST:
                if (ctx->rsa.signature.md != NULL &&
                    EVP_MD_get_size(ctx->rsa.signature.md) <
                                            ctx->rsa.signature.pss.saltlen ) {
                    put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                     "Saltlen should be >= %d, but digest size is %d",
                                     ctx->rsa.signature.pss.saltlen,
                                     EVP_MD_get_size(
                                             ctx->rsa.signature.md));
                    return 0;
                }
                break;
            default:
                if (saltlen >= 0 && saltlen < ctx->rsa.signature.pss.saltlen) {
                    put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                   "Saltlen should be more than %d, but is %d",
                                   ctx->rsa.signature.pss.saltlen, saltlen);
                    return 0;
                }
            }
        }

        ctx->rsa.signature.saltlen = saltlen;
        ibmca_debug_op_ctx(ctx, "saltlen: %d", saltlen);
    }

    /* OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, &props);
    if (rc == 0)
        return 0;

    /* OSSL_SIGNATURE_PARAM_MGF1_DIGEST */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_SIGNATURE_PARAM_MGF1_DIGEST, &name);
    if (rc == 0)
        return 0;
    if (rc > 0 &&
        ibmca_signature_rsa_set_mgf1_md(ctx, name, 0, props) == 0)
        return 0;

    return 1;
}

static const OSSL_PARAM ibmca_signature_rsa_gettable_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_signature_rsa_gettable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    for (p = ibmca_signature_rsa_gettable_params;
                                    p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_signature_rsa_gettable_params;
}

static const OSSL_PARAM ibmca_signature_rsa_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_signature_rsa_settable_params_no_digest[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_signature_rsa_settable_ctx_params(
                                                    void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p, *params;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    if (ctx->rsa.signature.set_md_allowed)
        params = ibmca_signature_rsa_settable_params;
    else
        params = ibmca_signature_rsa_settable_params_no_digest;

    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return params;
}

static int ibmca_signature_rsa_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_get_ctx_md_params(ctx, ctx->rsa.signature.md_ctx, params);
}

static int ibmca_signature_rsa_set_ctx_md_params(void *vctx,
                                                 const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_set_ctx_md_params(ctx, ctx->rsa.signature.md_ctx, params);
}

static const OSSL_PARAM *ibmca_signature_rsa_gettable_ctx_md_params(void *vctx)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_gettable_ctx_md_params(ctx, ctx->rsa.signature.md);
}

static const OSSL_PARAM *ibmca_signature_rsa_settable_ctx_md_params(void *vctx)
{
    struct ibmca_op_ctx *ctx = vctx;

    return ibmca_settable_ctx_md_params(ctx, ctx->rsa.signature.md);
}

static const OSSL_DISPATCH ibmca_rsa_signature_functions[] = {
    /* Signature context constructor, destructor */
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ibmca_signature_rsa_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ibmca_op_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ibmca_op_dupctx },
    /* Signing */
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,
            (void (*)(void))ibmca_signature_rsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ibmca_signature_rsa_sign },
    /* Verifying */
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
            (void (*)(void))ibmca_signature_rsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ibmca_signature_rsa_verify },
    /* Verify recover */
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
            (void (*)(void))ibmca_signature_rsa_verifyrecover_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
            (void (*)(void))ibmca_signature_rsa_verify_recover },
    /* Digest Sign */
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
            (void (*)(void))ibmca_signature_rsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
           (void (*)(void))ibmca_signature_rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
            (void (*)(void))ibmca_signature_rsa_digest_sign_final },
    /* Digest Verify */
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
            (void (*)(void))ibmca_signature_rsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
            (void (*)(void))ibmca_signature_rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
            (void (*)(void))ibmca_signature_rsa_digest_verify_final },
    /* Signature parameters */
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
            (void (*)(void))ibmca_signature_rsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
            (void (*)(void))ibmca_signature_rsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void
            (*)(void))ibmca_signature_rsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
            (void (*)(void))ibmca_signature_rsa_settable_ctx_params },
    /* MD parameters */
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
            (void (*)(void))ibmca_signature_rsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        (void (*)(void))ibmca_signature_rsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
            (void (*)(void))ibmca_signature_rsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        (void (*)(void))ibmca_signature_rsa_settable_ctx_md_params },
    { 0, NULL }
};

const OSSL_ALGORITHM ibmca_rsa_signature[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", NULL,
      ibmca_rsa_signature_functions, "IBMCA RSA signature implementation" },
    { NULL, NULL, NULL, NULL }
};

