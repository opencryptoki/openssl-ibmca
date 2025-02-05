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
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "p_ibmca.h"

struct ibmca_op_ctx *ibmca_op_newctx(const struct ibmca_prov_ctx *provctx,
                                     const char *propq, int type,
                                     void (*free_cb)(struct ibmca_op_ctx *ctx),
                                     int (*dup_cb)
                                                (const struct ibmca_op_ctx *ctx,
                                                 struct ibmca_op_ctx *new_ctx))
{
    struct ibmca_op_ctx *ctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "propq: %s type: %d", propq != NULL ? propq : "",
                 type);

    ctx = P_ZALLOC(provctx, sizeof(struct ibmca_op_ctx));
    if (ctx == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate operation context");
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->type = type;
    ctx->free_cb = free_cb;
    ctx->dup_cb = dup_cb;

    if (propq != NULL) {
        ctx->propq = P_STRDUP(provctx, propq);
        if (ctx->propq == NULL) {
            put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED, "strdup failed");
            P_FREE(provctx, ctx);
            return NULL;
        }
    }

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);
    return ctx;
}

void ibmca_op_freectx(void *vctx)
{
    struct ibmca_op_ctx *ctx = vctx;

    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->key != NULL)
        ibmca_keymgmt_free(ctx->key);
    ctx->key = NULL;

    if (ctx->propq != NULL)
        P_FREE(ctx->provctx, (void *)ctx->propq);
    ctx->propq = NULL;

    if (ctx->free_cb != NULL)
        ctx->free_cb(ctx);

    if (ctx->tbuf != NULL)
        P_SECURE_CLEAR_FREE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);
    ctx->tbuf = NULL;
    ctx->tbuf_len = 0;

    P_FREE(ctx->provctx, ctx);
}

void *ibmca_op_dupctx(void *vctx)
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_op_ctx *new_ctx;

    if (ctx == NULL)
        return NULL;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    new_ctx = ibmca_op_newctx(ctx->provctx, ctx->propq, ctx->type,
                              ctx->free_cb, ctx->dup_cb);
    if (new_ctx == NULL) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_newctx failed");
        return NULL;
    }

    new_ctx->operation = ctx->operation;

    if (ctx->key != NULL) {
        new_ctx->key = ctx->key;
        ibmca_keymgmt_upref(ctx->key);
    }

    if (ctx->dup_cb != NULL) {
        if (ctx->dup_cb(ctx, new_ctx) == 0) {
            ibmca_debug_op_ctx(ctx, "ERROR: dup_cb failed");
            ibmca_op_freectx(new_ctx);
            return NULL;
        }
    }

    ibmca_debug_op_ctx(ctx, "new_ctx: %p", new_ctx);
    return new_ctx;
}

int ibmca_op_init(struct ibmca_op_ctx *ctx, struct ibmca_key *key,
                  int operation)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p operation: %d", ctx, key,
                       operation);

    if (key != NULL) {
        switch (ctx->type) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA_PSS:
            if (key->type != EVP_PKEY_RSA &&
                key->type != EVP_PKEY_RSA_PSS) {
                put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                                 "key type mismatch: ctx type: %d key type: %d",
                                 ctx->type, key->type);
                return 0;
            }
            break;
        case EVP_PKEY_EC:
            if (key->type != EVP_PKEY_EC) {
                put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                                 "key type mismatch: ctx type: %d key type: %d",
                                 ctx->type, key->type);
                return 0;
            }
            break;
        case EVP_PKEY_DH:
        case EVP_PKEY_DHX:
            if (key->type != EVP_PKEY_DH &&
                key->type != EVP_PKEY_DHX) {
                put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                                 "key type mismatch: ctx type: %d key type: %d",
                                 ctx->type, key->type);
                return 0;
            }
            break;
        default:
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "key type unknown: ctx type: %d key type: %d",
                             ctx->type, key->type);
            return 0;
        }

        switch (operation) {
        case EVP_PKEY_OP_DECRYPT:
        case EVP_PKEY_OP_DERIVE:
        case EVP_PKEY_OP_SIGN:
        case EVP_PKEY_OP_SIGNCTX:
            if (key->has(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                              OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 1) {
                put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                 "operation %d not possible without a private key",
                                 operation);
                return 0;
            }
            break;

        case EVP_PKEY_OP_ENCRYPT:
        case EVP_PKEY_OP_VERIFY:
        case EVP_PKEY_OP_VERIFYCTX:
            if (key->has(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                              OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 1) {
                put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                 "operation %d not possible without a public key",
                                 operation);
                return 0;
            }
            break;
        }

        ibmca_keymgmt_upref(key);
    }

    if (ctx->key != NULL)
        ibmca_keymgmt_free(ctx->key);

    ctx->key = key;
    ctx->operation = operation;

    return 1;
}

int ibmca_op_alloc_tbuf(struct ibmca_op_ctx *ctx, size_t tbuf_len)
{
    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->tbuf != NULL) {
        if (ctx->tbuf_len >= tbuf_len)
            return 1;

        P_FREE(ctx->provctx, ctx->tbuf);
        ctx->tbuf_len = 0;
    }

    ctx->tbuf = P_SECURE_ZALLOC(ctx->provctx, tbuf_len);
    if (ctx->tbuf == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED,
                         "Failed to allocate temporary buffer");
        return 0;
    }

    ctx->tbuf_len = tbuf_len;

    return 1;
}

int ibmca_digest_signverify_update(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                                   const unsigned char *data, size_t datalen)
{
    if (ctx == NULL || data == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p datalen: %lu", ctx, ctx->key,
                       datalen);

    if (ctx->key == NULL || md_ctx == NULL ||
        (ctx->operation != EVP_PKEY_OP_SIGNCTX &&
         ctx->operation != EVP_PKEY_OP_VERIFYCTX)) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "sign operation not initialized");
        return 0;
    }

    if (EVP_DigestUpdate(md_ctx, data, datalen) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_DigestUpdate failed");
        return 0;
    }

    return 1;
}

int ibmca_digest_sign_final(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                            OSSL_FUNC_signature_sign_fn *sign_func,
                            unsigned char *sig, size_t *siglen, size_t sigsize)
{
    unsigned char tbs[EVP_MAX_MD_SIZE];
    unsigned int tbslen = 0;

    if (ctx == NULL || siglen == NULL || sign_func == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p sigsize: %lu",
                       ctx, ctx->key, sigsize);

    if (ctx->key == NULL || md_ctx == NULL ||
        ctx->operation != EVP_PKEY_OP_SIGNCTX) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "sign operation not initialized");
        return 0;
    }

    if (sig != NULL) {
       if (EVP_DigestFinal_ex(md_ctx, tbs, &tbslen) == 0) {
           put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                            "EVP_DigestFinal_ex failed");
           return 0;
       }
    }

    if (sign_func(ctx, sig, siglen, sigsize, tbs, (size_t)tbslen) == 0) {
        ibmca_debug_op_ctx(ctx, "ERROR: sign_func failed");
        return 0;
    }

    ibmca_debug_op_ctx(ctx, "siglen: %lu", *siglen);

    return 1;
}

int ibmca_digest_verify_final(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                              OSSL_FUNC_signature_verify_fn *verify_func,
                              const unsigned char *sig, size_t siglen)
{
    unsigned char tbs[EVP_MAX_MD_SIZE];
    unsigned int tbslen = 0;

    if (ctx == NULL || sig == NULL || verify_func == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p siglen: %lu",
                       ctx, ctx->key, siglen);

    if (ctx->key == NULL || md_ctx == NULL ||
        ctx->operation != EVP_PKEY_OP_VERIFYCTX) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "verify operation not initialized");
        return 0;
    }

    if (EVP_DigestFinal_ex(md_ctx, tbs, &tbslen) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_DigestFinal_ex failed");
        return 0;
    }

    return verify_func(ctx, sig, siglen, tbs, (size_t)tbslen);
}

int ibmca_get_ctx_md_params(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                            OSSL_PARAM *params)
{
    const OSSL_PARAM *p;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
         ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    if (md_ctx == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Digest sign/verify context not initialized");
        return 0;
    }

    if (EVP_MD_CTX_get_params(md_ctx, params) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_MD_CTX_get_params failed");
        return 0;
    }

    return 1;
}

int ibmca_set_ctx_md_params(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                            const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
         ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    if (md_ctx == NULL) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Digest sign/verify context not initialized");
        return 0;
    }

    if (EVP_MD_CTX_set_params(md_ctx, params) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_MD_CTX_set_params failed");
        return 0;
    }

    return 1;
}

const OSSL_PARAM *ibmca_gettable_ctx_md_params(const struct ibmca_op_ctx *ctx,
                                               const EVP_MD *md)
{
    const OSSL_PARAM *p, *params;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (md == NULL) {
        if (ctx != NULL)
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Digest sign/verify context not initialized");
        return NULL;
    }

    params = EVP_MD_gettable_ctx_params(md);

    for (p = params; p != NULL && p->key != NULL; p++)
         ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    return params;
}

const OSSL_PARAM *ibmca_settable_ctx_md_params(const struct ibmca_op_ctx *ctx,
                                               const EVP_MD *md)
{
    const OSSL_PARAM *p, *params;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (md == NULL) {
        if (ctx != NULL)
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                            "Digest sign/verify context not initialized");
        return NULL;
    }

    params = EVP_MD_settable_ctx_params(md);

    for (p = params; p != NULL && p->key != NULL; p++)
         ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    return params;
}
