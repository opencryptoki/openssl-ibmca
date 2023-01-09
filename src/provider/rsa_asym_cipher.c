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
#include <openssl/rsa.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "p_ibmca.h"


static OSSL_FUNC_asym_cipher_newctx_fn ibmca_asym_cipher_rsa_newctx;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn
                                    ibmca_asym_cipher_rsa_get_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn
                                    ibmca_asym_cipher_rsa_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn
                                    ibmca_asym_cipher_rsa_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn
                                    ibmca_asym_cipher_rsa_settable_ctx_params;
static OSSL_FUNC_asym_cipher_encrypt_init_fn ibmca_asym_cipher_rsa_encrypt_init;
static OSSL_FUNC_asym_cipher_encrypt_fn ibmca_asym_cipher_rsa_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_init_fn ibmca_asym_cipher_rsa_decrypt_init;
static OSSL_FUNC_asym_cipher_decrypt_fn ibmca_asym_cipher_rsa_decrypt;

static void ibmca_asym_cipher_rsa_free_cb(struct ibmca_op_ctx *ctx);
static int ibmca_asym_cipher_rsa_dup_cb(const struct ibmca_op_ctx *ctx,
                                        struct ibmca_op_ctx *new_ctx);

static void *ibmca_asym_cipher_rsa_newctx(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    struct ibmca_op_ctx *opctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    opctx = ibmca_op_newctx(provctx, NULL, EVP_PKEY_RSA,
                            ibmca_asym_cipher_rsa_free_cb,
                            ibmca_asym_cipher_rsa_dup_cb);
    if (opctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_op_newctx failed");
        return NULL;
    }

    ibmca_debug_ctx(provctx, "opctx: %p", opctx);

    return opctx;
}

static void ibmca_asym_cipher_rsa_free_cb(struct ibmca_op_ctx *ctx)
{
    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->rsa.cipher.oaep_md != NULL)
        EVP_MD_free(ctx->rsa.cipher.oaep_md);
    ctx->rsa.cipher.oaep_md = NULL;

    if (ctx->rsa.cipher.mgf1_md != NULL)
        EVP_MD_free(ctx->rsa.cipher.mgf1_md);
    ctx->rsa.cipher.mgf1_md = NULL;

    if (ctx->rsa.cipher.oaep_label != NULL)
        P_FREE(ctx->provctx, ctx->rsa.cipher.oaep_label);
    ctx->rsa.cipher.oaep_label = NULL;
    ctx->rsa.cipher.oaep_labellen = 0;
}

static int ibmca_asym_cipher_rsa_dup_cb(const struct ibmca_op_ctx *ctx,
                                        struct ibmca_op_ctx *new_ctx)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p new_ctx: %p", ctx, new_ctx);

    new_ctx->rsa.cipher.oaep_md = ctx->rsa.cipher.oaep_md;
    if (new_ctx->rsa.cipher.oaep_md != NULL &&
        EVP_MD_up_ref(new_ctx->rsa.cipher.oaep_md) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR, "EVP_MD_up_ref failed");
        return 0;
    }

    new_ctx->rsa.cipher.mgf1_md = ctx->rsa.cipher.mgf1_md;
    if (new_ctx->rsa.cipher.mgf1_md != NULL &&
        EVP_MD_up_ref(new_ctx->rsa.cipher.mgf1_md) == 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR, "EVP_MD_up_ref failed");
        return 0;
    }

    new_ctx->rsa.cipher.oaep_label = NULL;
    new_ctx->rsa.cipher.oaep_labellen = 0;

    return 1;
}

static int ibmca_asym_cipher_rsa_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    const OSSL_PARAM *p;
    const char *name = NULL;
    int i, rc;

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    /* OSSL_ASYM_CIPHER_PARAM_PAD_MODE */
    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            rc = ibmca_param_build_set_int(ctx->provctx, NULL, params,
                                           OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                           ctx->rsa.cipher.pad_mode);
            if (rc == 0)
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            for (i = 0; ibmca_rsa_padding_table[i].id != 0; i++) {
                if ((int)ibmca_rsa_padding_table[i].id ==
                                                ctx->rsa.cipher.pad_mode) {
                    name = ibmca_rsa_padding_table[i].ptr;
                    break;
                }
            }
            if (name == NULL) {
                put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                                 "Invalid RSA padding mode: %d",
                                 ctx->rsa.cipher.pad_mode);
                return 0;
            }

            rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                            OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                            name);
             if (rc == 0)
                 return 0;
            break;
        default:
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid param type for: '%s'",
                             OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
            return 0;
        }
    }

    /* OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST */
    if (ctx->rsa.cipher.oaep_md != NULL)
        name = EVP_MD_get0_name(ctx->rsa.cipher.oaep_md);
    else
        name = "";
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                    name);
    if (rc == 0)
        return 0;

    /* OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST */
    if (ctx->rsa.cipher.mgf1_md != NULL)
        name = EVP_MD_get0_name(ctx->rsa.cipher.mgf1_md);
    rc = ibmca_param_build_set_utf8(ctx->provctx, NULL, params,
                                    OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                    name);
    if (rc == 0)
        return 0;

    /* OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL */
    rc = ibmca_param_build_set_octet_ptr(ctx->provctx, NULL, params,
                                         OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                         ctx->rsa.cipher.oaep_label,
                                         ctx->rsa.cipher.oaep_labellen);
    if (rc == 0)
        return 0;

    /* OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION */
    rc = ibmca_param_build_set_uint(ctx->provctx, NULL, params,
                                    OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
                                    ctx->rsa.cipher.tls_clnt_version);
    if (rc == 0)
        return 0;

    /* OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION */
    rc = ibmca_param_build_set_uint(ctx->provctx, NULL, params,
                                    OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
                                    ctx->rsa.cipher.tls_alt_version);
    if (rc == 0)
        return 0;

#ifdef OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION
    /* OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION */
    rc = ibmca_param_build_set_uint(ctx->provctx, NULL, params,
                                    OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION,
                                    0);
    if (rc == 0)
        return 0;
#endif

    return 1;
}

static int ibmca_asym_cipher_rsa_set_ctx_params(void *vctx,
                                                const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    const OSSL_PARAM *p;
    const char *name, *props;
    void *label = NULL;
    size_t labellen = 0;
    int i, rc;
#ifdef OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION
    unsigned int implicit_rejection;
#endif

    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    /* OSSL_ASYM_CIPHER_PARAM_PAD_MODE */
    p = OSSL_PARAM_locate((OSSL_PARAM *)params,
                          OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            rc = ibmca_param_get_int(ctx->provctx, params,
                                     OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                     &ctx->rsa.cipher.pad_mode);
            if (rc == 0)
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            rc = ibmca_param_get_utf8(ctx->provctx, params,
                                      OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &name);
            if (rc == 1) {
                ctx->rsa.cipher.pad_mode = 0;
                for (i = 0; ibmca_rsa_padding_table[i].id != 0; i++) {
                    if (strcmp(name, ibmca_rsa_padding_table[i].ptr) == 0) {
                        ctx->rsa.cipher.pad_mode =
                                            ibmca_rsa_padding_table[i].id;
                        break;
                    }
                }
            }
            break;
        default:
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid param type for: '%s'",
                             OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
            return 0;
        }

        switch (ctx->rsa.cipher.pad_mode) {
        case RSA_NO_PADDING:
        case RSA_PKCS1_PADDING:
        case RSA_PKCS1_WITH_TLS_PADDING:
            break;
        case RSA_PKCS1_OAEP_PADDING:
            /* Setup default md if not already set */
            if (ctx->rsa.cipher.oaep_md == NULL) {
                ctx->rsa.cipher.oaep_md = EVP_MD_fetch(ctx->provctx->libctx,
                              OBJ_nid2sn(IBMCA_RSA_OAEP_DEFAULT_DIGEST), NULL);
                if (ctx->rsa.cipher.oaep_md == NULL) {
                    put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                                  "Failed to fetch default OAEP digest");
                    return 0;
                }
            }
            break;
        case RSA_PKCS1_PSS_PADDING: /* PSS is for signatures only */
        case RSA_X931_PADDING: /* X.931 is for signatures only */
        default:
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                                      "Invalid RSA padding mode: %d",
                                      ctx->rsa.cipher.pad_mode);
            return 0;
        }
    }

    /* OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS */
    props = NULL;
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS, &props);
    if (rc == 0)
        return 0;

    /* OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (ctx->rsa.cipher.oaep_md != NULL)
            EVP_MD_free(ctx->rsa.cipher.oaep_md);
        ctx->rsa.cipher.oaep_md = EVP_MD_fetch(ctx->provctx->libctx, name,
                                               props);
        if (ctx->rsa.cipher.oaep_md == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                              "Invalid RSA OAEP digest: '%s'", name);
            return 0;
        }
    }

    /* OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS */
    props = NULL;
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, &props);
    if (rc == 0)
        return 0;

    /* OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST */
    rc = ibmca_param_get_utf8(ctx->provctx, params,
                              OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (ctx->rsa.cipher.mgf1_md != NULL)
            EVP_MD_free(ctx->rsa.cipher.mgf1_md);
        ctx->rsa.cipher.mgf1_md = EVP_MD_fetch(ctx->provctx->libctx, name,
                                               props);
        if (ctx->rsa.cipher.mgf1_md == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                              "Invalid RSA MGF1 digest: '%s'", name);
            return 0;
        }
    }

    /* OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL */
    rc = ibmca_param_get_octet_string(ctx->provctx, params,
                                      OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                      &label, &labellen);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (ctx->rsa.cipher.oaep_label != NULL)
            P_FREE(ctx->provctx, ctx->rsa.cipher.oaep_label);

        ctx->rsa.cipher.oaep_label = label;
        ctx->rsa.cipher.oaep_labellen = labellen;
    }

    /* OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION */
    rc = ibmca_param_get_uint(ctx->provctx, params,
                              OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
                              &ctx->rsa.cipher.tls_clnt_version);
    if (rc == 0)
        return 0;

    /* OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION */
    rc = ibmca_param_get_uint(ctx->provctx, params,
                              OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION,
                              &ctx->rsa.cipher.tls_alt_version);
    if (rc == 0)
        return 0;

#ifdef OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION
    rc = ibmca_param_get_uint(ctx->provctx, params,
                              OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION,
                              &implicit_rejection);
    if (rc == 0)
        return 0;
    if (rc > 0 && implicit_rejection != 0) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "RSA: Implicit rejection is not supported");
        return 0;
    }
#endif

    return 1;
}

static const OSSL_PARAM ibmca_asym_cipher_rsa_gettable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
#ifdef OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, NULL),
#endif
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_asym_cipher_rsa_gettable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    for (p = ibmca_asym_cipher_rsa_gettable_params;
                                    p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_asym_cipher_rsa_gettable_params;
}

static const OSSL_PARAM ibmca_asym_cipher_rsa_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
#ifdef OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, NULL),
#endif
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_asym_cipher_rsa_settable_ctx_params(
                                                void *vctx, void *vprovctx)
{
    const struct ibmca_op_ctx *ctx = vctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    ibmca_debug_ctx(provctx, "ctx: %p", ctx);

    for (p = ibmca_asym_cipher_rsa_settable_params;
                                p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_asym_cipher_rsa_settable_params;
}

static int ibmca_asym_cipher_rsa_op_init(struct ibmca_op_ctx *ctx,
                                         struct ibmca_key *key,
                                         const OSSL_PARAM params[],
                                         int operation)
{
    const OSSL_PARAM *p;

    if (ctx == NULL || key == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p operation: %d", ctx, key,
                       operation);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(ctx, "param: %s", p->key);

    if (ibmca_op_init(ctx, key, operation) == 0) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_init failed");
        return 0;
    }

    if (key->type == EVP_PKEY_RSA_PSS) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Encrypt/decrypt operation not support for RSA-PSS keys");
        return 0;
    }

    /* Setup defaults for this context */
    ibmca_asym_cipher_rsa_free_cb(ctx);
    ctx->rsa.cipher.pad_mode = RSA_PKCS1_PADDING;
    ctx->rsa.cipher.mgf1_md = NULL;
    ctx->rsa.cipher.oaep_md = NULL;
    ctx->rsa.cipher.oaep_label = NULL;
    ctx->rsa.cipher.oaep_labellen = 0;

    if (params != NULL) {
        if (ibmca_asym_cipher_rsa_set_ctx_params(ctx, params) == 0) {
            ibmca_debug_op_ctx(ctx,
                    "ERROR: ibmca_asym_cipher_rsa_set_ctx_params failed");
            return 0;
        }
    }

    return 1;

}

static int ibmca_asym_cipher_rsa_encrypt_init(void *vctx, void *vkey,
                                              const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_asym_cipher_rsa_op_init(ctx, key, params, EVP_PKEY_OP_ENCRYPT);
}

static int ibmca_asym_cipher_rsa_decrypt_init(void *vctx, void *vkey,
                                              const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *ctx = vctx;
    struct ibmca_key *key = vkey;

    return ibmca_asym_cipher_rsa_op_init(ctx, key, params, EVP_PKEY_OP_DECRYPT);
}

static int ibmca_asym_cipher_rsa_encrypt_fallback(struct ibmca_op_ctx *ctx,
                                                  unsigned char *out,
                                                  size_t outsize,
                                                  const unsigned char *in,
                                                  size_t inlen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen;
    int rc = 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p inlen: %lu out: %p outsize: %lu",
                       ctx, ctx->key, inlen, out, outsize);

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

    if (EVP_PKEY_encrypt_init(pctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_encrypt_init/EVP_PKEY_CTX_set_rsa_padding failed");
        goto out;
    }

    if (ibmca_check_fallback_provider(ctx->provctx, pctx) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_check_fallback_provider failed");
        goto out;
    }

    outlen = outsize;
    if (EVP_PKEY_encrypt(pctx, out, &outlen, in, inlen) != 1 ||
        outlen != outsize) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_encrypt failed");
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

static int ibmca_asym_cipher_rsa_encrypt(void *vctx,
                                         unsigned char *out, size_t *outlen,
                                         size_t outsize,
                                         const unsigned char *in, size_t inlen)
{
    struct ibmca_op_ctx *ctx = vctx;
    unsigned char *enc_data;
    size_t enc_data_len, rsa_size;
    int rc = 1;

    if (ctx == NULL || in == NULL || outlen == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p inlen: %lu out: %p outsize: %lu",
                       ctx, ctx->key, inlen, out, outsize);

    if (ctx->operation != EVP_PKEY_OP_ENCRYPT) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR, "Invalid operation");
        return 0;
    }

    rsa_size = ctx->key->get_max_param_size(ctx->key);
    *outlen = rsa_size;

    if (out == NULL) /* size query */
        goto out;

    if (outsize < *outlen) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Output buffer too small");
        return 0;
    }

    ibmca_debug_op_ctx(ctx, "pad_mode: %d", ctx->rsa.cipher.pad_mode);

    /* Allocate padding buffer, if required by padding mode */
    switch (ctx->rsa.cipher.pad_mode) {
    case RSA_NO_PADDING:
        if (inlen != rsa_size) {
            put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                             "Invalid input length");
            return 0;
        }
        enc_data = (unsigned char *)in;
        enc_data_len = inlen;
        break;

    case RSA_PKCS1_PADDING:
    case RSA_PKCS1_OAEP_PADDING:
        if (ibmca_op_alloc_tbuf(ctx, rsa_size) == 0) {
            ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
            return 0;
        }

        enc_data_len = ctx->tbuf_len;
        enc_data = ctx->tbuf;
        break;

    case RSA_X931_PADDING:
    case RSA_PKCS1_PSS_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING: /* Only valid for decrypt */
    default:
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Invalid padding mode: %d", ctx->rsa.cipher.pad_mode);
        return 0;
    }

    /* Perform padding */
    switch (ctx->rsa.cipher.pad_mode) {
    case RSA_NO_PADDING:
        rc = 1;
        break;

    case RSA_PKCS1_PADDING:
        rc = ibmca_rsa_add_pkcs1_padding(ctx->key->provctx, 2, in, inlen,
                                         enc_data, enc_data_len);
        break;

    case RSA_PKCS1_OAEP_PADDING:
        rc = ibmca_rsa_add_oaep_mgf1_padding(ctx->key->provctx, in, inlen,
                                             enc_data, enc_data_len,
                                             ctx->rsa.cipher.oaep_md,
                                             ctx->rsa.cipher.mgf1_md,
                                             ctx->rsa.cipher.oaep_label,
                                             ctx->rsa.cipher.oaep_labellen);
        break;

    case RSA_X931_PADDING:
    case RSA_PKCS1_PSS_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING: /* Only valid for decrypt */
    default:
        rc = 0;
        goto out;
    }
    if (rc == 0)
        goto out;

    /* Perform public key encrypt */
    rc = ica_rsa_mod_expo(ctx->provctx->ica_adapter, enc_data,
                          &ctx->key->rsa.public, out);
    if (rc != 0) {
        ibmca_debug_op_ctx(ctx, "ica_rsa_mod_expo failed with: %s",
                           strerror(rc));

        rc = ibmca_asym_cipher_rsa_encrypt_fallback(ctx, out, *outlen,
                                                    enc_data, enc_data_len);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_asym_cipher_rsa_encrypt_fallback failed");
            rc = 0;
            goto out;
        }
    }

    rc = 1;

 out:
     if (ctx->tbuf != NULL)
         P_CLEANSE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);

    ibmca_debug_op_ctx(ctx, "outlen: %lu rc: %d", *outlen, rc);

    return rc;

}

static int ibmca_asym_cipher_rsa_decrypt_fallback(struct ibmca_op_ctx *ctx,
                                                  unsigned char *out,
                                                  size_t outsize,
                                                  const unsigned char *in,
                                                  size_t inlen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen;
    int rc = 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p inlen: %lu out: %p outsize: %lu",
                       ctx, ctx->key, inlen, out, outsize);

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

    if (EVP_PKEY_decrypt_init(pctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) != 1) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_decrypt_init/EVP_PKEY_CTX_set_rsa_padding failed");
        goto out;
    }

    if (ibmca_check_fallback_provider(ctx->provctx, pctx) != 1) {
        ibmca_debug_op_ctx(ctx, "ERROR: ibmca_check_fallback_provider failed");
        goto out;
    }

    outlen = outsize;
    if (EVP_PKEY_decrypt(pctx, out, &outlen, in, inlen) != 1 ||
        outlen != outsize) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_decrypt failed");
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

static int ibmca_asym_cipher_rsa_decrypt(void *vctx,
                                         unsigned char *out, size_t *outlen,
                                         size_t outsize,
                                         const unsigned char *in, size_t inlen)
{
    struct ibmca_op_ctx *ctx = vctx;
    unsigned char *dec_data;
    size_t dec_data_len, rsa_size;
    int rc = 1;

    if (ctx == NULL || in == NULL || outlen == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p key: %p inlen: %lu out: %p outsize: %lu",
                       ctx, ctx->key, inlen, out, outsize);

    if (ctx->operation != EVP_PKEY_OP_DECRYPT) {
        put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR, "Invalid operation");
        return 0;
    }

    rsa_size = ctx->key->get_max_param_size(ctx->key);

    if (ctx->rsa.cipher.pad_mode == RSA_PKCS1_WITH_TLS_PADDING)
        *outlen = IBMCA_SSL_MAX_MASTER_KEY_LENGTH;
    else
        *outlen = rsa_size;

    if (out == NULL) /* size query */
        goto out;

    if (outsize < *outlen) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM, "Output buffer too small");
        return 0;
    }

    if (inlen != rsa_size) {
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Invalid input length");
        return 0;
    }

    ibmca_debug_op_ctx(ctx, "pad_mode: %d", ctx->rsa.cipher.pad_mode);

    /* Allocate padding buffer, if required by padding mode */
    switch (ctx->rsa.cipher.pad_mode) {
    case RSA_NO_PADDING:
        dec_data = out;
        dec_data_len = *outlen;
        break;

    case RSA_PKCS1_PADDING:
    case RSA_PKCS1_OAEP_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING:
        if (ibmca_op_alloc_tbuf(ctx, rsa_size) == 0) {
            ibmca_debug_op_ctx(ctx, "ERROR: ibmca_op_alloc_tbuf failed");
            return 0;
        }

        dec_data_len = ctx->tbuf_len;
        dec_data = ctx->tbuf;
        break;

    case RSA_X931_PADDING:
    case RSA_PKCS1_PSS_PADDING:
    default:
        put_error_op_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                         "Invalid padding mode: %d", ctx->rsa.cipher.pad_mode);
        return 0;
    }

    /* Perform private key decrypt */
    rc = ica_rsa_crt(ctx->provctx->ica_adapter, (unsigned char *)in,
                     &ctx->key->rsa.private, dec_data);
    if (rc != 0) {
        ibmca_debug_op_ctx(ctx, "ica_rsa_crt failed with: %s", strerror(rc));

        rc = ibmca_asym_cipher_rsa_decrypt_fallback(ctx, dec_data, dec_data_len,
                                                    in, inlen);
        if (rc != 1) {
            ibmca_debug_op_ctx(ctx,
                               "ERROR: ibmca_asym_cipher_rsa_decrypt_fallback failed");
            rc = 0;
            goto out;
        }
    }

    /* Perform padding check */
    switch (ctx->rsa.cipher.pad_mode) {
    case RSA_NO_PADDING:
        /* outlen is already set */
        rc = 1;
        break;

    case RSA_PKCS1_PADDING:
        rc = ibmca_rsa_check_pkcs1_padding(ctx->key->provctx, 2,
                                           dec_data, dec_data_len,
                                           out, outsize, NULL, outlen);
        break;

    case RSA_PKCS1_OAEP_PADDING:
        rc = ibmca_rsa_check_oaep_mgf1_padding(ctx->key->provctx,
                                               dec_data, dec_data_len,
                                               out, outsize, NULL, outlen,
                                               ctx->rsa.cipher.oaep_md,
                                               ctx->rsa.cipher.mgf1_md,
                                               ctx->rsa.cipher.oaep_label,
                                               ctx->rsa.cipher.oaep_labellen);
        break;

    case RSA_PKCS1_WITH_TLS_PADDING:
        rc = ibmca_rsa_check_pkcs1_tls_padding(ctx->key->provctx,
                                               ctx->rsa.cipher.tls_clnt_version,
                                               ctx->rsa.cipher.tls_alt_version,
                                               dec_data, dec_data_len,
                                               out, outsize, outlen);
        break;

    case RSA_X931_PADDING:
    case RSA_PKCS1_PSS_PADDING:
    default:
        rc = 0;
        goto out;
    }
    if (rc == 0)
        goto out;

    rc = 1;

out:
    if (ctx->tbuf != NULL)
        P_CLEANSE(ctx->provctx, ctx->tbuf, ctx->tbuf_len);

    ibmca_debug_op_ctx(ctx, "outlen: %lu rc: %d", *outlen, rc);

    return rc;
}

static const OSSL_DISPATCH ibmca_rsa_asym_cipher_functions[] = {
    /* RSA context constructor, destructor */
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX,
            (void (*)(void))ibmca_asym_cipher_rsa_newctx },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))ibmca_op_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX,
            (void (*)(void))ibmca_op_dupctx },
    /* RSA context set/get parameters */
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
            (void (*)(void))ibmca_asym_cipher_rsa_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
            (void (*)(void))ibmca_asym_cipher_rsa_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
            (void (*)(void))ibmca_asym_cipher_rsa_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
            (void (*)(void))ibmca_asym_cipher_rsa_settable_ctx_params },
    /* RSA encrypt */
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
            (void (*)(void))ibmca_asym_cipher_rsa_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
            (void (*)(void))ibmca_asym_cipher_rsa_encrypt },
    /* RSA decrypt */
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
            (void (*)(void))ibmca_asym_cipher_rsa_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT,
            (void (*)(void))ibmca_asym_cipher_rsa_decrypt },
    { 0, NULL }
};

const OSSL_ALGORITHM ibmca_rsa_asym_cipher[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", NULL,
      ibmca_rsa_asym_cipher_functions, "IBMCA RSA asym cipher implementation" },
    { NULL, NULL, NULL, NULL }
};
