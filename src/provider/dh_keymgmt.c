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
#include <openssl/dh.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/prov_ssl.h>

#include "p_ibmca.h"

static OSSL_FUNC_keymgmt_new_fn ibmca_keymgmt_dh_new;
static OSSL_FUNC_keymgmt_new_fn ibmca_keymgmt_dhx_new;
static OSSL_FUNC_keymgmt_gen_init_fn ibmca_keymgmt_dh_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn ibmca_keymgmt_dhx_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn ibmca_keymgmt_dh_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn ibmca_keymgmt_dh_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn
                                        ibmca_keymgmt_dh_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn ibmca_keymgmt_dh_gen;
static OSSL_FUNC_keymgmt_has_fn ibmca_keymgmt_dh_has;
static OSSL_FUNC_keymgmt_match_fn ibmca_keymgmt_dh_match;
static OSSL_FUNC_keymgmt_validate_fn ibmca_keymgmt_dh_validate;
static OSSL_FUNC_keymgmt_query_operation_name_fn
                                        ibmca_keymgmt_dh_query_operation_name;
static OSSL_FUNC_keymgmt_get_params_fn ibmca_keymgmt_dh_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn ibmca_keymgmt_dh_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn ibmca_keymgmt_dh_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn ibmca_keymgmt_dh_settable_params;
static OSSL_FUNC_keymgmt_export_fn ibmca_keymgmt_dh_export;
static OSSL_FUNC_keymgmt_export_types_fn ibmca_keymgmt_dh_imexport_types;
static OSSL_FUNC_keymgmt_import_fn ibmca_keymgmt_dh_import;

static void ibmca_keymgmt_dh_free_cb(struct ibmca_key *key);
static int ibmca_keymgmt_dh_dup_cb(const struct ibmca_key *key,
                                   struct ibmca_key *new_key);
static size_t ibmca_keymgmt_dh_get_prime_size(const struct ibmca_key *key);

static struct ibmca_key *ibmca_keymgmt_dh_new_type(
                                       const struct ibmca_prov_ctx *provctx,
                                       int type,  const char *algorithm)
{
    struct ibmca_key *key;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p type: %d algorithm: '%s'", provctx,
                    type, algorithm);

    key = ibmca_keymgmt_new(provctx, type, algorithm,
                            ibmca_keymgmt_dh_free_cb,
                            ibmca_keymgmt_dh_dup_cb,
                            ibmca_keymgmt_dh_get_prime_size,
                            ibmca_keymgmt_dh_export,
                            ibmca_keymgmt_dh_import,
                            ibmca_keymgmt_dh_has,
                            ibmca_keymgmt_dh_match);
    if (key == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_keymgmt_new failed");
        return NULL;
    }

    key->dh.ffc_params.group_nid = NID_undef;
    key->dh.ffc_params.length = 0;
    key->dh.ffc_params.seed = NULL;
    key->dh.ffc_params.seed_len = 0;
    key->dh.ffc_params.gindex = -1;
    key->dh.ffc_params.pcounter = -1;
    key->dh.ffc_params.hindex = 0;
    key->dh.ffc_params.validate_pq = true;
    key->dh.ffc_params.validate_g = true;
    key->dh.ffc_params.validate_legacy = false;

    return key;
}
static void *ibmca_keymgmt_dh_new(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    return ibmca_keymgmt_dh_new_type(provctx, EVP_PKEY_DH, "DH");
}

static void *ibmca_keymgmt_dhx_new(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    return ibmca_keymgmt_dh_new_type(provctx, EVP_PKEY_DHX, "DHX");
}

static void ibmca_keymgmt_dh_free_cb(struct ibmca_key *key)
{
    if (key == NULL)
        return;

    ibmca_debug_key(key, "key: %p", key);

    if (key->dh.priv != NULL)
        BN_clear_free(key->dh.priv);
    key->dh.priv = NULL;

    if (key->dh.pub != NULL)
        BN_free(key->dh.pub);
    key->dh.pub = NULL;

    if (key->dh.ffc_params.p != NULL)
        BN_free(key->dh.ffc_params.p);
    key->dh.ffc_params.p = NULL;

    if (key->dh.ffc_params.q != NULL)
        BN_free(key->dh.ffc_params.q);
    key->dh.ffc_params.q = NULL;

    if (key->dh.ffc_params.g != NULL)
        BN_free(key->dh.ffc_params.g);
    key->dh.ffc_params.g = NULL;

    if (key->dh.ffc_params.cofactor != NULL)
        BN_free(key->dh.ffc_params.cofactor);
    key->dh.ffc_params.cofactor = NULL;

    if (key->dh.ffc_params.seed != NULL)
        P_FREE(key->provctx, key->dh.ffc_params.seed);
    key->dh.ffc_params.seed = NULL;
    key->dh.ffc_params.seed_len = 0;

    if (key->dh.ffc_params.mdname != NULL)
        P_FREE(key->provctx, (char *)key->dh.ffc_params.mdname);
    key->dh.ffc_params.mdname = NULL;

    if (key->dh.ffc_params.mdprops != NULL)
        P_FREE(key->provctx, (char *)key->dh.ffc_params.mdprops);
    key->dh.ffc_params.mdprops = NULL;

    key->dh.ffc_params.group_nid = NID_undef;
    key->dh.ffc_params.length = 0;
    key->dh.ffc_params.gindex = -1;
    key->dh.ffc_params.pcounter = -1;
    key->dh.ffc_params.hindex = 0;
    key->dh.ffc_params.validate_pq = true;
    key->dh.ffc_params.validate_g = true;
    key->dh.ffc_params.validate_legacy = false;
}

static int ibmca_keymgmt_dh_dup_params(const struct ibmca_key *key,
                                       struct ibmca_key *new_key)
{
    if (key == NULL || new_key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p new_key: %p", key, new_key);

    if (key->dh.ffc_params.p != NULL) {
        new_key->dh.ffc_params.p = BN_dup(key->dh.ffc_params.p);
        if (new_key->dh.ffc_params.p == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            return 0;
        }
    }

    if (key->dh.ffc_params.q != NULL) {
        new_key->dh.ffc_params.q = BN_dup(key->dh.ffc_params.q);
        if (new_key->dh.ffc_params.q == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            return 0;
        }
    }

    if (key->dh.ffc_params.g != NULL) {
        new_key->dh.ffc_params.g = BN_dup(key->dh.ffc_params.g);
        if (new_key->dh.ffc_params.g == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            return 0;
        }
    }

    if (key->dh.ffc_params.cofactor != NULL) {
        new_key->dh.ffc_params.cofactor = BN_dup(key->dh.ffc_params.cofactor);
        if (new_key->dh.ffc_params.cofactor == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            return 0;
        }
    }

    if (key->dh.ffc_params.seed != NULL && key->dh.ffc_params.seed_len > 0) {
        new_key->dh.ffc_params.seed = P_MEMDUP(key->provctx,
                                               key->dh.ffc_params.seed,
                                               key->dh.ffc_params.seed_len);
        if (new_key->dh.ffc_params.seed == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            return 0;
        }
        new_key->dh.ffc_params.seed_len = key->dh.ffc_params.seed_len;
    }

    new_key->dh.ffc_params.group_nid = key->dh.ffc_params.group_nid;
    new_key->dh.ffc_params.length = key->dh.ffc_params.length;
    new_key->dh.ffc_params.gindex = key->dh.ffc_params.gindex;
    new_key->dh.ffc_params.pcounter = key->dh.ffc_params.pcounter;
    new_key->dh.ffc_params.hindex = key->dh.ffc_params.hindex;
    new_key->dh.ffc_params.validate_pq = key->dh.ffc_params.validate_pq;
    new_key->dh.ffc_params.validate_g = key->dh.ffc_params.validate_g;
    new_key->dh.ffc_params.validate_legacy = key->dh.ffc_params.validate_legacy;

    return 1;
}

static int ibmca_keymgmt_dh_dup_cb(const struct ibmca_key *key,
                                   struct ibmca_key *new_key)
{
    if (key == NULL || new_key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p new_key: %p", key, new_key);

    if (key->dh.priv != NULL) {
        new_key->dh.priv = BN_dup(key->dh.priv);
        if (new_key->dh.priv == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            return 0;
        }
    }

    if (key->dh.pub != NULL) {
        new_key->dh.pub = BN_dup(key->dh.pub);
        if (new_key->dh.pub == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            return 0;
        }
    }

    return ibmca_keymgmt_dh_dup_params(key, new_key);
}

static size_t ibmca_keymgmt_dh_get_prime_bits(const struct ibmca_key *key)
{
    if (key->dh.ffc_params.p != NULL)
        return BN_num_bits(key->dh.ffc_params.p);

    put_error_key(key, IBMCA_ERR_INVALID_PARAM, "No DH parameters available");
    return 0;
}

static size_t ibmca_keymgmt_dh_get_prime_size(const struct ibmca_key *key)
{
    return (ibmca_keymgmt_dh_get_prime_bits(key) + 7) / 8;
}

static int ibmca_keymgmt_dh_get_security_bits(const struct ibmca_key *key)
{
    int n;

    if (key->dh.ffc_params.p != NULL)
        n =  BN_num_bits(key->dh.ffc_params.p);
    else
        n = key->dh.ffc_params.length;
    if (n == 0)
        n = -1;

    if (key->dh.ffc_params.p != NULL)
        return BN_security_bits(BN_num_bits(key->dh.ffc_params.p), n);

    put_error_key(key, IBMCA_ERR_INVALID_PARAM, "No DH parameters available");
    return -1;
}

static void ibmca_keymgmt_dh_gen_free_cb(struct ibmca_op_ctx *ctx)
{
    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->dh.gen.pctx != NULL)
        EVP_PKEY_CTX_free(ctx->dh.gen.pctx);
    ctx->dh.gen.pctx = NULL;

    ctx->dh.gen.selection = 0;
    ctx->dh.gen.priv_len = 0;
}

static int ibmca_keymgmt_dh_gen_dup_cb(const struct ibmca_op_ctx *ctx,
                                       struct ibmca_op_ctx *new_ctx)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p new_ctx: %p", ctx, new_ctx);

    if (ctx->dh.gen.pctx != NULL) {
        new_ctx->dh.gen.pctx = EVP_PKEY_CTX_dup(ctx->dh.gen.pctx);
        if (new_ctx->dh.gen.pctx == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                             "EVP_PKEY_CTX_dup failed");
            return 0;
        }
    }

    new_ctx->dh.gen.selection = ctx->dh.gen.selection;
    new_ctx->dh.gen.priv_len = ctx->dh.gen.priv_len;

    return 1;
}

static int ibmca_keymgmt_dh_gen_init_pctx(struct ibmca_op_ctx *genctx,
                                          int operation, EVP_PKEY *templ_pkey)
{
    const char *algorithm = NULL;

    ibmca_debug_op_ctx(genctx, "genctx: %p operation: %d templ_pkey: %p", genctx,
                       operation, templ_pkey);

    switch (genctx->type) {
    case EVP_PKEY_DH:
        algorithm = "DH";
        break;
    case EVP_PKEY_DHX:
        algorithm = "DHX";
        break;
    default:
        put_error_op_ctx(genctx, IBMCA_ERR_INTERNAL_ERROR,
                         "Invalid context type");
        return 0;
    }

    genctx->dh.gen.pctx = ibmca_new_fallback_pkey_ctx(genctx->provctx,
                                                      templ_pkey,
                                                      algorithm);
    if (genctx->dh.gen.pctx == NULL) {
        ibmca_debug_op_ctx(genctx, "ERROR: ibmca_new_fallback_pkey_ctx failed");
        return 0;
    }

    switch (operation) {
    case EVP_PKEY_OP_KEYGEN:
        if (EVP_PKEY_keygen_init(genctx->dh.gen.pctx) != 1) {
            put_error_op_ctx(genctx, IBMCA_ERR_INTERNAL_ERROR,
                            "EVP_PKEY_keygen_init failed");
            goto error;
        }
        break;
    case EVP_PKEY_OP_PARAMGEN:
        if (EVP_PKEY_paramgen_init(genctx->dh.gen.pctx) != 1) {
            put_error_op_ctx(genctx, IBMCA_ERR_INTERNAL_ERROR,
                            "EVP_PKEY_paramgen_init failed");
            goto error;
        }
        break;
    default:
        put_error_op_ctx(genctx, IBMCA_ERR_INTERNAL_ERROR,
                                 "Invalid operation type");
        goto error;
    }

    if (ibmca_check_fallback_provider(genctx->provctx,
                                      genctx->dh.gen.pctx) != 1) {
        ibmca_debug_op_ctx(genctx,
                           "ERROR: ibmca_check_fallback_provider failed");
        return 0;
    }

    return 1;

error:
    EVP_PKEY_CTX_free(genctx->dh.gen.pctx);
    genctx->dh.gen.pctx = NULL;

    return 0;
}

static struct ibmca_op_ctx *ibmca_keymgmt_dh_gen_init_type(
                                            const struct ibmca_prov_ctx *provctx,
                                            int selection,
                                            const OSSL_PARAM params[],
                                            int type)
{
    struct ibmca_op_ctx *ctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p selection: 0x%x type: %d", provctx,
                    selection, type);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR |
                      OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) == 0)
        return NULL;

    ctx = ibmca_keymgmt_gen_init(provctx, type,
                                 ibmca_keymgmt_dh_gen_free_cb,
                                 ibmca_keymgmt_dh_gen_dup_cb);
    if (ctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_keymgmt_gen_init failed");
        return NULL;
    }

    ibmca_keymgmt_dh_gen_free_cb(ctx);

    ctx->dh.gen.selection = selection;

    if (ibmca_keymgmt_dh_gen_init_pctx(ctx, EVP_PKEY_OP_PARAMGEN, NULL) != 1) {
        ibmca_debug_ctx(provctx,
                        "ERROR: ibmca_keymgmt_dh_gen_init_pctx failed");
        goto error;
    }

    if (params != NULL) {
        if (ibmca_keymgmt_dh_gen_set_params(ctx, params) == 0) {
            ibmca_debug_ctx(provctx,
                            "ERROR: ibmca_keymgmt_dh_gen_set_params failed");
            goto error;
        }
    }

    return ctx;

error:
    ibmca_op_freectx(ctx);
    return NULL;
}

static void *ibmca_keymgmt_dh_gen_init(void *vprovctx, int selection,
                                       const OSSL_PARAM params[])
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    return ibmca_keymgmt_dh_gen_init_type(provctx, selection, params,
                                          EVP_PKEY_DH);
}

static void *ibmca_keymgmt_dhx_gen_init(void *vprovctx, int selection,
                                        const OSSL_PARAM params[])
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    return ibmca_keymgmt_dh_gen_init_type(provctx, selection, params,
                                          EVP_PKEY_DHX);
}

static int ibmca_keymgmt_dh_gen_set_template(void *vgenctx, void *vtempl)
{
    struct ibmca_op_ctx *genctx = vgenctx;
    struct ibmca_key *templ = vtempl;

    if (genctx == NULL || templ == NULL)
        return 0;

    ibmca_debug_op_ctx(genctx, "genctx: %p templ: %p", genctx, templ);

    if (genctx->type != templ->type) {
        put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                         "invalid template key type");
        return 0;
    }

    /* Don't generate DH parameters */
    if (genctx->dh.gen.pctx != NULL)
        EVP_PKEY_CTX_free(genctx->dh.gen.pctx);
    genctx->dh.gen.pctx = NULL;

    ibmca_keymgmt_upref(templ);
    genctx->key = templ;

    return 1;
}

static int ibmca_keymgmt_dh_gen_set_params(void *vgenctx,
                                           const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *genctx = vgenctx;
    const OSSL_PARAM *p;
    int rc;

    if (genctx == NULL)
        return 0;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(genctx, "param: %s", p->key);

    if (genctx->dh.gen.pctx == NULL) {
        put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                         "Can not set parameters when template is used");
        return 0;
    }

    if (EVP_PKEY_CTX_set_params(genctx->dh.gen.pctx, params) != 1) {
        put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                         "EVP_PKEY_CTX_set_params failed");
        return 0;
    }

    /*  OSSL_PKEY_PARAM_DH_PRIV_LEN */
    rc = ibmca_param_get_int(genctx->provctx, params,
                             OSSL_PKEY_PARAM_DH_PRIV_LEN,
                             &genctx->dh.gen.priv_len);
    if (rc == 0)
        return 0;

    return 1;
}

static const OSSL_PARAM *ibmca_keymgmt_dh_gen_settable_params(void *vgenctx,
                                                              void *vprovctx)
{
    const struct ibmca_op_ctx *genctx = vgenctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p, *params;

    UNUSED(genctx);

    if (provctx == NULL)
        return NULL;

    if (genctx->dh.gen.pctx == NULL)
        return NULL;

    params = EVP_PKEY_CTX_settable_params(genctx->dh.gen.pctx);

    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return params;
}

static int ibmca_keymgmt_dh_gen_fallback(struct ibmca_op_ctx *genctx,
                                         struct ibmca_key *key,
                                         OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct ibmca_keygen_cb_data cbdata;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *params = NULL;
    int rc = 0;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);

    params = ibmca_new_fallback_pkey(key);
    if (params == NULL) {
        ibmca_debug_op_ctx(genctx,"ERROR: ibmca_new_fallback_pkey failed");
        goto out;
    }

    pctx = ibmca_new_fallback_pkey_ctx(genctx->provctx, params, NULL);
    if (pctx == NULL) {
        ibmca_debug_op_ctx(genctx, "ERROR: ibmca_new_fallback_pkey_ctx failed");
        goto out;
    }

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                     "EVP_PKEY_keygen_init failed");
        goto out;
    }

    if (ibmca_check_fallback_provider(genctx->provctx, pctx) != 1) {
        ibmca_debug_op_ctx(genctx,
                           "ERROR: ibmca_check_fallback_provider failed");
        goto out;
    }

    if (osslcb != NULL) {
        cbdata.osslcb = osslcb;
        cbdata.cbarg = cbarg;
        EVP_PKEY_CTX_set_cb(pctx, ibmca_keygen_cb);
        EVP_PKEY_CTX_set_app_data(pctx, &cbdata);
    }

    if (EVP_PKEY_generate(pctx, &pkey) != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_PKEY_generate failed");
        goto out;
    }

    rc = ibmca_import_from_fallback_pkey(key, pkey, OSSL_KEYMGMT_SELECT_ALL);
    if (rc != 1) {
        ibmca_debug_op_ctx(genctx,
                           "ERROR: ibmca_import_from_fallback_pkey failed");
        goto out;
    }

    rc = 1;

out:
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (params != NULL)
        EVP_PKEY_free(params);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return rc;
}

static int ibmca_keymgmt_dh_gen_priv_key(struct ibmca_key *key, BN_CTX *bn_ctx,
                                             int priv_len, int strength)
{
    int rc = 0, qbits = BN_num_bits(key->dh.ffc_params.q);
    BIGNUM *m, *two_powN = NULL;

    ibmca_debug_key(key, "key: %p priv_len: %d strength: %d", key, priv_len,
                    strength);

    /* Generate a private key in the interval [1, min(2 ^ N - 1, q - 1)]. */

    if (priv_len == 0)
        priv_len = qbits;
    if (strength == 0)
        strength = priv_len / 2;

    if (priv_len < 2 * strength || priv_len > qbits) {
        put_error_key(key, IBMCA_ERR_INVALID_PARAM, "priv_len is invalid");
        return 0;
    }

    two_powN = BN_new();
    if (two_powN == NULL ||
        BN_lshift(two_powN, BN_value_one(), priv_len) != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_new/BN_lshift failed");
        goto out;
    }

    m = (BN_cmp(two_powN, key->dh.ffc_params.q) > 0) ?
                                            key->dh.ffc_params.q : two_powN;

    key->dh.priv = BN_secure_new();
    if (key->dh.priv == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto out;
    }

    do {
        if (BN_priv_rand_range_ex(key->dh.priv, two_powN, 0, bn_ctx) != 1 ||
            BN_add_word(key->dh.priv, 1) != 1) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_priv_rand_range_ex/BN_add_word failed");
            goto out;
        }

        if (BN_cmp(key->dh.priv, m) < 0)
            break;
    } while (1);

    rc = 1;

out:
    if (two_powN != NULL)
        BN_free(two_powN);
    if (rc != 1 && key->dh.priv != NULL) {
        BN_clear_free(key->dh.priv);
        key->dh.priv = NULL;
    }

    return rc;
}

static int ibmca_keymgmt_dh_gen_libica(struct ibmca_key *key, int priv_len,
                                       OSSL_CALLBACK *osslcb, void *cbarg)
{
    OSSL_PARAM cb_params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };
    int rc = 0, p, n, max_strength, len;
    ica_rsa_key_mod_expo_t mod_exp;
    BN_CTX *bn_ctx = NULL;
    size_t prime_size = 0;
    unsigned char *buf = NULL, *pub;

    ibmca_debug_key(key, "key: %p priv_len: %d", key, priv_len);

    cb_params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    cb_params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);

    if (ibmca_keymgmt_dh_has(key,
                             OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "required DH parameters not available");
        return 0;
    }

    ibmca_debug_key(key, "group_nid: %d", key->dh.ffc_params.group_nid);

    /* Generate private key */

    p = 0;
    n = 0;
    if (osslcb != NULL && osslcb(cb_params, cbarg) == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "osslcb failed");
        goto out;
    }

    bn_ctx = BN_CTX_new_ex(key->provctx->libctx);
    if (bn_ctx == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_CTX_new_ex failed");
        return 0;
    }

    if (key->dh.priv != NULL)
        BN_free(key->dh.priv);
    key->dh.priv = NULL;
    if (key->dh.pub != NULL)
        BN_free(key->dh.pub);
    key->dh.pub = NULL;

    if (key->dh.ffc_params.group_nid != NID_undef) {
        /* named group */
        if (key->dh.ffc_params.q == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "required DH parameters not available");
            goto out;
        }

        if (priv_len > BN_num_bits(key->dh.ffc_params.q)) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "priv_len too large");
            goto out;
        }

        max_strength = ibmca_keymgmt_dh_get_security_bits(key);

        if (ibmca_keymgmt_dh_gen_priv_key(key, bn_ctx, priv_len,
                                          max_strength) != 1) {
            ibmca_debug_key(key, "ERROR: ibmca_keymgmt_dh_gen_priv_key failed");
            goto out;
        }
    } else if (key->dh.ffc_params.q == NULL) {
        /* secret exponent length, must satisfy 2^(l-1) <= p */
        if (priv_len >= BN_num_bits(key->dh.ffc_params.p)) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "priv_len too large");
            goto out;
        }
        len = priv_len > 0 ? priv_len : BN_num_bits(key->dh.ffc_params.p) - 1;

        key->dh.priv = BN_secure_new();
        if (key->dh.priv == NULL) {
            put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
            goto out;
        }

        if (BN_priv_rand_ex(key->dh.priv, len, BN_RAND_TOP_ONE,
                            BN_RAND_BOTTOM_ANY, 0, bn_ctx) != 1) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_priv_rand_ex failed");
            BN_clear_free(key->dh.priv);
            key->dh.priv = NULL;
            goto out;
        }

        /*
         * Check for one known case where g is a quadratic non-residue:
         * for g = 2: p % 8 == 3
         */
        if (BN_is_word(key->dh.ffc_params.g, DH_GENERATOR_2) &&
            !BN_is_bit_set(key->dh.ffc_params.p, 2)) {
             /* clear bit 0, since it won't be a secret anyway */
             if (BN_clear_bit(key->dh.priv, 0) != 1) {
                 put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                               "BN_clear_bit failed");
                 BN_clear_free(key->dh.priv);
                 key->dh.priv = NULL;
                 goto out;
             }
        }
    } else {
        if (ibmca_keymgmt_dh_gen_priv_key(key, bn_ctx,
                                          BN_num_bits(key->dh.ffc_params.q),
                                          key->provctx->fips ? 112 : 80) != 1) {
            ibmca_debug_key(key, "ERROR: ibmca_keymgmt_dh_gen_priv_key failed");
            goto out;
        }
    }

    /* Generate public key */

    p = 1;
    n = 0;
    if (osslcb != NULL && osslcb(cb_params, cbarg) == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "osslcb failed");
        goto out;
    }

    prime_size = ibmca_keymgmt_dh_get_prime_size(key);
    buf = P_SECURE_ZALLOC(key->provctx, prime_size * 4);
    if (buf == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate mod-expo buffer");
        goto out;
    }

    /* pub_key = g^priv_key mod p */
    mod_exp.key_length = prime_size;
    mod_exp.modulus = buf + prime_size;
    mod_exp.exponent = buf + 2 * prime_size;
    pub = buf + 3 * prime_size;

    if (BN_bn2binpad(key->dh.ffc_params.p, mod_exp.modulus, prime_size) <= 0 ||
        BN_bn2binpad(key->dh.priv, mod_exp.exponent, prime_size) <= 0 ||
        BN_bn2binpad(key->dh.ffc_params.g, buf, prime_size) <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bn2binpad failed");
        goto out;
    }

    rc = ica_rsa_mod_expo(key->provctx->ica_adapter, buf, &mod_exp, pub);
    if (rc != 0) {
        ibmca_debug_key(key, "ica_rsa_mod_expo failed with: %s", strerror(rc));
        rc = 0;
        goto out;
    }

    key->dh.pub = BN_bin2bn(pub, prime_size, NULL);
    if (key->dh.pub == NULL)  {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bin2bn failed");
        goto out;
    }

    p = 3;
    n = 0;
    if (osslcb != NULL && osslcb(cb_params, cbarg) == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "osslcb failed");
        goto out;
    }

    rc = 1;

out:
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);
    if (buf != NULL)
        P_CLEAR_FREE(key->provctx, buf, prime_size * 4);

    return rc;
}

static void *ibmca_keymgmt_dh_gen(void *vgenctx, OSSL_CALLBACK *osslcb,
                                  void *cbarg)
{
    struct ibmca_op_ctx *genctx = vgenctx;
    struct ibmca_key *key = NULL;
    struct ibmca_keygen_cb_data cbdata;
    EVP_PKEY *pkey = NULL;
    int rc;

    if (genctx == NULL)
        return NULL;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);

    key = ibmca_keymgmt_new(genctx->provctx, genctx->type,
                            genctx->type == EVP_PKEY_DHX ? "DHX" : "DH",
                            ibmca_keymgmt_dh_free_cb,
                            ibmca_keymgmt_dh_dup_cb,
                            ibmca_keymgmt_dh_get_prime_size,
                            ibmca_keymgmt_dh_export,
                            ibmca_keymgmt_dh_import,
                            ibmca_keymgmt_dh_has,
                            ibmca_keymgmt_dh_match);
    if (key == NULL) {
        ibmca_debug_op_ctx(genctx, "ERROR: ibmca_keymgmt_new failed");
        return NULL;
    }

    if (genctx->dh.gen.pctx != NULL) {
        /* Generate DH parameters only */
        if (osslcb != NULL) {
            cbdata.osslcb = osslcb;
            cbdata.cbarg = cbarg;
            EVP_PKEY_CTX_set_cb(genctx->dh.gen.pctx, ibmca_keygen_cb);
            EVP_PKEY_CTX_set_app_data(genctx->dh.gen.pctx, &cbdata);
        }

        if (EVP_PKEY_generate(genctx->dh.gen.pctx, &pkey) != 1) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EVP_PKEY_generate failed");
            goto error;
        }

        rc = ibmca_import_from_fallback_pkey(key, pkey,
                                             OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);
        if (rc != 1) {
            ibmca_debug_op_ctx(genctx,
                               "ERROR: ibmca_import_from_fallback_pkey failed");
            goto error;
        }
    } else if (genctx->key != NULL) {
        /* Copy parameters from template key */
        if (ibmca_keymgmt_dh_dup_params(genctx->key, key) != 1) {
            ibmca_debug_op_ctx(genctx,
                               "ERROR: ibmca_keymgmt_dh_dup_params failed");
            goto error;
        }
    } else {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "Neither parmagen context nor template key available");
        goto error;
    }

    if (genctx->dh.gen.selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        if (ibmca_keymgmt_dh_gen_libica(key, genctx->dh.gen.priv_len, osslcb,
                                        cbarg) != 1) {
            ibmca_debug_op_ctx(genctx,
                               "ERROR: ibmca_keymgmt_dh_gen_libica failed");

            if (ibmca_keymgmt_dh_gen_fallback(genctx, key,
                                              osslcb, cbarg) != 1) {
                ibmca_debug_op_ctx(genctx,
                                   "ERROR: ibmca_keymgmt_dh_gen_fallback failed");
                goto error;
            }
        }
     }

    goto out;

error:
    ibmca_keymgmt_free(key);
    key = NULL;

out:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return key;
}

static int ibmca_keymgmt_dh_has(const void *vkey, int selection)
{
    const struct ibmca_key *key = vkey;
    int ok = 1;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x", key, selection);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (key->dh.pub != NULL);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (key->dh.priv != NULL);

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        ok = ok && (key->dh.ffc_params.p != NULL &&
                    key->dh.ffc_params.g != NULL);
        if (key->type == EVP_PKEY_DHX)
            ok = ok && (key->dh.ffc_params.q != NULL);
    }

    ibmca_debug_key(key, "ok: %d", ok);

    return ok;
}

static int ibmca_keymgmt_dh_match(const void *vkey1, const void *vkey2,
                                  int selection)
{
    const struct ibmca_key *key1 = vkey1;
    const struct ibmca_key *key2 = vkey2;
    int ok = 1, checked = 0;

    if (key1 == NULL || key2 == NULL)
        return 0;

    ibmca_debug_key(key1, "key1: %p key2: %p selection: 0x%x", key1, key2,
                    selection);

    if (ibmca_keymgmt_match(key1, key2) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            if (key1->dh.pub != NULL || key2->dh.pub != NULL) {
                ok = ok && (BN_cmp(key1->dh.pub, key2->dh.pub) == 0);
                checked = 1;
            }
        }

        if (!checked && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            if (key1->dh.priv != NULL || key2->dh.priv != NULL) {
                ok = ok && (BN_cmp(key1->dh.priv, key2->dh.priv) == 0);
                checked = 1;
            }
        }

        ok = ok && checked;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        ok = ok && (BN_cmp(key1->dh.ffc_params.p, key2->dh.ffc_params.p) == 0);
        ok = ok && (BN_cmp(key1->dh.ffc_params.g, key2->dh.ffc_params.g) == 0);
        if (key1->type == EVP_PKEY_DHX)
            ok = ok &&
                 (BN_cmp(key1->dh.ffc_params.q, key2->dh.ffc_params.q) == 0);
    }

    ibmca_debug_key(key1, "ok: %d", ok);

    return ok;
}

static int ibmca_keymgmt_dh_validate(const void *vkey, int selection,
                                     int checktype)
{
    struct ibmca_key *key = (struct ibmca_key *)vkey;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc = 0;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x checktype: 0x%x", key,
                    selection, checktype);

    pkey = ibmca_new_fallback_pkey(key);
    if (pkey == NULL)
        goto out;

    pctx = ibmca_new_fallback_pkey_ctx(key->provctx, pkey, NULL);
    if (pctx == NULL)
        goto out;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
                            == OSSL_KEYMGMT_SELECT_KEYPAIR) {
        rc = EVP_PKEY_check(pctx);
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        rc = EVP_PKEY_public_check(pctx);
    } else if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        rc = EVP_PKEY_param_check(pctx);
    }

out:
    ibmca_debug_key(key, "valid: %d", rc);

    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return rc;
}

static const char *ibmca_keymgmt_dh_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "DH"; /* DHX also uses "DH" as operation name for KEYEXCH */
    }

    return NULL;
}

static const OSSL_PARAM ibmca_dh_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_dh_gettable_params(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    for (p = ibmca_dh_gettable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_dh_gettable_params;
}

static int ibmca_keymgmt_dh_get_params(void *vkey, OSSL_PARAM params[])
{
    struct ibmca_key *key = vkey;
    OSSL_PARAM *parm;
    const char *name;
    unsigned char *enc = NULL;
    size_t size;
    int rc;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p", key);
    for (parm = params; parm != NULL && parm->key != NULL; parm++)
        ibmca_debug_key(key, "param: %s", parm->key);

    /* OSSL_PKEY_PARAM_BITS */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS) != NULL) {
        size = ibmca_keymgmt_dh_get_prime_bits(key);
        if (size == 0)
            return 0;

        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_BITS, size);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_SECURITY_BITS */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS) != NULL) {
        size = ibmca_keymgmt_dh_get_security_bits(key);
        if (size == 0)
            return 0;

        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_SECURITY_BITS, size);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_MAX_SIZE */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE) != NULL) {
        size = ibmca_keymgmt_dh_get_prime_size(key);
        if (size == 0)
            return 0;

        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_MAX_SIZE, size);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) != NULL &&
        key->dh.pub != NULL) {
        size = ibmca_keymgmt_dh_get_prime_size(key);
        if (size == 0)
            return 0;

        enc = P_ZALLOC(key->provctx, size);
        if (enc == NULL) {
            put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                          "Failed to allocate encoded pubkey buffer");
            return 0;
        }
        if (BN_bn2binpad(key->dh.pub, enc, size) <= 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bn2binpad failed");
            P_FREE(key->provctx, enc);
            return 0;
        }

        rc = ibmca_param_build_set_octet_ptr(key->provctx, NULL, params,
                                             OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                             enc, size);
        P_FREE(key->provctx, enc);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_PRIV_KEY */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY) != NULL &&
        key->dh.priv != NULL) {
        rc = ibmca_param_build_set_bn(key->provctx, NULL, params,
                                      OSSL_PKEY_PARAM_PRIV_KEY,
                                      key->dh.priv);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_PUB_KEY */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY) != NULL &&
        key->dh.pub != NULL) {
        rc = ibmca_param_build_set_bn(key->provctx, NULL, params,
                                      OSSL_PKEY_PARAM_PUB_KEY,
                                      key->dh.pub);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_P */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_P) != NULL &&
        key->dh.ffc_params.p != NULL) {
        rc = ibmca_param_build_set_bn(key->provctx, NULL, params,
                                      OSSL_PKEY_PARAM_FFC_P,
                                      key->dh.ffc_params.p);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_Q */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_Q) != NULL &&
        key->dh.ffc_params.q != NULL) {
        rc = ibmca_param_build_set_bn(key->provctx, NULL, params,
                                      OSSL_PKEY_PARAM_FFC_Q,
                                      key->dh.ffc_params.q);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_G */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_G) != NULL &&
        key->dh.ffc_params.g != NULL) {
        rc = ibmca_param_build_set_bn(key->provctx, NULL, params,
                                      OSSL_PKEY_PARAM_FFC_G,
                                      key->dh.ffc_params.g);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_COFACTOR */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_COFACTOR) != NULL &&
        key->dh.ffc_params.cofactor != NULL) {
        rc = ibmca_param_build_set_bn(key->provctx, NULL, params,
                                      OSSL_PKEY_PARAM_FFC_COFACTOR,
                                      key->dh.ffc_params.cofactor);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_GINDEX */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_GINDEX) != NULL) {
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_FFC_GINDEX,
                                       key->dh.ffc_params.gindex);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_PCOUNTER */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_PCOUNTER) != NULL) {
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_FFC_PCOUNTER,
                                       key->dh.ffc_params.pcounter);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_H */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_H) != NULL) {
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_FFC_H,
                                       key->dh.ffc_params.hindex);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_SEED */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_SEED) != NULL &&
        key->dh.ffc_params.seed != NULL && key->dh.ffc_params.seed_len > 0) {
        rc = ibmca_param_build_set_octet_ptr(key->provctx, NULL, params,
                                             OSSL_PKEY_PARAM_FFC_SEED,
                                             key->dh.ffc_params.seed,
                                             key->dh.ffc_params.seed_len);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_GROUP_NAME */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME) != NULL &&
        key->dh.ffc_params.group_nid != NID_undef) {
        name = OBJ_nid2sn(key->dh.ffc_params.group_nid);
        rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                        OSSL_PKEY_PARAM_GROUP_NAME, name);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_VALIDATE_PQ */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ) != NULL) {
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_FFC_VALIDATE_PQ,
                                       key->dh.ffc_params.validate_pq);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_VALIDATE_G */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_VALIDATE_G) != NULL) {
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_FFC_VALIDATE_G,
                                       key->dh.ffc_params.validate_g);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY)
                                                                    != NULL) {
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY,
                                       key->dh.ffc_params.validate_legacy);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_DIGEST */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_DIGEST) != NULL &&
        key->dh.ffc_params.mdname != NULL) {
        rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                        OSSL_PKEY_PARAM_FFC_DIGEST,
                                        key->dh.ffc_params.mdname);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_FFC_DIGEST_PROPS */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS) != NULL &&
        key->dh.ffc_params.mdname != NULL) {
        rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                        OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
                                        key->dh.ffc_params.mdprops);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_DH_PRIV_LEN */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DH_PRIV_LEN) != NULL &&
        key->dh.ffc_params.length > 0) {
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_DH_PRIV_LEN,
                                       key->dh.ffc_params.length);
        if (rc == 0)
            return 0;
    }

    return 1;
}

static const OSSL_PARAM ibmca_dh_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_dh_settable_params(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    for (p = ibmca_dh_settable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_dh_settable_params;
}

static int ibmca_keymgmt_dh_set_params(void *vkey, const OSSL_PARAM params[])
{
    struct ibmca_key *key = vkey;
    const OSSL_PARAM *parm;
    unsigned char *enc = NULL;
    size_t size = 0;
    int rc;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p", key);
    for (parm = params; parm != NULL && parm->key != NULL; parm++)
        ibmca_debug_key(key, "param: %s", parm->key);

    /* OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY */
    rc = ibmca_param_get_octet_string(key->provctx, params,
                                      OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                      (void **)&enc, &size);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (key->dh.pub != NULL)
            BN_free(key->dh.pub);
        key->dh.pub = BN_bin2bn(enc, size, NULL);
        if (key->dh.pub == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bin2bn failed");
            return 0;
        }
        /* public key must be same size as p */
        if (BN_is_zero(key->dh.pub) ||
            size != ibmca_keymgmt_dh_get_prime_size(key)) {
            BN_free(key->dh.pub);
            key->dh.pub = NULL;
            put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                          "DH '%s' invalid public key",
                          OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
            return 0;
        }

        ibmca_clean_fallback_pkey_cache(key);
    }

    return 1;
}

static const OSSL_PARAM ibmca_keymgmt_dh_imexport_dom_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_dh_imexport_priv_key_dom_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_dh_imexport_pub_key_dom_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_dh_imexport_key_pair_dom_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_dh_imexport_key_pair[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_dh_imexport_public_key[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_dh_imexport_private_key[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_dh_imexport_types(int selection)
{
    selection &= (OSSL_KEYMGMT_SELECT_KEYPAIR |
                  OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS);

    switch (selection) {
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY:
        return ibmca_keymgmt_dh_imexport_private_key;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return ibmca_keymgmt_dh_imexport_public_key;
    case OSSL_KEYMGMT_SELECT_KEYPAIR:
        return ibmca_keymgmt_dh_imexport_key_pair;
    case OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return ibmca_keymgmt_dh_imexport_dom_params;
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return ibmca_keymgmt_dh_imexport_priv_key_dom_params;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return ibmca_keymgmt_dh_imexport_pub_key_dom_params;
    case OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return ibmca_keymgmt_dh_imexport_key_pair_dom_params;
    }

    return NULL;
}

static int ibmca_keymgmt_dh_export(void *vkey, int selection,
                                   OSSL_CALLBACK *param_callback, void *cbarg)
{
    struct ibmca_key *key = vkey;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params = NULL;
    const char *name;
    int rc = 1;

    if (key == NULL || param_callback == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x", key, selection);

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "OSSL_PARAM_BLD_new failed");
        return 0;
    }

    /* Domain parameters are required when exporting public or private key */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;


    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* OSSL_PKEY_PARAM_PUB_KEY */
        if (key->dh.pub != NULL) {
            rc = ibmca_param_build_set_bn(key->provctx, bld, NULL,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          key->dh.pub);
            if (rc == 0)
                goto error;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* OSSL_PKEY_PARAM_PRIV_KEY */
        if (key->dh.priv != NULL) {
            rc = ibmca_param_build_set_bn(key->provctx, bld, NULL,
                                          OSSL_PKEY_PARAM_PRIV_KEY,
                                          key->dh.priv);
            if (rc == 0)
                goto error;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /* OSSL_PKEY_PARAM_FFC_P */
        if (key->dh.ffc_params.p != NULL) {
            rc = ibmca_param_build_set_bn(key->provctx, bld, NULL,
                                          OSSL_PKEY_PARAM_FFC_P,
                                          key->dh.ffc_params.p);
            if (rc == 0)
                goto error;
        }

        /* OSSL_PKEY_PARAM_FFC_Q */
        if (key->dh.ffc_params.q != NULL) {
            rc = ibmca_param_build_set_bn(key->provctx, bld, NULL,
                                          OSSL_PKEY_PARAM_FFC_Q,
                                          key->dh.ffc_params.q);
            if (rc == 0)
                goto error;
        }

        /* OSSL_PKEY_PARAM_FFC_G */
        if (key->dh.ffc_params.g != NULL) {
            rc = ibmca_param_build_set_bn(key->provctx, bld, NULL,
                                          OSSL_PKEY_PARAM_FFC_G,
                                          key->dh.ffc_params.g);
            if (rc == 0)
                goto error;
        }

        /* OSSL_PKEY_PARAM_FFC_COFACTOR */
        if (key->dh.ffc_params.cofactor != NULL) {
            rc = ibmca_param_build_set_bn(key->provctx, bld, NULL,
                                          OSSL_PKEY_PARAM_FFC_COFACTOR,
                                          key->dh.ffc_params.cofactor);
            if (rc == 0)
                goto error;
        }

        /* OSSL_PKEY_PARAM_FFC_GINDEX */
        rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                       OSSL_PKEY_PARAM_FFC_GINDEX,
                                       key->dh.ffc_params.gindex);
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_FFC_PCOUNTER */
        rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                       OSSL_PKEY_PARAM_FFC_PCOUNTER,
                                       key->dh.ffc_params.pcounter);
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_FFC_H */
        rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                       OSSL_PKEY_PARAM_FFC_H,
                                       key->dh.ffc_params.hindex);
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_FFC_SEED */
        if (key->dh.ffc_params.seed != NULL &&
            key->dh.ffc_params.seed_len > 0) {
            rc = ibmca_param_build_set_octet_ptr(key->provctx, bld, NULL,
                                                 OSSL_PKEY_PARAM_FFC_SEED,
                                                 key->dh.ffc_params.seed,
                                                 key->dh.ffc_params.seed_len);
            if (rc == 0)
                goto error;
        }

        /* OSSL_PKEY_PARAM_GROUP_NAME */
        if (key->dh.ffc_params.group_nid != NID_undef) {
            name = OBJ_nid2sn(key->dh.ffc_params.group_nid);
            rc = ibmca_param_build_set_utf8(key->provctx, bld, NULL,
                                            OSSL_PKEY_PARAM_GROUP_NAME, name);
            if (rc == 0)
                goto error;
        }

        /* OSSL_PKEY_PARAM_FFC_VALIDATE_PQ */
        rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                       OSSL_PKEY_PARAM_FFC_VALIDATE_PQ,
                                       key->dh.ffc_params.validate_pq);
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_FFC_VALIDATE_G */
        rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                       OSSL_PKEY_PARAM_FFC_VALIDATE_G,
                                       key->dh.ffc_params.validate_g);
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY */
        rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                       OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY,
                                       key->dh.ffc_params.validate_legacy);
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_FFC_DIGEST */
        if (key->dh.ffc_params.mdname != NULL) {
            rc = ibmca_param_build_set_utf8(key->provctx, bld, NULL,
                                            OSSL_PKEY_PARAM_FFC_DIGEST,
                                            key->dh.ffc_params.mdname);
            if (rc == 0)
                goto error;
        }

        /* OSSL_PKEY_PARAM_FFC_DIGEST_PROPS */
        if (key->dh.ffc_params.mdname != NULL) {
            rc = ibmca_param_build_set_utf8(key->provctx, bld, NULL,
                                            OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
                                            key->dh.ffc_params.mdprops);
            if (rc == 0)
                goto error;
        }

        /* OSSL_PKEY_PARAM_DH_PRIV_LEN */
        if (key->dh.ffc_params.length > 0) {
            rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                           OSSL_PKEY_PARAM_DH_PRIV_LEN,
                                           key->dh.ffc_params.length);
            if (rc == 0)
                goto error;
        }
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "OSSL_PARAM_BLD_to_param failed");
        rc = 0;
        goto error;
    }

    rc = param_callback(params, cbarg);
    OSSL_PARAM_free(params);

error:
    OSSL_PARAM_BLD_free(bld);

    return rc;
}

static int ibmca_keymgmt_dh_import(void *vkey, int selection,
                                   const OSSL_PARAM params[])
{
    struct ibmca_key *key = vkey;
    const OSSL_PARAM *parm;
    const char *name;
    int rc = 0, val;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x", key, selection);
    for (parm = params; parm != NULL && parm->key != NULL; parm++)
        ibmca_debug_key(key, "param: %s", parm->key);

    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR |
                      OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) == 0) {
        put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                       "Nothing to import");
        return 0;
    }

    /* Clear any already existing key components */
    ibmca_keymgmt_dh_free_cb(key);
    ibmca_clean_fallback_pkey_cache(key);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
         /* OSSL_PKEY_PARAM_PUB_KEY */
        rc = ibmca_param_get_bn(key->provctx, params,
                                OSSL_PKEY_PARAM_PUB_KEY, &key->dh.pub);
        if (rc == 0)
            return 0;
     }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
         /* OSSL_PKEY_PARAM_PRIV_KEY */
        key->dh.priv = BN_secure_new();
        if (key->dh.priv == NULL) {
            put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
            return 0;
        }

        rc = ibmca_param_get_bn(key->provctx, params,
                                OSSL_PKEY_PARAM_PRIV_KEY, &key->dh.priv);
        if (rc == 0)
            return 0;
     }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /* OSSL_PKEY_PARAM_FFC_P */
        rc = ibmca_param_get_bn(key->provctx, params,
                                OSSL_PKEY_PARAM_FFC_P, &key->dh.ffc_params.p);
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_FFC_Q */
        rc = ibmca_param_get_bn(key->provctx, params,
                                OSSL_PKEY_PARAM_FFC_Q, &key->dh.ffc_params.q);
        if (rc == 0)
            return 0;


        /* OSSL_PKEY_PARAM_FFC_G */
        rc = ibmca_param_get_bn(key->provctx, params,
                                OSSL_PKEY_PARAM_FFC_G, &key->dh.ffc_params.g);
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_FFC_COFACTOR */
        rc = ibmca_param_get_bn(key->provctx, params,
                                OSSL_PKEY_PARAM_FFC_COFACTOR,
                                &key->dh.ffc_params.cofactor);
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_FFC_GINDEX */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_FFC_GINDEX,
                                 &key->dh.ffc_params.gindex);
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_FFC_PCOUNTER */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_FFC_PCOUNTER,
                                 &key->dh.ffc_params.pcounter);
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_FFC_H */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_FFC_H,
                                 &key->dh.ffc_params.hindex);
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_FFC_SEED */
        rc = ibmca_param_get_octet_string(key->provctx, params,
                                          OSSL_PKEY_PARAM_FFC_SEED,
                                          (void **)&key->dh.ffc_params.seed,
                                          &key->dh.ffc_params.seed_len);
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_GROUP_NAME */
        rc = ibmca_param_get_utf8(key->provctx, params,
                                  OSSL_PKEY_PARAM_GROUP_NAME, &name);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            key->dh.ffc_params.group_nid = OBJ_sn2nid(name);
            if (key->dh.ffc_params.group_nid == NID_undef) {
                put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                              "DH '%s': '%s' is an unsupported group",
                              OSSL_PKEY_PARAM_GROUP_NAME, name);
                return 0;
            }
            ibmca_debug_key(key, "group_nid: %d", key->dh.ffc_params.group_nid);
        }

        /* OSSL_PKEY_PARAM_FFC_VALIDATE_PQ */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, &val);
        if (rc == 0)
            return 0;
        if (rc > 0)
            key->dh.ffc_params.validate_pq = val;

        /* OSSL_PKEY_PARAM_FFC_VALIDATE_G */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_FFC_VALIDATE_G, &val);
        if (rc == 0)
            return 0;
        if (rc > 0)
            key->dh.ffc_params.validate_g = val;

        /* OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY, &val);
        if (rc == 0)
            return 0;
        if (rc > 0)
            key->dh.ffc_params.validate_legacy = val;

        /* OSSL_PKEY_PARAM_FFC_DIGEST */
        rc = ibmca_param_get_utf8(key->provctx, params,
                                  OSSL_PKEY_PARAM_FFC_DIGEST,
                                  &name);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            key->dh.ffc_params.mdname = P_STRDUP(key->provctx, name);
            if (key->dh.ffc_params.mdname == NULL) {
                put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "P_STRDUP failed");
                return 0;
            }
        }

        /* OSSL_PKEY_PARAM_FFC_DIGEST_PROPS */
        rc = ibmca_param_get_utf8(key->provctx, params,
                                  OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
                                  &name);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            key->dh.ffc_params.mdprops = P_STRDUP(key->provctx, name);
            if (key->dh.ffc_params.mdprops == NULL) {
                put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "P_STRDUP failed");
                return 0;
            }
        }

        /* OSSL_PKEY_PARAM_DH_PRIV_LEN */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_DH_PRIV_LEN,
                                 &key->dh.ffc_params.length);
        if (rc == 0)
            return 0;
    }

    return 1;
}

static const OSSL_DISPATCH ibmca_dh_keymgmt_functions[] = {
    /* Constructor, destructor */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ibmca_keymgmt_dh_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ibmca_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ibmca_keymgmt_dup },

    /* Key generation and loading */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,
            (void (*)(void))ibmca_keymgmt_dh_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
            (void (*)(void))ibmca_keymgmt_dh_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
            (void (*)(void))ibmca_keymgmt_dh_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
            (void (*)(void))ibmca_keymgmt_dh_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ibmca_keymgmt_dh_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
              (void (*)(void))ibmca_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ibmca_keymgmt_load },

    /* Key object checking */
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ibmca_keymgmt_dh_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ibmca_keymgmt_dh_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,
            (void (*)(void))ibmca_keymgmt_dh_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
            (void (*)(void))ibmca_keymgmt_dh_query_operation_name },

    /* Key object information */
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
            (void (*) (void))ibmca_keymgmt_dh_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
            (void (*) (void))ibmca_keymgmt_dh_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
            (void (*) (void))ibmca_keymgmt_dh_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
            (void (*) (void))ibmca_keymgmt_dh_settable_params },

    /* Import and export routines */
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ibmca_keymgmt_dh_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_dh_imexport_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ibmca_keymgmt_dh_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_dh_imexport_types },

    { 0, NULL }
};

static const OSSL_DISPATCH ibmca_dhx_keymgmt_functions[] = {
    /* Constructor, destructor */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ibmca_keymgmt_dhx_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ibmca_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ibmca_keymgmt_dup },

    /* Key generation and loading */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,
            (void (*)(void))ibmca_keymgmt_dhx_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
            (void (*)(void))ibmca_keymgmt_dh_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
            (void (*)(void))ibmca_keymgmt_dh_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
            (void (*)(void))ibmca_keymgmt_dh_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ibmca_keymgmt_dh_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
              (void (*)(void))ibmca_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ibmca_keymgmt_load },

    /* Key object checking */
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ibmca_keymgmt_dh_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ibmca_keymgmt_dh_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,
            (void (*)(void))ibmca_keymgmt_dh_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
            (void (*)(void))ibmca_keymgmt_dh_query_operation_name },

    /* Key object information */
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
            (void (*) (void))ibmca_keymgmt_dh_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
            (void (*) (void))ibmca_keymgmt_dh_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
            (void (*) (void))ibmca_keymgmt_dh_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
            (void (*) (void))ibmca_keymgmt_dh_settable_params },

    /* Import and export routines */
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ibmca_keymgmt_dh_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_dh_imexport_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ibmca_keymgmt_dh_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_dh_imexport_types },

    { 0, NULL }
};

const OSSL_ALGORITHM ibmca_dh_keymgmt[] = {
    { "DH:dhKeyAgreement:1.2.840.113549.1.3.1", NULL,
      ibmca_dh_keymgmt_functions, "IBMCA DH implementation" },
    { "DHX:X9.42 DH:dhpublicnumber:1.2.840.10046.2.1", NULL,
      ibmca_dhx_keymgmt_functions, "IBMCA DHX implementation" },
    { NULL, NULL, NULL, NULL }
};

struct ibmca_tls_group_constants {
    unsigned int group_id;
    unsigned int secbits;
    int mintls;
    int maxtls;
    int mindtls;
    int maxdtls;
};

#define IBMCA_TLS_GROUP_ID_ffdhe2048        256
#define IBMCA_TLS_GROUP_ID_ffdhe3072        257
#define IBMCA_TLS_GROUP_ID_ffdhe4096        258
#define IBMCA_TLS_GROUP_ID_ffdhe6144        259
#define IBMCA_TLS_GROUP_ID_ffdhe8192        260

static const struct ibmca_tls_group_constants ibmca_tls_group_consts[5] = {
    { IBMCA_TLS_GROUP_ID_ffdhe2048, 112, TLS1_3_VERSION, 0, -1, -1 },
    { IBMCA_TLS_GROUP_ID_ffdhe3072, 128, TLS1_3_VERSION, 0, -1, -1 },
    { IBMCA_TLS_GROUP_ID_ffdhe4096, 128, TLS1_3_VERSION, 0, -1, -1 },
    { IBMCA_TLS_GROUP_ID_ffdhe6144, 128, TLS1_3_VERSION, 0, -1, -1 },
    { IBMCA_TLS_GROUP_ID_ffdhe8192, 192, TLS1_3_VERSION, 0, -1, -1 },
};

#define IBMCA_TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               tlsname, sizeof(tlsname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               realname, sizeof(realname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               algorithm, sizeof(algorithm)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&ibmca_tls_group_consts[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&ibmca_tls_group_consts[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                       (unsigned int *)&ibmca_tls_group_consts[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                       (unsigned int *)&ibmca_tls_group_consts[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                       (unsigned int *)&ibmca_tls_group_consts[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                       (unsigned int *)&ibmca_tls_group_consts[idx].maxdtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM ibmca_dh_ffdhe2048[] =
        IBMCA_TLS_GROUP_ENTRY("ffdhe2048", "ffdhe2048", "DH", 0);
static const OSSL_PARAM ibmca_dh_ffdhe3072[] =
        IBMCA_TLS_GROUP_ENTRY("ffdhe3072", "ffdhe3072", "DH", 1);
static const OSSL_PARAM ibmca_dh_ffdhe4096[] =
        IBMCA_TLS_GROUP_ENTRY("ffdhe4096", "ffdhe4096", "DH", 2);
static const OSSL_PARAM ibmca_dh_ffdhe6144[] =
        IBMCA_TLS_GROUP_ENTRY("ffdhe6144", "ffdhe6144", "DH", 3);
static const OSSL_PARAM ibmca_dh_ffdhe8192[] =
        IBMCA_TLS_GROUP_ENTRY("ffdhe8192", "ffdhe8192", "DH", 4);

static const OSSL_PARAM *ibmca_dh_tls_group[] = {
    ibmca_dh_ffdhe2048,
    ibmca_dh_ffdhe3072,
    ibmca_dh_ffdhe4096,
    ibmca_dh_ffdhe6144,
    ibmca_dh_ffdhe8192,
    NULL
};

const struct ibmca_mech_capability ibmca_dh_capabilities[] = {
    { "TLS-GROUP", ibmca_dh_tls_group },
    { NULL, NULL }
};
