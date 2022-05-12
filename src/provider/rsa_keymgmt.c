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
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>

#include "p_ibmca.h"

#define ICA_P_LEN(key_len)          (((key_len) + 1) / 2 + 8)
#define ICA_Q_LEN(key_len)          (((key_len) + 1) / 2)
#define ICA_DP_LEN(key_len)         (((key_len) + 1) / 2 + 8)
#define ICA_DQ_LEN(key_len)         (((key_len) + 1) / 2)
#define ICA_QINV_LEN(key_len)       (((key_len) + 1) / 2 + 8)

static const struct ibmca_pss_params ibmca_rsa_pss_defaults =
                                            IBMCA_RSA_PSS_DEFAULTS;

static OSSL_FUNC_keymgmt_new_fn ibmca_keymgmt_rsa_new;
static OSSL_FUNC_keymgmt_new_fn ibmca_keymgmt_rsa_pss_new;
static OSSL_FUNC_keymgmt_gen_init_fn ibmca_keymgmt_rsa_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn ibmca_keymgmt_rsa_pss_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn ibmca_keymgmt_rsa_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn ibmca_keymgmt_rsa_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn
                                        ibmca_keymgmt_rsa_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn ibmca_keymgmt_rsa_gen;
static OSSL_FUNC_keymgmt_has_fn ibmca_keymgmt_rsa_has;
static OSSL_FUNC_keymgmt_match_fn ibmca_keymgmt_rsa_match;
static OSSL_FUNC_keymgmt_validate_fn ibmca_keymgmt_rsa_validate;
static OSSL_FUNC_keymgmt_query_operation_name_fn
                                        ibmca_keymgmt_rsa_query_operation_name;
static OSSL_FUNC_keymgmt_get_params_fn ibmca_keymgmt_rsa_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn ibmca_keymgmt_rsa_gettable_params;
static OSSL_FUNC_keymgmt_gettable_params_fn
                                        ibmca_keymgmt_rsa_pss_gettable_params;
static OSSL_FUNC_keymgmt_export_fn ibmca_keymgmt_rsa_export;
static OSSL_FUNC_keymgmt_export_types_fn ibmca_keymgmt_rsa_export_types;
static OSSL_FUNC_keymgmt_export_types_fn ibmca_keymgmt_rsa_pss_export_types;
static OSSL_FUNC_keymgmt_import_fn ibmca_keymgmt_rsa_import;
static OSSL_FUNC_keymgmt_import_types_fn ibmca_keymgmt_rsa_import_types;
static OSSL_FUNC_keymgmt_import_types_fn ibmca_keymgmt_rsa_pss_import_types;

static void ibmca_keymgmt_rsa_free_cb(struct ibmca_key *key);
static int ibmca_keymgmt_rsa_dup_cb(const struct ibmca_key *key,
                                    struct ibmca_key *new_key);

static int ibmca_keymgmt_rsa_pss_parms_from_data(
                                        const struct ibmca_prov_ctx *provctx,
                                        const OSSL_PARAM params[],
                                        struct ibmca_pss_params *pss)
{
    const char *props = NULL;
    const char *name;
    EVP_MD *md;
    int rc;

    /* OSSL_PKEY_PARAM_RSA_DIGEST_PROPS */
    rc = ibmca_param_get_utf8(provctx, params,
                              OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, &props);
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_RSA_DIGEST */
    rc = ibmca_param_get_utf8(provctx, params,
                              OSSL_PKEY_PARAM_RSA_DIGEST, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        md = EVP_MD_fetch(provctx->libctx, name, props);
        if (md == NULL) {
            put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                          "RSA PSS '%s'='%s' could not be fetched",
                          OSSL_PKEY_PARAM_RSA_DIGEST, name);
            return 0;
        }

        pss->digest_nid = EVP_MD_get_type(md);
        EVP_MD_free(md);
        pss->restricted = true;
    }

    /* OSSL_PKEY_PARAM_RSA_MASKGENFUNC */
    rc = ibmca_param_get_utf8(provctx, params,
                              OSSL_PKEY_PARAM_RSA_MASKGENFUNC, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (strcasecmp(name, OBJ_nid2sn(IBMCA_RSA_PSS_DEFAULT_MGF)) != 0) {
            put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                          "RSA PSS '%s'='%s' is not supported",
                          OSSL_PKEY_PARAM_RSA_MASKGENFUNC, name);
            return 0;
        }

        pss->mgf_nid = IBMCA_RSA_PSS_DEFAULT_MGF;
        pss->restricted = true;
    }

    /* OSSL_PKEY_PARAM_RSA_MGF1_DIGEST */
    rc = ibmca_param_get_utf8(provctx, params,
                              OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        md = EVP_MD_fetch(provctx->libctx, name, props);
        if (md == NULL) {
            put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                          "RSA PSS '%s'='%s' could not be fetched",
                          OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, name);
            return 0;
        }

        pss->mgf_digest_nid = EVP_MD_get_type(md);
        EVP_MD_free(md);
        pss->restricted = true;
    }

    /* OSSL_PKEY_PARAM_RSA_PSS_SALTLEN */
    rc = ibmca_param_get_int(provctx, params,
                             OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
                             &pss->saltlen);
    if (rc == 0)
        return 0;
    if (rc > 0)
        pss->restricted = true;

    return 1;
}

static int ibmca_keymgmt_rsa_pss_parms_to_data(
                                        const struct ibmca_prov_ctx *provctx,
                                        OSSL_PARAM_BLD *bld,
                                        OSSL_PARAM params[],
                                        struct ibmca_pss_params *pss)
{
    const char *name;
    int rc;

    /* OSSL_PKEY_PARAM_RSA_DIGEST */
    name = OBJ_nid2sn(pss->digest_nid);
    rc = ibmca_param_build_set_utf8(provctx, bld, params,
                                    OSSL_PKEY_PARAM_RSA_DIGEST, name);
    if (rc == 0)
       return 0;

    /* OSSL_PKEY_PARAM_RSA_MASKGENFUNC */
    name = OBJ_nid2sn(pss->mgf_nid);
    rc = ibmca_param_build_set_utf8(provctx, bld, params,
                                    OSSL_PKEY_PARAM_RSA_MASKGENFUNC, name);
    if (rc == 0)
       return 0;

    /* OSSL_PKEY_PARAM_RSA_MGF1_DIGEST */
    name = OBJ_nid2sn(pss->mgf_digest_nid);
    rc = ibmca_param_build_set_utf8(provctx, bld, params,
                                    OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, name);
    if (rc == 0)
       return 0;

    /* OSSL_PKEY_PARAM_RSA_PSS_SALTLEN */
    rc = ibmca_param_build_set_int(provctx, bld, params,
                                   OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
                                   pss->saltlen);
    if (rc == 0)
       return 0;

    return 1;
}

static int ibmca_keymgmt_rsa_pub_key_from_data(
                                        const struct ibmca_prov_ctx *provctx,
                                        const OSSL_PARAM params[],
                                        BIGNUM **n, BIGNUM **e)
{
    int rc;

    /* OSSL_PKEY_PARAM_RSA_N */
    rc = ibmca_param_get_bn(provctx, params, OSSL_PKEY_PARAM_RSA_N, n);
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_RSA_E */
    rc = ibmca_param_get_bn(provctx, params, OSSL_PKEY_PARAM_RSA_E, e);
    if (rc == 0)
        return 0;

    return 1;
}


static int ibmca_keymgmt_rsa_pub_key_to_data(
                                        const struct ibmca_prov_ctx *provctx,
                                        OSSL_PARAM_BLD *bld,
                                        OSSL_PARAM params[],
                                        BIGNUM *n, BIGNUM *e)
{
    int rc;

    /* OSSL_PKEY_PARAM_RSA_N */
    rc = (n == NULL || ibmca_param_build_set_bn(provctx, bld, params,
                                                OSSL_PKEY_PARAM_RSA_N, n));
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_RSA_E */
    rc = (e == NULL || ibmca_param_build_set_bn(provctx, bld, params,
                                                OSSL_PKEY_PARAM_RSA_E, e));
    if (rc == 0)
        return 0;

    return 1;
}

static int ibmca_keymgmt_rsa_priv_key_from_data(
                                        const struct ibmca_prov_ctx *provctx,
                                        const OSSL_PARAM params[],
                                        BIGNUM **d, BIGNUM **p,
                                        BIGNUM **q, BIGNUM **dp,
                                        BIGNUM **dq, BIGNUM **qinv)
{
    int rc;

    /* OSSL_PKEY_PARAM_RSA_D */
    *d = BN_secure_new();
    if (*d == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto error;
    }
    rc = ibmca_param_get_bn(provctx, params, OSSL_PKEY_PARAM_RSA_D, d);
    if (rc == 0)
        goto error;

    /* OSSL_PKEY_PARAM_RSA_FACTOR1 */
    *p = BN_secure_new();
    if (*p == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto error;
    }
    rc = ibmca_param_get_bn(provctx, params, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
    if (rc == 0)
        goto error;

    /* OSSL_PKEY_PARAM_RSA_FACTOR2 */
    *q = BN_secure_new();
    if (*q == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto error;
    }
    rc = ibmca_param_get_bn(provctx, params, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
    if (rc == 0)
        goto error;

    /* OSSL_PKEY_PARAM_RSA_EXPONENT1 */
    *dp = BN_secure_new();
    if (*dp == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto error;
    }
    rc = ibmca_param_get_bn(provctx, params, OSSL_PKEY_PARAM_RSA_EXPONENT1,
                            dp);
    if (rc == 0)
        goto error;

    /* OSSL_PKEY_PARAM_RSA_EXPONENT2 */
    *dq = BN_secure_new();
    if (*dq == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto error;
    }
    rc = ibmca_param_get_bn(provctx, params, OSSL_PKEY_PARAM_RSA_EXPONENT2,
                            dq);
    if (rc == 0)
        goto error;

    /* OSSL_PKEY_PARAM_RSA_COEFFICIENT1 */
    *qinv = BN_secure_new();
    if (*qinv == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto error;
    }
    rc = ibmca_param_get_bn(provctx, params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                            qinv);
    if (rc == 0)
        goto error;

    return 1;

error:
    BN_clear_free(*d);
    *d = NULL;
    BN_clear_free(*p);
    *p = NULL;
    BN_clear_free(*dp);
    *dp = NULL;
    BN_clear_free(*dq);
    *dq = NULL;
    BN_clear_free(*qinv);
    *qinv = NULL;

    return 0;
}

static int ibmca_keymgmt_rsa_priv_key_to_data(
                                        const struct ibmca_prov_ctx *provctx,
                                        OSSL_PARAM_BLD *bld,
                                        OSSL_PARAM params[],
                                        BIGNUM *d, BIGNUM *p, BIGNUM *q,
                                        BIGNUM *dp, BIGNUM *dq,
                                        BIGNUM *qinv)
{
    int rc;

    /* OSSL_PKEY_PARAM_RSA_D */
    rc = (d == NULL || ibmca_param_build_set_bn(provctx, bld, params,
                                                OSSL_PKEY_PARAM_RSA_D, d));
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_RSA_FACTOR1 */
    rc = (p == NULL || ibmca_param_build_set_bn(provctx, bld, params,
                                                OSSL_PKEY_PARAM_RSA_FACTOR1,
                                                p));
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_RSA_FACTOR2 */
    rc = (q == NULL || ibmca_param_build_set_bn(provctx, bld, params,
                                                OSSL_PKEY_PARAM_RSA_FACTOR2,
                                                q));
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_RSA_EXPONENT1 */
    rc = (dp == NULL || ibmca_param_build_set_bn(provctx, bld, params,
                                                 OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                                 dp));
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_RSA_EXPONENT2 */
    rc = (dq == NULL || ibmca_param_build_set_bn(provctx, bld, params,
                                                OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                                dq));
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_RSA_COEFFICIENT1 */
    rc = (qinv == NULL || ibmca_param_build_set_bn(provctx, bld, params,
                                              OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                              qinv));
    if (rc == 0)
        return 0;

    return 1;
}

static size_t ibmca_keymgmt_rsa_get_max_param_size(const struct ibmca_key *key)
{
    return (key->rsa.bits + 7) / 8;
}

static struct ibmca_key *ibmca_keymgmt_rsa_new_type(
                                        const struct ibmca_prov_ctx *provctx,
                                        int type)
{
    struct ibmca_key *key;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p type: %d", provctx, type);

    key = ibmca_keymgmt_new(provctx, type, "RSA",
                            ibmca_keymgmt_rsa_free_cb,
                            ibmca_keymgmt_rsa_dup_cb,
                            ibmca_keymgmt_rsa_get_max_param_size,
                            ibmca_keymgmt_rsa_export,
                            ibmca_keymgmt_rsa_import,
                            ibmca_keymgmt_rsa_has,
                            ibmca_keymgmt_rsa_match);
    if (key == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_keymgmt_new failed");
        return NULL;
    }

    /* Set defaults */
    if (type == EVP_PKEY_RSA_PSS)
        key->rsa.pss = ibmca_rsa_pss_defaults;

    return key;
}

static void *ibmca_keymgmt_rsa_new(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);
    return ibmca_keymgmt_rsa_new_type(provctx, EVP_PKEY_RSA);
}

static void *ibmca_keymgmt_rsa_pss_new(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);
    return ibmca_keymgmt_rsa_new_type(provctx, EVP_PKEY_RSA_PSS);
}

static int ibmca_keymgmt_rsa_alloc_pub(struct ibmca_key *key)
{
    key->rsa.public.key_length = (key->rsa.bits + 7) / 8;

    key->rsa.public.modulus = P_ZALLOC(key->provctx,
                                       key->rsa.public.key_length);
    key->rsa.public.exponent = P_ZALLOC(key->provctx,
                                        key->rsa.public.key_length);
    if (key->rsa.public.modulus == NULL || key->rsa.public.exponent == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                     "Failed to allocate libica public RSA key");
        return 0;
    }

    return 1;
}

static int ibmca_keymgmt_rsa_alloc_priv(struct ibmca_key *key)
{
    key->rsa.private.key_length = (key->rsa.bits + 7) / 8;
    key->rsa.private.p = P_SECURE_ZALLOC(key->provctx,
                            ICA_P_LEN(key->rsa.private.key_length));
    key->rsa.private.q = P_SECURE_ZALLOC(key->provctx,
                            ICA_Q_LEN(key->rsa.private.key_length));
    key->rsa.private.dp = P_SECURE_ZALLOC(key->provctx,
                            ICA_DP_LEN(key->rsa.private.key_length));
    key->rsa.private.dq = P_SECURE_ZALLOC(key->provctx,
                            ICA_DQ_LEN(key->rsa.private.key_length));
    key->rsa.private.qInverse = P_SECURE_ZALLOC(key->provctx,
                            ICA_QINV_LEN(key->rsa.private.key_length));
    if (key->rsa.private.p == NULL || key->rsa.private.q == NULL ||
        key->rsa.private.dp == NULL || key->rsa.private.dq == NULL ||
        key->rsa.private.qInverse == NULL ) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate libica private RSA key");
        return 0;
    }

    return 1;
}

static void ibmca_keymgmt_rsa_free_pub(struct ibmca_key *key)
{
    if (key->rsa.public.modulus != NULL)
        P_CLEAR_FREE(key->provctx, key->rsa.public.modulus,
                     key->rsa.public.key_length);
    key->rsa.public.modulus = NULL;
    if (key->rsa.public.exponent != NULL)
        P_CLEAR_FREE(key->provctx, key->rsa.public.exponent,
                     key->rsa.public.key_length);
    key->rsa.public.exponent = NULL;
    key->rsa.public.key_length = 0;
}

static void ibmca_keymgmt_rsa_free_priv(struct ibmca_key *key)
{
    if (key->rsa.private.p != NULL)
         P_SECURE_CLEAR_FREE(key->provctx, key->rsa.private.p,
                             ICA_P_LEN(key->rsa.private.key_length));
     key->rsa.private.p = NULL;
     if (key->rsa.private.q != NULL)
         P_SECURE_CLEAR_FREE(key->provctx, key->rsa.private.q,
                             ICA_Q_LEN(key->rsa.private.key_length));
     key->rsa.private.q = NULL;
     if (key->rsa.private.dp != NULL)
         P_SECURE_CLEAR_FREE(key->provctx, key->rsa.private.dp,
                             ICA_DP_LEN(key->rsa.private.key_length));
     key->rsa.private.dp = NULL;
     if (key->rsa.private.dq != NULL)
         P_SECURE_CLEAR_FREE(key->provctx, key->rsa.private.dq,
                             ICA_DQ_LEN(key->rsa.private.key_length));
     key->rsa.private.dq = NULL;
     if (key->rsa.private.qInverse != NULL)
         P_SECURE_CLEAR_FREE(key->provctx, key->rsa.private.qInverse,
                             ICA_QINV_LEN(key->rsa.private.key_length));
     key->rsa.private.qInverse = NULL;
     key->rsa.private.key_length = 0;
}

static void ibmca_keymgmt_rsa_free_cb(struct ibmca_key *key)
{
    if (key == NULL)
        return;

    ibmca_debug_key(key, "key: %p", key);

    ibmca_keymgmt_rsa_free_priv(key);
    ibmca_keymgmt_rsa_free_pub(key);

    if (key->type == EVP_PKEY_RSA_PSS)
        key->rsa.pss = ibmca_rsa_pss_defaults;
}

static int ibmca_keymgmt_rsa_dup_pub(const struct ibmca_key *key,
                                     struct ibmca_key *new_key)
{
    new_key->rsa.public.key_length = key->rsa.public.key_length;

    new_key->rsa.public.modulus = P_MEMDUP(key->provctx,
                                           key->rsa.public.modulus,
                                           key->rsa.public.key_length);
    new_key->rsa.public.exponent = P_MEMDUP(key->provctx,
                                            key->rsa.public.exponent,
                                            key->rsa.public.key_length);
    if (new_key->rsa.public.modulus == NULL ||
        new_key->rsa.public.exponent == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate libica RSA key");
        return 0;
    }

    return 1;
}

static int ibmca_keymgmt_rsa_dup_priv(const struct ibmca_key *key,
                                      struct ibmca_key *new_key)
{
    new_key->rsa.private.key_length = key->rsa.private.key_length;

    new_key->rsa.private.p = P_SECURE_MEMDUP(key->provctx, key->rsa.private.p,
                                      ICA_P_LEN(key->rsa.private.key_length));
    new_key->rsa.private.q = P_SECURE_MEMDUP(key->provctx, key->rsa.private.q,
                                      ICA_Q_LEN(key->rsa.private.key_length));
    new_key->rsa.private.dp = P_SECURE_MEMDUP(key->provctx, key->rsa.private.dp,
                                       ICA_DP_LEN(key->rsa.private.key_length));
    new_key->rsa.private.dq = P_SECURE_MEMDUP(key->provctx, key->rsa.private.dq,
                                       ICA_DQ_LEN(key->rsa.private.key_length));
    new_key->rsa.private.qInverse = P_SECURE_MEMDUP(key->provctx,
                                       key->rsa.private.qInverse,
                                       ICA_QINV_LEN(
                                                 key->rsa.private.key_length));

    if (new_key->rsa.private.p == NULL ||
        new_key->rsa.private.q == NULL ||
        new_key->rsa.private.dp == NULL ||
        new_key->rsa.private.dq == NULL ||
        new_key->rsa.private.qInverse == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate libica RSA key");
        return 0;
    }

    return 1;
}

static int ibmca_keymgmt_rsa_dup_cb(const struct ibmca_key *key,
                                    struct ibmca_key *new_key)
{
    if (key == NULL || new_key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p new_key: %p", key, new_key);

    new_key->rsa.bits = key->rsa.bits;

    if (key->rsa.public.key_length != 0) {
        if (ibmca_keymgmt_rsa_dup_pub(key, new_key) == 0)
            return 0;
    }

    if (key->rsa.private.key_length != 0) {
        if (ibmca_keymgmt_rsa_dup_priv(key, new_key) == 0)
            return 0;
    }

    if (key->type == EVP_PKEY_RSA_PSS)
        new_key->rsa.pss = key->rsa.pss;

    return 1;
}

static int ibmca_keymgmt_rsa_has(const void *vkey, int selection)
{
    const struct ibmca_key *key = vkey;
    int ok = 1;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x", key, selection);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (key->rsa.public.key_length != 0 &&
                    key->rsa.public.modulus != NULL &&
                    key->rsa.public.exponent != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (key->rsa.private.key_length != 0 &&
                    key->rsa.private.p != NULL &&
                    key->rsa.private.q != NULL &&
                    key->rsa.private.dp != NULL &&
                    key->rsa.private.dq != NULL &&
                    key->rsa.private.qInverse != NULL);

    ibmca_debug_key(key, "ok: %d", ok);
    return ok;
}

static int ibmca_keymgmt_rsa_match(const void *vkey1, const void *vkey2,
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

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        ok = ok && (key1->rsa.public.key_length ==
                           key2->rsa.public.key_length &&
                    memcmp(key1->rsa.public.exponent,
                           key2->rsa.public.exponent,
                           key1->rsa.public.key_length) == 0 &&
                    memcmp(key1->rsa.public.modulus,
                           key2->rsa.public.modulus,
                           key1->rsa.public.key_length) == 0);
        checked = 1;
    }

    if (!checked && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (key1->rsa.private.key_length ==
                           key2->rsa.private.key_length &&
                    CRYPTO_memcmp(key1->rsa.private.p,
                           key2->rsa.private.p,
                           ICA_P_LEN(key1->rsa.private.key_length)) == 0 &&
                    CRYPTO_memcmp(key1->rsa.private.q,
                           key2->rsa.private.q,
                           ICA_Q_LEN(key1->rsa.private.key_length)) == 0 &&
                    CRYPTO_memcmp(key1->rsa.private.dp,
                           key2->rsa.private.dp,
                           ICA_DP_LEN(key1->rsa.private.key_length)) == 0 &&
                    CRYPTO_memcmp(key1->rsa.private.dq,
                           key2->rsa.private.dq,
                           ICA_DQ_LEN(key1->rsa.private.key_length)) == 0 &&
                    CRYPTO_memcmp(key1->rsa.private.qInverse,
                           key2->rsa.private.qInverse,
                           ICA_QINV_LEN(key1->rsa.private.key_length)) == 0);

    ibmca_debug_key(key1, "ok: %d", ok);
    return ok;
}

static int ibmca_keymgmt_rsa_validate(const void *vkey, int selection,
                                      int checktype)
{
    struct ibmca_key *key = (struct ibmca_key *)vkey;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = NULL;
    int rc = 0;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x checktype: 0x%x", key,
                    selection, checktype);

    /*
     * Validate RSA key with OpenSSL, not libica. Libica does not provide a
     * way to validate an RSA key.
     */
    pkey = ibmca_new_fallback_pkey(key);
    if (pkey == NULL)
        return 0;

    pctx = ibmca_new_fallback_pkey_ctx(key->provctx, pkey, NULL);
    if (pctx == NULL)
        goto out;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
                            == OSSL_KEYMGMT_SELECT_KEYPAIR) {
        rc = EVP_PKEY_check(pctx);
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        rc = EVP_PKEY_public_check(pctx);
    }

    ibmca_debug_key(key, "valid: %d", rc);

out:
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return rc;
}

static const char *ibmca_keymgmt_rsa_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
    case OSSL_OP_ASYM_CIPHER:
        return "RSA";
    }

    return NULL;
}

static void ibmca_keymgmt_rsa_gen_free_cb(struct ibmca_op_ctx *ctx)
{
    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    if (ctx->rsa.gen.pub_exp != NULL) {
        BN_free((BIGNUM *)ctx->rsa.gen.pub_exp);
        ctx->rsa.gen.pub_exp = NULL;
    }
}

static int ibmca_keymgmt_rsa_gen_dup_cb(const struct ibmca_op_ctx *ctx,
                                        struct ibmca_op_ctx *new_ctx)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p new_ctx: %p", ctx, new_ctx);

    new_ctx->rsa.gen.bits = ctx->rsa.gen.bits;
    if (ctx->rsa.gen.pub_exp != NULL) {
        new_ctx->rsa.gen.pub_exp = BN_dup(ctx->rsa.gen.pub_exp);
        if (new_ctx->rsa.gen.pub_exp == NULL) {
            put_error_op_ctx(ctx, IBMCA_ERR_MALLOC_FAILED, "BN_dup failed");
            return 0;
        }
    }

    if (ctx->type == EVP_PKEY_RSA_PSS)
        new_ctx->rsa.gen.pss = ctx->rsa.gen.pss;

    return 1;
}

static struct ibmca_op_ctx *ibmca_keymgmt_rsa_gen_init_type(
                            const struct ibmca_prov_ctx *provctx, int selection,
                            const OSSL_PARAM params[], int type)
{
    struct ibmca_op_ctx *ctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p selection: 0x%x type: %d", provctx,
                    selection, type);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "selection is not KEYPAIR");
        return NULL;
    }

    ctx = ibmca_keymgmt_gen_init(provctx, type, ibmca_keymgmt_rsa_gen_free_cb,
                                 ibmca_keymgmt_rsa_gen_dup_cb);
    if (ctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_keymgmt_gen_init failed");
        return NULL;
    }

    /* set defaults */
    ctx->rsa.gen.bits = IBMCA_RSA_DEFAULT_BITS;
    ctx->rsa.gen.pub_exp = BN_new();
    if (ctx->rsa.gen.pub_exp == NULL ||
        BN_set_word(ctx->rsa.gen.pub_exp, IBMCA_RSA_DEFAULT_PUB_EXP) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "BN_new/BN_set_word failed");
        ibmca_op_freectx(ctx);
        return NULL;
    }

    if (type == EVP_PKEY_RSA_PSS)
        ctx->rsa.gen.pss = ibmca_rsa_pss_defaults;

    if (params != NULL) {
        if (ibmca_keymgmt_rsa_gen_set_params(ctx, params) == 0) {
            ibmca_debug_ctx(provctx, "ERROR: ibmca_keymgmt_rsa_gen_set_params failed");
            ibmca_op_freectx(ctx);
            return NULL;
        }
    }

    return ctx;
}

static void *ibmca_keymgmt_rsa_gen_init(void *vprovctx, int selection,
                                        const OSSL_PARAM params[])
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);
    return ibmca_keymgmt_rsa_gen_init_type(provctx, selection, params,
                                           EVP_PKEY_RSA);
}

static void *ibmca_keymgmt_rsa_pss_gen_init(void *vprovctx, int selection,
                                            const OSSL_PARAM params[])
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);
    return ibmca_keymgmt_rsa_gen_init_type(provctx, selection, params,
                                           EVP_PKEY_RSA_PSS);
}

static int ibmca_keymgmt_rsa_gen_set_template(void *vgenctx, void *vtempl)
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

    ibmca_keymgmt_rsa_gen_free_cb(genctx);

    genctx->rsa.gen.bits = templ->rsa.bits;
    if (templ->rsa.public.exponent != NULL)  {
        genctx->rsa.gen.pub_exp = BN_bin2bn(templ->rsa.public.exponent,
                                            templ->rsa.public.key_length,
                                            NULL);
        if (genctx->rsa.gen.pub_exp == NULL) {
            put_error_op_ctx(genctx, IBMCA_ERR_MALLOC_FAILED,
                             "BN_bin2bn failed");
            return 0;
        }
    }

    if (genctx->type == EVP_PKEY_RSA_PSS)
        genctx->rsa.gen.pss = templ->rsa.pss;

    return 1;
}

static const OSSL_PARAM ibmca_rsa_op_ctx_settable_params[] = {
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_rsa_pss_op_ctx_settable_params[] = {
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_rsa_gen_settable_params(void *vgenctx,
                                                               void *vprovctx)
{
    const struct ibmca_op_ctx *genctx = vgenctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;

    const OSSL_PARAM *params, *p;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "type: %d", genctx->type);

    if (genctx->type == EVP_PKEY_RSA_PSS)
        params = ibmca_rsa_pss_op_ctx_settable_params;
    else
        params = ibmca_rsa_op_ctx_settable_params;

    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return params;
}

static int ibmca_keymgmt_rsa_gen_set_params(void *vgenctx,
                                            const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *genctx = vgenctx;
    const OSSL_PARAM *p;
    size_t primes;
    int rc;

    if (genctx == NULL)
        return 0;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(genctx, "param: %s", p->key);

    /* OSSL_PKEY_PARAM_RSA_BITS */
    rc = ibmca_param_get_size_t(genctx->provctx, params,
                                OSSL_PKEY_PARAM_RSA_BITS,
                                &genctx->rsa.gen.bits);
    if (rc == 0)
        return 0;
    if (rc > 0 && genctx->rsa.gen.bits < IBMCA_RSA_MIN_MODULUS_BITS) {
        put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                         "RSA '%s': %u is below minimum",
                         OSSL_PKEY_PARAM_RSA_BITS, genctx->rsa.gen.bits);
        return 0;
    }

    /* OSSL_PKEY_PARAM_RSA_PRIMES */
    rc = ibmca_param_get_size_t(genctx->provctx, params,
                                OSSL_PKEY_PARAM_RSA_PRIMES, &primes);
    if (rc == 0)
        return 0;
    if (rc > 0 && primes != 2) {
        put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                         "RSA '%s' value is not 2",
                         OSSL_PKEY_PARAM_RSA_PRIMES);
        return 0;
    }

    /* OSSL_PKEY_PARAM_RSA_E */
    rc = ibmca_param_get_bn(genctx->provctx, params,
                            OSSL_PKEY_PARAM_RSA_E, &genctx->rsa.gen.pub_exp);
    if (rc == 0)
        return 0;

    if (genctx->type == EVP_PKEY_RSA_PSS) {
        /* PSS restriction parameters */
        rc = ibmca_keymgmt_rsa_pss_parms_from_data(genctx->provctx, params,
                                                   &genctx->rsa.gen.pss);
        if (rc == 0)
            return 0;
    }

    return 1;
}

static int ibmca_keymgmt_rsa_gen_fallback(struct ibmca_op_ctx *genctx,
                                          struct ibmca_key *key,
                                          OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct ibmca_keygen_cb_data cbdata;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int rc = 0;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);

    pctx = ibmca_new_fallback_pkey_ctx(genctx->provctx, NULL, "RSA");
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

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, genctx->rsa.gen.bits) != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                     "EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        goto out;
    }

    if (genctx->rsa.gen.pub_exp != NULL) {
        if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pctx,
                                                genctx->rsa.gen.pub_exp) != 1) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                         "EVP_PKEY_CTX_set1_rsa_keygen_pubexp failed");
            goto out;
        }
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

    rc = ibmca_import_from_fallback_pkey(key, pkey,
                                         OSSL_KEYMGMT_SELECT_KEYPAIR);
    if (rc != 1) {
        ibmca_debug_op_ctx(genctx,
                           "ERROR: ibmca_import_from_fallback_pkey failed");
        goto out;
    }

    rc = 1;

out:
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return rc;
}

static void *ibmca_keymgmt_rsa_gen(void *vgenctx, OSSL_CALLBACK *osslcb,
                                   void *cbarg)
{
    struct ibmca_op_ctx *genctx = vgenctx;
    OSSL_PARAM cb_params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };
    struct ibmca_key *key = NULL;
    int rc, p, n;
    char *str;

    if (genctx == NULL)
        return NULL;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);

    cb_params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    cb_params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);

    key = ibmca_keymgmt_new(genctx->provctx, genctx->type, "RSA",
                            ibmca_keymgmt_rsa_free_cb,
                            ibmca_keymgmt_rsa_dup_cb,
                            ibmca_keymgmt_rsa_get_max_param_size,
                            ibmca_keymgmt_rsa_export,
                            ibmca_keymgmt_rsa_import,
                            ibmca_keymgmt_rsa_has,
                            ibmca_keymgmt_rsa_match);
    if (key == NULL) {
        ibmca_debug_op_ctx(genctx, "ERROR: ibmca_keymgmt_new failed");
        return NULL;
    }

    key->rsa.bits = genctx->rsa.gen.bits;
    ibmca_debug_op_ctx(genctx, "bits: %lu", key->rsa.bits);

    if (ibmca_keymgmt_rsa_alloc_pub(key) == 0) {
        ibmca_keymgmt_free(key);
        return NULL;
    }

    if (ibmca_keymgmt_rsa_alloc_priv(key) == 0) {
        ibmca_keymgmt_free(key);
        return NULL;
    }

    if (genctx->rsa.gen.pub_exp != NULL) {
        if (BN_bn2binpad(genctx->rsa.gen.pub_exp, key->rsa.public.exponent,
                         key->rsa.public.key_length) <= 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_bn2binpad failed for public exponent");
            ibmca_keymgmt_free(key);
            return NULL;
        }

        str = BN_bn2hex(genctx->rsa.gen.pub_exp);
        ibmca_debug_op_ctx(genctx, "public exponent: 0x%s (%d bits)", str,
                        BN_num_bits(genctx->rsa.gen.pub_exp));
        P_FREE(genctx->provctx, str);
    }

    p = 0;
    n = 0;
    if (osslcb != NULL && osslcb(cb_params, cbarg) == 0) {
        put_error_op_ctx(genctx, IBMCA_ERR_INTERNAL_ERROR, "osslcb failed");
        ibmca_keymgmt_free(key);
        return NULL;
    }

    rc = ica_rsa_key_generate_crt(genctx->provctx->ica_adapter, key->rsa.bits,
                                  &key->rsa.public, &key->rsa.private);
    if (rc != 0) {
        ibmca_debug_op_ctx(genctx, "ica_rsa_key_generate_crt failed with: %s",
                           strerror(rc));

        rc = ibmca_keymgmt_rsa_gen_fallback(genctx, key, osslcb, cbarg);
        if (rc != 1) {
            ibmca_debug_op_ctx(genctx,
                               "ERROR: ibmca_keymgmt_rsa_gen_fallback failed");
            ibmca_keymgmt_free(key);
            return NULL;
        }
    }

    p = 3;
    n = 0;
    if (osslcb != NULL && osslcb(cb_params, cbarg) == 0) {
        put_error_op_ctx(genctx, IBMCA_ERR_INTERNAL_ERROR, "osslcb failed");
        ibmca_keymgmt_free(key);
        return NULL;
    }

    if (genctx->type == EVP_PKEY_RSA_PSS)
        key->rsa.pss = genctx->rsa.gen.pss;

    ibmca_debug_op_ctx(genctx, "key: %p", key);

    return key;
}

static int ibmca_keymgmt_rsa_security_bits(size_t bits)
{
    switch (bits) {
    case 512:
        return 0; /* ??? */
    case 1024:
        return 80;
    case 2048:
        return 112;
    case 3072:
        return 128;
    case 4096:
        return 152;
    case 6144:
        return 176;
    case 7680:
        return 192;
    case 8192:
        return 200;
    case 15360:
        return 256;
    default:
        return 0;
    }
}

static int ibmca_keymgmt_rsa_pub_as_bn(struct ibmca_key *key,
                                       BIGNUM **n, BIGNUM **e)
{
    if (key->rsa.public.modulus == NULL || key->rsa.public.exponent == NULL)
        return 0;

    *n = BN_bin2bn(key->rsa.public.modulus, key->rsa.public.key_length, NULL);
    *e = BN_bin2bn(key->rsa.public.exponent, key->rsa.public.key_length, NULL);
    if (*n == NULL || *e == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bin2bn failed");
       goto error;
    }

    return 1;

error:
    BN_free(*n);
    *n = NULL;
    BN_free(*e);
    *e = NULL;

    return 0;
}


static int ibmca_keymgmt_rsa_priv_as_bn(struct ibmca_key *key, BIGNUM **p,
                                        BIGNUM **q, BIGNUM **dp, BIGNUM **dq,
                                        BIGNUM **qinv)
{
    if (key->rsa.private.p == NULL || key->rsa.private.q == NULL ||
        key->rsa.private.dp == NULL || key->rsa.private.dq == NULL ||
        key->rsa.private.qInverse == NULL)
        return 0;

    *p = BN_secure_new();
    *q = BN_secure_new();
    *dp = BN_secure_new();
    *dq = BN_secure_new();
    *qinv = BN_secure_new();
    if (*p == NULL || *q == NULL || *dp == NULL ||
        *dq == NULL || *qinv == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto error;
    }

    *p = BN_bin2bn(key->rsa.private.p,
                   ICA_P_LEN(key->rsa.private.key_length), *p);
    *q = BN_bin2bn(key->rsa.private.q,
                   ICA_Q_LEN(key->rsa.private.key_length), *q);
    *dp = BN_bin2bn(key->rsa.private.dp,
                    ICA_DP_LEN(key->rsa.private.key_length),
                    *dp);
    *dq = BN_bin2bn(key->rsa.private.dq,
                    ICA_DQ_LEN(key->rsa.private.key_length), *dq);
    *qinv = BN_bin2bn(key->rsa.private.qInverse,
                      ICA_QINV_LEN(key->rsa.private.key_length), *qinv);
    if (*p == NULL || *q == NULL || *dp == NULL ||
        *dq == NULL || *qinv == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bin2bn failed");
       goto error;
    }

    return 1;

error:
    BN_clear_free(*p);
    *p = NULL;
    BN_clear_free(*q);
    *q = NULL;
    BN_clear_free(*dp);
    *dp = NULL;
    BN_clear_free(*dq);
    *dq = NULL;
    BN_clear_free(*qinv);
    *qinv = NULL;

    return 0;
}

static int ibmca_keymgmt_rsa_calc_priv_d(struct ibmca_key *key, BIGNUM *n,
                                         BIGNUM *e, BIGNUM *p, BIGNUM *q,
                                         BIGNUM **d)
{
    BN_CTX *bn_ctx;

    /*
     * phi(n) = (p - 1 )(q - 1) = n - p - q + 1
     * d = e ^{-1} mod phi(n).
     */
    bn_ctx = BN_CTX_new();
    *d = BN_secure_new();
    if (bn_ctx == NULL || *d == NULL ||
        BN_copy(*d, n) == NULL ||
        BN_sub(*d, *d, p) == 0 ||
        BN_sub(*d, *d, q) == 0 ||
        BN_add_word(*d, 1) == 0 ||
        BN_mod_inverse(*d, e, *d, bn_ctx) == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to calculate private key part d");
        BN_CTX_free(bn_ctx);
        BN_clear_free(*d);
        *d = NULL;
        return 0;
    }
    BN_CTX_free(bn_ctx);

    return 1;
}

static int ibmca_keymgmt_rsa_get_params(void *vkey, OSSL_PARAM params[])
{
    struct ibmca_key *key = vkey;
    OSSL_PARAM *parm;
    bool empty;
    const char *name;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *dp = NULL, *dq = NULL, *qinv = NULL;
    int rc;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p", key);
    for (parm = params; parm != NULL && parm->key != NULL; parm++)
        ibmca_debug_key(key, "param: %s", parm->key);

    empty = (key->rsa.public.key_length == 0 ||
             key->rsa.private.key_length == 0);

    if (!empty) {
        /* OSSL_PKEY_PARAM_BITS */
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_BITS, key->rsa.bits);
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_SECURITY_BITS */
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_SECURITY_BITS,
                                       ibmca_keymgmt_rsa_security_bits(
                                                               key->rsa.bits));
        if (rc == 0)
            return 0;

        /* OSSL_PKEY_PARAM_MAX_SIZE */
        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_MAX_SIZE,
                                       ibmca_keymgmt_rsa_get_max_param_size(
                                                                       key));
        if (rc == 0)
            return 0;
    }

    /*
     * For non-PSS keys or unrestricted RSA-PSS keys only:
     * OSSL_PKEY_PARAM_DEFAULT_DIGEST
     */
    if ((key->type != EVP_PKEY_RSA_PSS || !key->rsa.pss.restricted)) {
        name = OBJ_nid2sn(IBMCA_RSA_DEFAULT_DIGEST);
        rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                        OSSL_PKEY_PARAM_DEFAULT_DIGEST, name);
        if (rc == 0)
            return 0;
    }

    /*
     * For restricted RSA-PSS keys only:
     * OSSL_PKEY_PARAM_MANDATORY_DIGEST
     */
    if ((key->type == EVP_PKEY_RSA_PSS && key->rsa.pss.restricted)) {
        name = OBJ_nid2sn(key->rsa.pss.digest_nid);
        rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                        OSSL_PKEY_PARAM_MANDATORY_DIGEST, name);
        if (rc == 0)
            return 0;
    }

    /* Public key parts */
    rc =  ibmca_keymgmt_rsa_pub_as_bn(key, &n, &e);
    if (rc == 1) {
        rc = ibmca_keymgmt_rsa_pub_key_to_data(key->provctx, NULL, params, n, e);
        if (rc == 0)
            goto out;
    }

    /* Private key parts */
    rc = ibmca_keymgmt_rsa_priv_as_bn(key, &p, &q, &dp, &dq, &qinv);
    if (rc == 1) {
        rc = ibmca_keymgmt_rsa_calc_priv_d(key, n, e, p, q, &d);
        if (rc == 0)
            goto out;

        rc = ibmca_keymgmt_rsa_priv_key_to_data(key->provctx, NULL, params, d,
                                                p, q, dp, dq, qinv);
        if (rc == 0)
            goto out;
    }

    /* Return RSA-PSS parameters only for restricted RSA-PSS keys */
    if (key->type == EVP_PKEY_RSA_PSS && key->rsa.pss.restricted) {
        rc = ibmca_keymgmt_rsa_pss_parms_to_data(key->provctx, NULL, params,
                                                 &key->rsa.pss);
        if (rc == 0)
            goto out;
    }

    rc = 1;

out:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dp);
    BN_free(dq);
    BN_free(qinv);

    return rc;
}

static const OSSL_PARAM ibmca_rsa_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_rsa_gettable_params(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    for (p = ibmca_rsa_gettable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_rsa_gettable_params;
}

static const OSSL_PARAM ibmca_rsa_pss_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_rsa_pss_gettable_params(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    for (p = ibmca_rsa_pss_gettable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_rsa_pss_gettable_params;
}

static const OSSL_PARAM ibmca_rsa_eximport_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_rsa_pss_params_eximport_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_rsa_pss_export_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_rsa_pss_import_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_rsa_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ibmca_rsa_eximport_types;

    return NULL;
}

static const OSSL_PARAM *ibmca_keymgmt_rsa_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ibmca_rsa_eximport_types;

    return NULL;
}

static const OSSL_PARAM *ibmca_keymgmt_rsa_pss_export_types(int selection)
{
    if (selection == OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
        return ibmca_rsa_pss_params_eximport_types;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) == 0 &&
        (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ibmca_rsa_eximport_types;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 &&
        (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ibmca_rsa_pss_export_types;

    return NULL;
}

static const OSSL_PARAM *ibmca_keymgmt_rsa_pss_import_types(int selection)
{
    if (selection == OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
        return ibmca_rsa_pss_params_eximport_types;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) == 0 &&
        (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ibmca_rsa_eximport_types;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 &&
        (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ibmca_rsa_pss_import_types;

    return NULL;
}

int ibmca_keymgmt_rsa_export(void *vkey, int selection,
                             OSSL_CALLBACK *param_callback, void *cbarg)
{
    struct ibmca_key *key = vkey;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *dp = NULL;
    BIGNUM *dq = NULL, *qinv = NULL;
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

    /* Public key is required if private key is exported */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* Public key parts */
        rc =  ibmca_keymgmt_rsa_pub_as_bn(key, &n, &e);
        if (rc == 1) {
            rc = ibmca_keymgmt_rsa_pub_key_to_data(key->provctx, bld, NULL,
                                                   n, e);
            if (rc == 0)
                goto error;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* Private key parts */
        rc = ibmca_keymgmt_rsa_priv_as_bn(key, &p, &q, &dp, &dq, &qinv);
        if (rc == 1) {
            rc = ibmca_keymgmt_rsa_calc_priv_d(key, n, e, p, q, &d);
            if (rc == 0)
                goto error;

            rc = ibmca_keymgmt_rsa_priv_key_to_data(key->provctx, bld, NULL, d,
                                                    p, q, dp, dq, qinv);
            if (rc == 0)
                goto error;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 &&
        key->type == EVP_PKEY_RSA_PSS &&
        key->rsa.pss.restricted) {
        /* PSS parameters */
        rc = ibmca_keymgmt_rsa_pss_parms_to_data(key->provctx, bld, NULL,
                                                 &key->rsa.pss);
        if (rc == 0)
            goto error;
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

    if (n != NULL)
        BN_free(n);
    if (e != NULL)
        BN_free(e);
    if (d != NULL)
        BN_free(d);
    if (p != NULL)
        BN_free(p);
    if (q != NULL)
        BN_free(q);
    if (dp != NULL)
        BN_free(dp);
    if (dq != NULL)
        BN_free(dq);
    if (qinv != NULL)
        BN_free(qinv);

    return rc;
}

int ibmca_keymgmt_rsa_import(void *vkey, int selection,
                             const OSSL_PARAM params[])
{
    struct ibmca_key *key = vkey;
    const OSSL_PARAM *parm;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *dp = NULL, *dq = NULL, *qinv = NULL;
    int rc = 0;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x", key, selection);
    for (parm = params; parm != NULL && parm->key != NULL; parm++)
        ibmca_debug_key(key, "param: %s", parm->key);

    /* Clear any already existing key components */
    ibmca_keymgmt_rsa_free_cb(key);
    ibmca_clean_fallback_pkey_cache(key);

    /* Import public key parts */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0) {
        put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                      "RSA public key parts are mandatory");
        return 0;
    }

    rc = ibmca_keymgmt_rsa_pub_key_from_data(key->provctx, params, &n, &e);
    if (rc == 0)
        return 0;

    key->rsa.bits = BN_num_bits(n);
    ibmca_debug_key(key, "key: %p bits: %u", key, key->rsa.bits);

    if (ibmca_keymgmt_rsa_alloc_pub(key) == 0)
        goto out;

    if (BN_bn2binpad(n, key->rsa.public.modulus,
                     key->rsa.public.key_length) <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "BN_bn2binpad failed for modulus");
        goto out;
    }

    if (BN_bn2binpad(e, key->rsa.public.exponent,
                     key->rsa.public.key_length) <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "BN_bn2binpad failed for public exponent");
        goto out;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* Import private key parts */
        if (ibmca_keymgmt_rsa_alloc_priv(key) == 0)
            goto out;

        rc = ibmca_keymgmt_rsa_priv_key_from_data(key->provctx, params, &d,
                                                  &p, &q, &dp, &dq, &qinv);
        if (rc == 0)
            goto out;

        if (BN_bn2binpad(p, key->rsa.private.p,
                         ICA_P_LEN(key->rsa.private.key_length)) <= 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_bn2binpad failed for private d");
            goto out;
        }
        if (BN_bn2binpad(q, key->rsa.private.q,
                         ICA_Q_LEN(key->rsa.private.key_length)) <= 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_bn2binpad failed for private q");
            goto out;
        }
        if (BN_bn2binpad(dp, key->rsa.private.dp,
                         ICA_DP_LEN(key->rsa.private.key_length)) <= 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_bn2binpad failed for private dp");
            goto out;
        }
        if (BN_bn2binpad(dq, key->rsa.private.dq,
                         ICA_DQ_LEN(key->rsa.private.key_length)) <= 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_bn2binpad failed for private dq");
            goto out;
        }
        if (BN_bn2binpad(qinv, key->rsa.private.qInverse,
                         ICA_QINV_LEN(key->rsa.private.key_length)) <= 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_bn2binpad failed for private qinv");
            goto out;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 &&
        key->type == EVP_PKEY_RSA_PSS) {
        /* Import PSS restriction parameters */
        rc = ibmca_keymgmt_rsa_pss_parms_from_data(key->provctx, params,
                                                   &key->rsa.pss);
        if (rc == 0)
            goto out;
    }

    rc = 1;

out:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dp);
    BN_free(dq);
    BN_free(qinv);

    return rc;
}

static const OSSL_DISPATCH ibmca_rsa_keymgmt_functions[] = {
    /* Constructor, destructor */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ibmca_keymgmt_rsa_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ibmca_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ibmca_keymgmt_dup },

    /* Key generation and loading */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,
            (void (*)(void))ibmca_keymgmt_rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
            (void (*)(void))ibmca_keymgmt_rsa_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
            (void (*)(void))ibmca_keymgmt_rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
            (void (*)(void))ibmca_keymgmt_rsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ibmca_keymgmt_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
            (void (*)(void))ibmca_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ibmca_keymgmt_load },

    /* Key object checking */
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ibmca_keymgmt_rsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ibmca_keymgmt_rsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ibmca_keymgmt_rsa_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
            (void (*)(void))ibmca_keymgmt_rsa_query_operation_name },

    /* Key object information */
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
            (void (*) (void))ibmca_keymgmt_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
            (void (*) (void))ibmca_keymgmt_rsa_gettable_params },

    /* Import and export routines */
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ibmca_keymgmt_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ibmca_keymgmt_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_rsa_import_types },

    { 0, NULL }
};

static const OSSL_DISPATCH ibmca_rsapss_keymgmt_functions[] = {
    /* Constructor, destructor */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ibmca_keymgmt_rsa_pss_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ibmca_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ibmca_keymgmt_dup },

    /* Key generation and loading */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,
            (void (*)(void))ibmca_keymgmt_rsa_pss_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
            (void (*)(void))ibmca_keymgmt_rsa_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
            (void (*)(void))ibmca_keymgmt_rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
            (void (*)(void))ibmca_keymgmt_rsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ibmca_keymgmt_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
            (void (*)(void))ibmca_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ibmca_keymgmt_load },

    /* Key object checking */
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ibmca_keymgmt_rsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ibmca_keymgmt_rsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ibmca_keymgmt_rsa_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (void (*)(void))ibmca_keymgmt_rsa_query_operation_name },

    /* Key object information */
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
            (void (*) (void))ibmca_keymgmt_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        (void (*) (void))ibmca_keymgmt_rsa_pss_gettable_params },

    /* Import and export routines */
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ibmca_keymgmt_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_rsa_pss_export_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ibmca_keymgmt_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_rsa_pss_import_types },

    { 0, NULL }
};

const OSSL_ALGORITHM ibmca_rsa_keymgmt[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", NULL,
      ibmca_rsa_keymgmt_functions, "IBMCA RSA implementation" },
    { "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", NULL,
      ibmca_rsapss_keymgmt_functions, "IBMCA RSA-PSS implementation" },
    { NULL, NULL, NULL, NULL }
};


