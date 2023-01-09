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
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/prov_ssl.h>

#include "p_ibmca.h"

static OSSL_FUNC_keymgmt_new_fn ibmca_keymgmt_ec_new;
static OSSL_FUNC_keymgmt_gen_init_fn ibmca_keymgmt_ec_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn ibmca_keymgmt_ec_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn ibmca_keymgmt_ec_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn
                                        ibmca_keymgmt_ec_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn ibmca_keymgmt_ec_gen;
static OSSL_FUNC_keymgmt_has_fn ibmca_keymgmt_ec_has;
static OSSL_FUNC_keymgmt_match_fn ibmca_keymgmt_ec_match;
static OSSL_FUNC_keymgmt_validate_fn ibmca_keymgmt_ec_validate;
static OSSL_FUNC_keymgmt_query_operation_name_fn
                                        ibmca_keymgmt_ec_query_operation_name;
static OSSL_FUNC_keymgmt_get_params_fn ibmca_keymgmt_ec_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn ibmca_keymgmt_ec_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn ibmca_keymgmt_ec_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn ibmca_keymgmt_ec_settable_params;
static OSSL_FUNC_keymgmt_export_fn ibmca_keymgmt_ec_export;
static OSSL_FUNC_keymgmt_export_types_fn ibmca_keymgmt_ec_imexport_types;
static OSSL_FUNC_keymgmt_import_fn ibmca_keymgmt_ec_import;

static void ibmca_keymgmt_ec_free_cb(struct ibmca_key *key);
static int ibmca_keymgmt_ec_dup_cb(const struct ibmca_key *key,
                                   struct ibmca_key *new_key);

static size_t ibmca_keymgmt_ec_get_prime_size(const struct ibmca_key *key);
static size_t ibmca_keymgmt_ec_get_max_param_size(const struct ibmca_key *key);

static int ibmca_keymgmt_ec_pub_key_as_buf(const struct ibmca_key *key,
                                           unsigned char **x,
                                           unsigned char **y)
{
    unsigned char *q = NULL;
    unsigned int len, i;
    bool all_zero;
    int rc = 0;

    *x = NULL;
    *y = NULL;

    if (key->ec.key == NULL || key->ec.prime_size == 0 ||
        key->ec.curve_nid == NID_undef)
        return -1;

    q = P_ZALLOC(key->provctx, key->ec.prime_size * 2);
    if (q == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate public EC key part");
        goto out;
    }

    rc = ica_ec_key_get_public_key(key->ec.key, q, &len);
    if ((rc != 0 && rc != EINVAL) || len != key->ec.prime_size * 2) {
        put_error_key(key, IBMCA_ERR_LIBICA_FAILED,
                      "Failed to get public EC key from libica key: %s",
                      strerror(rc));
        rc = 0;
        goto out;
    }
    if (rc == EINVAL) { /* No public key */
        rc = -1;
        goto out;
    }

    for (i = 0, all_zero = true; i < len && all_zero; i++) {
        if (q[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) { /* No public key */
        rc = -1;
        goto out;
    }

    *x = P_ZALLOC(key->provctx, key->ec.prime_size);
    *y = P_ZALLOC(key->provctx, key->ec.prime_size);
    if (*x == NULL || *y == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate public EC key parts");
        P_CLEAR_FREE(key->provctx, *x, key->ec.prime_size);
        *x = NULL;
        P_CLEAR_FREE(key->provctx, *y, key->ec.prime_size);
        *y = NULL;
        goto out;
    }

    memcpy(*x, q, key->ec.prime_size);
    memcpy(*y, q + key->ec.prime_size, key->ec.prime_size);

    rc = 1;

out:
    if (q != NULL)
        P_CLEAR_FREE(key->provctx, q, key->ec.prime_size * 2);

    return rc;
}

static int ibmca_keymgmt_ec_priv_key_as_buf(const struct ibmca_key *key,
                                            unsigned char **d)
{

    unsigned int len, i;
    int all_zero;
    int rc = 0;

    if (key->ec.key == NULL || key->ec.prime_size == 0 ||
        key->ec.curve_nid == NID_undef)
        return -1;


    *d = P_SECURE_ZALLOC(key->provctx, key->ec.prime_size);
    if (*d == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate private EC key part");
        goto out;
    }

    rc = ica_ec_key_get_private_key(key->ec.key, *d, &len);
    if ((rc != 0 && rc != EINVAL) || len != key->ec.prime_size) {
        put_error_key(key, IBMCA_ERR_LIBICA_FAILED,
                      "Failed to get private EC key from libica key: %s",
                      strerror(rc));
        rc = 0;
        goto out;
    }

    if (rc == EINVAL) { /* No private key */
        rc = -1;
        goto out;
    }

    for (i = 0, all_zero = 1; i < len && all_zero; i++)
        all_zero &= ((*d)[i] == 0);
    if (all_zero) { /* No private key */
        rc = -1;
        goto out;
    }

    rc = 1;

out:
    if (rc != 1 && *d != NULL) {
        P_SECURE_CLEAR_FREE(key->provctx, *d, key->ec.prime_size);
        *d = NULL;
    }

    return rc;
}

static int ibmca_keymgmt_ec_pub_key_as_bn(const struct ibmca_key *key,
                                          BIGNUM **x, BIGNUM **y)
{
    unsigned char *buf_x = NULL, *buf_y = NULL;
    int rc;

    if (key->ec.fallback.x != NULL && key->ec.fallback.y != NULL) {
        *x = BN_dup(key->ec.fallback.x);
        *y = BN_dup(key->ec.fallback.y);

        if (*x == NULL || *y == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            goto error;
        }

        return 1;
    }

    rc = ibmca_keymgmt_ec_pub_key_as_buf(key, &buf_x, &buf_y);
    if (rc != 1)
        return rc;

    *x = BN_bin2bn(buf_x, key->ec.prime_size, NULL);
    *y = BN_bin2bn(buf_y, key->ec.prime_size, NULL);
    if (*x == NULL || *y == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bin2bn failed");
       goto error;
    }

    P_CLEAR_FREE(key->provctx, buf_x, key->ec.prime_size);
    P_CLEAR_FREE(key->provctx, buf_y, key->ec.prime_size);

    return 1;

error:
    if (*x != NULL)
        BN_free(*x);
    *x = NULL;
    if (*y != NULL)
        BN_free(*y);
    *y = NULL;

    if (buf_x != NULL)
        P_CLEAR_FREE(key->provctx, buf_x, key->ec.prime_size);
    if (buf_y != NULL)
        P_CLEAR_FREE(key->provctx, buf_y, key->ec.prime_size);

    return 0;
}

static int ibmca_keymgmt_ec_priv_key_as_bn(const struct ibmca_key *key,
                                           BIGNUM **d)
{
    unsigned char *buf_d = NULL;
    int rc;

    if (key->ec.fallback.d != NULL) {
        *d = BN_dup(key->ec.fallback.d);

        if (*d == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
            goto error;
        }

        return 1;
    }
    rc = ibmca_keymgmt_ec_priv_key_as_buf(key, &buf_d);
    if (rc != 1)
        return rc;

    *d = BN_secure_new();
    if (*d == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        goto error;
    }

    *d = BN_bin2bn(buf_d, key->ec.prime_size, *d);
    if (*d == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bin2bn failed");
       goto error;
    }

    P_SECURE_CLEAR_FREE(key->provctx, buf_d, key->ec.prime_size);

    return 1;

error:
    if (*d != NULL)
        BN_clear_free(*d);
    *d = NULL;

    if (buf_d != NULL)
        P_SECURE_CLEAR_FREE(key->provctx, buf_d, key->ec.prime_size);

    return 0;
}

static int ibmca_keymgmt_ec_pub_key_from_bn(struct ibmca_key *key,
                                            BIGNUM *x, BIGNUM *y)
{
    unsigned int privlen;
    unsigned char *x_buf = NULL, *y_buf = NULL;
    int rc = 0;

    if (x == NULL || y == NULL) {
        put_error_key(key, IBMCA_ERR_INVALID_PARAM, "Need both, x and y");
        return 0;
    }

    if (key->ec.curve_nid == NID_undef) {
        put_error_key(key, IBMCA_ERR_INVALID_PARAM, "Curve nid is not known");
        return 0;
    }

    if (key->ec.key == NULL) {
        key->ec.prime_size = ibmca_keymgmt_ec_get_prime_size(key);
        if (key->ec.prime_size == 0) {
            put_error_key(key, IBMCA_ERR_EC_CURVE_NOT_SUPPORTED,
                          "Unsupported curve nid: %d", key->ec.curve_nid);
            return 0;
        }

        ibmca_debug_key(key, "prime_size: %lu", key->ec.prime_size);

        key->ec.key = ica_ec_key_new(key->ec.curve_nid, &privlen);
        if (key->ec.key == NULL || key->ec.prime_size != privlen) {
            ibmca_debug_key(key,  "ica_ec_key_new failed");
            goto fallback;
        }
    }

    x_buf = P_ZALLOC(key->provctx, key->ec.prime_size);
    y_buf = P_ZALLOC(key->provctx, key->ec.prime_size);
    if (x_buf == NULL || y_buf == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate public EC key parts");
        goto out;
    }

    if (BN_bn2binpad(x, x_buf, key->ec.prime_size) <= 0 ||
        BN_bn2binpad(y, y_buf, key->ec.prime_size) <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bn2binpad failed");
        goto out;
    }

    rc = ica_ec_key_init(x_buf, y_buf, NULL, key->ec.key);
    if (rc != 0) {
        ibmca_debug_key(key, "ica_ec_key_init failed: %s",
                        strerror(rc));
        rc = 0;
        goto fallback;
    }

    rc = 1;
    goto out;

fallback:
    ibmca_debug_key(key, "using fallback");

    if (key->ec.key != NULL)
        ica_ec_key_free(key->ec.key);
    key->ec.key = NULL;

    if (key->ec.fallback.x != NULL)
        BN_free(key->ec.fallback.x);
    if (key->ec.fallback.y != NULL)
        BN_free(key->ec.fallback.y);

    key->ec.fallback.x = BN_dup(x);
    key->ec.fallback.y = BN_dup(y);
    if (key->ec.fallback.x == NULL || key->ec.fallback.y == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
        goto out;
    }
    rc = 1;

out:
    if (x_buf != NULL)
        P_CLEAR_FREE(key->provctx, x_buf, key->ec.prime_size);
    if (y_buf != NULL)
        P_CLEAR_FREE(key->provctx, y_buf, key->ec.prime_size);

    return rc;
}

static int ibmca_keymgmt_ec_priv_key_from_bn(struct ibmca_key *key, BIGNUM *d)
{
    unsigned int privlen;
    unsigned char *d_buf = NULL;
    int rc = 0;

    if (d == NULL) {
        put_error_key(key, IBMCA_ERR_INVALID_PARAM, "Need private part d");
        return 0;
    }

    if (key->ec.curve_nid == NID_undef) {
        put_error_key(key, IBMCA_ERR_INVALID_PARAM, "Curve nid is not known");
        return 0;
    }

    if (key->ec.key == NULL) {
        key->ec.prime_size = ibmca_keymgmt_ec_get_prime_size(key);
        if (key->ec.prime_size == 0) {
            put_error_key(key, IBMCA_ERR_EC_CURVE_NOT_SUPPORTED,
                          "Unsupported curve nid: %d", key->ec.curve_nid);
            return 0;
        }

        ibmca_debug_key(key, "prime_size: %lu", key->ec.prime_size);

        key->ec.key = ica_ec_key_new(key->ec.curve_nid, &privlen);
        if (key->ec.key == NULL || key->ec.prime_size != privlen) {
            ibmca_debug_key(key, "ica_ec_key_new failed");
            goto fallback;
        }
    }

    d_buf = P_SECURE_ZALLOC(key->provctx, key->ec.prime_size);
    if (d_buf == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate private EC key part");
        goto out;
    }

    if (BN_bn2binpad(d, d_buf, key->ec.prime_size) <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bn2binpad failed");
        goto out;
    }

    rc = ica_ec_key_init(NULL, NULL, d_buf, key->ec.key);
    if (rc != 0) {
        ibmca_debug_key(key, "ica_ec_key_init failed: %s",
                        strerror(rc));
        rc = 0;
        goto fallback;
    }

    rc = 1;
    goto out;

fallback:
    ibmca_debug_key(key, "using fallback");

    if (key->ec.key != NULL)
        ica_ec_key_free(key->ec.key);
    key->ec.key = NULL;

    if (key->ec.fallback.d != NULL)
        BN_free(key->ec.fallback.d);

    key->ec.fallback.d = BN_dup(d);
    if (key->ec.fallback.d == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_dup failed");
        goto out;
    }
    rc = 1;

out:
    if (d_buf != NULL)
        P_SECURE_CLEAR_FREE(key->provctx, d_buf, key->ec.prime_size);

    return rc;
}

static int ibmca_keymgmt_ec_pub_key_to_data(struct ibmca_key *key,
                                            BIGNUM *x, BIGNUM *y,
                                            OSSL_PARAM_BLD *bld,
                                            OSSL_PARAM params[])
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *enc = NULL;
    size_t enc_len = 0;
    int rc = 0;

    /* OSSL_PKEY_PARAM_EC_PUB_X */
    rc = ibmca_param_build_set_bn(key->provctx, bld, params,
                                  OSSL_PKEY_PARAM_EC_PUB_X, x);
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_EC_PUB_Y */
    rc = ibmca_param_build_set_bn(key->provctx, bld, params,
                                  OSSL_PKEY_PARAM_EC_PUB_Y, y);
    if (rc == 0)
        return 0;

    group = EC_GROUP_new_by_curve_name(key->ec.curve_nid);
    if (group == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EC_GROUP_new_by_curve_name failed");
        goto out;
    }

    point = EC_POINT_new(group);
    if (point == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EC_POINT_new failed");
        goto out;
    }

    if (EC_POINT_set_affine_coordinates(group, point, x, y, NULL) == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EC_POINT_set_affine_coordinates failed");
        goto out;
    }

    /* OSSL_PKEY_PARAM_PUB_KEY */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY) != NULL) {
        enc_len = EC_POINT_point2buf(group, point, POINT_CONVERSION_COMPRESSED,
                                     &enc, NULL);
        if (enc_len == 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_POINT_point2buf failed");
            goto out;
        }

        rc = ibmca_param_build_set_octet_ptr(key->provctx, bld, params,
                                             OSSL_PKEY_PARAM_PUB_KEY,
                                             enc, enc_len);
        if (rc == 0)
            goto out;

        P_FREE(key->provctx, enc);
        enc = NULL;
    }

    /* OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) != NULL) {
        enc_len = EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                     &enc, NULL);
        if (enc_len == 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_POINT_point2buf failed");
            goto out;
        }

        rc = ibmca_param_build_set_octet_ptr(key->provctx, bld, params,
                                             OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                             enc, enc_len);
        if (rc == 0)
            goto out;

        P_FREE(key->provctx, enc);
        enc = NULL;
    }

    rc = 1;

out:
    EC_GROUP_free(group);
    EC_POINT_free(point);
    if (enc != NULL)
        P_FREE(key->provctx, enc);

    return rc;
}

static int ibmca_keymgmt_ec_priv_key_to_data(struct ibmca_key *key,
                                             BIGNUM *d,
                                             OSSL_PARAM_BLD *bld,
                                             OSSL_PARAM params[])
{
    int rc = 0;

    /* OSSL_PKEY_PARAM_PRIV_KEY */
    rc = ibmca_param_build_set_bn(key->provctx, bld, params,
                                  OSSL_PKEY_PARAM_PRIV_KEY, d);
    if (rc == 0)
        return 0;

    return 1;
}

static void *ibmca_keymgmt_ec_new(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    struct ibmca_key *key;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    key = ibmca_keymgmt_new(provctx, EVP_PKEY_EC, "EC",
                            ibmca_keymgmt_ec_free_cb,
                            ibmca_keymgmt_ec_dup_cb,
                            ibmca_keymgmt_ec_get_max_param_size,
                            ibmca_keymgmt_ec_export,
                            ibmca_keymgmt_ec_import,
                            ibmca_keymgmt_ec_has,
                            ibmca_keymgmt_ec_match);
    if (key == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_keymgmt_new failed");
        return NULL;
    }

    key->ec.curve_nid = NID_undef;
    key->ec.format = POINT_CONVERSION_UNCOMPRESSED;
    key->ec.prime_size = 0;
    key->ec.include_pub = true;

    return key;
}

static void ibmca_keymgmt_ec_free_cb(struct ibmca_key *key)
{
    if (key == NULL)
        return;

    ibmca_debug_key(key, "key: %p", key);

    if (key->ec.key != NULL)
        ica_ec_key_free(key->ec.key);
    key->ec.key = NULL;

    if (key->ec.fallback.x != NULL)
        BN_free(key->ec.fallback.x);
    key->ec.fallback.x = NULL;
    if (key->ec.fallback.y != NULL)
        BN_free(key->ec.fallback.y);
    key->ec.fallback.y = NULL;
    if (key->ec.fallback.d != NULL)
        BN_free(key->ec.fallback.d);
    key->ec.fallback.d = NULL;

    key->ec.curve_nid = NID_undef;
    key->ec.format = POINT_CONVERSION_UNCOMPRESSED;
    key->ec.prime_size = 0;
    key->ec.include_pub = true;
}

static int ibmca_keymgmt_ec_dup_cb(const struct ibmca_key *key,
                                   struct ibmca_key *new_key)
{
    unsigned int privlen;
    unsigned char *x = NULL, *y = NULL, *d = NULL;
    bool has_pub = false, has_priv = false;
    int rc = 0;

    if (key == NULL || new_key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p new_key: %p", key, new_key);

    new_key->ec.curve_nid = key->ec.curve_nid;
    new_key->ec.format = key->ec.format;
    new_key->ec.include_pub = key->ec.include_pub;
    new_key->ec.prime_size = key->ec.prime_size;

    if (key->ec.key != NULL) {
        new_key->ec.key = ica_ec_key_new(new_key->ec.curve_nid, &privlen);
        if (new_key->ec.key == NULL) {
            put_error_key(key, IBMCA_ERR_LIBICA_FAILED,
                          "Failed to allocate libica EC key");
            goto out;
        }

        if (privlen != new_key->ec.prime_size) {
            put_error_key(key, IBMCA_ERR_LIBICA_FAILED,
                          "Newly allocated libica EC key has a different size");
            goto out;
        }

        rc = ibmca_keymgmt_ec_pub_key_as_buf(key, &x, &y);
        if (rc == 0)
            goto out;
        has_pub = (rc == 1);

        rc = ibmca_keymgmt_ec_priv_key_as_buf(key, &d);
        if (rc == 0)
            goto out;
        has_priv = (rc == 1);

        rc = ica_ec_key_init(has_pub ? x : NULL, has_pub ? y : NULL,
                             has_priv ? d : NULL, new_key->ec.key);
        if (rc != 0) {
            put_error_key(key, IBMCA_ERR_LIBICA_FAILED,
                          "Failed to initialize libica EC key: %s",
                          strerror(rc));
            rc = 0;
            goto out;
        }
    }

    if (key->ec.fallback.x != NULL && key->ec.fallback.y != NULL) {
        new_key->ec.fallback.x = BN_dup(key->ec.fallback.x);
        new_key->ec.fallback.y = BN_dup(key->ec.fallback.y);
        if (new_key->ec.fallback.x == NULL || new_key->ec.fallback.y == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_dup failed");
            goto out;
        }
    }

    if (key->ec.fallback.d != NULL) {
        new_key->ec.fallback.d = BN_dup(key->ec.fallback.d);
        if (new_key->ec.fallback.d == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_dup failed");
            goto out;
        }
    }

    rc = 1;

out:
    if (x != NULL)
        P_CLEAR_FREE(key->provctx, x, privlen);
    if (y != NULL)
        P_CLEAR_FREE(key->provctx, y, privlen);
    if (d != NULL)
        P_SECURE_CLEAR_FREE(key->provctx, d, privlen);

    return rc;
}

static int ibmca_keymgmt_ec_has(const void *vkey, int selection)
{
    const struct ibmca_key *key = vkey;
    BIGNUM *x = NULL, *y = NULL, *d = NULL;
    int rc, ok = 1;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x", key, selection);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        rc = ibmca_keymgmt_ec_pub_key_as_bn(key, &x, &y);
        if (rc == 0)
            goto out;
        ok = ok & (rc == 1);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        rc = ibmca_keymgmt_ec_priv_key_as_bn(key, &d);
        if (rc == 0)
            goto out;
        ok = ok & (rc == 1);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok & (key->ec.curve_nid != NID_undef);

out:
    if (x != NULL)
        BN_free(x);
    if (y != NULL)
        BN_free(y);
    if (d != NULL)
        BN_free(d);

    ibmca_debug_key(key, "ok: %d", ok);

    return ok;
}

static int ibmca_keymgmt_ec_match(const void *vkey1, const void *vkey2,
                                  int selection)
{
    const struct ibmca_key *key1 = vkey1;
    const struct ibmca_key *key2 = vkey2;
    BIGNUM *x1 = NULL, *y1 = NULL, *d1 = NULL;
    BIGNUM *x2 = NULL, *y2 = NULL, *d2 = NULL;
    int ok = 1, rc1, rc2, checked = 0;

    if (key1 == NULL || key2 == NULL)
        return 0;

    ibmca_debug_key(key1, "key1: %p key2: %p selection: 0x%x", key1, key2,
                    selection);

    if (ibmca_keymgmt_match(key1, key2) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = (key1->ec.curve_nid == key2->ec.curve_nid &&
              key1->ec.prime_size == key2->ec.prime_size);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        rc1 = ibmca_keymgmt_ec_pub_key_as_bn(key1, &x1, &y1);
        if (rc1 == 0) {
            ok = 0;
            goto out;
        }

        rc2 = ibmca_keymgmt_ec_pub_key_as_bn(key2, &x2, &y2);
        if (rc2 == 0) {
             ok = 0;
             goto out;
        }

        ok = ok && (rc1 == rc2 && (rc1 == -1 ||
                    (BN_cmp(x1, x2) == 0 && BN_cmp(y1, y2) == 0)));
        checked = 1;
    }

    if (!checked && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        rc1 = ibmca_keymgmt_ec_priv_key_as_bn(key1, &d1);
        if (rc1 == 0) {
            ok = 0;
            goto out;
        }

        rc2 = ibmca_keymgmt_ec_priv_key_as_bn(key2, &d2);
        if (rc2 == 0) {
             ok = 0;
             goto out;
        }

        ok = ok && (rc1 == rc2 && (rc1 == -1 ||
                    (BN_cmp(d1, d2) == 0)));
    }

out:
    if (x1 != NULL)
        BN_free(x1);
    if (x2 != NULL)
        BN_free(x2);
    if (y1 != NULL)
        BN_free(y1);
    if (y2 != NULL)
        BN_free(y2);
    if (d1 != NULL)
        BN_free(d1);
    if (d2 != NULL)
        BN_free(d2);

    ibmca_debug_key(key1, "ok: %d", ok);

    return ok;
}

static int ibmca_keymgmt_ec_validate(const void *vkey, int selection,
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

    if ((key->ec.fallback.x != NULL && key->ec.fallback.y != NULL) ||
        key->ec.fallback.d != NULL) {
        /* Check fallback key using OpenSSL */
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
        }
        goto out;
    }

    /*
     * If the selected key parts are present, they are valid:
     * Either the EC key has been generated by libica, then the EC is valid per
     * definition, or the EC key has been imported, then the validity has
     * already been checked during ica_ec_key_init().
     */
    if (ibmca_keymgmt_ec_has(key, selection) == 0)
        goto out;

    rc = 1;

out:
    ibmca_debug_key(key, "valid: %d", rc);

    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return rc;
}


static const char *ibmca_keymgmt_ec_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    }

    return NULL;
}

static void ibmca_keymgmt_ec_gen_free_cb(struct ibmca_op_ctx *ctx)
{
    if (ctx == NULL)
        return;

    ibmca_debug_op_ctx(ctx, "ctx: %p", ctx);

    ctx->ec.gen.curve_nid = NID_undef;
    ctx->ec.gen.format = POINT_CONVERSION_UNCOMPRESSED;
}

static int ibmca_keymgmt_ec_gen_dup_cb(const struct ibmca_op_ctx *ctx,
                                       struct ibmca_op_ctx *new_ctx)
{
    if (ctx == NULL)
        return 0;

    ibmca_debug_op_ctx(ctx, "ctx: %p new_ctx: %p", ctx, new_ctx);

    new_ctx->ec.gen.curve_nid = ctx->ec.gen.curve_nid;
    new_ctx->ec.gen.format = ctx->ec.gen.format;

    return 1;
}

static void *ibmca_keymgmt_ec_gen_init(void *vprovctx, int selection,
                                       const OSSL_PARAM params[])
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    struct ibmca_op_ctx *ctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p selection: 0x%x", provctx, selection);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR |
                      OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "selection is not KEYPAIR and/or parameters");
        return NULL;
    }

    ctx = ibmca_keymgmt_gen_init(provctx, EVP_PKEY_EC,
                                 ibmca_keymgmt_ec_gen_free_cb,
                                 ibmca_keymgmt_ec_gen_dup_cb);
    if (ctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_keymgmt_gen_init failed");
        return NULL;
    }

    /* set defaults */
    ctx->ec.gen.selection = selection;
    ctx->ec.gen.curve_nid = NID_undef;
    ctx->ec.gen.format = POINT_CONVERSION_UNCOMPRESSED;

    if (params != NULL) {
        if (ibmca_keymgmt_ec_gen_set_params(ctx, params) == 0) {
            ibmca_debug_ctx(provctx,
                            "ERROR: ibmca_keymgmt_ec_gen_set_params failed");
            ibmca_op_freectx(ctx);
            return NULL;
        }
    }

    return ctx;
}

static int ibmca_keymgmt_ec_gen_set_template(void *vgenctx, void *vtempl)
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

    ibmca_keymgmt_ec_gen_free_cb(genctx);

    genctx->ec.gen.curve_nid = templ->ec.curve_nid;
    genctx->ec.gen.format = templ->ec.format;

    ibmca_debug_op_ctx(genctx, "curve_nid: %d", genctx->ec.gen.curve_nid);
    ibmca_debug_op_ctx(genctx, "format: %d", genctx->ec.gen.format);

    return 1;
}

static int ibmca_keymgmt_ec_gen_set_params(void *vgenctx,
                                           const OSSL_PARAM params[])
{
    struct ibmca_op_ctx *genctx = vgenctx;
    OSSL_PARAM grp_params[] = { OSSL_PARAM_END, OSSL_PARAM_END };
    const OSSL_PARAM *p;
    const char *name;
    EC_GROUP *group;
    int rc, value;

    if (genctx == NULL)
        return 0;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_op_ctx(genctx, "param: %s", p->key);

    /* OSSL_PKEY_PARAM_GROUP_NAME */
    rc = ibmca_param_get_utf8(genctx->provctx, params,
                              OSSL_PKEY_PARAM_GROUP_NAME, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        grp_params[0] = OSSL_PARAM_construct_utf8_ptr(
                                    OSSL_PKEY_PARAM_GROUP_NAME,
                                    (char **)&name, 0);
        group = EC_GROUP_new_from_params(grp_params, genctx->provctx->libctx,
                                         NULL);
        if (group == NULL) {
            put_error_op_ctx(genctx, IBMCA_ERR_EC_CURVE_NOT_SUPPORTED,
                             "EC '%s': '%s' is an unsupported curve",
                             OSSL_PKEY_PARAM_GROUP_NAME, name);
            return 0;
        }

        genctx->ec.gen.curve_nid = EC_GROUP_get_curve_name(group);
        EC_GROUP_free(group);
    }

    /* OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT */
    rc = ibmca_param_get_utf8(genctx->provctx, params,
                              OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                              &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (strcasecmp(name,
                OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED) != 0) {
            genctx->ec.gen.format = POINT_CONVERSION_UNCOMPRESSED;
        } else if (strcasecmp(name,
                OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED) != 0) {
            genctx->ec.gen.format = POINT_CONVERSION_COMPRESSED;
        } else if (strcasecmp(name,
                OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID) != 0) {
            genctx->ec.gen.format = POINT_CONVERSION_HYBRID;
        } else {
            put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                             "EC '%s': '%s' is an unsupported format",
                             OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, name);
            return 0;
        }
    }

    /* OSSL_PKEY_PARAM_EC_ENCODING */
    rc = ibmca_param_get_utf8(genctx->provctx, params,
                              OSSL_PKEY_PARAM_EC_ENCODING, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        /* We only support named curves */
        if (strcasecmp(name, OSSL_PKEY_EC_ENCODING_GROUP) != 0) {
            put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                             "EC '%s': '%s' is an unsupported encoding",
                             OSSL_PKEY_PARAM_EC_ENCODING, name);
            return 0;
        }
    }

    /*  OSSL_PKEY_PARAM_USE_COFACTOR_ECDH */
    rc = ibmca_param_get_int(genctx->provctx, params,
                             OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, &value);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        /* We do not support Cofactor DH (ECC CDH) */
        if (value != 0) {
            put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                             "EC '%s': %d is not supported",
                             OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, value);
            return 0;
        }
    }

#ifdef OSSL_PKEY_PARAM_DHKEM_IKM
    if (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DHKEM_IKM) != NULL) {
        put_error_op_ctx(genctx, IBMCA_ERR_INVALID_PARAM,
                         "EC parameter '%s' is not supported",
                         OSSL_PKEY_PARAM_DHKEM_IKM);
        return 0;
    }
#endif

    return 1;
}

static const OSSL_PARAM ibmca_ec_op_ctx_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_ec_gen_settable_params(void *vgenctx,
                                                              void *vprovctx)
{
    const struct ibmca_op_ctx *genctx = vgenctx;
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    UNUSED(genctx);

    if (provctx == NULL)
        return NULL;

    for (p = ibmca_ec_op_ctx_settable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_ec_op_ctx_settable_params;
}

static int ibmca_keymgmt_ec_gen_fallback(struct ibmca_op_ctx *genctx,
                                         struct ibmca_key *key,
                                         OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct ibmca_keygen_cb_data cbdata;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int rc = 0;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);

    pctx = ibmca_new_fallback_pkey_ctx(genctx->provctx, NULL, "EC");
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

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                               genctx->ec.gen.curve_nid) != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                     "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
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
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return rc;
}

static void *ibmca_keymgmt_ec_gen(void *vgenctx, OSSL_CALLBACK *osslcb,
                                  void *cbarg)
{
    struct ibmca_op_ctx *genctx = vgenctx;
    OSSL_PARAM cb_params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };
    struct ibmca_key *key = NULL;
    unsigned int privlen;
    int rc, p, n;
    bool fallback = false;

    if (genctx == NULL)
        return NULL;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);

    cb_params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    cb_params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);

    key = ibmca_keymgmt_new(genctx->provctx, genctx->type, "EC",
                            ibmca_keymgmt_ec_free_cb,
                            ibmca_keymgmt_ec_dup_cb,
                            ibmca_keymgmt_ec_get_max_param_size,
                            ibmca_keymgmt_ec_export,
                            ibmca_keymgmt_ec_import,
                            ibmca_keymgmt_ec_has,
                            ibmca_keymgmt_ec_match);
    if (key == NULL) {
        ibmca_debug_op_ctx(genctx, "ERROR: ibmca_keymgmt_new failed");
        return NULL;
    }

    key->ec.curve_nid = genctx->ec.gen.curve_nid;
    key->ec.format = genctx->ec.gen.format;
    key->ec.include_pub = true;

    ibmca_debug_op_ctx(genctx, "curve_nid: %d", key->ec.curve_nid);
    ibmca_debug_op_ctx(genctx, "format: %d", key->ec.format);
    ibmca_debug_op_ctx(genctx, "include_pub: %d", key->ec.include_pub);

    key->ec.prime_size = ibmca_keymgmt_ec_get_prime_size(key);
    if (key->ec.prime_size == 0) {
        put_error_op_ctx(genctx, IBMCA_ERR_EC_CURVE_NOT_SUPPORTED,
                         "Unsupported curve nid: %d", key->ec.curve_nid);
        ibmca_keymgmt_free(key);
        return NULL;
    }

    ibmca_debug_op_ctx(genctx, "prime_size: %lu", key->ec.prime_size);

    if ((genctx->ec.gen.selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        goto out;

    key->ec.key = ica_ec_key_new(key->ec.curve_nid, &privlen);
    if (key->ec.key == NULL || key->ec.prime_size != privlen) {
        ibmca_debug_op_ctx(genctx, "ica_ec_key_new failed");
        fallback = true;
    }

    p = 0;
    n = 0;
    if (osslcb != NULL && osslcb(cb_params, cbarg) == 0) {
        put_error_op_ctx(genctx, IBMCA_ERR_INTERNAL_ERROR, "osslcb failed");
        ibmca_keymgmt_free(key);
        return NULL;
    }

    if (!fallback)
        rc = ica_ec_key_generate(genctx->provctx->ica_adapter, key->ec.key);
    else
        rc = ENODEV;
    if (rc != 0 || fallback) {
        if (!fallback)
            ibmca_debug_op_ctx(genctx, "ica_ec_key_generate failed with: %s",
                               strerror(rc));

        if (key->ec.key != NULL)
            ica_ec_key_free(key->ec.key);
        key->ec.key = NULL;

        rc = ibmca_keymgmt_ec_gen_fallback(genctx, key, osslcb, cbarg);
        if (rc != 1) {
            ibmca_debug_op_ctx(genctx,
                               "ERROR: ibmca_keymgmt_ec_gen_fallback failed");
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

out:
    ibmca_debug_op_ctx(genctx, "key: %p", key);

    return key;
}

static int ibmca_keymgmt_ec_pub_key_from_data(const struct ibmca_key *key,
                                              const OSSL_PARAM params[],
                                              BIGNUM **x, BIGNUM **y,
                                              point_conversion_form_t *format)
{
    int rc = 0;
    unsigned char *enc = NULL;
    size_t enc_len = 0;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;

    *format = POINT_CONVERSION_UNCOMPRESSED;

    /* OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY */
    rc = ibmca_param_get_octet_string(key->provctx, params,
                                      OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                      (void **)&enc, &enc_len);
    if (rc == 0)
        return 0;
    if (rc < 0) {
        /* OSSL_PKEY_PARAM_PUB_KEY */
        rc = ibmca_param_get_octet_string(key->provctx, params,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          (void **)&enc, &enc_len);
        if (rc == 0)
            return 0;
    }
    if (rc > 0) {
        group = EC_GROUP_new_by_curve_name(key->ec.curve_nid);
        if (group == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_GROUP_new_by_curve_name failed");
            goto out;
        }

        point = EC_POINT_new(group);
        if (point == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_POINT_new failed");
            goto out;
        }

        if (EC_POINT_oct2point(group, point, enc, enc_len, NULL) == 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_POINT_oct2point failed");
            goto out;
        }

        *x = BN_new();
        *y = BN_new();
        if (*x == NULL || *y == NULL) {
            put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "BN_new failed");
            goto out;
        }

        if (EC_POINT_get_affine_coordinates(group, point, *x, *y, NULL) == 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_POINT_get_affine_coordinates failed");
            goto out;
        }

        *format = (point_conversion_form_t)(enc[0] & ~0x01);

        rc = 1;

out:
        if (group != NULL)
            EC_GROUP_free(group);
        if (point != NULL)
            EC_POINT_free(point);
        if (enc != NULL)
            P_FREE(key->provctx, enc);

        return rc; /* do not check for X and Y params anymore */
    }

    /* OSSL_PKEY_PARAM_EC_PUB_X */
    rc = ibmca_param_get_bn(key->provctx, params, OSSL_PKEY_PARAM_EC_PUB_X, x);
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_EC_PUB_Y */
    rc = ibmca_param_get_bn(key->provctx, params, OSSL_PKEY_PARAM_EC_PUB_Y, y);
    if (rc == 0)
        return 0;

   return 1;
}

static int ibmca_keymgmt_ec_priv_key_from_data(const struct ibmca_key *key,
                                               const OSSL_PARAM params[],
                                               BIGNUM **d)
{
    int rc = 0;

    /* OSSL_PKEY_PARAM_PRIV_KEY */
    *d = BN_secure_new();
    if (*d == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "BN_secure_new failed");
        return 0;
    }

    rc = ibmca_param_get_bn(key->provctx, params, OSSL_PKEY_PARAM_PRIV_KEY, d);
    if (rc == 0) {
        BN_clear_free(*d);
        *d = NULL;
        return 0;
    }

   return 1;
}

static const OSSL_PARAM ibmca_ec_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_ec_gettable_params(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    for (p = ibmca_ec_gettable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_ec_gettable_params;
}

static size_t ibmca_keymgmt_ec_get_max_param_size(const struct ibmca_key *key)
{
    int rc = 0;
    ECDSA_SIG *sig = NULL;
    EC_GROUP *group = NULL;
    const BIGNUM *bn;
    BIGNUM *r = NULL, *s = NULL;

    group = EC_GROUP_new_by_curve_name(key->ec.curve_nid);
    if (group == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EC_GROUP_new_by_curve_name failed");
        goto out;
    }

    bn = EC_GROUP_get0_order(group);
    if (bn == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EC_GROUP_get0_order failed");
        goto out;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED, "ECDSA_SIG_new failed");
        goto out;
    }

    r = BN_dup(bn);
    s = BN_dup(bn);
    if (ECDSA_SIG_set0(sig, r, s) == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "ECDSA_SIG_set0 failed");
        goto out;
    }

    rc = i2d_ECDSA_SIG(sig, NULL);
    if (rc <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "i2d_ECDSA_SIG failed");
        rc = 0;
        goto out;
    }

out:
    if (group != NULL)
        EC_GROUP_free(group);
    if (sig != NULL)
        ECDSA_SIG_free(sig);

    return rc;
}

static size_t ibmca_keymgmt_ec_get_prime_bits(const struct ibmca_key *key)
{
    int rc = 0;
    EC_GROUP *group = NULL;

    group = EC_GROUP_new_by_curve_name(key->ec.curve_nid);
    if (group == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EC_GROUP_new_by_curve_name failed");
        goto out;
    }

    rc = EC_GROUP_order_bits(group);
    if (rc <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EC_GROUP_order_bits failed");
        rc = 0;
        goto out;
    }

out:
    if (group != NULL)
        EC_GROUP_free(group);

    return rc;
}

static size_t ibmca_keymgmt_ec_get_prime_size(const struct ibmca_key *key)
{
    return (ibmca_keymgmt_ec_get_prime_bits(key) + 7) / 8;
}

static int ibmca_keymgmt_ec_get_security_bits(const struct ibmca_key *key)
{
    int bits;

    bits = ibmca_keymgmt_ec_get_prime_bits(key);
    if (bits == 0)
        return 0;

    /*
     * The following estimates are based on the values published
     * in Table 2 of "NIST Special Publication 800-57 Part 1 Revision 4"
     * at http://dx.doi.org/10.6028/NIST.SP.800-57pt1r4 .
     */
    if (bits >= 512)
        bits = 256;
    else if (bits >= 384)
        bits = 192;
    else if (bits >= 256)
        bits = 128;
    else if (bits >= 224)
        bits = 112;
    else if (bits >= 160)
        bits = 80;
    else
        bits = bits / 2;

    return bits;
}

static int ibmca_keymgmt_ec_get_params(void *vkey, OSSL_PARAM params[])
{
    struct ibmca_key *key = vkey;
    OSSL_PARAM *parm;
    const char *name;
    BIGNUM *x = NULL, *y = NULL, *d = NULL;
    int rc, size;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p", key);
    for (parm = params; parm != NULL && parm->key != NULL; parm++)
        ibmca_debug_key(key, "param: %s", parm->key);

    /* OSSL_PKEY_PARAM_BITS */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS) != NULL) {
        size = ibmca_keymgmt_ec_get_prime_bits(key);
        if (size == 0)
            return 0;

        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_BITS, size);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_SECURITY_BITS */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS) != NULL) {
        size = ibmca_keymgmt_ec_get_security_bits(key);
        if (size == 0)
            return 0;

        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_SECURITY_BITS, size);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_MAX_SIZE */
    if (OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE) != NULL) {
        size = ibmca_keymgmt_ec_get_max_param_size(key);
        if (size == 0)
            return 0;

        rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                       OSSL_PKEY_PARAM_MAX_SIZE, size);
        if (rc == 0)
            return 0;
    }

    /* OSSL_PKEY_PARAM_DEFAULT_DIGEST */
    rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                    OSSL_PKEY_PARAM_DEFAULT_DIGEST,
                                    OBJ_nid2sn(IBMCA_EC_DEFAULT_DIGEST));
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS */
    rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                    OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, 0);
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_USE_COFACTOR_ECDH */
    rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                   OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, 0);
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_EC_ENCODING */
    rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                    OSSL_PKEY_PARAM_EC_ENCODING,
                                    OSSL_PKEY_EC_ENCODING_GROUP);
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT */
    switch (key->ec.format) {
    case POINT_CONVERSION_COMPRESSED:
        name = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED;
        break;
    case POINT_CONVERSION_UNCOMPRESSED:
        name = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED;
        break;
    case POINT_CONVERSION_HYBRID:
        name = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID;
        break;
    default:
        name = "";
        break;
    }
    rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                    OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                    name);
    if (rc == 0)
        return 0;

    /* OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC */
    rc = ibmca_param_build_set_int(key->provctx, NULL, params,
                                   OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                                   key->ec.include_pub ? 1 : 0);
    if (rc == 0)
        return 0;

    rc = ibmca_param_build_set_utf8(key->provctx, NULL, params,
                                    OSSL_PKEY_PARAM_GROUP_NAME,
                                    OBJ_nid2sn(key->ec.curve_nid));
    if (rc == 0)
        return 0;

    /*
     * OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY
     * OSSL_PKEY_PARAM_PUB_KEY
     * OSSL_PKEY_PARAM_EC_PUB_X
     * OSSL_PKEY_PARAM_EC_PUB_Y
     */
    rc = ibmca_keymgmt_ec_pub_key_as_bn(key, &x, &y);
    if (rc == 0)
        goto out;
    if (rc > 0) {
        rc = ibmca_keymgmt_ec_pub_key_to_data(key, x, y, NULL, params);
        if (rc == 0)
            goto out;
    }

    /* OSSL_PKEY_PARAM_PRIV_KEY */
    rc = ibmca_keymgmt_ec_priv_key_as_bn(key, &d);
    if (rc == 0)
        goto out;
    if (rc > 0) {
        rc = ibmca_keymgmt_ec_priv_key_to_data(key, d, NULL, params);
        if (rc == 0)
            goto out;
    }

    rc = 1;
out:
    if (x != NULL)
        BN_free(x);
    if (y != NULL)
        BN_free(y);
    if (d != NULL)
        BN_free(d);

    return rc;
}

static const OSSL_PARAM ibmca_ec_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_ec_settable_params(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    const OSSL_PARAM *p;

    if (provctx == NULL)
        return NULL;

    for (p = ibmca_ec_settable_params; p != NULL && p->key != NULL; p++)
        ibmca_debug_ctx(provctx, "param: %s", p->key);

    return ibmca_ec_settable_params;
}

static int ibmca_keymgmt_ec_set_params(void *vkey, const OSSL_PARAM params[])
{
    struct ibmca_key *key = vkey;
    const OSSL_PARAM *parm;
    BIGNUM *x = NULL, *y = NULL;
    point_conversion_form_t format;
    const char *name;
    int rc, value;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p", key);
    for (parm = params; parm != NULL && parm->key != NULL; parm++)
        ibmca_debug_key(key, "param: %s", parm->key);

    /* OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT */
    rc = ibmca_param_get_utf8(key->provctx, params,
                              OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                              &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        if (strcasecmp(name,
                OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED) != 0) {
            key->ec.format = POINT_CONVERSION_UNCOMPRESSED;
        } else if (strcasecmp(name,
                OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED) != 0) {
            key->ec.format = POINT_CONVERSION_COMPRESSED;
        } else if (strcasecmp(name,
                OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID) != 0) {
            key->ec.format = POINT_CONVERSION_HYBRID;
        } else {
            put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                          "EC '%s': '%s' is an unsupported format",
                          OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, name);
            rc = 0;
            goto out;
        }

        ibmca_clean_fallback_pkey_cache(key);
    }

    /* OSSL_PKEY_PARAM_EC_ENCODING */
    rc = ibmca_param_get_utf8(key->provctx, params,
                              OSSL_PKEY_PARAM_EC_ENCODING, &name);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        /* We only support named curves */
        if (strcasecmp(name, OSSL_PKEY_EC_ENCODING_GROUP) != 0) {
            put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                          "EC '%s': '%s' is an unsupported encoding",
                          OSSL_PKEY_PARAM_EC_ENCODING, name);
            rc = 0;
            goto out;
        }

        ibmca_clean_fallback_pkey_cache(key);
    }

    /*  OSSL_PKEY_PARAM_USE_COFACTOR_ECDH */
    rc = ibmca_param_get_int(key->provctx, params,
                             OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, &value);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        /* We do not support Cofactor DH (ECC CDH) */
        if (value != 0) {
            put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                          "EC '%s': %d is not supported",
                          OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, value);
            rc = 0;
            goto out;
        }

        ibmca_clean_fallback_pkey_cache(key);
    }

    /* OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY */
    rc = ibmca_keymgmt_ec_pub_key_from_data(key, params, &x, &y, &format);
    if (rc == 0)
        goto out;
    if (rc > 0 && x != NULL && y != NULL) {
        rc = ibmca_keymgmt_ec_pub_key_from_bn(key, x, y);
        if (rc == 0)
            goto out;

        key->ec.format = format;
        ibmca_clean_fallback_pkey_cache(key);
    }

    /* OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC */
    rc = ibmca_param_get_int(key->provctx, params,
                             OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, &value);
    if (rc == 0)
        return 0;
    if (rc > 0) {
        key->ec.include_pub = (value != 0);
        ibmca_clean_fallback_pkey_cache(key);
    }

    rc = 1;

out:
    BN_free(x);
    BN_free(y);

    return rc;
}

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_priv_key[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_pub_key[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_key_pair[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_dom_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_priv_key_dom_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_pub_key_dom_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_key_pair_dom_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_other_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_priv_key_other_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_pub_key_other_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_key_pair_other_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_all_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_priv_key_all_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_pub_key_all_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM ibmca_keymgmt_ec_imexport_key_pair_all_params[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_keymgmt_ec_imexport_types(int selection)
{
    selection &= OSSL_KEYMGMT_SELECT_ALL;

    switch (selection) {
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY:
        return ibmca_keymgmt_ec_imexport_priv_key;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return ibmca_keymgmt_ec_imexport_pub_key;
    case OSSL_KEYMGMT_SELECT_KEYPAIR:
        return ibmca_keymgmt_ec_imexport_key_pair;
    case OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_dom_params;
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_priv_key_dom_params;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_pub_key_dom_params;
    case OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_key_pair_dom_params;
    case OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_other_params;
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_priv_key_other_params;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_pub_key_other_params;
    case OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_key_pair_other_params;
    case OSSL_KEYMGMT_SELECT_ALL_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_all_params;
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_priv_key_all_params;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_pub_key_all_params;
    case OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS:
        return ibmca_keymgmt_ec_imexport_key_pair_all_params;
    }

    return NULL;
}

static int ibmca_keymgmt_ec_export(void *vkey, int selection,
                                   OSSL_CALLBACK *param_callback, void *cbarg)
{
    struct ibmca_key *key = vkey;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *enc = NULL;
    size_t enc_len = 0;
    BIGNUM *x = NULL, *y = NULL, *d = NULL;
    char *name;
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

    /* Public key is required when exporting private key */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    /* Domain parameters are required when exporting public or private key */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* Public key parts */
        rc = ibmca_keymgmt_ec_pub_key_as_bn(key, &x, &y);
        if (rc == 0)
            goto error;

        group = EC_GROUP_new_by_curve_name(key->ec.curve_nid);
        if (group == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_GROUP_new_by_curve_name failed");
            rc = 0;
            goto error;
        }

        point = EC_POINT_new(group);
        if (point == NULL) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_POINT_new failed");
            rc = 0;
            goto error;
        }

        if (EC_POINT_set_affine_coordinates(group, point, x, y, NULL) == 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_POINT_set_affine_coordinates failed");
            rc = 0;
            goto error;
        }

        /* OSSL_PKEY_PARAM_PUB_KEY */
        enc_len = EC_POINT_point2buf(group, point, POINT_CONVERSION_COMPRESSED,
                                     &enc, NULL);
        if (enc_len == 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EC_POINT_point2buf failed");
            rc = 0;
            goto error;
        }

        rc = ibmca_param_build_set_octet_ptr(key->provctx, bld, params,
                                             OSSL_PKEY_PARAM_PUB_KEY,
                                             enc, enc_len);
        if (rc == 0)
            goto error;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* Private key parts */
        rc = ibmca_keymgmt_ec_priv_key_as_bn(key, &d);
        if (rc == 0)
            goto error;
        if (rc > 0) {
            rc = ibmca_keymgmt_ec_priv_key_to_data(key, d, bld, NULL);
            if (rc == 0)
                goto error;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /* OSSL_PKEY_PARAM_GROUP_NAME */
        rc = ibmca_param_build_set_utf8(key->provctx, bld, NULL,
                                        OSSL_PKEY_PARAM_GROUP_NAME,
                                        OBJ_nid2sn(key->ec.curve_nid));
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_EC_ENCODING */
        rc = ibmca_param_build_set_utf8(key->provctx, bld, NULL,
                                        OSSL_PKEY_PARAM_EC_ENCODING,
                                        OSSL_PKEY_EC_ENCODING_GROUP);
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT */
        switch (key->ec.format) {
        case POINT_CONVERSION_COMPRESSED:
            name = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED;
            break;
        case POINT_CONVERSION_UNCOMPRESSED:
            name = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED;
            break;
        case POINT_CONVERSION_HYBRID:
            name = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID;
            break;
        default:
            name = "";
            break;
        }
        rc = ibmca_param_build_set_utf8(key->provctx, bld, NULL,
                                    OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                    name);
        if (rc == 0)
            goto error;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) {
        /* OSSL_PKEY_PARAM_USE_COFACTOR_ECDH */
        rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                       OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, 0);
        if (rc == 0)
            goto error;

        /* OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC */
        rc = ibmca_param_build_set_int(key->provctx, bld, NULL,
                                       OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                                       key->ec.include_pub ? 1 : 0);
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
    if (x != NULL)
        BN_free(x);
    if (y != NULL)
        BN_free(y);
    if (d != NULL)
        BN_free(d);
    if (group != NULL)
        EC_GROUP_free(group);
    if (point != NULL)
        EC_POINT_free(point);
    if (enc != NULL)
        P_FREE(key->provctx, enc);

    return rc;
}

static int ibmca_keymgmt_ec_import(void *vkey, int selection,
                                   const OSSL_PARAM params[])
{
    struct ibmca_key *key = vkey;
    const OSSL_PARAM *parm;
    point_conversion_form_t format;
    BIGNUM *x = NULL, *y = NULL, *d = NULL;
    OSSL_PARAM grp_params[] = { OSSL_PARAM_END, OSSL_PARAM_END };
    EC_GROUP *group;
    const char *name;
    int value, rc = 0;

    if (key == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p selection: 0x%x", key, selection);
    for (parm = params; parm != NULL && parm->key != NULL; parm++)
        ibmca_debug_key(key, "param: %s", parm->key);

    /* Clear any already existing key components */
    ibmca_keymgmt_ec_free_cb(key);
    ibmca_clean_fallback_pkey_cache(key);

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0) {
        put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                       "EC domain parameters are mandatory");
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /* OSSL_PKEY_PARAM_GROUP_NAME */
        rc = ibmca_param_get_utf8(key->provctx, params,
                                  OSSL_PKEY_PARAM_GROUP_NAME, &name);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            grp_params[0] = OSSL_PARAM_construct_utf8_ptr(
                                        OSSL_PKEY_PARAM_GROUP_NAME,
                                        (char **)&name, 0);
            group = EC_GROUP_new_from_params(grp_params, key->provctx->libctx,
                                             NULL);
            if (group == NULL) {
                put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                              "EC '%s': '%s' is an unsupported curve",
                              OSSL_PKEY_PARAM_GROUP_NAME, name);
                return 0;
            }

            key->ec.curve_nid = EC_GROUP_get_curve_name(group);
            EC_GROUP_free(group);

            ibmca_debug_key(key, "curve_nid: %d", key->ec.curve_nid);
        }

        /* OSSL_PKEY_PARAM_EC_ENCODING */
        rc = ibmca_param_get_utf8(key->provctx, params,
                                  OSSL_PKEY_PARAM_EC_ENCODING, &name);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            /* We only support named curves */
            if (strcasecmp(name, OSSL_PKEY_EC_ENCODING_GROUP) != 0) {
                put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                              "EC '%s': '%s' is an unsupported encoding",
                              OSSL_PKEY_PARAM_EC_ENCODING, name);
                return 0;
            }
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) {
        /* OSSL_PKEY_PARAM_USE_COFACTOR_ECDH */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, &value);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            /* We do not support Cofactor DH (ECC CDH) */
            if (value != 0) {
                put_error_key(key, IBMCA_ERR_INVALID_PARAM,
                              "EC '%s': %d is not supported",
                              OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, value);
                return 0;
            }
        }

        /* OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC */
        rc = ibmca_param_get_int(key->provctx, params,
                                 OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, &value);
        if (rc == 0)
            return 0;
        if (rc > 0) {
            key->ec.include_pub = (value != 0);
            ibmca_debug_key(key, "include_pub: %d", key->ec.include_pub);
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* Public key parts */

        /* OSSL_PKEY_PARAM_PUB_KEY */
        rc = ibmca_keymgmt_ec_pub_key_from_data(key, params, &x, &y, &format);
        if (rc == 0)
            goto out;
        if (rc > 0 && x != NULL && y != NULL) {
            rc = ibmca_keymgmt_ec_pub_key_from_bn(key, x, y);
            if (rc == 0)
                goto out;

            key->ec.format = format;
            ibmca_debug_key(key, "format: %d", key->ec.format);
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* OSSL_PKEY_PARAM_PRIV_KEY */
        rc = ibmca_keymgmt_ec_priv_key_from_data(key, params, &d);
        if (rc == 0)
            goto out;
        if (rc > 0 && d != NULL) {
            rc = ibmca_keymgmt_ec_priv_key_from_bn(key, d);
            if (rc == 0)
                goto out;

            key->ec.format = format;
            ibmca_debug_key(key, "format: %d", key->ec.format);
        }
    }

    rc = 1;

out:
    if (x != NULL)
        BN_free(x);
    if (y != NULL)
        BN_free(y);
    if (d != NULL)
        BN_free(d);

    return rc;
}

static const OSSL_DISPATCH ibmca_ec_keymgmt_functions[] = {
    /* Constructor, destructor */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ibmca_keymgmt_ec_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ibmca_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ibmca_keymgmt_dup },

    /* Key generation and loading */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,
            (void (*)(void))ibmca_keymgmt_ec_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
            (void (*)(void))ibmca_keymgmt_ec_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
            (void (*)(void))ibmca_keymgmt_ec_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))ibmca_keymgmt_ec_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ibmca_keymgmt_ec_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
            (void (*)(void))ibmca_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ibmca_keymgmt_load },

    /* Key object checking */
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ibmca_keymgmt_ec_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ibmca_keymgmt_ec_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,
            (void (*)(void))ibmca_keymgmt_ec_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (void (*)(void))ibmca_keymgmt_ec_query_operation_name },

    /* Key object information */
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
            (void (*) (void))ibmca_keymgmt_ec_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
            (void (*) (void))ibmca_keymgmt_ec_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
            (void (*) (void))ibmca_keymgmt_ec_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
            (void (*) (void))ibmca_keymgmt_ec_settable_params },

    /* Import and export routines */
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ibmca_keymgmt_ec_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_ec_imexport_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ibmca_keymgmt_ec_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
            (void (*)(void))ibmca_keymgmt_ec_imexport_types },

    { 0, NULL }
};

const OSSL_ALGORITHM ibmca_ec_keymgmt[] = {
    { "EC:id-ecPublicKey:1.2.840.10045.2.1", NULL,
      ibmca_ec_keymgmt_functions, "IBMCA EC implementation" },
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

#define IBMCA_TLS_GROUP_ID_secp192r1        19
#define IBMCA_TLS_GROUP_ID_secp224r1        21
#define IBMCA_TLS_GROUP_ID_secp256r1        23
#define IBMCA_TLS_GROUP_ID_secp384r1        24
#define IBMCA_TLS_GROUP_ID_secp521r1        25
#define IBMCA_TLS_GROUP_ID_brainpoolP256r1  28
#define IBMCA_TLS_GROUP_ID_brainpoolP384r1  27
#define IBMCA_TLS_GROUP_ID_brainpoolP512r1  28

static const struct ibmca_tls_group_constants ibmca_tls_group_consts[8] = {
    { IBMCA_TLS_GROUP_ID_secp192r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { IBMCA_TLS_GROUP_ID_secp224r1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { IBMCA_TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { IBMCA_TLS_GROUP_ID_secp384r1, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { IBMCA_TLS_GROUP_ID_secp521r1, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { IBMCA_TLS_GROUP_ID_brainpoolP256r1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { IBMCA_TLS_GROUP_ID_brainpoolP384r1, 192, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { IBMCA_TLS_GROUP_ID_brainpoolP512r1, 256, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
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

static const OSSL_PARAM ibmca_ec_secp192r1[] =
        IBMCA_TLS_GROUP_ENTRY("secp192r1", "prime192v1", "EC", 0);
static const OSSL_PARAM ibmca_ec_p192[] =
        IBMCA_TLS_GROUP_ENTRY("P-192", "prime192v1", "EC", 0);
static const OSSL_PARAM ibmca_ec_secp224r1[] =
        IBMCA_TLS_GROUP_ENTRY("secp224r1", "secp224r1", "EC", 1);
static const OSSL_PARAM ibmca_ec_p224[] =
        IBMCA_TLS_GROUP_ENTRY("P-224", "secp224r1", "EC", 1);
static const OSSL_PARAM ibmca_ec_secp256r1[] =
        IBMCA_TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 2);
static const OSSL_PARAM ibmca_ec_p256[] =
        IBMCA_TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 2);
static const OSSL_PARAM ibmca_ec_secp384r1[] =
        IBMCA_TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 3);
static const OSSL_PARAM ibmca_ec_p384[] =
        IBMCA_TLS_GROUP_ENTRY("P-384", "secp384r1", "EC", 3);
static const OSSL_PARAM ibmca_ec_secp521r1[] =
        IBMCA_TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 4);
static const OSSL_PARAM ibmca_ec_p521[] =
        IBMCA_TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 4);
static const OSSL_PARAM ibmca_ec_brainpoolP256r1[] =
        IBMCA_TLS_GROUP_ENTRY("brainpoolP256r1", "brainpoolP256r1", "EC", 5);
static const OSSL_PARAM ibmca_ec_brainpoolP384r1[] =
        IBMCA_TLS_GROUP_ENTRY("brainpoolP384r1", "brainpoolP384r1", "EC", 6);
static const OSSL_PARAM ibmca_ec_brainpoolP512r1[] =
        IBMCA_TLS_GROUP_ENTRY("brainpoolP512r1", "brainpoolP512r1", "EC", 7);

static const OSSL_PARAM *ibmca_ec_tls_group[] = {
    ibmca_ec_secp192r1,
    ibmca_ec_p192,
    ibmca_ec_secp224r1,
    ibmca_ec_p224,
    ibmca_ec_secp256r1,
    ibmca_ec_p256,
    ibmca_ec_secp384r1,
    ibmca_ec_p384,
    ibmca_ec_secp521r1,
    ibmca_ec_p521,
    ibmca_ec_brainpoolP256r1,
    ibmca_ec_brainpoolP384r1,
    ibmca_ec_brainpoolP512r1,
    NULL
};

const struct ibmca_mech_capability ibmca_ec_capabilities[] = {
    { "TLS-GROUP", ibmca_ec_tls_group },
    { NULL, NULL }
};
