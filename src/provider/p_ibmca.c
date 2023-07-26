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
#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <err.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>

#include "p_ibmca.h"

#ifndef IBMCA_LOGDIR
#error "IBMCA_LOGDIR must be defined"
#endif
#ifndef IBMCA_VERSION
#error "IBMCA_VERSION must be defined"
#endif

static OSSL_FUNC_provider_teardown_fn ibmca_teardown;
static OSSL_FUNC_provider_gettable_params_fn ibmca_gettable_params;
static OSSL_FUNC_provider_get_params_fn ibmca_get_params;
static OSSL_FUNC_provider_query_operation_fn ibmca_query;
static OSSL_FUNC_provider_get_reason_strings_fn ibmca_get_reason_strings;
static OSSL_FUNC_provider_get_capabilities_fn ibmca_prov_get_capabilities;
static OSSL_FUNC_provider_self_test_fn ibmca_prov_self_tests;

struct ibmca_config_item {
    const char *key;
    int (*func)(struct ibmca_prov_ctx *provctx, const char *key,
                const char *value);
};

static int ibmca_config_debug(struct ibmca_prov_ctx *provctx,
                              const char *key, const char *value);
static int ibmca_config_debug_path(struct ibmca_prov_ctx *provctx,
                                   const char *key, const char *value);
static int ibmca_config_fips(struct ibmca_prov_ctx *provctx,
                             const char *key, const char *value);
static int ibmca_config_algorithms(struct ibmca_prov_ctx *provctx,
                                   const char *key, const char *value);
static int ibmca_config_fallback_props(struct ibmca_prov_ctx *provctx,
                                       const char *key, const char *value);
static int ibmca_config_module_filename(struct ibmca_prov_ctx *provctx,
                                        const char *key, const char *value);
static int ibmca_config_openssl_version(struct ibmca_prov_ctx *provctx,
                                        const char *key, const char *value);

static const struct ibmca_config_item config_items[] = {
    { IBMCA_CONF_DEBUG_PATH, ibmca_config_debug_path },
    { IBMCA_CONF_DEBUG, ibmca_config_debug },
    { IBMCA_CONF_FIPS, ibmca_config_fips },
    { IBMCA_CONF_ALGORITHMS, ibmca_config_algorithms },
    { IBMCA_CONF_FALLBACK_PROPS, ibmca_config_fallback_props },
    { OSSL_PROV_PARAM_CORE_MODULE_FILENAME, ibmca_config_module_filename },
    { OSSL_PROV_PARAM_CORE_VERSION, ibmca_config_openssl_version },
};

#define NUM_CONFIG_ITEMS    \
    (sizeof(config_items) / sizeof(struct ibmca_config_item))

struct ibmca_mech_algorithm {
    int operation;
    const OSSL_ALGORITHM *algorithms;
};

struct ibmca_ica_mech_info {
    const char *algo;
    const unsigned int *ica_mechs;
    const struct ibmca_mech_algorithm *algos;
    const struct ibmca_mech_capability *capabilities;
};

static const unsigned int ica_rsa_mech[] = {
    RSA_ME,
    RSA_CRT,
    /* RSA_KEY_GEN_CRT is always supported, but only in SW */
    0
};

static const struct ibmca_mech_algorithm ibmca_rsa_algorithms[] = {
    { OSSL_OP_KEYMGMT, ibmca_rsa_keymgmt },
    { OSSL_OP_ASYM_CIPHER, ibmca_rsa_asym_cipher },
    { OSSL_OP_SIGNATURE, ibmca_rsa_signature },
    { 0, NULL }
};

static const unsigned int ica_ec_mech[] = {
    EC_DH,
    EC_DSA_SIGN,
    EC_DSA_VERIFY,
    EC_KGEN,
    0
};

static const  struct ibmca_mech_algorithm ibmca_ec_algorithms[] = {
    { OSSL_OP_KEYMGMT, ibmca_ec_keymgmt },
    { OSSL_OP_SIGNATURE, ibmca_ec_signature },
    { OSSL_OP_KEYEXCH, ibmca_ec_keyexch },
    { 0, NULL }
};

static const  struct ibmca_mech_algorithm ibmca_dh_algorithms[] = {
    { OSSL_OP_KEYMGMT, ibmca_dh_keymgmt },
    { OSSL_OP_KEYEXCH, ibmca_dh_keyexch },
    { 0, NULL }
};

static const unsigned int ica_dh_mech[] = {
    RSA_ME, /* DH uses RSA mod-expo for derive */
    0
};

static const struct ibmca_ica_mech_info ica_mech_infos[] = {
    { IBMCA_CONFIG_ALGO_RSA, ica_rsa_mech, ibmca_rsa_algorithms, NULL },
    { IBMCA_CONFIG_ALGO_EC, ica_ec_mech, ibmca_ec_algorithms,
                                                    ibmca_ec_capabilities },
    { IBMCA_CONFIG_ALGO_DH, ica_dh_mech, ibmca_dh_algorithms,
                                                    ibmca_dh_capabilities },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ITEM ibmca_reason_strings[] = {
    { IBMCA_ERR_INTERNAL_ERROR, "Internal error" },
    { IBMCA_ERR_MALLOC_FAILED,  "Memory allocation failed" },
    { IBMCA_ERR_INVALID_PARAM,  "Invalid parameter encountered" },
    { IBMCA_ERR_CONFIGURATION,  "Provider configuration error" },
    { IBMCA_ERR_LIBICA_FAILED,  "A libica function returned an error" },
    { IBMCA_ERR_SIGNATURE_BAD,  "Signature bad" },
    { IBMCA_ERR_EC_CURVE_NOT_SUPPORTED, "EC curve not supported" },
    { 0, NULL }
};

void ibmca_debug_print(struct ibmca_prov_ctx *provctx, const char *func,
                       const char *fmt, ...)
{
    char tmp_fmt[500];
    char time_buf[200] = "";
    va_list ap;
    time_t t;
    struct tm *tm;
    pid_t old_pid;

    t = time(NULL);
    tm = localtime(&t);
    if (strftime(time_buf, sizeof(time_buf), "%m/%d/%Y %H:%M:%S", tm) == 0)
        return;

    if (snprintf(tmp_fmt, sizeof(tmp_fmt), "DBG: %s %u %s: %s",
                 time_buf, (unsigned int)gettid(), func, fmt) >
                                                    (int)sizeof(tmp_fmt))
        return;

    (void)pthread_mutex_lock(&provctx->debug_mutex);
    /* no error checking here: if lock fails print trace msg anyway */

    if (provctx->debug_file != NULL && getpid() != provctx->debug_pid) {
        /* process was forked off from parent process: open new trace file */
        old_pid = provctx->debug_pid;
        fclose(provctx->debug_file);
        provctx->debug_file = NULL;

        /* avoid recursive call from ibmca_config_debug/ibmca_config_bool */
        provctx->debug = false;
        if (ibmca_config_debug(provctx, IBMCA_CONF_DEBUG, "on") == 0)
            goto out;

        fprintf(provctx->debug_file,
                "*** Forked off from parent process %u ***\n", old_pid);
    }

    va_start(ap, fmt);
    if (provctx->debug_file != NULL) {
        vfprintf(provctx->debug_file, tmp_fmt, ap);
        fputc('\n', provctx->debug_file);
        fflush(provctx->debug_file);
    } else {
        vwarnx(tmp_fmt, ap);
    }
    va_end(ap);

out:
    pthread_mutex_unlock(&provctx->debug_mutex);
}

void ibmca_put_error(const struct ibmca_prov_ctx *provctx, int err,
                     const char *file, int line, const char *func,
                     char *fmt, ...)
{
    va_list ap;

    if (provctx == NULL)
        return;

    va_start(ap, fmt);
    provctx->c_new_error(provctx->handle);
    provctx->c_set_error_debug(provctx->handle, file, line, func);
    provctx->c_vset_error(provctx->handle, err, fmt, ap);
    va_end(ap);
}

char *ibmca_strdup(const struct ibmca_prov_ctx *provctx, const char *str,
                   const char* file, int line)
{
    char *ret;

    if (str == NULL || provctx == NULL)
        return NULL;

    ret = provctx->c_malloc(strlen(str) + 1, file, line);
    if (ret != NULL)
        strcpy(ret, str);

    return ret;
}

void *ibmca_memdup(const struct ibmca_prov_ctx *provctx, const void *data,
                   size_t size, const char* file, int line)
{
    void *ret;

    if (data == NULL || size >= INT_MAX)
        return NULL;

    ret = provctx->c_malloc(size, file, line);
    if (ret != NULL)
        memcpy(ret, data, size);

    return ret;
}

void *ibmca_secure_memdup(const struct ibmca_prov_ctx *provctx,
                          const void *data, size_t size,
                          const char* file, int line)
{
    void *ret;

    if (data == NULL || size >= INT_MAX)
        return NULL;

    ret = provctx->c_secure_malloc(size, file, line);
    if (ret != NULL)
        memcpy(ret, data, size);

    return ret;
}

int ibmca_param_build_set_bn(const struct ibmca_prov_ctx *provctx,
                             OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                             const char *key, const BIGNUM *bn)
{
    char *str;

    if (bn == NULL)
        return 0;

    if (bld != NULL) {
        if (OSSL_PARAM_BLD_push_BN(bld, key, bn) == 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Failed to return param '%s'", key);
            return 0;
        }
        goto out;
    }

    p = OSSL_PARAM_locate(p, key);
    if (p == NULL)
        return 1;

    if (OSSL_PARAM_set_BN(p, bn) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to return param '%s'", key);
        return 0;
    }

out:
    if (provctx->debug) {
        if (BN_get_flags(bn, BN_FLG_SECURE)) {
            ibmca_debug_ctx(provctx,
                            "param '%s': [sensitive value omitted] (%d bits)",
                            key, BN_num_bits(bn));
        } else {
            str = BN_bn2hex(bn);
            ibmca_debug_ctx(provctx, "param '%s': 0x%s (%d bits)", key, str,
                            BN_num_bits(bn));
            P_FREE(provctx, str);
        }
    }

    return 1;
}

int ibmca_param_build_set_int(const struct ibmca_prov_ctx *provctx,
                              OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                              const char *key, int val)
{
    if (bld != NULL) {
        if (OSSL_PARAM_BLD_push_int(bld, key, val) == 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Failed to return param '%s'", key);
            return 0;
        }
        goto out;
    }

    p = OSSL_PARAM_locate(p, key);
    if (p == NULL)
        return 1;

    if (OSSL_PARAM_set_int(p, val) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to return param '%s'", key);
        return 0;
    }

out:
    ibmca_debug_ctx(provctx, "param '%s': %d", key, val);
    return 1;
}

int ibmca_param_build_set_uint(const struct ibmca_prov_ctx *provctx,
                               OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                               const char *key, unsigned int val)
{
    if (bld != NULL) {
        if (OSSL_PARAM_BLD_push_uint(bld, key, val) == 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Failed to return param '%s'", key);
            return 0;
        }
        goto out;
    }

    p = OSSL_PARAM_locate(p, key);
    if (p == NULL)
        return 1;

    if (OSSL_PARAM_set_uint(p, val) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to return param '%s'", key);
        return 0;
    }

out:
    ibmca_debug_ctx(provctx, "param '%s': %u", key, val);
    return 1;
}

int ibmca_param_build_set_utf8(const struct ibmca_prov_ctx *provctx,
                               OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                               const char *key, const char *str)
{
    if (str == NULL)
        return 0;

    if (bld != NULL) {
        if (OSSL_PARAM_BLD_push_utf8_string(bld, key, str, 0) == 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Failed to return param '%s'", key);
            return 0;
        }
        goto out;
    }

    p = OSSL_PARAM_locate(p, key);
    if (p == NULL)
        return 1;

    if (OSSL_PARAM_set_utf8_string(p, str) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to return param '%s'", key);
        return 0;
    }

out:
    ibmca_debug_ctx(provctx, "param '%s': '%s'", key, str);
    return 1;
}

int ibmca_param_build_set_octet_ptr(const struct ibmca_prov_ctx *provctx,
                                    OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                    const char *key, const void *val,
                                    size_t len)
{
    if (val == NULL)
        return 0;

    if (bld != NULL) {
        if (OSSL_PARAM_BLD_push_octet_string(bld, key, val, len) == 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Failed to return param '%s'", key);
            return 0;
        }
        goto out;
    }

    p = OSSL_PARAM_locate(p, key);
    if (p == NULL)
        return 1;

    if (OSSL_PARAM_set_octet_string(p, val, len) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to return param '%s'", key);
        return 0;
    }

out:
    ibmca_debug_ctx(provctx, "param '%s': [octet string] (%lu bytes)", key,
                    len);
    return 1;
}

int ibmca_param_build_set_size_t(const struct ibmca_prov_ctx *provctx,
                                 OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                 const char *key, size_t val)
{
    if (bld != NULL) {
        if (OSSL_PARAM_BLD_push_size_t(bld, key, val) == 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Failed to return param '%s'", key);
            return 0;
        }
        goto out;
    }

    p = OSSL_PARAM_locate(p, key);
    if (p == NULL)
        return 1;

    if (OSSL_PARAM_set_size_t(p, val) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to return param '%s'", key);
        return 0;
    }

out:
    ibmca_debug_ctx(provctx, "param '%s': %lu", key, val);
    return 1;
}

int ibmca_param_get_bn(const struct ibmca_prov_ctx *provctx,
                       const OSSL_PARAM params[], const char *key, BIGNUM **bn)
{
    const OSSL_PARAM *p;

    if (bn == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, key);
    if (p == NULL)
        return -1;

    if (OSSL_PARAM_get_BN(p, bn) == 0 || *bn == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Failed to get param '%s'", key);
        return 0;
    }

    if (provctx->debug) {
        if (BN_get_flags(*bn, BN_FLG_SECURE)) {
            ibmca_debug_ctx(provctx,
                            "param '%s': [sensitive value omitted] (%d bits)",
                            key, BN_num_bits(*bn));
        } else {
            char *str = BN_bn2hex(*bn);
            ibmca_debug_ctx(provctx, "param '%s': 0x%s (%d bits)", key,
                            str != NULL ? str : "", BN_num_bits(*bn));
            P_FREE(provctx, str);
        }
    }

    return 1;
}

int ibmca_param_get_int(const struct ibmca_prov_ctx *provctx,
                        const OSSL_PARAM params[], const char *key, int *val)
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, key);
    if (p == NULL)
        return -1;

    if (OSSL_PARAM_get_int(p, val) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Failed to get param '%s'", key);
        return 0;
    }

    ibmca_debug_ctx(provctx, "param '%s': %d", key, *val);
    return 1;
}

int ibmca_param_get_uint(const struct ibmca_prov_ctx *provctx,
                         const OSSL_PARAM params[], const char *key,
                         unsigned int *val)
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, key);
    if (p == NULL)
        return -1;

    if (OSSL_PARAM_get_uint(p, val) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Failed to get param '%s'", key);
        return 0;
    }

    ibmca_debug_ctx(provctx, "param '%s': %u", key, *val);
    return 1;
}

int ibmca_param_get_size_t(const struct ibmca_prov_ctx *provctx,
                           const OSSL_PARAM params[], const char *key,
                           size_t *val)
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, key);
    if (p == NULL)
        return -1;

    if (OSSL_PARAM_get_size_t(p, val) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Failed to get param '%s'", key);
        return 0;
    }

    ibmca_debug_ctx(provctx, "param '%s': %lu", key, *val);
    return 1;
}

int ibmca_param_get_utf8(const struct ibmca_prov_ctx *provctx,
                         const OSSL_PARAM params[], const char *key,
                         const char **str)
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, key);
    if (p == NULL)
        return -1;

    if (p->data_type == OSSL_PARAM_UTF8_STRING) {
        *str = p->data;
    } else if (OSSL_PARAM_get_utf8_ptr(p, str) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Failed to get param '%s'", key);
        return 0;
    }

    ibmca_debug_ctx(provctx, "param '%s': '%s'", key, *str);
    return 1;
}

int ibmca_param_get_octet_string(const struct ibmca_prov_ctx *provctx,
                                 const OSSL_PARAM params[], const char *key,
                                 void **val, size_t *len)
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, key);
    if (p == NULL)
        return -1;

    if (OSSL_PARAM_get_octet_string(p, val, 0, len) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Failed to get param '%s'", key);
        return 0;
    }

    ibmca_debug_ctx(provctx, "param '%s': [octet string] (%lu bytes)",
                    key, *len);
    return 1;
}

static void ibmca_teardown(void *vprovctx)
{
    struct ibmca_prov_ctx *provctx = vprovctx;
    int i;

    if (provctx == NULL)
        return;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    if (provctx->ica_adapter > DRIVER_NOT_LOADED)
        ica_close_adapter(provctx->ica_adapter);

    for (i = 0; i < OSSL_OP__HIGHEST; i++) {
        if (provctx->algorithms[i] != NULL)
            P_FREE(provctx, provctx->algorithms[i]);
    }

    if (provctx->algo_enabled != NULL)
        P_FREE(provctx, provctx->algo_enabled);

    if (provctx->property_def != NULL)
        P_FREE(provctx, provctx->property_def);

    if (provctx->fallback_property_query != NULL &&
        provctx->fallback_property_query != provctx->fallback_props_conf)
        P_FREE(provctx, provctx->fallback_property_query);

    if (provctx->libctx != NULL)
        OSSL_LIB_CTX_free(provctx->libctx);

    if (provctx->debug_file != NULL)
        fclose(provctx->debug_file);

    pthread_mutex_destroy(&provctx->debug_mutex);

    P_FREE(provctx, provctx);
#if HAVE_DECL_ICA_CLEANUP == 1
    ica_cleanup();
#endif
}

static const OSSL_PARAM ibmca_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ibmca_gettable_params(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);
    return ibmca_param_types;
}

static int ibmca_get_params(void *vprovctx, OSSL_PARAM params[])
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    OSSL_PARAM *p;

    if (provctx == NULL)
        return 0;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, provctx->name)) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "OSSL_PARAM_set_utf8_ptr failed");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, IBMCA_VERSION)) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "OSSL_PARAM_set_utf8_ptr failed");
    return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, IBMCA_VERSION)) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "OSSL_PARAM_set_utf8_ptr failed");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "OSSL_PARAM_set_int failed");
        return 0;
    }

    return 1;
}

static const OSSL_ALGORITHM *ibmca_query(void *vprovctx, int operation_id,
                                         int *no_cache)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    if (provctx == NULL)
        return NULL;

    *no_cache = 0;

    ibmca_debug_ctx(provctx, "provctx: %p operation_id: %d", provctx,
                    operation_id);

    if (operation_id < 0 || operation_id > OSSL_OP__HIGHEST)
        return NULL;

    ibmca_debug_ctx(provctx, "algorithms: %p",
                    provctx->algorithms[operation_id]);

    return provctx->algorithms[operation_id];
}

static const OSSL_ITEM *ibmca_get_reason_strings(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);
    return ibmca_reason_strings;
}

static int ibmca_prov_get_capabilities(void *vprovctx, const char *capability,
                                       OSSL_CALLBACK *cb, void *arg)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;
    int i, k, rc = 0;
    const struct ibmca_mech_capability *cap;

    if (capability == NULL || cb == NULL)
        return 0;

    ibmca_debug_ctx(provctx, "provctx: %p capability: %s", provctx,
                    capability);

    for (i = 0; ica_mech_infos[i].algo != NULL; i++) {
        for (cap = ica_mech_infos[i].capabilities;
             cap != NULL && cap->capability != NULL; cap++) {
            if (strcasecmp(capability, cap->capability) != 0)
                continue;

            ibmca_debug_ctx(provctx, "algorithm '%s' supports this capability",
                            ica_mech_infos[i].algo);

            for (k = 0; cap->details[k] != NULL; k++) {
                rc = cb(cap->details[k], arg);
                if (rc == 0)
                    break;
            }

            if (rc == 0)
                break;
        }
    }

    return rc;
}

static int ibmca_prov_self_tests(void *vprovctx)
{
    const struct ibmca_prov_ctx *provctx = vprovctx;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    if (provctx->fips == 0)
        return 1;

    /*
     * libica performs FIPS self-tests if running in FIPS mode. If any of
     * the fips tests failed, additional flags are on.
     */
    return (provctx->ica_fips_status == ICA_FIPS_MODE) ? 1 : 0;
}

static const OSSL_DISPATCH ibmca_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ibmca_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
                (void (*)(void))ibmca_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))ibmca_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ibmca_query },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
                (void (*)(void))ibmca_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
                (void (*)(void))ibmca_prov_get_capabilities },
    { OSSL_FUNC_PROVIDER_SELF_TEST,
                (void (*)(void))ibmca_prov_self_tests },
    { 0, NULL }
};

static int ibmca_config_const_string(struct ibmca_prov_ctx *provctx,
                                     const char *key, const char *value,
                                     const char **string)
{
    ibmca_debug_ctx(provctx, "provctx: %p key: '%s' value: '%s'",
                    provctx, key, value);

    *string = value;

    return 1;
}

static int ibmca_config_module_filename(struct ibmca_prov_ctx *provctx,
                                        const char *key, const char *value)
{
    return ibmca_config_const_string(provctx, key, value,
                                     &provctx->module_filename);
}

static int ibmca_config_openssl_version(struct ibmca_prov_ctx *provctx,
                                        const char *key, const char *value)
{
    return ibmca_config_const_string(provctx, key, value,
                                     &provctx->openssl_version);
}

static int ibmca_config_fallback_props(struct ibmca_prov_ctx *provctx,
                                       const char *key, const char *value)
{
    return ibmca_config_const_string(provctx, key, value,
                                     &provctx->fallback_props_conf);
}

static int ibmca_config_bool(struct ibmca_prov_ctx *provctx,
                             const char *key, const char *value, bool *bval)
{
    ibmca_debug_ctx(provctx, "provctx: %p key: '%s' value: '%s'",
                    provctx, key, value);

    if (strcasecmp(value, "on") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "1") == 0) {
        *bval = true;
    } else if (strcasecmp(value, "off") == 0 ||
        strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "no") == 0 ||
        strcasecmp(value, "0") == 0) {
        *bval = false;
    } else {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Failed to parse config value: '%s' = '%s'", key, value);
        return 0;
    }

    return 1;
}

static int ibmca_config_debug(struct ibmca_prov_ctx *provctx,
                              const char *key, const char *value)
{
    char debug_file[PATH_MAX];
    char prov_name[PATH_MAX];
    char *p;

    /*
     * If debug is already on (e.g. due to IBMCA_DEBUG environment variable)
     * do not override the setting.
     */
    if (provctx->debug == true)
        return 1;

    if (strcasecmp(value, "stderr") == 0) {
        provctx->debug = true;
        return 1;
    }

    if (ibmca_config_bool(provctx, key, value, &provctx->debug) == 0)
        return 0;

    if (provctx->debug == true) {
        provctx->debug_pid = getpid();

        strncpy(prov_name, provctx->name, sizeof(prov_name));
        prov_name[sizeof(prov_name) - 1] = '\0';
        while ((p = strchr(prov_name, '/')) != NULL)
            *p = '_';

        if (snprintf(debug_file, sizeof(debug_file), "%s/trace-%s.%d",
                     provctx->debug_path != NULL ? provctx->debug_path :
                                                   IBMCA_LOGDIR,
                     prov_name, provctx->debug_pid)
                                        >= (int)sizeof(debug_file)) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "IBMCA_LOGDIR too long: '%s'", IBMCA_LOGDIR);
            return 0;
        }

        provctx->debug_file = fopen(debug_file, "a");
        if (provctx->debug_file == NULL) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Failed to open trace file: '%s': %s - tracing to stderr instead",
                          debug_file, strerror(errno));
            return 1;
        }

        fprintf(provctx->debug_file,
                "*** Trace activated for IBMCA version %s ***\n",
                IBMCA_VERSION);
    }

    return 1;
}

static int ibmca_config_debug_path(struct ibmca_prov_ctx *provctx,
                                   const char *key, const char *value)
{
    /*
     * If the debug path is already set (e.g. due to IBMCA_DEBUG_PATH
     * environment variable) do not override the setting.
     */
    if (provctx->debug_path != NULL)
        return 1;

    return ibmca_config_const_string(provctx, key, value,
                                     &provctx->debug_path);
}

static int ibmca_config_fips(struct ibmca_prov_ctx *provctx,
                             const char *key, const char *value)
{
    if (ibmca_config_bool(provctx, key, value, &provctx->fips) == 0)
        return 0;

    provctx->fips_configured = true;
    return 1;
}

static int ibmca_config_algorithms(struct ibmca_prov_ctx *provctx,
                                   const char *key, const char *value)
{
    char *val, *tok;
    int i, rc = 1;
    bool found;

    ibmca_debug_ctx(provctx, "provctx: %p key: '%s' value: '%s'",
                    provctx, key, value);

    val = P_STRDUP(provctx, value);
    if (val == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to strdup config value");
        return 0;
    }

    for (i = 0; ica_mech_infos[i].algo != NULL; i++)
        provctx->algo_enabled[i] = false;

    for (tok = strtok(val, ","); tok != NULL; tok = strtok(NULL, ",")) {
        ibmca_debug_ctx(provctx, "algorithm: '%s'", tok);

        if (strcasecmp(tok, IBMCA_CONFIG_ALGO_ALL) == 0) {
            for (i = 0; ica_mech_infos[i].algo != NULL; i++)
                provctx->algo_enabled[i] = true;

            continue;
        }

        for (i = 0, found = false; ica_mech_infos[i].algo != NULL; i++) {
            if (strcasecmp(tok, ica_mech_infos[i].algo) == 0) {
                provctx->algo_enabled[i] = true;
                found = true;
                break;
            }
        }
        if (found)
            continue;

        put_error_ctx(provctx, IBMCA_ERR_CONFIGURATION,
                      "Unknown algorithm name '%s' in configuration for provider '%s'",
                      tok, provctx->name);
        rc = 0;
        break;
    }

    P_FREE(provctx, val);
    return rc;
}

static int ibmca_get_configuration(struct ibmca_prov_ctx *provctx)
{
    OSSL_PARAM params[NUM_CONFIG_ITEMS + 1];
    char *param_ptrs[NUM_CONFIG_ITEMS];
    const char *value;
    int i, num;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    for (num = 0; ica_mech_infos[num].algo != NULL; num++)
        ;
    provctx->algo_enabled = P_ZALLOC(provctx, num * sizeof(bool));
    if (provctx->algo_enabled == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate memory for algorithm list");
        return 0;
    }
    for (i = 0; ica_mech_infos[i].algo != NULL; i++)
        provctx->algo_enabled[i] = true;

    for (i = 0; i < (int)NUM_CONFIG_ITEMS; i++)
        params[i] = OSSL_PARAM_construct_utf8_ptr(config_items[i].key,
                                                  &param_ptrs[i],
                                                  sizeof(param_ptrs[i]));
    params[NUM_CONFIG_ITEMS] = OSSL_PARAM_construct_end();

    if (provctx->c_get_params(provctx->handle, params) != 1) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "Failed to get configuration parameters for provider '%s'",
                      provctx->name);
        return 0;
    }

    for (i = 0; i < (int)NUM_CONFIG_ITEMS; i++) {
        if (!OSSL_PARAM_modified(&params[i]))
            continue;

        if (OSSL_PARAM_get_utf8_ptr(&params[i], &value) != 1) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "Failed to get configuration parameter '%s' for provider '%s'",
                          params[i].key, provctx->name);
            return 0;
        }

        if (config_items[i].func(provctx, params[i].key, value) != 1)
            return 0;
    }

    return 1;
}

static bool ibmca_libica_mechs_supported(const unsigned int *mechs,
                                         libica_func_list_element *mech_list,
                                         unsigned int mech_len)
{
    unsigned int i, k;
    bool found;

    for (i = 0; mechs[i] != 0; i++) {
        for (k = 0, found = false; k < mech_len; k++) {
            if (mech_list[k].mech_mode_id != mechs[i])
                continue;

            if (mech_list[k].flags &
                (ICA_FLAG_SW | ICA_FLAG_SHW | ICA_FLAG_DHW))
                found = true;

            break;
        }

        if (!found)
            return false;
    }

    return true;
}

static int ibmca_libica_init(struct ibmca_prov_ctx *provctx)
{
    unsigned int mech_len, i;
    libica_func_list_element *mech_list = NULL;
    int rc, ret = 1;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    ica_set_fallback_mode(0);

    provctx->ica_fips_status = ica_fips_status();
    ibmca_debug_ctx(provctx, "ica_fips_status: %d", provctx->ica_fips_status);

    if (provctx->fips_configured == false) {
        /* FIPS not configured, auto-detect from libica */
        provctx->fips = (provctx->ica_fips_status == ICA_FIPS_MODE);
    } else if (provctx->fips == true) {
        /* Ensure libica is also running in fips mode */
        if (provctx->ica_fips_status != ICA_FIPS_MODE) {
            put_error_ctx(provctx, IBMCA_ERR_CONFIGURATION,
                          "'fips=yes' is configured, but libica is not running in FIPS mode");
            syslog(LOG_ERR, "IBMCA provider: 'fips=yes' is configured, but libica is not running in FIPS mode");
            return 0;
        }
    }
    ibmca_debug_ctx(provctx, "fips: %d", provctx->fips);

    rc = ica_open_adapter(&provctx->ica_adapter);
    if (rc != 0) {
        put_error_ctx(provctx, IBMCA_ERR_LIBICA_FAILED,
                      "ica_open_adapter failed: %s", strerror(rc));
        syslog(LOG_ERR, "IBMCA provider: ica_open_adapter failed: %s", strerror(rc));
        provctx->ica_adapter = DRIVER_NOT_LOADED;
        return 0;
    }

    ibmca_debug_ctx(provctx, "ica_adapter: %p", provctx->ica_adapter);

    rc = ica_get_functionlist(NULL, &mech_len);
    if (rc != 0) {
        put_error_ctx(provctx, IBMCA_ERR_LIBICA_FAILED,
                      "ica_get_functionlist failed: %s", strerror(rc));
        return 0;
    }

    ibmca_debug_ctx(provctx, "mech_len: %u", mech_len);

    mech_list = P_ZALLOC(provctx,
                  sizeof(libica_func_list_element) * mech_len);
    if (mech_list == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate memory for mechanism list");
        return 0;
    }

    rc = ica_get_functionlist(mech_list, &mech_len);
    if (rc != 0) {
        put_error_ctx(provctx, IBMCA_ERR_LIBICA_FAILED,
                      "ica_get_functionlist failed: %s", strerror(rc));
        ret = 0;
        goto done;
    }

    for (i = 0; ica_mech_infos[i].algo != NULL; i++) {
        if (!ibmca_libica_mechs_supported(ica_mech_infos[i].ica_mechs,
                                          mech_list, mech_len)) {
            ibmca_debug_ctx(provctx, "algo '%s' not supported by libica",
                            ica_mech_infos[i].algo);
            provctx->algo_enabled[i] = false;
        }
    }

done:
    P_FREE(provctx, mech_list);
    return ret;
}

static int ibmca_add_algorithm(struct ibmca_prov_ctx *provctx,
                               int operation,
                               const char *names,
                               const OSSL_DISPATCH *implementation,
                               const char *description)
{
    unsigned int num;
    OSSL_ALGORITHM *alg, *new_algs;

    ibmca_debug_ctx(provctx, "provctx: %p operation: %d names: '%s'",
                    provctx, operation, names);

    for (alg = provctx->algorithms[operation], num = 0;
         alg != NULL && alg->algorithm_names != NULL; alg++, num++)
        ;

    new_algs = P_REALLOC(provctx, provctx->algorithms[operation],
                         (num + 2) * sizeof(OSSL_ALGORITHM));
    if (new_algs == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate memory for algorithm array");
        return 0;
    }

    new_algs[num].algorithm_names = names;
    new_algs[num].property_definition = provctx->property_def;
    new_algs[num].implementation = implementation;
    new_algs[num].algorithm_description = description;

    memset(&new_algs[num + 1], 0, sizeof(OSSL_ALGORITHM));

    provctx->algorithms[operation] = new_algs;

    return 1;
}

static int ibmca_setup_algorithms(struct ibmca_prov_ctx *provctx)
{
    unsigned int i;
    size_t len;
    const struct ibmca_mech_algorithm *alg;
    const OSSL_ALGORITHM *ossl_alg;

    ibmca_debug_ctx(provctx, "provctx: %p", provctx);

    len = strlen("provider=") + strlen(provctx->name) + 1;
    if (provctx->fips)
        len += strlen(",fips=yes");
    provctx->property_def = P_ZALLOC(provctx, len);
    if (provctx->property_def == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate memory for property definition");
        return 0;
    }
    sprintf(provctx->property_def, "provider=%s%s", provctx->name,
            provctx->fips ? ",fips=yes" : "");

    ibmca_debug_ctx(provctx, "property_def: '%s'", provctx->property_def);

    if (provctx->fallback_props_conf != NULL) {
        provctx->fallback_property_query =
                                    (char *)provctx->fallback_props_conf;
    } else {
        /*
         * Build a property query string for fall-back operations that excludes
         * the IBMCA provider, since this would produce an endless loop.
         */
        len = strlen("provider!=") + strlen(provctx->name) + 1;
        if (provctx->fips)
            len += strlen(",fips=yes");
        provctx->fallback_property_query = P_ZALLOC(provctx, len);
        if (provctx->fallback_property_query == NULL) {
            put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                          "Failed to allocate property fallback query string");
            return 0;
        }
        sprintf(provctx->fallback_property_query, "provider!=%s%s",
                provctx->name, provctx->fips ? ",fips=yes" : "");
    }

    ibmca_debug_ctx(provctx, "fallback_property_query: '%s'",
                    provctx->fallback_property_query);

    for (i = 0; ica_mech_infos[i].algo != NULL; i++) {
        ibmca_debug_ctx(provctx, "algorithm '%s' enabled: %d",
                        ica_mech_infos[i].algo, provctx->algo_enabled[i]);

        if (provctx->algo_enabled[i] == false)
            continue;

        for (alg = ica_mech_infos[i].algos; alg->operation != 0; alg++) {
            for (ossl_alg = alg->algorithms; ossl_alg != NULL &&
                    ossl_alg->algorithm_names != NULL; ossl_alg++) {
                if (ibmca_add_algorithm(provctx, alg->operation,
                    ossl_alg->algorithm_names,
                    ossl_alg->implementation,
                    ossl_alg->algorithm_description) != 1) {
                    put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                                  "Failed to algorithm '%s' for operation %d",
                                  ossl_alg->algorithm_names, alg->operation);
                    return 0;
                }
            }
        }

    }

    return 1;
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    const OSSL_DISPATCH *dptc;
    OSSL_FUNC_CRYPTO_zalloc_fn *c_zalloc = NULL;
    OSSL_FUNC_CRYPTO_free_fn *c_free = NULL;
    OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug = NULL;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    OSSL_FUNC_core_vset_error_fn *c_vset_error = NULL;
    OSSL_FUNC_core_new_error_fn *c_new_error = NULL;
    OSSL_FUNC_provider_name_fn *c_provider_name = NULL;
    struct ibmca_prov_ctx *ctx;
    char *val;
    *provctx = NULL;

    if (handle == NULL || in == NULL || out == NULL || provctx == NULL)
        return 0;

    for (dptc = in; dptc->function_id != 0; dptc++) {
        switch (dptc->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(dptc);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_FUNC_core_new_error(dptc);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_FUNC_core_set_error_debug(dptc);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_FUNC_core_vset_error(dptc);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            c_zalloc = OSSL_FUNC_CRYPTO_zalloc(dptc);
            break;
        case OSSL_FUNC_CRYPTO_FREE:
            c_free = OSSL_FUNC_CRYPTO_free(dptc);
            break;
        case OSSL_FUNC_PROVIDER_NAME:
            c_provider_name = OSSL_FUNC_provider_name(dptc);
            break;
        default:
            /* Just ignore anything we don't understand for now */
            break;
        }
    }

    if (c_get_libctx == NULL || c_zalloc == NULL || c_free == NULL ||
        c_new_error == NULL || c_set_error_debug == NULL ||
        c_vset_error == NULL || c_provider_name == NULL)
        return 0;

    ctx = c_zalloc(sizeof(struct ibmca_prov_ctx), __FILE__, __LINE__);
    if (ctx == NULL) {
        c_new_error(handle);
        c_set_error_debug(handle, __FILE__, __LINE__, __func__);
        c_vset_error(handle, IBMCA_ERR_MALLOC_FAILED,
                     "Failed to allocate provider context", NULL);
        return 0;
    }

    ctx->handle = handle;
    ctx->name = c_provider_name(handle);
    ctx->c_get_libctx = c_get_libctx;
    ctx->c_new_error = c_new_error;
    ctx->c_set_error_debug = c_set_error_debug;
    ctx->c_vset_error = c_vset_error;
    ctx->c_zalloc = c_zalloc;
    ctx->c_free = c_free;
    ctx->ica_adapter = DRIVER_NOT_LOADED;

    val = secure_getenv(IBMCA_DEBUG_PATH_ENVVAR);
    if (val != NULL)
        ibmca_config_debug_path(ctx, IBMCA_CONF_DEBUG_PATH, val);
    val = getenv(IBMCA_DEBUG_ENVVAR);
    if (val != NULL)
        ibmca_config_debug(ctx, IBMCA_CONF_DEBUG, val);
    if (pthread_mutex_init(&ctx->debug_mutex, NULL) != 0) {
        put_error_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                      "pthread_mutex_init failed for provider '%s': %s",
                      ctx->name, strerror(errno));
        c_free(ctx, __FILE__, __LINE__);
        return 0;
    }

    ctx->libctx = OSSL_LIB_CTX_new_child(handle, in);
    if (ctx->libctx == NULL) {
        put_error_ctx(ctx, IBMCA_ERR_INTERNAL_ERROR,
                      "OSSL_LIB_CTX_new_child failed for provider '%s'",
                      ctx->name);
        ibmca_teardown(ctx);
        return 0;
    }

    for (dptc = in; dptc->function_id != 0; dptc++) {
        switch (dptc->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            ctx->c_gettable_params = OSSL_FUNC_core_gettable_params(dptc);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            ctx->c_get_params = OSSL_FUNC_core_get_params(dptc);
            break;
        case OSSL_FUNC_CRYPTO_MALLOC:
            ctx->c_malloc = OSSL_FUNC_CRYPTO_malloc(dptc);
            break;
        case OSSL_FUNC_CRYPTO_REALLOC:
            ctx->c_realloc = OSSL_FUNC_CRYPTO_realloc(dptc);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            ctx->c_clear_free = OSSL_FUNC_CRYPTO_clear_free(dptc);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_MALLOC:
            ctx->c_secure_malloc = OSSL_FUNC_CRYPTO_secure_malloc(dptc);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ZALLOC:
            ctx->c_secure_zalloc = OSSL_FUNC_CRYPTO_secure_zalloc(dptc);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_FREE:
            ctx->c_secure_free = OSSL_FUNC_CRYPTO_secure_free(dptc);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
            ctx->c_secure_clear_free = OSSL_FUNC_CRYPTO_secure_clear_free(dptc);
            break;
        case OSSL_FUNC_OPENSSL_CLEANSE:
            ctx->c_cleanse = OSSL_FUNC_OPENSSL_cleanse(dptc);
            break;
        default:
            /* Just ignore anything we don't understand  */
            break;
        }
    }

    if (ctx->c_gettable_params == NULL || ctx->c_get_params == NULL ||
        ctx->c_malloc == NULL || ctx->c_realloc == NULL ||
        ctx->c_clear_free == NULL || ctx->c_secure_malloc == NULL ||
        ctx->c_secure_zalloc == NULL || ctx->c_secure_free == NULL ||
        ctx->c_secure_clear_free == NULL || ctx->c_cleanse == NULL) {
        put_error_ctx(ctx, IBMCA_ERR_INVALID_PARAM,
                      "Not all required core functions are available for provider '%s'",
                      ctx->name);
        ibmca_teardown(ctx);
        return 0;
    }

    if (ibmca_get_configuration(ctx) != 1) {
        ibmca_teardown(ctx);
        return 0;
    }

    if (ibmca_libica_init(ctx) != 1) {
        ibmca_teardown(ctx);
        return 0;
    }

    ibmca_debug_ctx(ctx, "provctx: %p name: '%s'", ctx, ctx->name);

    if (ibmca_setup_algorithms(ctx) != 1) {
        ibmca_teardown(ctx);
        return 0;
    }

    *provctx = ctx;
    *out = ibmca_dispatch_table;
    return 1;
}
