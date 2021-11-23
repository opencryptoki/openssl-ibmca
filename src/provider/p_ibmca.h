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
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>

#include <ica_api.h>

/* Environment variable name to enable debug */
#define IBMCA_DEBUG_ENVVAR          "IBMCA_DEBUG"

/* IBMCA provider configuration key words */
#define IBMCA_CONF_DEBUG            "debug"
#define IBMCA_CONF_ALGORITHMS       "algorithms"
#define IBMCA_CONF_FIPS             "fips"
#define IBMCA_CONF_FALLBACK_PROPS   "fallback-properties"

/* IBMCA provider configuration key words for algorithms */
#define IBMCA_CONFIG_ALGO_ALL       "ALL"
#define IBMCA_CONFIG_ALGO_RSA       "RSA"
#define IBMCA_CONFIG_ALGO_EC        "EC"
#define IBMCA_CONFIG_ALGO_DH        "DH"

/* IBMCA provider context */
struct ibmca_prov_ctx {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    const char *name;
    const char *openssl_version;
    const char *module_filename;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
    OSSL_FUNC_core_new_error_fn *c_new_error;
    OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
    OSSL_FUNC_core_vset_error_fn *c_vset_error;
    OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
    OSSL_FUNC_core_get_params_fn *c_get_params;
    OSSL_FUNC_CRYPTO_zalloc_fn *c_zalloc;
    OSSL_FUNC_CRYPTO_malloc_fn *c_malloc;
    OSSL_FUNC_CRYPTO_realloc_fn *c_realloc;
    OSSL_FUNC_CRYPTO_free_fn *c_free;
    OSSL_FUNC_CRYPTO_clear_free_fn *c_clear_free;
    OSSL_FUNC_CRYPTO_secure_malloc_fn *c_secure_malloc;
    OSSL_FUNC_CRYPTO_secure_zalloc_fn *c_secure_zalloc;
    OSSL_FUNC_CRYPTO_secure_free_fn *c_secure_free;
    OSSL_FUNC_CRYPTO_secure_clear_free_fn *c_secure_clear_free;
    OSSL_FUNC_OPENSSL_cleanse_fn *c_cleanse;
    bool debug;
    FILE *debug_file;
    pid_t debug_pid;
    pthread_mutex_t debug_mutex;
    bool fips;
    bool fips_configured;
    bool *algo_enabled;
    char *property_def;
    const char *fallback_props_conf;
    ica_adapter_handle_t ica_adapter;
    int ica_fips_status;
    OSSL_ALGORITHM *algorithms[OSSL_OP__HIGHEST + 1];
};

/* Macros for calling core functions */
#define P_ZALLOC(prov_ctx, size)                    \
        (prov_ctx)->c_zalloc((size), __FILE__ , __LINE__)
#define P_MALLOC(prov_ctx, size)                    \
        (prov_ctx)->c_malloc((size), __FILE__ , __LINE__)
#define P_REALLOC(prov_ctx, ptr, size)              \
        (prov_ctx)->c_realloc((ptr), (size), __FILE__ , __LINE__)
#define P_FREE(prov_ctx, ptr)                       \
        (prov_ctx)->c_free((ptr), __FILE__ , __LINE__)
#define P_CLEAR_FREE(prov_ctx, ptr, size)           \
        (prov_ctx)->c_clear_free((ptr), (size), __FILE__ , __LINE__)
#define P_SECURE_MALLOC(prov_ctx, size)             \
        (prov_ctx)->c_secure_malloc((size), __FILE__ , __LINE__)
#define P_SECURE_ZALLOC(prov_ctx, size)             \
        (prov_ctx)->c_secure_zalloc((size), __FILE__ , __LINE__)
#define P_SECURE_FREE(prov_ctx, ptr)                \
        (prov_ctx)->c_secure_free((ptr), __FILE__ , __LINE__)
#define P_SECURE_CLEAR_FREE(prov_ctx, ptr, size)    \
        (prov_ctx)->c_secure_clear_free((ptr), (size), __FILE__ , __LINE__)
#define P_CLEANSE(prov_ctx, ptr, size)              \
        (prov_ctx)->c_cleanse((ptr), (size))
#define P_STRDUP(prov_ctx, str)                     \
        ibmca_strdup((prov_ctx), (str), __FILE__ , __LINE__)
#define P_MEMDUP(prov_ctx, data, size)              \
        ibmca_memdup((prov_ctx), (data), (size), __FILE__ , __LINE__)
#define P_SECURE_MEMDUP(prov_ctx, data, size)       \
        ibmca_secure_memdup((prov_ctx), (data), (size), __FILE__ , __LINE__)

char *ibmca_strdup(const struct ibmca_prov_ctx *provctx, const char *str,
                   const char* file, int line);
void *ibmca_memdup(const struct ibmca_prov_ctx *provctx, const void *data,
                   size_t size, const char* file, int line);
void *ibmca_secure_memdup(const struct ibmca_prov_ctx *provctx,
                          const void *data, size_t size,
                          const char* file, int line);

/* Debug and error handling functions and macros */
void ibmca_debug_print(struct ibmca_prov_ctx *provctx, const char *func,
                       const char *fmt, ...);

#define ibmca_debug(ctx, fmt...)                                       \
        do {                                                           \
            if ((ctx)->debug)                                          \
                ibmca_debug_print((struct ibmca_prov_ctx*)(ctx),       \
                                  __func__, fmt);                      \
        } while (0)

#define ibmca_debug_ctx(ctx, fmt...)    ibmca_debug((ctx), fmt)

void ibmca_put_error(const struct ibmca_prov_ctx *provctx, int err,
                     const char *file, int line, const char *func,
                     char *fmt, ...);

#define put_error_ctx(ctx, err, fmt...)             \
        do {                                        \
            ibmca_debug_ctx((ctx), "ERROR: "fmt);   \
            ibmca_put_error((ctx), (err), __FILE__, \
                __LINE__, __func__, fmt);           \
        } while (0)

#define IBMCA_ERR_INTERNAL_ERROR                1
#define IBMCA_ERR_MALLOC_FAILED                 2
#define IBMCA_ERR_INVALID_PARAM                 3
#define IBMCA_ERR_CONFIGURATION                 4
#define IBMCA_ERR_LIBICA_FAILED                 5

#define UNUSED(var)                             ((void)(var))

/* Algorithm support definitions */

struct ibmca_mech_capability {
    const char *capability;
    const OSSL_PARAM **details;
};

