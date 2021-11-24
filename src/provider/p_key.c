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
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "p_ibmca.h"

void ibmca_keymgmt_upref(struct ibmca_key *key)
{
    ibmca_debug_key(key, "key: %p", key);

    __sync_add_and_fetch(&key->ref_count, 1);

    ibmca_debug_key(key, "ref_count: %u", key->ref_count);
}

unsigned int ibmca_keymgmt_downref(struct ibmca_key *key)
{
    const struct ibmca_prov_ctx *provctx;
    unsigned int cnt;

    assert(key->ref_count > 0);

    provctx = key->provctx;
    ibmca_debug_ctx(provctx, "key: %p ", key);

    cnt = __sync_sub_and_fetch(&key->ref_count, 1);
    ibmca_debug_ctx(provctx, "ref_count: %u", cnt);

    return cnt;
}

struct ibmca_key *ibmca_keymgmt_new(const struct ibmca_prov_ctx *provctx,
                                    int type, const char *algorithm,
                                    void (*free_cb)(struct ibmca_key *key),
                                    int (*dup_cb)(const struct ibmca_key *key,
                                                  struct ibmca_key *new_key),
                                    size_t (*get_max_param_size)(
                                                  const struct ibmca_key *key),
                                    OSSL_FUNC_keymgmt_export_fn *export,
                                    OSSL_FUNC_keymgmt_import_fn *import,
                                    OSSL_FUNC_keymgmt_has_fn *has,
                                    OSSL_FUNC_keymgmt_match_fn *match)
{
    struct ibmca_key *key;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "provctx: %p type: %d algorithm: '%s'", provctx,
                    type, algorithm);

    key = P_ZALLOC(provctx, sizeof(struct ibmca_key));
    if (key == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate a key");
        return NULL;
    }

    key->provctx = provctx;
    key->type = type;
    key->algorithm = algorithm;
    key->free_cb = free_cb;
    key->dup_cb = dup_cb;
    key->get_max_param_size = get_max_param_size;
    key->export = export;
    key->import = import;
    key->has = has;
    key->match = match;

    if (pthread_rwlock_init(&key->fallback_pkey_cache_lock, NULL) != 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "pthread_rwlock_init failed: %s", strerror(errno));
        P_FREE(provctx, key);
        return NULL;
    }

    ibmca_keymgmt_upref(key);

    ibmca_debug_ctx(provctx, "key: %p", key);

    return key;
}

void ibmca_keymgmt_free(void *vkey)
{
    struct ibmca_key *key = vkey;

    if (key == NULL)
        return;

    ibmca_debug_key(key, "key: %p", key);

    if (ibmca_keymgmt_downref(key) > 0)
        return;

    ibmca_debug_key(key, "free key: %p", key);

    if (key->free_cb != NULL)
        key->free_cb(key);

    ibmca_clean_fallback_pkey_cache(key);

    pthread_rwlock_destroy(&key->fallback_pkey_cache_lock);

    P_FREE(key->provctx, key);
}

void *ibmca_keymgmt_dup(const void *vfrom, int selection)
{
    const struct ibmca_key *from = vfrom;
    struct ibmca_key *key;

    if (from == NULL)
        return NULL;

    ibmca_debug_key(from, "from: %p selection: 0x%x", from, selection);

    if ((selection & OSSL_KEYMGMT_SELECT_ALL) == 0)
        return NULL;

    key = ibmca_keymgmt_new(from->provctx, from->type, from->algorithm,
                            from->free_cb, from->dup_cb,
                            from->get_max_param_size,
                            from->export, from->import, from->has, from->match);
    if (key == NULL) {
        ibmca_debug_key(from, "ERROR: ibmca_keymgmt_new failed");
        return NULL;
    }

    if (from->dup_cb != NULL) {
        if (from->dup_cb(from, key) == 0) {
            ibmca_debug_key(from, "ERROR: dup_cb failed");
            ibmca_keymgmt_free(key);
            return NULL;
        }
    }

    return key;
}

int ibmca_keymgmt_match(const struct ibmca_key *key1,
                        const struct ibmca_key *key2)
{
    if (key1 == NULL || key2 == NULL)
        return 0;

    ibmca_debug_key(key1, "key1: %p key2: %p", key1, key2);

    if (key1->provctx != key2->provctx)
        return 0;
    if (key1->type != key2->type)
        return 0;

    return 1;
}

struct ibmca_op_ctx *ibmca_keymgmt_gen_init(
                                        const struct ibmca_prov_ctx *provctx,
                                        int type,
                                        void (*free_cb)
                                            (struct ibmca_op_ctx *ctx),
                                        int (*dup_cb)
                                            (const struct ibmca_op_ctx *ctx,
                                             struct ibmca_op_ctx *new_ctx))
{
    struct ibmca_op_ctx *genctx;

    if (provctx == NULL)
        return NULL;

    ibmca_debug_ctx(provctx, "type: %d", type);

    genctx = ibmca_op_newctx(provctx, NULL, type, free_cb, dup_cb);
    if (genctx == NULL) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_op_newctx failed");
        return NULL;
    }

    if (ibmca_op_init(genctx, NULL, EVP_PKEY_OP_KEYGEN) == 0) {
        ibmca_debug_ctx(provctx, "ERROR: ibmca_op_init failed");
        ibmca_op_freectx(genctx);
        return NULL;
    }

    ibmca_debug_ctx(provctx, "genctx: %p", genctx);
    return genctx;
}

void ibmca_keymgmt_gen_cleanup(void *vgenctx)
{
    struct ibmca_op_ctx *genctx = vgenctx;

    if (genctx == NULL)
        return;

    ibmca_debug_op_ctx(genctx, "genctx: %p", genctx);
    ibmca_op_freectx(genctx);
}

void *ibmca_keymgmt_load(const void *reference, size_t reference_sz)
{
    struct ibmca_key *key;

    if (reference == NULL)
        return NULL;

    if (reference_sz == sizeof(struct ibmca_key)) {
        /* The contents of the reference is the address to our object */
        key = *(struct ibmca_key **)reference;

        /* We grabbed, so we detach it */
        *(struct ibmca_key **)reference = NULL;
        return key;
    }

    return NULL;
}

EVP_PKEY_CTX *ibmca_new_fallback_pkey_ctx(const struct ibmca_prov_ctx *provctx,
                                          EVP_PKEY *pkey,
                                          const char *algorithm)
{
    EVP_PKEY_CTX *pkey_ctx = NULL;

    ibmca_debug_ctx(provctx, "pkey: %p algorithm: '%s'", pkey,
                    algorithm != NULL ? algorithm : "(null)");

    if (pkey != NULL) {
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(provctx->libctx, pkey,
                                              provctx->fallback_property_query);
        if (pkey_ctx == NULL) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "EVP_PKEY_CTX_new_from_name for pkey %p failed",
                          pkey);
            return NULL;
        }
    } else if (algorithm != NULL) {
        pkey_ctx = EVP_PKEY_CTX_new_from_name(provctx->libctx, algorithm,
                                              provctx->fallback_property_query);
        if (pkey_ctx == NULL) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "EVP_PKEY_CTX_new_from_name for '%s' failed",
                          algorithm);
            return NULL;
        }
    } else {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Neither pkey nor algorithm specified");
    }

    return pkey_ctx;
}

struct ibmca_fallback_pkey_cb_data {
    const struct ibmca_key *key;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey;
};

static int ibmca_fallback_pkey_cb(const OSSL_PARAM params[], void *arg)
{
    struct ibmca_fallback_pkey_cb_data *data = arg;
    const OSSL_PARAM *p;
    int rc;

    ibmca_debug_key(data->key, "key: %p", data->key);
    for (p = params; p != NULL && p->key != NULL; p++)
        ibmca_debug_key(data->key, "param: %s", p->key);

    rc = EVP_PKEY_fromdata(data->pctx, &data->pkey,
                           OSSL_KEYMGMT_SELECT_KEYPAIR |
                                       OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                           (OSSL_PARAM *)params);
    if (rc == 0) {
        put_error_key(data->key, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_PKEY_fromdata failed");
        return 0;
    }

    return 1;
}

EVP_PKEY *ibmca_new_fallback_pkey(struct ibmca_key *key)
{
    struct ibmca_fallback_pkey_cb_data data;
    EVP_PKEY *pkey;
    int rc = 0;

    if (key == NULL)
        return NULL;

    ibmca_debug_key(key, "key: %p", key);

    /* Get from cache if one exists */
    if (pthread_rwlock_rdlock(&key->fallback_pkey_cache_lock) != 0) {
        ibmca_debug_key(key, "ERROR: pthread_rwlock_rdlock failed: %s",
                        strerror(errno));
        return NULL;
    }

retry:
    if (key->fallback_pkey_cache != NULL) {
        pkey = key->fallback_pkey_cache;
        if (EVP_PKEY_up_ref(pkey) != 1) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "EVP_PKEY_up_ref failed");
            pkey = NULL;
        }
        pthread_rwlock_unlock(&key->fallback_pkey_cache_lock);
        ibmca_debug_key(key, "got from cache: %p", pkey);
        return pkey;
    }
    pthread_rwlock_unlock(&key->fallback_pkey_cache_lock);

    /*
     * WR-lock the cache while creating a fallback PKEY to avoid other threads
     * from creating one on parallel. They will have to wait to get the RD-lock
     * above and will then get out fallback PKEY from the cache once we have
     * finished creating it.
     */
    if (pthread_rwlock_wrlock(&key->fallback_pkey_cache_lock) != 0) {
        ibmca_debug_key(key, "ERROR: pthread_rwlock_wrlock failed: %s",
                        strerror(errno));
        return NULL;
    }

    /*
     * Another thread might have put its pkey to the cache in the meantime.
     * There is a small time window when we gave up the RD-lock until we got
     * the WR-lock where another thread could have put its fallback pkey to
     * the cache.
     * So we need to check now while we are holding the WR-lock if there is
     * one in the cache and use that one if so.
     */
    if (key->fallback_pkey_cache != NULL)
        goto retry;

    data.key = key;
    data.pkey = NULL;
    data.pctx = ibmca_new_fallback_pkey_ctx(
                                    (struct ibmca_prov_ctx *)key->provctx,
                                    NULL, key->algorithm);
    if (data.pctx == NULL)
        goto out;

    if (EVP_PKEY_fromdata_init(data.pctx) == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_PKEY_fromdata_init failed");
        goto out;
    }

    rc = key->export((struct ibmca_key *)key,
                     OSSL_KEYMGMT_SELECT_KEYPAIR |
                                     OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                     ibmca_fallback_pkey_cb, &data);
    if (rc == 0 || data.pkey == NULL)
        goto out;

out:
    if (data.pctx != NULL)
        EVP_PKEY_CTX_free(data.pctx);
    if (rc != 1 && data.pkey != NULL) {
        EVP_PKEY_free(data.pkey);
        data.pkey = NULL;
    }

    /* Add pkey to cache */
    if (data.pkey != NULL) {
        if (EVP_PKEY_up_ref(data.pkey) == 1)
            key->fallback_pkey_cache = data.pkey;
    }

    pthread_rwlock_unlock(&key->fallback_pkey_cache_lock);

    return data.pkey;
}

void ibmca_clean_fallback_pkey_cache(struct ibmca_key *key)
{
    if (pthread_rwlock_wrlock(&key->fallback_pkey_cache_lock) != 0) {
        ibmca_debug_key(key, "ERROR: pthread_rwlock_wrlock failed: %s",
                        strerror(errno));
        return;
    }

    if (key->fallback_pkey_cache != NULL)
        EVP_PKEY_free(key->fallback_pkey_cache);
    key->fallback_pkey_cache = NULL;

    pthread_rwlock_unlock(&key->fallback_pkey_cache_lock);
}

int ibmca_import_from_fallback_pkey(struct ibmca_key *key, const EVP_PKEY *pkey,
                                    int selection)
{
    OSSL_PARAM *params = NULL;
    int rc = 0;

    if (key == NULL || pkey == NULL)
        return 0;

    ibmca_debug_key(key, "key: %p pkey: %p selection: 0x%x", key, pkey,
                    selection);

    if (EVP_PKEY_todata(pkey, selection, &params) == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_PKEY_todata failed");
        goto out;
    }

    rc = key->import(key, selection, params);
    if (rc == 0)
        goto out;

    rc = 1;

out:
    if (params != NULL)
        OSSL_PARAM_free(params);

    return rc;
}

int ibmca_check_fallback_provider(const struct ibmca_prov_ctx *provctx,
                                  EVP_PKEY_CTX *pctx)
{
    const char *name;

    if (EVP_PKEY_CTX_get0_provider(pctx) == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "PKEY Context is not initialized with a provider");
        return 0;
    }

    name = OSSL_PROVIDER_get0_name(EVP_PKEY_CTX_get0_provider(pctx));
    if (name == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "PKEY Context is not initialized with a provider");
        return 0;
    }

    ibmca_debug_ctx(provctx, "fallback provider: %s", name);

    if (strcmp(name, provctx->name) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Fallback provider can not be the %s provider itself",
                      provctx->name);
        return 0;
    }

    return 1;
}

int ibmca_keygen_cb(EVP_PKEY_CTX *ctx)
{
    struct ibmca_keygen_cb_data *cbdata = EVP_PKEY_CTX_get_app_data(ctx);
    OSSL_PARAM cb_params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };
    int p, n;

    if (cbdata == NULL || cbdata->osslcb == NULL)
        return 0;

    cb_params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    cb_params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);

    p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
    n = EVP_PKEY_CTX_get_keygen_info(ctx, 1);

    return cbdata->osslcb(cb_params, cbdata->cbarg);
}
