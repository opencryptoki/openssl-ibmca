/*
 * Copyright [2023] International Business Machines Corp.
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
#include <openssl/rsa.h>

#include "p_ibmca.h"

static BN_BLINDING *ibmca_rsa_setup_blinding(struct ibmca_key *key)
{
    BIGNUM *n = NULL, *e = NULL;
    BN_CTX *bn_ctx = NULL;
    BN_BLINDING *blinding = NULL;
    int rc;

    ibmca_debug_key(key, "key: %p", key);

    bn_ctx = BN_CTX_new_ex(key->provctx->libctx);
    if (bn_ctx == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_CTX_new_ex failed");
        goto out;
    }

    rc =  ibmca_keymgmt_rsa_pub_as_bn(key, &n, &e);
    if (rc == 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "No public key available");
        goto out;
    }

    BN_set_flags(n, BN_FLG_CONSTTIME);

    blinding = BN_BLINDING_create_param(NULL, e, n, bn_ctx, NULL, NULL);
    if (blinding == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "BN_BLINDING_create_param failed");
        goto out;
    }

    BN_BLINDING_set_current_thread(blinding);

out:
    BN_free(n);
    BN_free(e);
    BN_CTX_free(bn_ctx);

    ibmca_debug_key(key, "blinding: %p", blinding);

    return blinding;
}

static BN_BLINDING *ibmca_rsa_get_blinding(struct ibmca_key *key, bool *local)
{
    BN_BLINDING *blinding = NULL;

    ibmca_debug_key(key, "key: %p", key);

    if (pthread_rwlock_rdlock(&key->rsa.blinding_lock) != 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "pthread_rwlock_rdlock failed: %s", strerror(errno));
        goto out;
    }

    while (1) {
        blinding = key->rsa.blinding;
        if (blinding != NULL) {
            if (BN_BLINDING_is_current_thread(blinding)) {
                *local = true;
            } else {
                /*
                 * BN_BLINDING is shared, meaning that accesses require locks,
                 * and that the blinding factor must be stored outside the
                 * BN_BLINDING
                 */
                *local = false;
                blinding = key->rsa.mt_blinding;
            }
        }

        pthread_rwlock_unlock(&key->rsa.blinding_lock);

        if (blinding != NULL)
            break;

        /* WR-lock the blinding lock while setting up the blinding */
        if (pthread_rwlock_wrlock(&key->rsa.blinding_lock) != 0) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "pthread_rwlock_wrlock failed: %s", strerror(errno));
            goto out;
        }

        if (key->rsa.blinding == NULL) {
            key->rsa.blinding = ibmca_rsa_setup_blinding(key);
            if (key->rsa.blinding == NULL) {
                pthread_rwlock_unlock(&key->rsa.blinding_lock);
                goto out;
            }

            continue;
        }

        if (key->rsa.mt_blinding == NULL) {
            key->rsa.mt_blinding = ibmca_rsa_setup_blinding(key);
            if (key->rsa.mt_blinding == NULL) {
                pthread_rwlock_unlock(&key->rsa.blinding_lock);
                goto out;
            }

            continue;
        }
    }

out:
    ibmca_debug_key(key, "blinding: %p local: %d", blinding, *local);

    return blinding;
}

static int ibmca_rsa_blinding_convert(struct ibmca_key *key,
                                      BN_BLINDING *blinding,
                                      BIGNUM *unblind, BN_CTX *bn_ctx,
                                      const unsigned char *in,
                                      unsigned char *out,
                                      size_t rsa_size, bool local)
{
    BIGNUM *bn_in;
    int rc = 0;

    ibmca_debug_key(key, "key: %p rsa_size: %lu local: %d",
                    key, rsa_size, local);

    bn_in = BN_CTX_get(bn_ctx);
    if (bn_in == NULL ||
        BN_bin2bn(in, (int)rsa_size, bn_in) == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                     "BN_CTX_get/BN_bin2bn failed");
        goto out;
    }

    if (!local) {
        /* Shared blinding requires locks */
        if (!BN_BLINDING_lock(blinding)) {
            put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                          "BN_BLINDING_lock failed");
            goto out;
        }
    }

    rc = BN_BLINDING_convert_ex(bn_in, unblind, blinding, bn_ctx);

    if (!local)
        BN_BLINDING_unlock(blinding);

    if (rc != 1) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "BN_BLINDING_convert_ex failed");
        goto out;
    }

    rc = BN_bn2binpad(bn_in, out, rsa_size);
    if (rc != (int)rsa_size) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_bn2binpad failed");
        goto out;
    }

    rc = 1;

out:
    ibmca_debug_key(key, "rc: %d", rc);

    return rc;
}

static int ibmca_rsa_blinding_invert(struct ibmca_key *key,
                                     BIGNUM *unblind,
                                     const unsigned char *in,
                                     unsigned char *out,
                                     size_t rsa_size)
{
    int rc;

    ibmca_debug_key(key, "key: %p rsa_size: %lu", key, rsa_size);

    rc = ossl_bn_rsa_do_unblind(in, unblind, key->rsa.public.modulus,
                                out, rsa_size, NULL, 0);
    if (rc <= 0) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "ossl_bn_rsa_do_unblind failed");
        goto out;
    }

    rc = 1;

out:
    ibmca_debug_key(key, "rc: %d", rc);

    return rc;
}

int ibmca_rsa_crt_with_blinding(struct ibmca_key *key, const unsigned char *in,
                                unsigned char *out, size_t rsa_size)
{
    BN_BLINDING *blinding;
    bool local_blinding = false;
    BIGNUM *unblind = NULL;
    BN_CTX *bn_ctx = NULL;
    unsigned char *buf = NULL;
    int rc = 0;

    ibmca_debug_key(key, "key: %p rsa_size: %lu", key, rsa_size);

    if (rsa_size != key->rsa.private.key_length) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR,
                      "rsa_size is not modulus size");
        goto out;
    }

    bn_ctx = BN_CTX_new_ex(key->provctx->libctx);
    if (bn_ctx == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_CTX_new_ex failed");
        goto out;
    }

    buf = P_SECURE_ZALLOC(key->provctx, rsa_size * 2);
    if (buf == NULL) {
        put_error_key(key, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate blinding buffer");
        goto out;
    }

    blinding = ibmca_rsa_get_blinding(key, &local_blinding);
    if (blinding == NULL) {
        ibmca_debug_key(key, "ERROR: ibmca_keymgmt_rsa_get_blinding failed");
        goto out;
    }

    unblind = BN_CTX_get(bn_ctx);
    if (unblind == NULL) {
        put_error_key(key, IBMCA_ERR_INTERNAL_ERROR, "BN_CTX_get failed");
        goto out;
    }

    BN_set_flags(unblind, BN_FLG_CONSTTIME);

    rc = ibmca_rsa_blinding_convert(key, blinding, unblind, bn_ctx,
                                    in, buf, rsa_size, local_blinding);
    if (rc == 0) {
        ibmca_debug_key(key,
                        "ERROR: ibmca_keymgmt_rsa_blinding_convert failed");
        goto out;
    }

    rc = ica_rsa_crt(key->provctx->ica_adapter, buf,
                     &key->rsa.private, buf + rsa_size);
    if (rc != 0) {
        ibmca_debug_key(key, "ERROR: ica_rsa_crt failed with: %s",
                        strerror(rc));
        rc = 0;
        goto out;
    }

    rc = ibmca_rsa_blinding_invert(key, unblind, buf + rsa_size, out, rsa_size);
    if (rc == 0) {
        ibmca_debug_key(key,
                        "ERROR: ibmca_rsa_blinding_invert failed");
        goto out;
    }

    rc = 1;

out:
    if (buf != NULL)
        P_SECURE_CLEAR_FREE(key->provctx, buf, rsa_size * 2);
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);

    ibmca_debug_key(key, "rc: %d", rc);

    return rc;
}

