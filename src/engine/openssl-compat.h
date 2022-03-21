/*
 * Copyright 2022 International Business Machines Corp.
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
 */

#ifndef IBMCA_OPENSSL_COMPAT_H
#define IBMCA_OPENSSL_COMPAT_H

#include <openssl/opensslv.h>

typedef enum {
    ECX_KEY_TYPE_X25519,
    ECX_KEY_TYPE_X448,
    ECX_KEY_TYPE_ED25519,
    ECX_KEY_TYPE_ED448
} ECX_KEY_TYPE;

#ifdef OPENSSL_VERSION_PREREQ
/* This is 3.x */

#  define X25519_KEYLEN         32
#  define X448_KEYLEN           56
#  define ED25519_KEYLEN        32
#  define ED448_KEYLEN          57

#  define MAX_KEYLEN  ED448_KEYLEN

typedef int CRYPTO_REF_COUNT;

typedef struct ecx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    unsigned int haspubkey:1;
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
    size_t keylen;
    ECX_KEY_TYPE type;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
} ECX_KEY;

static inline ECX_KEY *ossl_ecx_key_new_simple(ECX_KEY_TYPE type)
{
    ECX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ret->libctx = NULL;
    ret->haspubkey = 0;
    switch (type) {
    case ECX_KEY_TYPE_X25519:
        ret->keylen = X25519_KEYLEN;
        break;
    case ECX_KEY_TYPE_X448:
        ret->keylen = X448_KEYLEN;
        break;
    case ECX_KEY_TYPE_ED25519:
        ret->keylen = ED25519_KEYLEN;
        break;
    case ECX_KEY_TYPE_ED448:
        ret->keylen = ED448_KEYLEN;
        break;
    }
    ret->type = type;
    ret->references = 1;

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL)
        goto err;
    return ret;
err:
    OPENSSL_free(ret);
    return NULL;
}

static inline void ossl_ecx_set0_privkey(ECX_KEY *key, unsigned char *privkey)
{
    key->privkey = privkey;
}

static inline unsigned char *ossl_ecx_get0_privkey(ECX_KEY *key)
{
    return key->privkey;
}

static inline unsigned char *ossl_ecx_get0_pubkey(ECX_KEY *key)
{
    return key->pubkey;
}

static inline void ossl_ecx_copypubkey(ECX_KEY *key, unsigned char *pubkey, size_t len)
{
    memcpy(key->pubkey, pubkey, len);
    key->haspubkey = 1;
}

#else
/* This is 1.1.x */

#include <openssl/evp.h>

/*
 * copied from evp_int.h:
 * missing set/get methods for opaque types.
 */

typedef struct {
    unsigned char pub[57];
    unsigned char *priv;
} ECX_KEY;

static inline ECX_KEY *ossl_ecx_key_new_simple(ECX_KEY_TYPE type)
{
    return calloc(1, sizeof(ECX_KEY));
}

static inline void ossl_ecx_set0_privkey(ECX_KEY *key, unsigned char *privkey)
{
    key->priv = privkey;
}

static inline unsigned char *ossl_ecx_get0_privkey(ECX_KEY *key)
{
    return key->priv;
}

static inline unsigned char *ossl_ecx_get0_pubkey(ECX_KEY *key)
{
    return key->pub;
}

static inline void ossl_ecx_copypubkey(ECX_KEY *key, unsigned char *pubkey, size_t len)
{
    memcpy(key->pub, pubkey, len);
}

#endif

#endif
