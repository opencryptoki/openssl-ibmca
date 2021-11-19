/*
 * Copyright [2005-2021] International Business Machines Corp.
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

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "ibmca.h"
#include "e_ibmca_err.h"

static int ibmca_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                          const unsigned char *iv, int enc)
{
    ICA_DES_CTX *pCtx = (ICA_DES_CTX *) EVP_CIPHER_CTX_get_cipher_data(ctx);

    memcpy(pCtx->key, key, EVP_CIPHER_CTX_key_length(ctx));

    return 1;
}

static int ibmca_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    return 1;
}


#define IMPLEMENT_IBMCA_DES_CIPHER_FN(name, NAME)                       \
static int ibmca_##name##_cipher(EVP_CIPHER_CTX *ctx,                   \
                                 unsigned char *out,                    \
                                 const unsigned char *in, size_t len)   \
{                                                                       \
    ICA_##NAME##_CTX *c =                                               \
        (ICA_##NAME##_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);        \
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);                 \
    const int mode = EVP_CIPHER_CTX_mode(ctx);                          \
    const int enc = EVP_CIPHER_CTX_encrypting(ctx) ?                    \
                                ICA_ENCRYPT : ICA_DECRYPT;              \
    int rv;                                                             \
                                                                        \
    switch (mode) {                                                     \
    case EVP_CIPH_ECB_MODE:                                             \
        rv = p_ica_##name##_ecb(in, out, len, c->key, enc);             \
        break;                                                          \
    case EVP_CIPH_CBC_MODE:                                             \
        rv = p_ica_##name##_cbc(in, out, len, c->key, iv, enc);         \
        break;                                                          \
    case EVP_CIPH_CFB_MODE:                                             \
        rv = p_ica_##name##_cfb(in, out, len, c->key, iv, 8, enc);      \
        break;                                                          \
    case EVP_CIPH_OFB_MODE:                                             \
        rv = p_ica_##name##_ofb(in, out, len, c->key, iv, enc);         \
        break;                                                          \
    default:                                                            \
        IBMCAerr(IBMCA_F_IBMCA_##NAME##_CIPHER,                         \
                 IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);                    \
        return 0;                                                       \
    }                                                                   \
    if (rv) {                                                           \
        IBMCAerr(IBMCA_F_IBMCA_##NAME##_CIPHER,                         \
            IBMCA_R_REQUEST_FAILED);                                    \
        return 0;                                                       \
    }                                                                   \
    return 1;                                                           \
}

IMPLEMENT_IBMCA_DES_CIPHER_FN(des, DES)
IMPLEMENT_IBMCA_DES_CIPHER_FN(3des, TDES)



#ifdef OLDER_OPENSSL
# define DECLARE_DES_EVP(mode, block_size, key_len, iv_len, flags,      \
                         ctx_size, init, do_cipher, cleanup,            \
                         set_asn1_parameters, get_asn1_parameters)      \
const EVP_CIPHER des_##mode = {                                         \
    NID_des_##mode,                                                     \
    block_size,                                                         \
    key_len,                                                            \
    iv_len,                                                             \
    flags,                                                              \
    init,                                                               \
    do_cipher,                                                          \
    cleanup,                                                            \
    ctx_size,                                                           \
    set_asn1_parameters,                                                \
    get_asn1_parameters,                                                \
    NULL,                                                               \
    NULL                                                                \
};                                                                      \
const EVP_CIPHER *ibmca_des_##mode(void)                                \
{                                                                       \
    return &des_##mode;                                                 \
}

#else
# define DECLARE_DES_EVP(mode, block_size, key_len, iv_len, flags,      \
                         ctx_size, init, do_cipher, cleanup,            \
                         set_asn1_parameters, get_asn1_parameters)      \
static EVP_CIPHER *des_##mode = NULL;                                   \
const EVP_CIPHER *ibmca_des_##mode(void)                                \
{                                                                       \
    EVP_CIPHER *cipher;                                                 \
                                                                        \
    if (des_##mode != NULL)                                             \
        goto done;                                                      \
                                                                        \
    if ((cipher = EVP_CIPHER_meth_new(NID_des_##mode,                   \
                                      block_size, key_len)) == NULL     \
         || !EVP_CIPHER_meth_set_iv_length(cipher, iv_len)              \
         || !EVP_CIPHER_meth_set_flags(cipher, flags)                   \
         || !EVP_CIPHER_meth_set_init(cipher, init)                     \
         || !EVP_CIPHER_meth_set_do_cipher(cipher, do_cipher)           \
         || !EVP_CIPHER_meth_set_cleanup(cipher, cleanup)               \
         || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, ctx_size)        \
         || !EVP_CIPHER_meth_set_set_asn1_params(cipher,                \
                                                 set_asn1_parameters)   \
         || !EVP_CIPHER_meth_set_get_asn1_params(cipher,                \
                                                 get_asn1_parameters)) {\
        EVP_CIPHER_meth_free(cipher);                                   \
        cipher = NULL;                                                  \
    }                                                                   \
    des_##mode = cipher;                                                \
done:                                                                   \
    return des_##mode;                                                  \
}                                                                       \
                                                                        \
void ibmca_des_##mode##_destroy(void)                                   \
{                                                                       \
    EVP_CIPHER_meth_free(des_##mode);                                   \
    des_##mode = NULL;                                                  \
}
#endif

DECLARE_DES_EVP(ecb, sizeof(ica_des_vector_t), sizeof(ica_des_key_single_t),
                sizeof(ica_des_vector_t), EVP_CIPH_ECB_MODE,
                sizeof(struct ibmca_des_context), ibmca_init_key,
                ibmca_des_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv)
DECLARE_DES_EVP(cbc, sizeof(ica_des_vector_t), sizeof(ica_des_key_single_t),
                sizeof(ica_des_vector_t), EVP_CIPH_CBC_MODE,
                sizeof(struct ibmca_des_context), ibmca_init_key,
                ibmca_des_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv)
DECLARE_DES_EVP(ofb, 1, sizeof(ica_des_key_single_t),
                sizeof(ica_des_vector_t), EVP_CIPH_OFB_MODE,
                sizeof(struct ibmca_des_context), ibmca_init_key,
                ibmca_des_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv)
DECLARE_DES_EVP(cfb, 1, sizeof(ica_des_key_single_t),
                sizeof(ica_des_vector_t), EVP_CIPH_CFB_MODE,
                sizeof(struct ibmca_des_context), ibmca_init_key,
                ibmca_des_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv)



#ifdef OLDER_OPENSSL
# define DECLARE_TDES_EVP(mode, block_size, key_len, iv_len, flags,     \
                          ctx_size, init, do_cipher, cleanup,           \
                          set_asn1_parameters, get_asn1_parameters)     \
const EVP_CIPHER tdes_##mode = {                                        \
    NID_des_ede3_##mode,                                                \
    block_size,                                                         \
    key_len,                                                            \
    iv_len,                                                             \
    flags,                                                              \
    init,                                                               \
    do_cipher,                                                          \
    cleanup,                                                            \
    ctx_size,                                                           \
    set_asn1_parameters,                                                \
    get_asn1_parameters,                                                \
    NULL,                                                               \
    NULL                                                                \
};                                                                      \
const EVP_CIPHER *ibmca_tdes_##mode(void)                               \
{                                                                       \
    return &tdes_##mode;                                                \
}

#else
# define DECLARE_TDES_EVP(mode, block_size, key_len, iv_len, flags,     \
                          ctx_size, init, do_cipher, cleanup,           \
                          set_asn1_parameters, get_asn1_parameters)     \
static EVP_CIPHER *tdes_##mode = NULL;                                  \
const EVP_CIPHER *ibmca_tdes_##mode(void)                               \
{                                                                       \
    EVP_CIPHER *cipher;                                                 \
                                                                        \
    if (tdes_##mode != NULL)                                            \
        goto done;                                                      \
                                                                        \
    if ((cipher = EVP_CIPHER_meth_new(NID_des_ede3_##mode,              \
                                      block_size, key_len)) == NULL     \
         || !EVP_CIPHER_meth_set_iv_length(cipher, iv_len)              \
         || !EVP_CIPHER_meth_set_flags(cipher, flags)                   \
         || !EVP_CIPHER_meth_set_init(cipher, init)                     \
         || !EVP_CIPHER_meth_set_do_cipher(cipher, do_cipher)           \
         || !EVP_CIPHER_meth_set_cleanup(cipher, cleanup)               \
         || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, ctx_size)        \
         || !EVP_CIPHER_meth_set_set_asn1_params(cipher,                \
                                                 set_asn1_parameters)   \
         || !EVP_CIPHER_meth_set_get_asn1_params(cipher,                \
                                                 get_asn1_parameters)) {\
        EVP_CIPHER_meth_free(cipher);                                   \
        cipher = NULL;                                                  \
    }                                                                   \
    tdes_##mode = cipher;                                               \
done:                                                                   \
    return tdes_##mode;                                                 \
}                                                                       \
                                                                        \
void ibmca_tdes_##mode##_destroy(void)                                  \
{                                                                       \
    EVP_CIPHER_meth_free(tdes_##mode);                                  \
    tdes_##mode = NULL;                                                 \
}
#endif

DECLARE_TDES_EVP(ecb, sizeof(ica_des_vector_t), sizeof(ica_des_key_triple_t),
                 sizeof(ica_des_vector_t), EVP_CIPH_ECB_MODE | EVP_CIPH_FLAG_FIPS,
                 sizeof(struct ibmca_des_context), ibmca_init_key,
                 ibmca_3des_cipher, ibmca_cipher_cleanup,
                 EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv)
DECLARE_TDES_EVP(cbc, sizeof(ica_des_vector_t), sizeof(ica_des_key_triple_t),
                 sizeof(ica_des_vector_t), EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_FIPS,
                 sizeof(struct ibmca_des_context), ibmca_init_key,
                 ibmca_3des_cipher, ibmca_cipher_cleanup,
                 EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv)
DECLARE_TDES_EVP(ofb, 1, sizeof(ica_des_key_triple_t),
                 sizeof(ica_des_vector_t), EVP_CIPH_OFB_MODE | EVP_CIPH_FLAG_FIPS,
                 sizeof(struct ibmca_des_context), ibmca_init_key,
                 ibmca_3des_cipher, ibmca_cipher_cleanup,
                 EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv)
DECLARE_TDES_EVP(cfb, 1, sizeof(ica_des_key_triple_t),
                 sizeof(ica_des_vector_t), EVP_CIPH_CFB_MODE | EVP_CIPH_FLAG_FIPS,
                 sizeof(struct ibmca_des_context), ibmca_init_key,
                 ibmca_3des_cipher, ibmca_cipher_cleanup,
                 EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv)


#ifndef OPENSSL_NO_AES_GCM
static int ibmca_gcm_aad(ICA_AES_GCM_CTX *ctx, const unsigned char *aad,
                         size_t len, int enc, int keylen)
{
    uint64_t alen = ctx->aadlen;

    if (ctx->ptlen)
        return -2;

    alen += len;
    if (alen > (1ULL << 61) || (sizeof(len) == 8 && alen < len))
        return -1;

    ctx->aadlen = alen;

    /* ctx->taglen is not set at this time... and is not needed. The
     * function only checks, if it's a valid gcm tag length. So we chose 16.
     */
    return !(p_ica_aes_gcm_intermediate(NULL, 0, NULL, ctx->ucb,
                                        (unsigned char *) aad, len,
                                        ctx->tag, 16, ctx->key, keylen,
                                        ctx->subkey, enc));
}

static int ibmca_aes_gcm(ICA_AES_GCM_CTX *ctx, const unsigned char *in,
                         unsigned char *out, size_t len, int enc, int keylen)
{
    uint64_t mlen = ctx->ptlen;
    unsigned char *pt, *ct;
    int rv;

    mlen += len;
    if (mlen > ((1ULL << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return 0;

    ctx->ptlen = mlen;

    if (enc) {
        pt = (unsigned char *) in;
        ct = out;
    } else {
        ct = (unsigned char *) in;
        pt = out;
    }

    /* ctx->taglen is not set at this time... and is not needed. The
     * function only checks, if it's a valid gcm tag length. So we chose 16.
     */
    rv = p_ica_aes_gcm_intermediate(pt, len, ct, ctx->ucb, NULL, 0,
                                      ctx->tag, 16, ctx->key, keylen,
                                      ctx->subkey, enc);
    if (rv)
        return 0;

    return 1;
}

static int ibmca_aes_gcm_init_key(EVP_CIPHER_CTX *ctx,
                                  const unsigned char *key,
                                  const unsigned char *iv, int enc)
{
    ICA_AES_GCM_CTX *gctx =
        (ICA_AES_GCM_CTX *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    const int gkeylen = EVP_CIPHER_CTX_key_length(ctx);

    if (!iv && !key)
        return 1;

    if (key) {
        memcpy(gctx->key, key, gkeylen);

        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;

        if (iv) {
            memset(gctx->icb, 0, sizeof(gctx->icb));
            memset(gctx->tag, 0, sizeof(gctx->tag));
            gctx->aadlen = 0;
            gctx->ptlen = 0;
            if (p_ica_aes_gcm_initialize(iv, gctx->ivlen,
                                         gctx->key, gkeylen,
                                         gctx->icb, gctx->ucb,
                                         gctx->subkey, enc))
                return 0;

            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        if (gctx->key_set) {
            memset(gctx->icb, 0, sizeof(gctx->icb));
            memset(gctx->tag, 0, sizeof(gctx->tag));
            gctx->aadlen = 0;
            gctx->ptlen = 0;
            if (p_ica_aes_gcm_initialize(iv, gctx->ivlen,
                                         gctx->key, gkeylen,
                                         gctx->icb, gctx->ucb,
                                         gctx->subkey, enc))
                return 0;
        } else {
            memcpy(gctx->iv, iv, gctx->ivlen);
        }
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

static int ibmca_aes_gcm_setiv(EVP_CIPHER_CTX *c)
{
    ICA_AES_GCM_CTX *gctx =
        (ICA_AES_GCM_CTX *) EVP_CIPHER_CTX_get_cipher_data(c);
    const int gkeylen = EVP_CIPHER_CTX_key_length(c);
    int enc = EVP_CIPHER_CTX_encrypting(c);

    if (!gctx->key_set)
        return 0;

    memset(gctx->icb, 0, sizeof(gctx->icb));
    memset(gctx->tag, 0, sizeof(gctx->tag));
    gctx->aadlen = 0;
    gctx->ptlen = 0;
    return !(p_ica_aes_gcm_initialize(gctx->iv, gctx->ivlen, gctx->key,
                                      gkeylen, gctx->icb, gctx->ucb,
                                      gctx->subkey, enc));
}

static int ibmca_aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    ICA_AES_GCM_CTX *gctx =
        (ICA_AES_GCM_CTX *) EVP_CIPHER_CTX_get_cipher_data(c);
    unsigned char *iv_noconst = EVP_CIPHER_CTX_iv_noconst(c);
    unsigned char *buf_noconst = EVP_CIPHER_CTX_buf_noconst(c);
    int enc = EVP_CIPHER_CTX_encrypting(c);
    EVP_CIPHER_CTX *out;
    ICA_AES_GCM_CTX *gctx_out;
    unsigned char *iv_noconst_out;
    unsigned int len;

    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_CTX_iv_length(c);
        gctx->iv = iv_noconst;
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aadlen = -1;
        return 1;
    case EVP_CTRL_GCM_SET_IVLEN:
        if (arg <= 0)
            return 0;
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != iv_noconst)
                OPENSSL_free(gctx->iv);
            gctx->iv = OPENSSL_malloc(arg);
            if (gctx->iv == NULL)
                return 0;
        }
        gctx->ivlen = arg;
        return 1;
    case EVP_CTRL_GCM_SET_TAG:
        if (arg <= 0 || arg > 16 || enc)
            return 0;
        memcpy(buf_noconst, ptr, arg);
        gctx->taglen = arg;
        return 1;
    case EVP_CTRL_GCM_GET_TAG:
        if (arg <= 0 || arg > 16 || !enc || gctx->taglen < 0)
            return 0;
        memcpy(ptr, buf_noconst, arg);
        return 1;
    case EVP_CTRL_GCM_SET_IV_FIXED:
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (enc && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;
    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        if (!ibmca_aes_gcm_setiv(c))
            return 0;
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        ++*(uint64_t *) (gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;
    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0 || enc)
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        if (!ibmca_aes_gcm_setiv(c))
            return 0;
        gctx->iv_set = 1;
        return 1;
    case EVP_CTRL_AEAD_TLS1_AAD:
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(buf_noconst, ptr, arg);
        gctx->tls_aadlen = arg;
        len = buf_noconst[arg - 2] << 8 | buf_noconst[arg - 1];
        if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
            return 0;
        len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
        if (!enc) {
            if (len < EVP_GCM_TLS_TAG_LEN)
                return 0;
            len -= EVP_GCM_TLS_TAG_LEN;
        }
        buf_noconst[arg - 2] = len >> 8;
        buf_noconst[arg - 1] = len & 0xff;
        return EVP_GCM_TLS_TAG_LEN;
    case EVP_CTRL_COPY:{
            out = ptr;
            gctx_out = (ICA_AES_GCM_CTX *)
                EVP_CIPHER_CTX_get_cipher_data(out);
            iv_noconst_out = EVP_CIPHER_CTX_iv_noconst(out);
            if (gctx->iv == iv_noconst) {
                gctx_out->iv = iv_noconst_out;
            } else {
                gctx_out->iv = OPENSSL_malloc(gctx->ivlen);
                if (gctx_out->iv == NULL)
                    return 0;
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
            return 1;
        }
    default:
        return -1;
    }
}

static int ibmca_gcm_tag(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, int taglen)
{
    ICA_AES_GCM_CTX *gctx =
        (ICA_AES_GCM_CTX *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    int enc = EVP_CIPHER_CTX_encrypting(ctx);
    const int gkeylen = EVP_CIPHER_CTX_key_length(ctx);

    if (p_ica_aes_gcm_last(gctx->icb, gctx->aadlen, gctx->ptlen,
                           gctx->tag, (unsigned char *) in, taglen,
                           gctx->key, gkeylen, gctx->subkey, enc))
        return 0;

    if (out)
        memcpy(out, gctx->tag, taglen);

    return 1;
}

static int ibmca_aes_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    const unsigned char *in, size_t len)
{
    ICA_AES_GCM_CTX *gctx =
        (ICA_AES_GCM_CTX *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    int enc = EVP_CIPHER_CTX_encrypting(ctx);
    const int keylen = EVP_CIPHER_CTX_key_length(ctx);
    int rv = -1;

    if (out != in || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    if (EVP_CIPHER_CTX_ctrl(ctx, enc ? EVP_CTRL_GCM_IV_GEN :
                            EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;

    if (!ibmca_gcm_aad(gctx, buf, gctx->tls_aadlen, enc, keylen))
        goto err;

    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;

    if (!ibmca_aes_gcm(gctx, in, out, len, enc, keylen))
        goto err;

    if (enc) {
        out += len;
        if (!ibmca_gcm_tag(ctx, out, NULL, EVP_GCM_TLS_TAG_LEN)) {
            goto err;
        }
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {
        if (!ibmca_gcm_tag(ctx, buf, in + len, EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }
err:
    gctx->iv_set = 0;
    gctx->tls_aadlen = -1;
    return rv;
}

static int ibmca_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    ICA_AES_GCM_CTX *gctx =
        (ICA_AES_GCM_CTX *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    int enc = EVP_CIPHER_CTX_encrypting(ctx);
    const int keylen = EVP_CIPHER_CTX_key_length(ctx);

    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aadlen >= 0)
        return ibmca_aes_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;

    if (in) {
        if (out == NULL) {
            if (!ibmca_gcm_aad(gctx, in, len, enc, keylen))
                return -1;
        } else {
            if (!ibmca_aes_gcm(gctx, in, out, len, enc, keylen))
                return -1;
        }
        return len;
    } else {
        if (enc) {
            gctx->taglen = 16;
            if (!ibmca_gcm_tag(ctx, buf, NULL, gctx->taglen))
                return -1;
        } else {
            if (gctx->taglen < 0)
                return -1;
            if (!ibmca_gcm_tag(ctx, NULL, buf, gctx->taglen))
                return -1;
        }
        gctx->iv_set = 0;
        return 0;
    }
}
#endif


#define IMPLEMENT_IBMCA_AES_CIPHER_FN(name, NAME)                       \
static int ibmca_##name##_cipher(EVP_CIPHER_CTX *ctx,                   \
                                 unsigned char *out,                    \
                                 const unsigned char *in, size_t len)   \
{                                                                       \
    ICA_##NAME##_CTX *c =                                               \
        (ICA_##NAME##_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);        \
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);                 \
    const int mode = EVP_CIPHER_CTX_mode(ctx);                          \
    const int enc = EVP_CIPHER_CTX_encrypting(ctx) ?                    \
                                ICA_ENCRYPT : ICA_DECRYPT;              \
    int rv;                                                             \
                                                                        \
    switch (mode) {                                                     \
    case EVP_CIPH_ECB_MODE:                                             \
        rv = p_ica_aes_ecb(in, out, len, c->key, NAME##_KEYLEN, enc);   \
        break;                                                          \
    case EVP_CIPH_CBC_MODE:                                             \
        rv = p_ica_aes_cbc(in, out, len, c->key, NAME##_KEYLEN,         \
                           iv, enc);                                    \
        break;                                                          \
    case EVP_CIPH_CFB_MODE:                                             \
        rv = p_ica_aes_cfb(in, out, len, c->key, NAME##_KEYLEN,         \
                           iv, 16, enc);                                \
        break;                                                          \
    case EVP_CIPH_OFB_MODE:                                             \
        rv = p_ica_aes_ofb(in, out, len, c->key, NAME##_KEYLEN,         \
                           iv, enc);                                    \
        break;                                                          \
    default:                                                            \
        IBMCAerr(IBMCA_F_IBMCA_##NAME##_CIPHER,                         \
                 IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);                    \
        return 0;                                                       \
    }                                                                   \
    if (rv) {                                                           \
        IBMCAerr(IBMCA_F_IBMCA_##NAME##_CIPHER,                         \
                 IBMCA_R_REQUEST_FAILED);                               \
        return 0;                                                       \
    }                                                                   \
                                                                        \
    return 1;                                                           \
}

IMPLEMENT_IBMCA_AES_CIPHER_FN(aes_128, AES_128)
IMPLEMENT_IBMCA_AES_CIPHER_FN(aes_192, AES_192)
IMPLEMENT_IBMCA_AES_CIPHER_FN(aes_256, AES_256)



#ifdef OLDER_OPENSSL
# define DECLARE_AES_EVP(kbits, mode, block_size, key_len, iv_len,      \
                         flags, ctx_size, init, do_cipher, cleanup,     \
                         set_asn1_parameters, get_asn1_parameters, ctrl)\
const EVP_CIPHER aes_##kbits##_##mode = {                               \
    NID_aes_##kbits##_##mode,                                           \
    block_size,                                                         \
    key_len,                                                            \
    iv_len,                                                             \
    flags,                                                              \
    init,                                                               \
    do_cipher,                                                          \
    cleanup,                                                            \
    ctx_size,                                                           \
    set_asn1_parameters,                                                \
    get_asn1_parameters,                                                \
    ctrl,                                                               \
    NULL                                                                \
};                                                                      \
const EVP_CIPHER *ibmca_aes_##kbits##_##mode(void)                      \
{                                                                       \
    return &aes_##kbits##_##mode;                                       \
}

#else
# define DECLARE_AES_EVP(kbits, mode, block_size, key_len, iv_len,      \
                         flags, ctx_size, init, do_cipher, cleanup,     \
                         set_asn1_parameters, get_asn1_parameters, ctrl)\
static EVP_CIPHER *aes_##kbits##_##mode = NULL;                         \
const EVP_CIPHER *ibmca_aes_##kbits##_##mode(void)                      \
{                                                                       \
    EVP_CIPHER *cipher;                                                 \
                                                                        \
    if (aes_##kbits##_##mode != NULL)                                   \
        goto done;                                                      \
                                                                        \
    if ((cipher = EVP_CIPHER_meth_new(NID_aes_##kbits##_##mode,         \
                                      block_size, key_len)) == NULL     \
         || !EVP_CIPHER_meth_set_iv_length(cipher, iv_len)              \
         || !EVP_CIPHER_meth_set_flags(cipher, flags)                   \
         || !EVP_CIPHER_meth_set_init(cipher, init)                     \
         || !EVP_CIPHER_meth_set_do_cipher(cipher, do_cipher)           \
         || !EVP_CIPHER_meth_set_cleanup(cipher, cleanup)               \
         || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, ctx_size)        \
         || !EVP_CIPHER_meth_set_set_asn1_params(cipher,                \
                                                 set_asn1_parameters)   \
         || !EVP_CIPHER_meth_set_get_asn1_params(cipher,                \
                                                 get_asn1_parameters)   \
         || !EVP_CIPHER_meth_set_ctrl(cipher, ctrl)) {                  \
        EVP_CIPHER_meth_free(cipher);                                   \
        cipher = NULL;                                                  \
    }                                                                   \
    aes_##kbits##_##mode = cipher;                                      \
done:                                                                   \
    return aes_##kbits##_##mode;                                        \
}                                                                       \
                                                                        \
void ibmca_aes_##kbits##_##mode##_destroy(void)                         \
{                                                                       \
    EVP_CIPHER_meth_free(aes_##kbits##_##mode);                         \
    aes_##kbits##_##mode = NULL;                                        \
}
#endif

DECLARE_AES_EVP(128, ecb, sizeof(ica_aes_vector_t),
                sizeof(ica_aes_key_len_128_t), sizeof(ica_aes_vector_t),
                EVP_CIPH_ECB_MODE | EVP_CIPH_FLAG_FIPS, sizeof(ICA_AES_128_CTX),
                ibmca_init_key, ibmca_aes_128_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(128, cbc, sizeof(ica_aes_vector_t),
                sizeof(ica_aes_key_len_128_t), sizeof(ica_aes_vector_t),
                EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_FIPS, sizeof(ICA_AES_128_CTX),
                ibmca_init_key, ibmca_aes_128_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(128, ofb, 1, sizeof(ica_aes_key_len_128_t),
                sizeof(ica_aes_vector_t), EVP_CIPH_OFB_MODE | EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_128_CTX), ibmca_init_key,
                ibmca_aes_128_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(128, cfb, 1, sizeof(ica_aes_key_len_128_t),
                sizeof(ica_aes_vector_t), EVP_CIPH_CFB_MODE | EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_128_CTX), ibmca_init_key,
                ibmca_aes_128_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
#ifndef OPENSSL_NO_AES_GCM
DECLARE_AES_EVP(128, gcm, 1, sizeof(ica_aes_key_len_128_t),
                sizeof(ica_aes_vector_t) - sizeof(uint32_t),
                EVP_CIPH_GCM_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT
                | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_AEAD_CIPHER
		| EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_GCM_CTX),
                ibmca_aes_gcm_init_key, ibmca_aes_gcm_cipher, NULL, NULL,
                NULL, ibmca_aes_gcm_ctrl)
#endif

DECLARE_AES_EVP(192, ecb, sizeof(ica_aes_vector_t),
                sizeof(ica_aes_key_len_192_t), sizeof(ica_aes_vector_t),
                EVP_CIPH_ECB_MODE | EVP_CIPH_FLAG_FIPS, sizeof(ICA_AES_192_CTX),
                ibmca_init_key, ibmca_aes_192_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(192, cbc, sizeof(ica_aes_vector_t),
                sizeof(ica_aes_key_len_192_t), sizeof(ica_aes_vector_t),
                EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_FIPS, sizeof(ICA_AES_192_CTX),
                ibmca_init_key, ibmca_aes_192_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(192, ofb, 1, sizeof(ica_aes_key_len_192_t),
                sizeof(ica_aes_vector_t), EVP_CIPH_OFB_MODE | EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_192_CTX), ibmca_init_key,
                ibmca_aes_192_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(192, cfb, 1, sizeof(ica_aes_key_len_192_t),
                sizeof(ica_aes_vector_t), EVP_CIPH_CFB_MODE | EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_192_CTX), ibmca_init_key,
                ibmca_aes_192_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
#ifndef OPENSSL_NO_AES_GCM
DECLARE_AES_EVP(192, gcm, 1, sizeof(ica_aes_key_len_192_t),
                sizeof(ica_aes_vector_t) - sizeof(uint32_t),
                EVP_CIPH_GCM_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT
                | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_AEAD_CIPHER
		| EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_GCM_CTX),
                ibmca_aes_gcm_init_key, ibmca_aes_gcm_cipher, NULL, NULL,
                NULL, ibmca_aes_gcm_ctrl)
#endif

DECLARE_AES_EVP(256, ecb, sizeof(ica_aes_vector_t),
                sizeof(ica_aes_key_len_256_t), sizeof(ica_aes_vector_t),
                EVP_CIPH_ECB_MODE | EVP_CIPH_FLAG_FIPS, sizeof(ICA_AES_256_CTX),
                ibmca_init_key, ibmca_aes_256_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(256, cbc, sizeof(ica_aes_vector_t),
                sizeof(ica_aes_key_len_256_t), sizeof(ica_aes_vector_t),
                EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_FIPS, sizeof(ICA_AES_256_CTX),
                ibmca_init_key, ibmca_aes_256_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(256, ofb, 1, sizeof(ica_aes_key_len_256_t),
                sizeof(ica_aes_vector_t), EVP_CIPH_OFB_MODE | EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_256_CTX), ibmca_init_key,
                ibmca_aes_256_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
DECLARE_AES_EVP(256, cfb, 1, sizeof(ica_aes_key_len_256_t),
                sizeof(ica_aes_vector_t), EVP_CIPH_CFB_MODE | EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_256_CTX), ibmca_init_key,
                ibmca_aes_256_cipher, ibmca_cipher_cleanup,
                EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv, NULL)
#ifndef OPENSSL_NO_AES_GCM
DECLARE_AES_EVP(256, gcm, 1, sizeof(ica_aes_key_len_256_t),
                sizeof(ica_aes_vector_t) - sizeof(uint32_t),
                EVP_CIPH_GCM_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT
                | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_AEAD_CIPHER
		| EVP_CIPH_FLAG_FIPS,
                sizeof(ICA_AES_GCM_CTX),
                ibmca_aes_gcm_init_key, ibmca_aes_gcm_cipher, NULL, NULL,
                NULL, ibmca_aes_gcm_ctrl)
#endif




