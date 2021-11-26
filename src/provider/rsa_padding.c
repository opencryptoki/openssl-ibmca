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
#include <openssl/rand.h>
#include <openssl/core_names.h>

#include "p_ibmca.h"

const OSSL_ITEM ibmca_rsa_padding_table[] = {
    { RSA_PKCS1_PADDING,        OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING,           OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_PKCS1_OAEP_PADDING,   OSSL_PKEY_RSA_PAD_MODE_OAEP },
    { RSA_PKCS1_OAEP_PADDING,   "oeap"   },
    { RSA_X931_PADDING,         OSSL_PKEY_RSA_PAD_MODE_X931 },
    { RSA_PKCS1_PSS_PADDING,    OSSL_PKEY_RSA_PAD_MODE_PSS },
    { RSA_PKCS1_WITH_TLS_PADDING, "" }, /* Will only be set as integer param */
    { 0,                        NULL     }
};

int ibmca_rsa_add_pkcs1_padding(const struct ibmca_prov_ctx *provctx, int type,
                                const unsigned char *in, size_t inlen,
                                unsigned char *out, size_t outlen)
{
    int i, pad_len;
    unsigned char *p;

    ibmca_debug_ctx(provctx, "type: %d inlen: %lu outlen: %lu", type,
                    inlen, outlen);

    /*
     * The format is
     * 00 || BT || PS || 00 || D
     * BT - block type
     * PS - padding string, at least 8 bytes of FF for BT = 1 or at least 8
     *      bytes of random non-zero data for BT = 2
     * D  - data.
     */
    if (outlen < (inlen + RSA_PKCS1_PADDING_SIZE)) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        return 0;
    }

    pad_len = outlen - 3 - inlen;
    if (pad_len < 8) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        return 0;
    }

    p = out;

    *(p++) = 0;
    *(p++) = type;

    switch (type) {
    case 1:
        memset(p, 0xff, pad_len);
        p += pad_len;
        break;

    case 2:
        if (RAND_bytes_ex(provctx->libctx, p, pad_len, 0) <= 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                                  "RAND_bytes_ex failed");
            return 0;
        }

        for (i = 0; i < pad_len; i++, p++) {
            while (*p == '\0') {
                if (RAND_bytes_ex(provctx->libctx, p, 1, 0) <= 0) {
                    put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                                  "RAND_bytes_ex failed");
                    return 0;
                }
            }
        }
        break;

    default:
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                       "Invalid PKCS1 block type: %d", type);
        return 0;
    }

    *(p++) = 0;
    memcpy(p, in, inlen);

    return 1;
}

int ibmca_rsa_check_pkcs1_padding(const struct ibmca_prov_ctx *provctx,
                                  int type,
                                  const unsigned char *in, size_t inlen,
                                  unsigned char *out, size_t outsize,
                                  unsigned char **outptr, size_t *outlen)
{
    const unsigned char *p;
    int found = 0;

    ibmca_debug_ctx(provctx, "type: %d inlen: %lu outsize: %lu", type,
                    inlen, outsize);

    /*
     * The format is
     * 00 || BT || PS || 00 || D
     * BT - block type
     * PS - padding string, at least 8 bytes of FF for BT = 1 or at least 8
     *      bytes of random non-zero data for BT = 2
     * D  - data.
     */
    if (inlen < RSA_PKCS1_PADDING_SIZE) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM, "PKCS1 encoding error");
        return 0;
    }

    p = in;

    if (*(p++) != 0 || *(p++) != type) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM, "PKCS1 encoding error");
        return 0;
    }

    switch (type) {
    case 1:
        while (p < in + inlen) {
            if (*p != 0xff) {
                if (*p == 0x00) {
                    found = 1;
                    break;
                }

                put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                              "PKCS1 encoding error");
                return 0;
            }
            p++;
        }
        break;

    case 2:
        while (p < in + inlen) {
            if (*p == 0x00) {
                found = 1;
                break;
            }
            p++;
        }
        break;

    default:
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                       "Invalid PKCS1 block type: %d", type);
        return 0;
    }

    if (!found) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "PKCS1 encoding error");
        return 0;
    }

    p++;

    *outlen = inlen - (p - in);

    if (outsize < *outlen) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Output buffer too small");
        return 0;
    }

    if (out != NULL)
        memcpy(out, p, *outlen);
    if (outptr != NULL)
        *outptr = (unsigned char *)p;

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    return 1;
}

static int ibmca_rsa_pkcs1_mgf1(const struct ibmca_prov_ctx *provctx,
                                unsigned char *mask, long mask_len,
                                const unsigned char *seed, long seed_len,
                                const EVP_MD *mgf1_md)
{
    long i, outlen = 0;
    unsigned char cnt[4];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdlen;
    int rc = 0;

    if (md_ctx == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_CTX_new failed");
        return 0;
    }

    mdlen = EVP_MD_get_size(mgf1_md);
    if (mdlen < 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_get_size failed");
        goto err;
    }

    /* step 4 */
    for (i = 0; outlen < mask_len; i++) {
        /* step 4a: D = I2BS(counter, 4) */
        cnt[0] = (unsigned char)((i >> 24) & 255);
        cnt[1] = (unsigned char)((i >> 16) & 255);
        cnt[2] = (unsigned char)((i >> 8)) & 255;
        cnt[3] = (unsigned char)(i & 255);

        /* step 4b: T =T || hash(mgfSeed || D) */
        if (!EVP_DigestInit_ex(md_ctx, mgf1_md, NULL)
            || !EVP_DigestUpdate(md_ctx, seed, seed_len)
            || !EVP_DigestUpdate(md_ctx, cnt, 4)) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "EVP_DigestInit_ex/EVP_DigestUpdate failed");
            goto err;
        }

        if (outlen + mdlen <= mask_len) {
            if (!EVP_DigestFinal_ex(md_ctx, mask + outlen, NULL)) {
                put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                              "EVP_DigestFinal_ex failed");
                goto err;
            }

            outlen += mdlen;
        } else {
            if (!EVP_DigestFinal_ex(md_ctx, md, NULL)) {
                put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                              "EVP_DigestFinal_ex failed");
                goto err;
            }

            memcpy(mask + outlen, md, mask_len - outlen);
            outlen = mask_len;
        }
    }

    rc = 1;

 err:
    OPENSSL_cleanse(md, sizeof(md));
    EVP_MD_CTX_free(md_ctx);

    return rc;
}

int ibmca_rsa_add_oaep_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                    const unsigned char *in, size_t inlen,
                                    unsigned char *out, size_t outlen,
                                    const EVP_MD *oaep_md,
                                    const EVP_MD *mgf1_md,
                                    const unsigned char *label,
                                    size_t label_len)
{
    int ps_len;
    size_t oaep_md_len, dbmask_len = 0, i;
    unsigned char *masked_seed, *masked_db, *dbmask = NULL;
    unsigned char seed[EVP_MAX_MD_SIZE];
    int rc = 0;

    if (oaep_md == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "No OAEP digest available");
        return 0;
    }

    if (mgf1_md == NULL)
        mgf1_md = oaep_md;

    ibmca_debug_ctx(provctx,
                    "inlen: %lu outlen: %lu oaep_md: '%s' mgf1_md: '%s' label_len: %lu",
                    inlen, outlen, EVP_MD_get0_name(oaep_md),
                    EVP_MD_get0_name(mgf1_md), label_len);

    oaep_md_len = EVP_MD_get_size(oaep_md);
    if (oaep_md_len <= 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_get_size failed");
        goto done;
    }

    if (inlen > outlen - (2 * oaep_md_len) - 2) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Data too large for the key type");
        return 0;
    }

    /*
     * pkcs1v2.2 Step i:
     * The encoded messages is a concatenated single octet, 0x00 with
     * maskedSeed and maskedDB to create encoded message EM.
     * So lets mark of the places in our output buffer.
     */
    memset(out, 0, outlen);
    masked_seed = out + 1;
    masked_db = out + oaep_md_len + 1;

    /*
     * pkcs1v2.2, Step b:
     * Generate an octet string PS and concatenate to DB.
     */
    ps_len = outlen - inlen - (2 * oaep_md_len) - 2;
    if (EVP_Digest((void *)label, label_len, masked_db, NULL,
                   oaep_md, NULL) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR, "EVP_Digest failed");
        goto done;
    }
    memset(masked_db + oaep_md_len, 0, ps_len);

    /*
     * pkcs1v2.2, Step c:
     * We have already concatenated hash and PS to maskedDB.
     * Now just concatenate 0x01 and message.
     */
    masked_db[oaep_md_len + ps_len] = 0x01;
    memcpy(masked_db + (oaep_md_len + ps_len + 1), in, inlen);

    /*
     * pkcs1v2.2, Step d:
     * Generate a random seed.
     */
    if (RAND_bytes_ex(provctx->libctx, seed, oaep_md_len, 0) <= 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR, "RAND_bytes_ex failed");
        goto done;
    }

    /* pkcs1v2.2, Step e:
     * Compute dbmask using MGF1.
     */
    dbmask_len = outlen - oaep_md_len - 1;
    dbmask = P_ZALLOC(provctx, dbmask_len);
    if (dbmask == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate mask buffer");
        goto done;
    }

    if (ibmca_rsa_pkcs1_mgf1(provctx, dbmask, dbmask_len, seed, oaep_md_len,
                             mgf1_md) == 0)
        goto done;

    /* pkcs1v2.2, Step f:
     * Compute maskedDB.
     */
    for (i = 0; i < dbmask_len; i++)
        masked_db[i] ^= dbmask[i];

    /* pkcs1v2.2, Step g:
     * Compute seedMask using MGF1.
     */
    memset(masked_seed, 0, oaep_md_len);
    if (ibmca_rsa_pkcs1_mgf1(provctx, masked_seed, oaep_md_len, masked_db,
                             dbmask_len, mgf1_md) == 0)
        goto done;

    /* pkcs1v2.2, Step h:
     * Compute maskedSeed.
     */
    for (i = 0; i < oaep_md_len; i++)
        masked_seed[i] ^= seed[i];

    rc = 1;

done:
    if (dbmask)
        P_CLEAR_FREE(provctx, dbmask, dbmask_len);
    P_CLEANSE(provctx, seed, sizeof(seed));

    return rc;
}

int ibmca_rsa_check_oaep_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                      const unsigned char *in, size_t inlen,
                                      unsigned char *out, size_t outsize,
                                      unsigned char **outptr, size_t *outlen,
                                      const EVP_MD *oaep_md,
                                      const EVP_MD *mgf1_md,
                                      const unsigned char *label,
                                      size_t label_len)
{
    int rc = 0, error = 0;
    size_t dbmask_len = 0, ps_len, i, oaep_md_len;
    const unsigned char *masked_seed, *masked_db;
    unsigned char *dbmask = NULL, *seed_mask = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];

    if (oaep_md == NULL) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "No OAEP digest available");
        return 0;
    }

    if (mgf1_md == NULL)
        mgf1_md = oaep_md;

    ibmca_debug_ctx(provctx,
                    "inlen: %lu outsize: %lu oaep_md: '%s' mgf1_md: '%s' label_len: %lu",
                    inlen, outsize, EVP_MD_get0_name(oaep_md),
                    EVP_MD_get0_name(mgf1_md), label_len);

    oaep_md_len = EVP_MD_get_size(oaep_md);
    if (oaep_md_len <= 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                      "EVP_MD_get_size failed");
        goto done;
    }

    if (inlen < oaep_md_len + 2) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Input size too small");
        goto done;
    }

    /* allocate memory now for later use */
    dbmask_len = outsize - oaep_md_len - 1;
    dbmask = P_ZALLOC(provctx, dbmask_len);
    seed_mask = P_ZALLOC(provctx, oaep_md_len);
    if ((seed_mask == NULL) || (dbmask == NULL)) {
        put_error_ctx(provctx, IBMCA_ERR_MALLOC_FAILED,
                      "Failed to allocate mask or seed buffer");
        goto done;
    }

    /* pkcs1v2.2, section 7.1.2, Step 3b:
     * Separate the encoded message EM and process the decrypted message.
     *
     * To mitigate fault and timing attacks, just flag errors and
     * keep going.
     */
    masked_seed = in + 1;
    masked_db = in + oaep_md_len + 1;

    /* pkcs1v2.2, section 7.1.2, Step 3c:
     * Compute seedMask using MGF1.
     */
    if (ibmca_rsa_pkcs1_mgf1(provctx, seed_mask, oaep_md_len, masked_db,
                             dbmask_len, mgf1_md) == 0)
        error++;

    /* pkcs1v2.2, section 7.1.2, Step 3d:
     * Compute seed using MGF1.
     */
    for (i = 0; i < oaep_md_len; i++)
        seed_mask[i] ^= masked_seed[i];

    /* pkcs1v2.2, section 7.1.2, Step 3e:
     * Compute dbmask using MGF1.
     */
    if (ibmca_rsa_pkcs1_mgf1(provctx, dbmask, dbmask_len, seed_mask,
                             oaep_md_len, mgf1_md) == 0)
        error++;

    /* pkcs1v2.2, section 7.1.2, Step 3f:
     * Compute db using MGF1.
     */
    for (i = 0; i < dbmask_len; i++)
        dbmask[i] ^= masked_db[i];

    /* pkcs1v2.2, section 7.1.2, Step 3g:
     * DB = lHash’ || PS || 0x01 || M .
     *
     * If there is no octet with hexadecimal value 0x01 to separate
     * PS from M, if lHash does not equal lHash’, output "decryption
     * error" and stop.
     */
    if (EVP_Digest((void *)label, label_len, hash, NULL,
                   oaep_md, NULL) == 0) {
        put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR, "EVP_Digest failed");
        goto done;
    }
    if (memcmp(dbmask, hash, oaep_md_len))
        error++;

    ps_len = oaep_md_len;
    while ((ps_len < dbmask_len) && (dbmask[ps_len] == 0x00))
        ps_len++;

    if (ps_len >= dbmask_len ||
        (ps_len < dbmask_len && dbmask[ps_len] != 0x01) ||
        in[0] != 0)
        error++;

    if (error)
        goto done;

    ps_len++;
    *outlen = dbmask_len - ps_len;

    if (outsize < *outlen) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Output buffer too small");
        goto done;
    }

    if (out != NULL)
        memcpy(out, dbmask + ps_len, *outlen);
    if (outptr != NULL)
        *outptr = dbmask + ps_len;

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    rc = 1;

done:
    if (seed_mask)
        P_CLEAR_FREE(provctx, seed_mask, oaep_md_len);
    if (dbmask)
        P_CLEAR_FREE(provctx, dbmask, dbmask_len);

    return rc;
}

int ibmca_rsa_check_pkcs1_tls_padding(const struct ibmca_prov_ctx *provctx,
                                      unsigned int client_version,
                                      unsigned int alt_version,
                                      const unsigned char *in, size_t inlen,
                                      unsigned char *out, size_t outsize,
                                      size_t *outlen)
{
    size_t i;
    bool ok, alt_ok;

    ibmca_debug_ctx(provctx,
                    "inlen: %lu outsize: %lu client_version: 0x%04x alt_version: 0x%04x" ,
                    inlen, outsize, client_version, alt_version);

    /*
     * The format is
     * 00 || 02 || PS || 00 || PreMasterSecret
     * BT - block type
     * PS - at least 8 bytes of random non-zero data for BT = 2
     * D  - data = PreMasterSecret (48 bytes)
     * PreMasterSecret:  Version-major | Version-minor | 64 bytes secret
     */

    if (inlen < RSA_PKCS1_PADDING_SIZE + IBMCA_SSL_MAX_MASTER_KEY_LENGTH) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM, "PKCS1 encoding error");
        return 0;
    }
    if (outsize < IBMCA_SSL_MAX_MASTER_KEY_LENGTH) {
        put_error_ctx(provctx, IBMCA_ERR_INVALID_PARAM,
                      "Output buffer too small");
        return 0;
    }

    /* Check PKCA#1 type 2 padding */
    if (in[0] != 0x00 || in[1] != 0x02) {
        ibmca_debug_ctx(provctx, "ERROR: PKCS1 encoding error");
        goto error;
    }
    for (i = 2; i < inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH - 1; i++) {
        if (in[i] == 0x00) {
            ibmca_debug_ctx(provctx, "ERROR: PKCS1 encoding error");
            goto error;
        }
    }
    if (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH - 1] != 0x00) {
        ibmca_debug_ctx(provctx, "ERROR: PKCS1 encoding error");
        goto error;
    }

    /* Check version */
    ok = (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH] ==
                                            ((client_version >> 8) & 0xff));
    ok &= (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH] ==
                                            (client_version & 0xff));

    if (alt_version != 0) {
        alt_ok = (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH] ==
                                                ((alt_version >> 8) & 0xff));
        alt_ok &= (in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH] ==
                                                (alt_version & 0xff));
        ok |= alt_ok;
    }
    if (!ok) {
        ibmca_debug_ctx(provctx, "ERROR: Version check failed");
        goto error;
    }

    *outlen = IBMCA_SSL_MAX_MASTER_KEY_LENGTH;
    if (out != NULL)
        memcpy(out, &in[inlen - IBMCA_SSL_MAX_MASTER_KEY_LENGTH],
               IBMCA_SSL_MAX_MASTER_KEY_LENGTH);

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    return 1;

error:
    /*
     * We must not leak whether a decryption failure occurs because of
     * Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
     * section 7.4.7.1). The code follows that advice of the TLS RFC and
     * generates a random premaster secret for the case that the decrypt
     * fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
     * So, whether we actually succeeded or not, return success.
     */
    *outlen = IBMCA_SSL_MAX_MASTER_KEY_LENGTH;
    if (out != NULL) {
        if (RAND_priv_bytes_ex(provctx->libctx, out,
                               IBMCA_SSL_MAX_MASTER_KEY_LENGTH, 0) <= 0) {
            put_error_ctx(provctx, IBMCA_ERR_INTERNAL_ERROR,
                          "RAND_priv_bytes_ex failed");
            return 0;
        }
    }

    ibmca_debug_ctx(provctx, "outlen: %lu", *outlen);

    return 1;
}
