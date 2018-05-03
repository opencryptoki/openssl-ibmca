/*
 * Copyright [2005-2018] International Business Machines Corp.
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
#include <openssl/rsa.h>
#include "ibmca.h"
#include "e_ibmca_err.h"

#ifndef OPENSSL_NO_SHA1
static int ibmca_sha1_init(EVP_MD_CTX *ctx)
{
    IBMCA_SHA_CTX *ibmca_sha_ctx = (IBMCA_SHA_CTX *) EVP_MD_CTX_md_data(ctx);

    memset((unsigned char *) ibmca_sha_ctx, 0, sizeof(*ibmca_sha_ctx));

    return 1;
}

static int ibmca_sha1_update(EVP_MD_CTX *ctx,
                             const void *in_data, unsigned long inlen)
{
    IBMCA_SHA_CTX *ibmca_sha_ctx = (IBMCA_SHA_CTX *) EVP_MD_CTX_md_data(ctx);
    unsigned int message_part = SHA_MSG_PART_MIDDLE, fill_size = 0;
    unsigned long in_data_len = inlen;
    unsigned char tmp_hash[SHA_HASH_LENGTH];

    if (in_data_len == 0)
        return 1;

    if (ibmca_sha_ctx->c.runningLength == 0 && ibmca_sha_ctx->tail_len == 0) {
        message_part = SHA_MSG_PART_FIRST;

        ibmca_sha_ctx->tail_len = in_data_len & 0x3f;
        if (ibmca_sha_ctx->tail_len) {
            in_data_len &= ~0x3f;
            memcpy(ibmca_sha_ctx->tail,
                   in_data + in_data_len, ibmca_sha_ctx->tail_len);
        }
    } else if (ibmca_sha_ctx->c.runningLength == 0
               && ibmca_sha_ctx->tail_len > 0) {
        /* Here we need to fill out the temporary tail buffer until
         * it has 64 bytes in it, then call ica_sha1 on that buffer.
         * If there weren't enough bytes passed in to fill it out,
         * just copy in what we can and return success without calling
         * ica_sha1. - KEY
         */

        fill_size = SHA_BLOCK_SIZE - ibmca_sha_ctx->tail_len;
        if (fill_size < in_data_len) {
            memcpy(ibmca_sha_ctx->tail + ibmca_sha_ctx->tail_len, in_data,
                   fill_size);

            /* Submit the filled out tail buffer */
            if (p_ica_sha1((unsigned int) SHA_MSG_PART_FIRST,
                           (unsigned int) SHA_BLOCK_SIZE, ibmca_sha_ctx->tail,
                           &ibmca_sha_ctx->c, tmp_hash)) {

                IBMCAerr(IBMCA_F_IBMCA_SHA1_UPDATE, IBMCA_R_REQUEST_FAILED);
                return 0;
            }
        } else {
            memcpy(ibmca_sha_ctx->tail + ibmca_sha_ctx->tail_len,
                   in_data, in_data_len);
            ibmca_sha_ctx->tail_len += in_data_len;

            return 1;
        }

        /* We had to use 'fill_size' bytes from in_data to fill out the
         * empty part of save data, so adjust in_data_len
         */
        in_data_len -= fill_size;

        ibmca_sha_ctx->tail_len = in_data_len & 0x3f;
        if (ibmca_sha_ctx->tail_len) {
            in_data_len &= ~0x3f;
            memcpy(ibmca_sha_ctx->tail,
                   in_data + fill_size + in_data_len, ibmca_sha_ctx->tail_len);
            /* fill_size is added to in_data down below */

        }
    } else if (ibmca_sha_ctx->c.runningLength > 0) {
        if (ibmca_sha_ctx->tail_len) {
            fill_size = SHA_BLOCK_SIZE - ibmca_sha_ctx->tail_len;
            if (fill_size < in_data_len) {
                memcpy(ibmca_sha_ctx->tail + ibmca_sha_ctx->tail_len,
                       in_data, fill_size);

                /* Submit the filled out save buffer */
                if (p_ica_sha1(message_part,
                               (unsigned int) SHA_BLOCK_SIZE,
                               ibmca_sha_ctx->tail, &ibmca_sha_ctx->c,
                               tmp_hash)) {

                    IBMCAerr(IBMCA_F_IBMCA_SHA1_UPDATE, IBMCA_R_REQUEST_FAILED);
                    return 0;
                }
            } else {
                memcpy(ibmca_sha_ctx->tail + ibmca_sha_ctx->tail_len,
                       in_data, in_data_len);
                ibmca_sha_ctx->tail_len += in_data_len;

                return 1;
            }

            /*
             * We had to use some of the data from in_data to
             * fill out the empty part of save data, so adjust
             * in_data_len
             */
            in_data_len -= fill_size;

            ibmca_sha_ctx->tail_len = in_data_len & 0x3f;
            if (ibmca_sha_ctx->tail_len) {
                in_data_len &= ~0x3f;
                memcpy(ibmca_sha_ctx->tail,
                       in_data + fill_size + in_data_len,
                       ibmca_sha_ctx->tail_len);
            }
        } else {
            /* This is the odd case, where we need to go ahead and
             * send the first X * 64 byte chunks in to be processed
             * and copy the last <64 byte area into the tail. -KEY
             */
            ibmca_sha_ctx->tail_len = in_data_len & 0x3f;
            if (ibmca_sha_ctx->tail_len) {
                in_data_len &= ~0x3f;
                memcpy(ibmca_sha_ctx->tail, in_data + in_data_len,
                       ibmca_sha_ctx->tail_len);
            }
        }
    }

    /* If the data passed in was <64 bytes, in_data_len will be 0 */
    if (in_data_len &&
        p_ica_sha1(message_part,
                   (unsigned int) in_data_len,
                   (unsigned char *) (in_data + fill_size), &ibmca_sha_ctx->c,
                   tmp_hash)) {

        IBMCAerr(IBMCA_F_IBMCA_SHA1_UPDATE, IBMCA_R_REQUEST_FAILED);
        return 0;
    }

    return 1;
}

static int ibmca_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    IBMCA_SHA_CTX *ibmca_sha_ctx = (IBMCA_SHA_CTX *) EVP_MD_CTX_md_data(ctx);
    unsigned int message_part = 0;

    if (ibmca_sha_ctx->c.runningLength)
        message_part = SHA_MSG_PART_FINAL;
    else
        message_part = SHA_MSG_PART_ONLY;

    if (p_ica_sha1(message_part,
                   ibmca_sha_ctx->tail_len,
                   (unsigned char *) ibmca_sha_ctx->tail,
                   &ibmca_sha_ctx->c, md)) {

        IBMCAerr(IBMCA_F_IBMCA_SHA1_FINAL, IBMCA_R_REQUEST_FAILED);
        return 0;
    }

    return 1;
}

static int ibmca_sha1_cleanup(EVP_MD_CTX *ctx)
{
    return 1;
}
#endif                          /* OPENSSL_NO_SHA1 */


#ifndef OPENSSL_NO_SHA256
static int ibmca_sha256_init(EVP_MD_CTX *ctx)
{
    IBMCA_SHA256_CTX *ibmca_sha256_ctx =
        (IBMCA_SHA256_CTX *) EVP_MD_CTX_md_data(ctx);

    memset((unsigned char *) ibmca_sha256_ctx, 0, sizeof(*ibmca_sha256_ctx));

    return 1;
}

static int ibmca_sha256_update(EVP_MD_CTX *ctx, const void *in_data,
                               unsigned long inlen)
{
    IBMCA_SHA256_CTX *ibmca_sha256_ctx =
        (IBMCA_SHA256_CTX *) EVP_MD_CTX_md_data(ctx);
    unsigned int message_part = SHA_MSG_PART_MIDDLE, fill_size = 0;
    unsigned long in_data_len = inlen;
    unsigned char tmp_hash[SHA256_HASH_LENGTH];

    if (in_data_len == 0)
        return 1;

    if (ibmca_sha256_ctx->c.runningLength == 0
        && ibmca_sha256_ctx->tail_len == 0) {
        message_part = SHA_MSG_PART_FIRST;

        ibmca_sha256_ctx->tail_len = in_data_len & 0x3f;
        if (ibmca_sha256_ctx->tail_len) {
            in_data_len &= ~0x3f;
            memcpy(ibmca_sha256_ctx->tail, in_data + in_data_len,
                   ibmca_sha256_ctx->tail_len);
        }
    } else if (ibmca_sha256_ctx->c.runningLength == 0
               && ibmca_sha256_ctx->tail_len > 0) {
        /* Here we need to fill out the temporary tail buffer
         * until it has 64 bytes in it, then call ica_sha256 on
         * that buffer.  If there weren't enough bytes passed
         * in to fill it out, just copy in what we can and
         * return success without calling ica_sha256. - KEY */

        fill_size = SHA256_BLOCK_SIZE - ibmca_sha256_ctx->tail_len;
        if (fill_size < in_data_len) {
            memcpy(ibmca_sha256_ctx->tail
                   + ibmca_sha256_ctx->tail_len, in_data, fill_size);

            /* Submit the filled out tail buffer */
            if (p_ica_sha256((unsigned int) SHA_MSG_PART_FIRST,
                             (unsigned int) SHA256_BLOCK_SIZE,
                             ibmca_sha256_ctx->tail,
                             &ibmca_sha256_ctx->c, tmp_hash)) {
                IBMCAerr(IBMCA_F_IBMCA_SHA256_UPDATE, IBMCA_R_REQUEST_FAILED);
                return 0;
            }
        } else {
            memcpy(ibmca_sha256_ctx->tail
                   + ibmca_sha256_ctx->tail_len, in_data, in_data_len);
            ibmca_sha256_ctx->tail_len += in_data_len;
            return 1;
        }

        /* We had to use 'fill_size' bytes from in_data to fill out the
         * empty part of save data, so adjust in_data_len */
        in_data_len -= fill_size;

        ibmca_sha256_ctx->tail_len = in_data_len & 0x3f;
        if (ibmca_sha256_ctx->tail_len) {
            in_data_len &= ~0x3f;
            memcpy(ibmca_sha256_ctx->tail,
                   in_data + fill_size + in_data_len,
                   ibmca_sha256_ctx->tail_len);
            /* fill_size is added to in_data down below */
        }
    } else if (ibmca_sha256_ctx->c.runningLength > 0) {
        if (ibmca_sha256_ctx->tail_len) {
            fill_size = SHA256_BLOCK_SIZE - ibmca_sha256_ctx->tail_len;
            if (fill_size < in_data_len) {
                memcpy(ibmca_sha256_ctx->tail
                       + ibmca_sha256_ctx->tail_len, in_data, fill_size);

                /* Submit the filled out save buffer */
                if (p_ica_sha256(message_part,
                                 (unsigned int) SHA256_BLOCK_SIZE,
                                 ibmca_sha256_ctx->tail,
                                 &ibmca_sha256_ctx->c, tmp_hash)) {
                    IBMCAerr(IBMCA_F_IBMCA_SHA256_UPDATE,
                             IBMCA_R_REQUEST_FAILED);
                    return 0;
                }
            } else {
                memcpy(ibmca_sha256_ctx->tail
                       + ibmca_sha256_ctx->tail_len, in_data, in_data_len);
                ibmca_sha256_ctx->tail_len += in_data_len;
                return 1;
            }

            /*
             * We had to use some of the data from in_data to
             * fill out the empty part of save data, so adjust
             * in_data_len
             */
            in_data_len -= fill_size;

            ibmca_sha256_ctx->tail_len = in_data_len & 0x3f;
            if (ibmca_sha256_ctx->tail_len) {
                in_data_len &= ~0x3f;
                memcpy(ibmca_sha256_ctx->tail,
                       in_data + fill_size + in_data_len,
                       ibmca_sha256_ctx->tail_len);
            }
        } else {
            /* This is the odd case, where we need to go
             * ahead and send the first X * 64 byte chunks
             * in to be processed and copy the last <64
             * byte area into the tail. -KEY */
            ibmca_sha256_ctx->tail_len = in_data_len & 0x3f;
            if (ibmca_sha256_ctx->tail_len) {
                in_data_len &= ~0x3f;
                memcpy(ibmca_sha256_ctx->tail,
                       in_data + in_data_len, ibmca_sha256_ctx->tail_len);
            }
        }
    }

    /* If the data passed in was <64 bytes, in_data_len will be 0 */
    if (in_data_len &&
        p_ica_sha256(message_part,
                     (unsigned int) in_data_len,
                     (unsigned char *) (in_data + fill_size),
                     &ibmca_sha256_ctx->c, tmp_hash)) {
        IBMCAerr(IBMCA_F_IBMCA_SHA256_UPDATE, IBMCA_R_REQUEST_FAILED);
        return 0;
    }

    return 1;
}

static int ibmca_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    IBMCA_SHA256_CTX *ibmca_sha256_ctx =
        (IBMCA_SHA256_CTX *) EVP_MD_CTX_md_data(ctx);
    unsigned int message_part = 0;

    if (ibmca_sha256_ctx->c.runningLength)
        message_part = SHA_MSG_PART_FINAL;
    else
        message_part = SHA_MSG_PART_ONLY;

    if (p_ica_sha256(message_part,
                     ibmca_sha256_ctx->tail_len,
                     (unsigned char *) ibmca_sha256_ctx->tail,
                     &ibmca_sha256_ctx->c, md)) {
        IBMCAerr(IBMCA_F_IBMCA_SHA256_FINAL, IBMCA_R_REQUEST_FAILED);
        return 0;
    }

    return 1;
}

static int ibmca_sha256_cleanup(EVP_MD_CTX *ctx)
{
    return 1;
}
#endif                          /* OPENSSL_NO_SHA256 */


#ifndef OPENSSL_NO_SHA512
static int ibmca_sha512_init(EVP_MD_CTX *ctx)
{
    IBMCA_SHA512_CTX *ibmca_sha512_ctx =
        (IBMCA_SHA512_CTX *) EVP_MD_CTX_md_data(ctx);

    memset((unsigned char *) ibmca_sha512_ctx, 0, sizeof(*ibmca_sha512_ctx));

    return 1;
}

static int ibmca_sha512_update(EVP_MD_CTX *ctx, const void *in_data,
                               unsigned long inlen)
{
    IBMCA_SHA512_CTX *ibmca_sha512_ctx =
        (IBMCA_SHA512_CTX *) EVP_MD_CTX_md_data(ctx);
    unsigned int message_part = SHA_MSG_PART_MIDDLE, fill_size = 0;
    unsigned long in_data_len = inlen;
    unsigned char tmp_hash[SHA512_HASH_LENGTH];

    if (in_data_len == 0)
        return 1;

    if (ibmca_sha512_ctx->c.runningLengthLow == 0
        && ibmca_sha512_ctx->tail_len == 0) {
        message_part = SHA_MSG_PART_FIRST;

        ibmca_sha512_ctx->tail_len = in_data_len & 0x7f;
        if (ibmca_sha512_ctx->tail_len) {
            in_data_len &= ~0x7f;
            memcpy(ibmca_sha512_ctx->tail, in_data + in_data_len,
                   ibmca_sha512_ctx->tail_len);
        }
    } else if (ibmca_sha512_ctx->c.runningLengthLow == 0
               && ibmca_sha512_ctx->tail_len > 0) {
        /* Here we need to fill out the temporary tail buffer
         * until it has 128 bytes in it, then call ica_sha512 on
         * that buffer.  If there weren't enough bytes passed
         * in to fill it out, just copy in what we can and
         * return success without calling ica_sha512.
         */

        fill_size = SHA512_BLOCK_SIZE - ibmca_sha512_ctx->tail_len;
        if (fill_size < in_data_len) {
            memcpy(ibmca_sha512_ctx->tail
                   + ibmca_sha512_ctx->tail_len, in_data, fill_size);

            /* Submit the filled out tail buffer */
            if (p_ica_sha512((unsigned int) SHA_MSG_PART_FIRST,
                             (unsigned int) SHA512_BLOCK_SIZE,
                             ibmca_sha512_ctx->tail,
                             &ibmca_sha512_ctx->c, tmp_hash)) {
                IBMCAerr(IBMCA_F_IBMCA_SHA512_UPDATE, IBMCA_R_REQUEST_FAILED);
                return 0;
            }
        } else {
            memcpy(ibmca_sha512_ctx->tail
                   + ibmca_sha512_ctx->tail_len, in_data, in_data_len);
            ibmca_sha512_ctx->tail_len += in_data_len;
            return 1;
        }

        /* We had to use 'fill_size' bytes from in_data to fill out the
         * empty part of save data, so adjust in_data_len
         */
        in_data_len -= fill_size;

        ibmca_sha512_ctx->tail_len = in_data_len & 0x7f;
        if (ibmca_sha512_ctx->tail_len) {
            in_data_len &= ~0x7f;
            memcpy(ibmca_sha512_ctx->tail,
                   in_data + fill_size + in_data_len,
                   ibmca_sha512_ctx->tail_len);
            /* fill_size is added to in_data down below */
        }
    } else if (ibmca_sha512_ctx->c.runningLengthLow > 0) {
        if (ibmca_sha512_ctx->tail_len) {
            fill_size = SHA512_BLOCK_SIZE - ibmca_sha512_ctx->tail_len;
            if (fill_size < in_data_len) {
                memcpy(ibmca_sha512_ctx->tail
                       + ibmca_sha512_ctx->tail_len, in_data, fill_size);

                /* Submit the filled out save buffer */
                if (p_ica_sha512(message_part,
                                 (unsigned int) SHA512_BLOCK_SIZE,
                                 ibmca_sha512_ctx->tail,
                                 &ibmca_sha512_ctx->c, tmp_hash)) {
                    IBMCAerr(IBMCA_F_IBMCA_SHA512_UPDATE,
                             IBMCA_R_REQUEST_FAILED);
                    return 0;
                }
            } else {
                memcpy(ibmca_sha512_ctx->tail
                       + ibmca_sha512_ctx->tail_len, in_data, in_data_len);
                ibmca_sha512_ctx->tail_len += in_data_len;
                return 1;
            }

            /*
             * We had to use some of the data from in_data to
             * fill out the empty part of save data, so adjust
             * in_data_len
             */
            in_data_len -= fill_size;

            ibmca_sha512_ctx->tail_len = in_data_len & 0x7f;
            if (ibmca_sha512_ctx->tail_len) {
                in_data_len &= ~0x7f;
                memcpy(ibmca_sha512_ctx->tail,
                       in_data + fill_size + in_data_len,
                       ibmca_sha512_ctx->tail_len);
            }
        } else {
            /* This is the odd case, where we need to go
             * ahead and send the first X * 128 byte chunks
             * in to be processed and copy the last <128
             * byte area into the tail.
             */
            ibmca_sha512_ctx->tail_len = in_data_len & 0x7f;
            if (ibmca_sha512_ctx->tail_len) {
                in_data_len &= ~0x7f;
                memcpy(ibmca_sha512_ctx->tail,
                       in_data + in_data_len, ibmca_sha512_ctx->tail_len);
            }
        }
    }

    /* If the data passed in was <128 bytes, in_data_len will be 0 */
    if (in_data_len &&
        p_ica_sha512(message_part, (unsigned int) in_data_len,
                     (unsigned char *) (in_data + fill_size),
                     &ibmca_sha512_ctx->c, tmp_hash)) {
        IBMCAerr(IBMCA_F_IBMCA_SHA512_UPDATE, IBMCA_R_REQUEST_FAILED);
        return 0;
    }

    return 1;
}

static int ibmca_sha512_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    IBMCA_SHA512_CTX *ibmca_sha512_ctx =
        (IBMCA_SHA512_CTX *) EVP_MD_CTX_md_data(ctx);
    unsigned int message_part = 0;

    if (ibmca_sha512_ctx->c.runningLengthLow)
        message_part = SHA_MSG_PART_FINAL;
    else
        message_part = SHA_MSG_PART_ONLY;

    if (p_ica_sha512(message_part, ibmca_sha512_ctx->tail_len,
                     (unsigned char *) ibmca_sha512_ctx->tail,
                     &ibmca_sha512_ctx->c, md)) {
        IBMCAerr(IBMCA_F_IBMCA_SHA512_FINAL, IBMCA_R_REQUEST_FAILED);
        return 0;
    }

    return 1;
}

static int ibmca_sha512_cleanup(EVP_MD_CTX *ctx)
{
    return 1;
}
#endif                          /* OPENSSL_NO_SHA512 */


#ifdef OLDER_OPENSSL
# define DECLARE_SHA_EVP(type, pkey_type, md_size, flags,               \
                         block_size, ctx_size, init, update,            \
                         final, copy, cleanup)                          \
static const EVP_MD type##_md = {                                       \
    NID_##type,                                                         \
    NID_##pkey_type,                                                    \
    md_size,                                                            \
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|flags,                            \
    init,                                                               \
    update,                                                             \
    final,                                                              \
    copy,                                                               \
    cleanup,                                                            \
    EVP_PKEY_RSA_method,                                                \
    block_size,                                                         \
    ctx_size                                                            \
};                                                                      \
const EVP_MD *ibmca_##type(void)                                        \
{                                                                       \
    return &type##_md;                                                  \
}

#else
# define DECLARE_SHA_EVP(type, pkey_type, md_size, flags,               \
                         block_size, ctx_size, init, update,            \
                         final, copy, cleanup)                          \
static EVP_MD *type##_md = NULL;                                        \
const EVP_MD *ibmca_##type(void)                                        \
{                                                                       \
    EVP_MD *md;                                                         \
                                                                        \
    if (type##_md != NULL)                                              \
        goto done;                                                      \
                                                                        \
    if ((md = EVP_MD_meth_new(NID_##type, NID_##pkey_type)) == NULL     \
         || !EVP_MD_meth_set_result_size(md, md_size)                   \
         || !EVP_MD_meth_set_input_blocksize(md, block_size)            \
         || !EVP_MD_meth_set_app_datasize(md, ctx_size)                 \
         || !EVP_MD_meth_set_flags(md, flags)                           \
         || !EVP_MD_meth_set_init(md, init)                             \
         || !EVP_MD_meth_set_update(md, update)                         \
         || !EVP_MD_meth_set_final(md, final)                           \
         || !EVP_MD_meth_set_cleanup(md, cleanup)) {                    \
        EVP_MD_meth_free(md);                                           \
        md = NULL;                                                      \
    }                                                                   \
    type##_md = md;                                                     \
done:                                                                   \
    return type##_md;                                                   \
}                                                                       \
                                                                        \
void ibmca_##type##_destroy(void)                                       \
{                                                                       \
    EVP_MD_meth_free(type##_md);                                        \
    type##_md = NULL;                                                   \
}
#endif

#ifndef OPENSSL_NO_SHA1
DECLARE_SHA_EVP(sha1, sha1WithRSAEncryption, SHA_HASH_LENGTH,
                EVP_MD_FLAG_FIPS, SHA_BLOCK_SIZE,
                sizeof(EVP_MD *) + sizeof(struct ibmca_sha1_ctx),
                ibmca_sha1_init, ibmca_sha1_update, ibmca_sha1_final,
                NULL, ibmca_sha1_cleanup)
#endif
#ifndef OPENSSL_NO_SHA256
DECLARE_SHA_EVP(sha256, sha256WithRSAEncryption, SHA256_HASH_LENGTH,
                EVP_MD_FLAG_FIPS, SHA256_BLOCK_SIZE,
                sizeof(EVP_MD *) + sizeof(struct ibmca_sha256_ctx),
                ibmca_sha256_init, ibmca_sha256_update, ibmca_sha256_final,
                NULL, ibmca_sha256_cleanup)
#endif
#ifndef OPENSSL_NO_SHA512
DECLARE_SHA_EVP(sha512, sha512WithRSAEncryption, SHA512_HASH_LENGTH,
                EVP_MD_FLAG_FIPS, SHA512_BLOCK_SIZE,
                sizeof(EVP_MD *) + sizeof(struct ibmca_sha512_ctx),
                ibmca_sha512_init, ibmca_sha512_update, ibmca_sha512_final,
                NULL, ibmca_sha512_cleanup)
#endif
