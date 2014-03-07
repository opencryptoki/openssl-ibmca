/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 * Digest and Cipher support added by Robert H Burroughs (burrough@us.ibm.com).
 *
 * DES/3DES/AES-CFB/OFB support added by Kent Yoder (yoder1@us.ibm.com)
 *
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2010, 2011 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/aes.h>

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_IBMCA

#include <ica_api.h>

#define IBMCA_LIB_NAME "ibmca engine"
#include "e_ibmca_err.c"

typedef struct ibmca_des_context {
	unsigned char key[sizeof(ica_des_key_triple_t)];
} ICA_DES_CTX;

typedef struct ibmca_aes_128_context {
	unsigned char key[sizeof(ica_aes_key_len_128_t)];
} ICA_AES_128_CTX;

typedef struct ibmca_aes_192_context {
	unsigned char key[sizeof(ica_aes_key_len_192_t)];
} ICA_AES_192_CTX;

typedef struct ibmca_aes_256_context {
	unsigned char key[sizeof(ica_aes_key_len_256_t)];
} ICA_AES_256_CTX;

#ifndef OPENSSL_NO_SHA1
#define SHA_BLOCK_SIZE 64
typedef struct ibmca_sha1_ctx {
	sha_context_t c;
	unsigned char tail[SHA_BLOCK_SIZE];
	unsigned int tail_len;
} IBMCA_SHA_CTX;
#endif

#ifndef OPENSSL_NO_SHA256
#define SHA256_BLOCK_SIZE 64
typedef struct ibmca_sha256_ctx {
	sha256_context_t c;
	unsigned char tail[SHA256_BLOCK_SIZE];
	unsigned int tail_len;
} IBMCA_SHA256_CTX;
#endif

static const char *IBMCA_LIBNAME = "ica";

#if defined(NID_aes_128_cfb128) && ! defined (NID_aes_128_cfb)
#define NID_aes_128_cfb NID_aes_128_cfb128
#endif

#if defined(NID_aes_128_ofb128) && ! defined (NID_aes_128_ofb)
#define NID_aes_128_ofb NID_aes_128_ofb128
#endif

#if defined(NID_aes_192_cfb128) && ! defined (NID_aes_192_cfb)
#define NID_aes_192_cfb NID_aes_192_cfb128
#endif

#if defined(NID_aes_192_ofb128) && ! defined (NID_aes_192_ofb)
#define NID_aes_192_ofb NID_aes_192_ofb128
#endif

#if defined(NID_aes_256_cfb128) && ! defined (NID_aes_256_cfb)
#define NID_aes_256_cfb NID_aes_256_cfb128
#endif

#if defined(NID_aes_256_ofb128) && ! defined (NID_aes_256_ofb)
#define NID_aes_256_ofb NID_aes_256_ofb128
#endif

#if defined(NID_des_ofb64) && ! defined (NID_des_ofb)
#define NID_des_ofb NID_des_ofb64
#endif

#if defined(NID_des_ede3_ofb64) && ! defined (NID_des_ede3_ofb)
#define NID_des_ede3_ofb NID_des_ede3_ofb64
#endif

#if defined(NID_des_cfb64) && ! defined (NID_des_cfb)
#define NID_des_cfb NID_des_cfb64
#endif

#if defined(NID_des_ede3_cfb64) && ! defined (NID_des_ede3_cfb)
#define NID_des_ede3_cfb NID_des_ede3_cfb64
#endif

static int ibmca_cipher_nids[] = {
	NID_des_ecb,
	NID_des_cbc,
	NID_des_ofb,
	NID_des_cfb,
	NID_des_ede3_ecb,
	NID_des_ede3_cbc,
	NID_des_ede3_ofb,
	NID_des_ede3_cfb,
	NID_aes_128_ecb,
	NID_aes_128_cbc,
	NID_aes_128_cfb,
	NID_aes_128_ofb,
	NID_aes_192_ecb,
	NID_aes_192_cbc,
	NID_aes_192_cfb,
	NID_aes_192_ofb,
	NID_aes_256_ecb,
	NID_aes_256_cbc,
	NID_aes_256_cfb,
	NID_aes_256_ofb
};

static int digest_nids[] = { 
#ifndef OPENSSL_NO_SHA1
	NID_sha1,
#endif
#ifndef OPENSSL_NO_SHA256
	NID_sha256
#endif
};

static int ibmca_destroy(ENGINE * e);
static int ibmca_init(ENGINE * e);
static int ibmca_finish(ENGINE * e);
static int ibmca_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ());

static ica_adapter_handle_t ibmca_handle = 0;

/* BIGNUM stuff */
static int ibmca_mod_exp(BIGNUM * r, const BIGNUM * a, const BIGNUM * p,
			 const BIGNUM * m, BN_CTX * ctx);

static int ibmca_mod_exp_crt(BIGNUM * r, const BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * q,
			     const BIGNUM * dmp1, const BIGNUM * dmq1,
			     const BIGNUM * iqmp, BN_CTX * ctx);

#ifndef OPENSSL_NO_RSA
/* RSA stuff */
static int ibmca_rsa_mod_exp(BIGNUM * r0, const BIGNUM * I, RSA * rsa,
                             BN_CTX *ctx);

static int ibmca_rsa_init(RSA *rsa);
#endif

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int ibmca_mod_exp_mont(BIGNUM * r, const BIGNUM * a,
			      const BIGNUM * p, const BIGNUM * m,
			      BN_CTX * ctx, BN_MONT_CTX * m_ctx);

#ifndef OPENSSL_NO_DSA
/* DSA stuff */
static int ibmca_dsa_mod_exp(DSA * dsa, BIGNUM * rr, BIGNUM * a1,
			     BIGNUM * p1, BIGNUM * a2, BIGNUM * p2,
			     BIGNUM * m, BN_CTX * ctx,
			     BN_MONT_CTX * in_mont);
static int ibmca_mod_exp_dsa(DSA * dsa, BIGNUM * r, BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * m,
			     BN_CTX * ctx, BN_MONT_CTX * m_ctx);
#endif

#ifndef OPENSSL_NO_DH
/* DH stuff */
/* This function is alised to mod_exp (with the DH and mont dropped). */
static int ibmca_mod_exp_dh(const DH * dh, BIGNUM * r,
			    const BIGNUM * a, const BIGNUM * p,
			    const BIGNUM * m, BN_CTX * ctx,
			    BN_MONT_CTX * m_ctx);
#endif

/* RAND stuff */
static int ibmca_rand_bytes(unsigned char *buf, int num);
static int ibmca_rand_status(void);

/* DES, TDES, AES declarations */
static int ibmca_usable_ciphers(const int **nids);

static int ibmca_engine_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
				const int **nids, int nid);

static int ibmca_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
			  const unsigned char *iv, int enc);

static int ibmca_des_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
			    const unsigned char *in, size_t inlen);

static int ibmca_tdes_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
			     const unsigned char *in, size_t inlen);

static int ibmca_aes_128_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				const unsigned char *in, size_t inlen);

static int ibmca_aes_192_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				const unsigned char *in, size_t inlen);

static int ibmca_aes_256_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				const unsigned char *in, size_t inlen);

static int ibmca_cipher_cleanup(EVP_CIPHER_CTX * ctx);

/* Sha1 stuff */
static int ibmca_usable_digests(const int **nids);

static int ibmca_engine_digests(ENGINE * e, const EVP_MD ** digest,
				const int **nids, int nid);

#ifndef OPENSSL_NO_SHA1
static int ibmca_sha1_init(EVP_MD_CTX * ctx);

static int ibmca_sha1_update(EVP_MD_CTX * ctx, const void *data,
			     unsigned long count);

static int ibmca_sha1_final(EVP_MD_CTX * ctx, unsigned char *md);

static int ibmca_sha1_cleanup(EVP_MD_CTX * ctx);
#endif

#ifndef OPENSSL_NO_SHA256
static int ibmca_sha256_init(EVP_MD_CTX * ctx);

static int ibmca_sha256_update(EVP_MD_CTX * ctx, const void *data,
			     unsigned long count);

static int ibmca_sha256_final(EVP_MD_CTX * ctx, unsigned char *md);

static int ibmca_sha256_cleanup(EVP_MD_CTX * ctx);
#endif

/* WJH - check for more commands, like in nuron */

/* The definitions for control commands specific to this engine */
#define IBMCA_CMD_SO_PATH		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN ibmca_cmd_defns[] = {
	{IBMCA_CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the 'atasi' shared library",
	 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};

#ifndef OPENSSL_NO_RSA
/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD ibmca_rsa = {
	"Ibmca RSA method",      /* name */
	NULL,                    /* rsa_pub_enc */
	NULL,                    /* rsa_pub_dec */
	NULL,                    /* rsa_priv_enc */
	NULL,                    /* rsa_priv_dec */
	ibmca_rsa_mod_exp,       /* rsa_mod_exp */
	ibmca_mod_exp_mont,      /* bn_mod_exp */
	ibmca_rsa_init,          /* init */
	NULL,                    /* finish */
	0,                       /* flags */
	NULL,                    /* app_data */
	NULL,                    /* rsa_sign */
	NULL                     /* rsa_verify */
};
#endif

#ifndef OPENSSL_NO_DSA
/* Our internal DSA_METHOD that we provide pointers to */
static DSA_METHOD ibmca_dsa = {
	"Ibmca DSA method",     /* name */
	NULL,			/* dsa_do_sign */
	NULL,			/* dsa_sign_setup */
	NULL,			/* dsa_do_verify */
	ibmca_dsa_mod_exp,	/* dsa_mod_exp */
	ibmca_mod_exp_dsa,	/* bn_mod_exp */
	NULL,			/* init */
	NULL,			/* finish */
	0,			/* flags */
	NULL			/* app_data */
};
#endif

#ifndef OPENSSL_NO_DH
/* Our internal DH_METHOD that we provide pointers to */
static DH_METHOD ibmca_dh = {
	"Ibmca DH method",     /* name */
	NULL,                  /* generate_key */
	NULL,                  /* compute_key */
	ibmca_mod_exp_dh,      /* bn_mod_exp */
	NULL,                  /* init */
	NULL,                  /* finish */
	0,                     /* flags */
	NULL                   /* app_data */
};
#endif

static RAND_METHOD ibmca_rand = {
	/* "IBMCA RAND method", */
	NULL,                  /* seed */
	ibmca_rand_bytes,      /* bytes */
	NULL,                  /* cleanup */
	NULL,                  /* add */
	ibmca_rand_bytes,      /* pseudorand */
	ibmca_rand_status,     /* status */
};

/* DES ECB EVP */
const EVP_CIPHER ibmca_des_ecb = {
	NID_des_ecb,                  /* nid */
	sizeof(ica_des_vector_t),     /* block_size */
	sizeof(ica_des_key_single_t), /* key_len */
	sizeof(ica_des_vector_t),     /* iv_len */
	EVP_CIPH_ECB_MODE,            /* flags */
	ibmca_init_key,               /* init */
	ibmca_des_cipher,             /* do_cipher */
	ibmca_cipher_cleanup,         /* cleanup */
	sizeof(struct ibmca_des_context), /* ctx_size */
	EVP_CIPHER_set_asn1_iv,       /* set_asn1_parameters */
	EVP_CIPHER_get_asn1_iv,       /* get_asn1_parameters */
	NULL,                         /* ctrl */
	NULL                          /* app_data */
};

/* DES CBC EVP */
const EVP_CIPHER ibmca_des_cbc = {
	NID_des_cbc,
	sizeof(ica_des_vector_t),
	sizeof(ica_des_key_single_t),
	sizeof(ica_des_vector_t),
	EVP_CIPH_CBC_MODE,
	ibmca_init_key,
	ibmca_des_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_des_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* DES OFB EVP */
const EVP_CIPHER ibmca_des_ofb = {
	NID_des_ofb,
	sizeof(ica_des_vector_t),
	sizeof(ica_des_key_single_t),
	sizeof(ica_des_vector_t),
	EVP_CIPH_OFB_MODE,
	ibmca_init_key, /* XXX check me */
	ibmca_des_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_des_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* DES CFB EVP */
const EVP_CIPHER ibmca_des_cfb = {
	NID_des_cfb,
	sizeof(ica_des_vector_t),
	sizeof(ica_des_key_single_t),
	sizeof(ica_des_vector_t),
	EVP_CIPH_CFB_MODE,
	ibmca_init_key, /* XXX check me */
	ibmca_des_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_des_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* 3DES ECB EVP	*/
const EVP_CIPHER ibmca_tdes_ecb = {
	NID_des_ede3_ecb,
	sizeof(ica_des_vector_t),
	sizeof(ica_des_key_triple_t),
	sizeof(ica_des_vector_t),
	EVP_CIPH_ECB_MODE,
	ibmca_init_key,
	ibmca_tdes_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_des_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* 3DES CBC EVP	*/
const EVP_CIPHER ibmca_tdes_cbc = {
	NID_des_ede3_cbc,
	sizeof(ica_des_vector_t),
	sizeof(ica_des_key_triple_t),
	sizeof(ica_des_vector_t),
	EVP_CIPH_CBC_MODE,
	ibmca_init_key,
	ibmca_tdes_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_des_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* 3DES OFB EVP */
const EVP_CIPHER ibmca_tdes_ofb = {
	NID_des_ede3_ofb,
	sizeof(ica_des_vector_t),
	sizeof(ica_des_key_triple_t),
	sizeof(ica_des_vector_t),
	EVP_CIPH_OFB_MODE,
	ibmca_init_key, /* XXX check me */
	ibmca_tdes_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_des_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* 3DES CFB EVP */
const EVP_CIPHER ibmca_tdes_cfb = {
	NID_des_ede3_cfb,
	sizeof(ica_des_vector_t),
	sizeof(ica_des_key_triple_t),
	sizeof(ica_des_vector_t),
	EVP_CIPH_CFB_MODE,
	ibmca_init_key, /* XXX check me */
	ibmca_tdes_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_des_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-128 ECB EVP */
const EVP_CIPHER ibmca_aes_128_ecb = {
	NID_aes_128_ecb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_128_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_ECB_MODE,
	ibmca_init_key,
	ibmca_aes_128_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_128_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-128 CBC EVP */
const EVP_CIPHER ibmca_aes_128_cbc = {
	NID_aes_128_cbc,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_128_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_CBC_MODE,
	ibmca_init_key,
	ibmca_aes_128_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_128_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-128 OFB EVP */
const EVP_CIPHER ibmca_aes_128_ofb = {
	NID_aes_128_ofb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_128_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_OFB_MODE,
	ibmca_init_key,
	ibmca_aes_128_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_128_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-128 CFB EVP */
const EVP_CIPHER ibmca_aes_128_cfb = {
	NID_aes_128_cfb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_128_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_CFB_MODE,
	ibmca_init_key,
	ibmca_aes_128_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_128_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-192 ECB EVP */
const EVP_CIPHER ibmca_aes_192_ecb = {
	NID_aes_192_ecb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_192_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_ECB_MODE,
	ibmca_init_key,
	ibmca_aes_192_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_192_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-192 CBC EVP */
const EVP_CIPHER ibmca_aes_192_cbc = {
	NID_aes_192_cbc,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_192_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_CBC_MODE,
	ibmca_init_key,
	ibmca_aes_192_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_192_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-192 OFB EVP */
const EVP_CIPHER ibmca_aes_192_ofb = {
	NID_aes_192_ofb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_192_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_OFB_MODE,
	ibmca_init_key,
	ibmca_aes_192_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_192_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-192 CFB EVP */
const EVP_CIPHER ibmca_aes_192_cfb = {
	NID_aes_192_cfb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_192_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_CFB_MODE,
	ibmca_init_key,
	ibmca_aes_192_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_192_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-256 ECB EVP */
const EVP_CIPHER ibmca_aes_256_ecb = {
	NID_aes_256_ecb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_256_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_ECB_MODE,
	ibmca_init_key,
	ibmca_aes_256_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_256_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-256 CBC EVP */
const EVP_CIPHER ibmca_aes_256_cbc = {
	NID_aes_256_cbc,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_256_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_CBC_MODE,
	ibmca_init_key,
	ibmca_aes_256_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_256_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-256 OFB EVP */
const EVP_CIPHER ibmca_aes_256_ofb = {
	NID_aes_256_ofb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_256_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_OFB_MODE,
	ibmca_init_key,
	ibmca_aes_256_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_256_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* AES-256 CFB EVP */
const EVP_CIPHER ibmca_aes_256_cfb = {
	NID_aes_256_cfb,
	sizeof(ica_aes_vector_t),
	sizeof(ica_aes_key_len_256_t),
	sizeof(ica_aes_vector_t),
	EVP_CIPH_CFB_MODE,
	ibmca_init_key,
	ibmca_aes_256_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_aes_256_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

#ifndef OPENSSL_NO_SHA1
static const EVP_MD ibmca_sha1 = {
	NID_sha1,
	NID_sha1WithRSAEncryption,
	SHA_HASH_LENGTH,
	0,
	ibmca_sha1_init,
	ibmca_sha1_update,
	ibmca_sha1_final,
	NULL,
	ibmca_sha1_cleanup,
	EVP_PKEY_RSA_method,
	SHA_BLOCK_SIZE,
	sizeof(EVP_MD *) + sizeof(struct ibmca_sha1_ctx)
};
#endif

#ifndef OPENSSL_NO_SHA256
static const EVP_MD ibmca_sha256 = {
	NID_sha256,
	NID_sha256WithRSAEncryption,
	SHA256_HASH_LENGTH,
	0,
	ibmca_sha256_init,
	ibmca_sha256_update,
	ibmca_sha256_final,
	NULL,
	ibmca_sha256_cleanup,
	EVP_PKEY_RSA_method,
	SHA_BLOCK_SIZE,
	sizeof(EVP_MD *) + sizeof(struct ibmca_sha256_ctx)
};
#endif

/* Constants used when creating the ENGINE */
static const char *engine_ibmca_id = "ibmca";
static const char *engine_ibmca_name = "Ibmca hardware engine support";

/* This internal function is used by ENGINE_ibmca() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE * e)
{
#ifndef OPENSSL_NO_RSA
	const RSA_METHOD *meth1;
#endif
#ifndef OPENSSL_NO_DSA
	const DSA_METHOD *meth2;
#endif
#ifndef OPENSSL_NO_DH
	const DH_METHOD *meth3;
#endif
	if (!ENGINE_set_id(e, engine_ibmca_id) ||
	    !ENGINE_set_name(e, engine_ibmca_name) ||
#ifndef OPENSSL_NO_RSA
	    !ENGINE_set_RSA(e, &ibmca_rsa) ||
#endif
#ifndef OPENSSL_NO_DSA
	    !ENGINE_set_DSA(e, &ibmca_dsa) ||
#endif
#ifndef OPENSSL_NO_DH
	    !ENGINE_set_DH(e, &ibmca_dh) ||
#endif
	    !ENGINE_set_RAND(e, &ibmca_rand) ||
	    !ENGINE_set_ciphers(e, ibmca_engine_ciphers) ||
	    !ENGINE_set_digests(e, ibmca_engine_digests) ||
	    !ENGINE_set_destroy_function(e, ibmca_destroy) ||
	    !ENGINE_set_init_function(e, ibmca_init) ||
	    !ENGINE_set_finish_function(e, ibmca_finish) ||
	    !ENGINE_set_ctrl_function(e, ibmca_ctrl) ||
	    !ENGINE_set_cmd_defns(e, ibmca_cmd_defns))
		return 0;

#ifndef OPENSSL_NO_RSA
	/* We know that the "PKCS1_SSLeay()" functions hook properly
	 * to the ibmca-specific mod_exp and mod_exp_crt so we use
	 * those functions. NB: We don't use ENGINE_openssl() or
	 * anything "more generic" because something like the RSAref
	 * code may not hook properly, and if you own one of these here
	 * cards then you have the right to do RSA operations on it
	 * anyway! */
	meth1 = RSA_PKCS1_SSLeay();
	ibmca_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
	ibmca_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
	ibmca_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
	ibmca_rsa.rsa_priv_dec = meth1->rsa_priv_dec;
#endif

#ifndef OPENSSL_NO_DSA
	/* Use the DSA_OpenSSL() method and just hook the mod_exp-ish
	 * bits. */
	meth2 = DSA_OpenSSL();
	ibmca_dsa.dsa_do_sign = meth2->dsa_do_sign;
	ibmca_dsa.dsa_sign_setup = meth2->dsa_sign_setup;
	ibmca_dsa.dsa_do_verify = meth2->dsa_do_verify;
#endif

#ifndef OPENSSL_NO_DH
	/* Much the same for Diffie-Hellman */
	meth3 = DH_OpenSSL();
	ibmca_dh.generate_key = meth3->generate_key;
	ibmca_dh.compute_key = meth3->compute_key;
#endif

	/* Ensure the ibmca error handling is set up */
	ERR_load_IBMCA_strings();
	return 1;
}

static ENGINE *engine_ibmca(void)
{
	ENGINE *ret = ENGINE_new();
	if (!ret)
		return NULL;
	if (!bind_helper(ret)) {
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void ENGINE_load_ibmca(void)
{
	/* Copied from eng_[openssl|dyn].c */
	ENGINE *toadd = engine_ibmca();
	if (!toadd)
		return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
}

/* Destructor (complements the "ENGINE_ibmca()" constructor) */
static int ibmca_destroy(ENGINE * e)
{
	/* Unload the ibmca error strings so any error state including our
	 * functs or reasons won't lead to a segfault (they simply get displayed
	 * without corresponding string data because none will be found). */
	ERR_unload_IBMCA_strings();
	return 1;
}

/* This is a process-global DSO handle used for loading and unloading
 * the Ibmca library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */

static DSO *ibmca_dso = NULL;

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */

typedef unsigned int (*ica_open_adapter_t)(ica_adapter_handle_t *);
typedef unsigned int (*ica_close_adapter_t)(ica_adapter_handle_t);
typedef unsigned int (*ica_rsa_mod_expo_t)(ica_adapter_handle_t, unsigned char *,
			ica_rsa_key_mod_expo_t *, unsigned char *);
typedef unsigned int (*ica_random_number_generate_t)(unsigned int, unsigned char *);
typedef unsigned int (*ica_rsa_crt_t)(ica_adapter_handle_t, unsigned char *,
			ica_rsa_key_crt_t *, unsigned char *);
typedef unsigned int (*ica_sha1_t)(unsigned int, unsigned int, unsigned char *, sha_context_t *,
			unsigned char *);
typedef unsigned int (*ica_des_encrypt_t)(unsigned int, unsigned int, unsigned char *,
			ica_des_vector_t *, ica_des_key_single_t *, unsigned char *);
typedef unsigned int (*ica_des_decrypt_t)(unsigned int, unsigned int, unsigned char *,
			ica_des_vector_t *, ica_des_key_single_t *, unsigned char *);
typedef unsigned int (*ica_3des_encrypt_t)(unsigned int, unsigned int, unsigned char *,
			ica_des_vector_t *, ica_des_key_triple_t *, unsigned char *);
typedef unsigned int (*ica_3des_decrypt_t)(unsigned int, unsigned int, unsigned char *,
			ica_des_vector_t *, ica_des_key_triple_t *, unsigned char *);
typedef unsigned int (*ica_aes_encrypt_t)(unsigned int, unsigned int, unsigned char *,
			ica_aes_vector_t *, unsigned int, unsigned char *, unsigned char *);
typedef unsigned int (*ica_aes_decrypt_t)(unsigned int, unsigned int, unsigned char *,
			ica_aes_vector_t *, unsigned int, unsigned char *, unsigned char *);
typedef unsigned int (*ica_sha256_t)(unsigned int, unsigned int, unsigned char *,
			sha256_context_t *, unsigned char *);
typedef unsigned int (*ica_des_ofb_t)(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned int key_length, unsigned char *iv,
			 unsigned int direction);
typedef unsigned int (*ica_des_cfb_t)(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned char *iv, unsigned int lcfb,
			 unsigned int direction);
typedef unsigned int (*ica_3des_cfb_t)(const unsigned char *, unsigned char *,
			unsigned long, const unsigned char *, unsigned char *,
			unsigned int, unsigned int);
typedef unsigned int (*ica_3des_ofb_t)(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
			  unsigned int key_length, unsigned char *iv,
			  unsigned int direction);
typedef unsigned int (*ica_aes_ofb_t)(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned int key_length, unsigned char *iv,
			 unsigned int direction);
typedef unsigned int (*ica_aes_cfb_t)(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
			 unsigned int key_length, unsigned char *iv, unsigned int lcfb,
			 unsigned int direction);

/* entry points into libica, filled out at DSO load time */
ica_open_adapter_t		p_ica_open_adapter;
ica_close_adapter_t		p_ica_close_adapter;
ica_rsa_mod_expo_t		p_ica_rsa_mod_expo;
ica_random_number_generate_t	p_ica_random_number_generate;
ica_rsa_crt_t			p_ica_rsa_crt;
ica_sha1_t			p_ica_sha1;
ica_des_encrypt_t		p_ica_des_encrypt;
ica_des_decrypt_t		p_ica_des_decrypt;
ica_3des_encrypt_t		p_ica_3des_encrypt;
ica_3des_decrypt_t		p_ica_3des_decrypt;
ica_aes_encrypt_t		p_ica_aes_encrypt;
ica_aes_decrypt_t		p_ica_aes_decrypt;
ica_sha256_t			p_ica_sha256;
ica_des_ofb_t			p_ica_des_ofb;
ica_des_cfb_t			p_ica_des_cfb;
ica_3des_cfb_t			p_ica_3des_cfb;
ica_3des_ofb_t			p_ica_3des_ofb;
ica_aes_ofb_t			p_ica_aes_ofb;
ica_aes_cfb_t			p_ica_aes_cfb;

/* utility function to obtain a context */
static int get_context(ica_adapter_handle_t * p_handle)
{
	unsigned int status = 0;

	status = p_ica_open_adapter(p_handle);
	if (status != 0)
		return 0;
	return 1;
}

/* similarly to release one. */
static void release_context(ica_adapter_handle_t i_handle)
{
	p_ica_close_adapter(i_handle);
}

/* (de)initialisation functions. */
static int ibmca_init(ENGINE * e)
{
	if (ibmca_dso != NULL) {
		IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_ALREADY_LOADED);
		goto err;
	}
	/* Attempt to load libatasi.so/atasi.dll/whatever. Needs to be
	 * changed unfortunately because the Ibmca drivers don't have
	 * standard library names that can be platform-translated well. */
	/* TODO: Work out how to actually map to the names the Ibmca
	 * drivers really use - for now a symbollic link needs to be
	 * created on the host system from libatasi.so to atasi.so on
	 * unix variants. */

	/* WJH XXX check name translation */

	ibmca_dso = DSO_load(NULL, IBMCA_LIBNAME, NULL,
			     /* DSO_FLAG_NAME_TRANSLATION */ 0);
	if (ibmca_dso == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_DSO_FAILURE);
		goto err;
	}

	if (!(p_ica_open_adapter = (ica_open_adapter_t)DSO_bind_func(ibmca_dso, "ica_open_adapter"))
	    || !(p_ica_close_adapter = (ica_close_adapter_t)DSO_bind_func(ibmca_dso,
									  "ica_close_adapter"))
	    || !(p_ica_rsa_mod_expo = (ica_rsa_mod_expo_t)DSO_bind_func(ibmca_dso,
									"ica_rsa_mod_expo"))
	    || !(p_ica_random_number_generate =
		    (ica_random_number_generate_t)DSO_bind_func(ibmca_dso,
								"ica_random_number_generate"))
	    || !(p_ica_rsa_crt = (ica_rsa_crt_t)DSO_bind_func(ibmca_dso, "ica_rsa_crt"))
	    || !(p_ica_sha1 = (ica_sha1_t)DSO_bind_func(ibmca_dso, "ica_sha1"))
	    || !(p_ica_des_encrypt = (ica_des_encrypt_t)DSO_bind_func(ibmca_dso, "ica_des_encrypt"))
	    || !(p_ica_des_decrypt = (ica_des_decrypt_t)DSO_bind_func(ibmca_dso, "ica_des_decrypt"))
	    || !(p_ica_3des_encrypt = (ica_3des_encrypt_t)DSO_bind_func(ibmca_dso,
									"ica_3des_encrypt"))
	    || !(p_ica_3des_decrypt = (ica_3des_decrypt_t)DSO_bind_func(ibmca_dso,
									"ica_3des_decrypt"))
	    || !(p_ica_aes_encrypt = (ica_aes_encrypt_t)DSO_bind_func(ibmca_dso, "ica_aes_encrypt"))
	    || !(p_ica_aes_decrypt = (ica_aes_decrypt_t)DSO_bind_func(ibmca_dso, "ica_aes_decrypt"))
	    || !(p_ica_sha256 = (ica_sha256_t)DSO_bind_func(ibmca_dso, "ica_sha256"))
	    || !(p_ica_aes_ofb = (ica_aes_ofb_t)DSO_bind_func(ibmca_dso, "ica_aes_ofb"))
	    || !(p_ica_des_ofb = (ica_des_ofb_t)DSO_bind_func(ibmca_dso, "ica_des_ofb"))
	    || !(p_ica_3des_ofb = (ica_3des_ofb_t)DSO_bind_func(ibmca_dso, "ica_3des_ofb"))
	    || !(p_ica_aes_cfb = (ica_aes_cfb_t)DSO_bind_func(ibmca_dso, "ica_aes_cfb"))
	    || !(p_ica_des_cfb = (ica_des_cfb_t)DSO_bind_func(ibmca_dso, "ica_des_cfb"))
	    || !(p_ica_3des_cfb = (ica_3des_cfb_t)DSO_bind_func(ibmca_dso, "ica_3des_cfb"))) {
		IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_DSO_FAILURE);
		goto err;
	}

	if (!get_context(&ibmca_handle)) {
		IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_UNIT_FAILURE);
		goto err;
	}

	return 1;
err:
	if (ibmca_dso) {
		DSO_free(ibmca_dso);
		ibmca_dso = NULL;
	}

	p_ica_open_adapter = NULL;
	p_ica_close_adapter = NULL;
	p_ica_rsa_mod_expo = NULL;
	p_ica_random_number_generate = NULL;
	p_ica_rsa_crt = NULL;
	p_ica_sha1 = NULL;
	p_ica_des_encrypt = NULL;
	p_ica_des_decrypt = NULL;
	p_ica_3des_encrypt = NULL;
	p_ica_3des_decrypt = NULL;
	p_ica_aes_encrypt = NULL;
	p_ica_aes_decrypt = NULL;
	p_ica_sha256 = NULL;
	p_ica_aes_ofb = NULL;
	p_ica_des_ofb = NULL;
	p_ica_3des_ofb = NULL;
	p_ica_aes_cfb = NULL;
	p_ica_des_cfb = NULL;
	p_ica_3des_cfb = NULL;

	return 0;
}

static int ibmca_finish(ENGINE * e)
{
	if (ibmca_dso == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_FINISH, IBMCA_R_NOT_LOADED);
		return 0;
	}
	release_context(ibmca_handle);
	if (!DSO_free(ibmca_dso)) {
		IBMCAerr(IBMCA_F_IBMCA_FINISH, IBMCA_R_DSO_FAILURE);
		return 0;
	}
	ibmca_dso = NULL;

	return 1;
}

static int ibmca_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ())
{
	int initialised = ((ibmca_dso == NULL) ? 0 : 1);
	switch (cmd) {
	case IBMCA_CMD_SO_PATH:
		if (p == NULL) {
			IBMCAerr(IBMCA_F_IBMCA_CTRL,
				 ERR_R_PASSED_NULL_PARAMETER);
			return 0;
		}
		if (initialised) {
			IBMCAerr(IBMCA_F_IBMCA_CTRL,
				 IBMCA_R_ALREADY_LOADED);
			return 0;
		}
		IBMCA_LIBNAME = (const char *) p;
		return 1;
	default:
		break;
	}
	IBMCAerr(IBMCA_F_IBMCA_CTRL, IBMCA_R_CTRL_COMMAND_NOT_IMPLEMENTED);
	return 0;
}

/*
 * ENGINE calls this to find out how to deal with
 * a particular NID in the ENGINE. 
 */
static int ibmca_engine_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
				const int **nids, int nid)
{
	if (!cipher)
		return (ibmca_usable_ciphers(nids));

	switch (nid) {
	case NID_des_ecb:
		*cipher = &ibmca_des_ecb;
		break;
	case NID_des_cbc:
		*cipher = &ibmca_des_cbc;
		break;
	case NID_des_ofb:
		*cipher = &ibmca_des_ofb;
		break;
	case NID_des_cfb:
		*cipher = &ibmca_des_cfb;
		break;
	case NID_des_ede3_ecb:
		*cipher = &ibmca_tdes_ecb;
		break;
	case NID_des_ede3_cbc:
		*cipher = &ibmca_tdes_cbc;
		break;
	case NID_des_ede3_ofb:
		*cipher = &ibmca_tdes_ofb;
		break;
	case NID_des_ede3_cfb:
		*cipher = &ibmca_tdes_cfb;
		break;
	case NID_aes_128_ecb:
		*cipher = &ibmca_aes_128_ecb;
		break;
	case NID_aes_128_cbc:
		*cipher = &ibmca_aes_128_cbc;
		break;
	case NID_aes_128_ofb:
		*cipher = &ibmca_aes_128_ofb;
		break;
	case NID_aes_128_cfb:
		*cipher = &ibmca_aes_128_cfb;
		break;
	case NID_aes_192_ecb:
		*cipher = &ibmca_aes_192_ecb;
		break;
	case NID_aes_192_cbc:
		*cipher = &ibmca_aes_192_cbc;
		break;
	case NID_aes_192_ofb:
		*cipher = &ibmca_aes_192_ofb;
		break;
	case NID_aes_192_cfb:
		*cipher = &ibmca_aes_192_cfb;
		break;
	case NID_aes_256_ecb:
		*cipher = &ibmca_aes_256_ecb;
		break;
	case NID_aes_256_cbc:
		*cipher = &ibmca_aes_256_cbc;
		break;
	case NID_aes_256_ofb:
		*cipher = &ibmca_aes_256_ofb;
		break;
	case NID_aes_256_cfb:
		*cipher = &ibmca_aes_256_cfb;
		break;
	default:
		*cipher = NULL;
		break;
	}
	return (*cipher != NULL);
}

static int ibmca_usable_ciphers(const int **nids)
{
	if (nids)
		*nids = ibmca_cipher_nids;
	return (sizeof(ibmca_cipher_nids) / sizeof(int));
}

static int ibmca_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
			  const unsigned char *iv, int enc)
{
	ICA_DES_CTX *pCtx = ctx->cipher_data;

	memcpy(pCtx->key, key, ctx->cipher->key_len);

	return 1;
}				// end ibmca_init_key

static int ibmca_des_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
			    const unsigned char *in, size_t inlen)
{
	int mode = 0;
	int rv;
	unsigned int len;
	ICA_DES_CTX *pCtx = ctx->cipher_data;
	ica_des_vector_t pre_iv;

	if (inlen > UINT32_MAX) {
		IBMCAerr(IBMCA_F_IBMCA_DES_CIPHER, IBMCA_R_OUTLEN_TO_LARGE);
		return 0;
	}
	len = inlen;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_CBC;
	} else if ((EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_CFB_MODE) &&
		   (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE)) {
		IBMCAerr(IBMCA_F_IBMCA_DES_CIPHER, 
				IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			rv = p_ica_des_cfb(in, out, len, pCtx->key, ctx->iv,
					   8, ICA_ENCRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_des_ofb(in, out, len, pCtx->key, 8, ctx->iv,
					   ICA_ENCRYPT);
		} else {
			rv = p_ica_des_encrypt(mode, len, (unsigned char *)in,
						(ica_des_vector_t *) ctx->iv,
						(ica_des_key_single_t *) pCtx->key, out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_DES_CIPHER, 
					IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv,
			       out + len - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
		}
	} else {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			/* Protect against decrypt in place */
			/* FIXME: Shouldn't we use EVP_CIPHER_CTX_iv_length() instead? */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_des_cfb(in, out, len, pCtx->key, ctx->iv,
					   8, ICA_DECRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_des_ofb(in, out, len, pCtx->key, 8, ctx->iv,
					   ICA_DECRYPT);
		} else {
			/* Protect against decrypt in place */
			/* FIXME: Shouldn't we use EVP_CIPHER_CTX_iv_length() instead? */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_des_decrypt(mode, len, (unsigned char *)in,
						(ica_des_vector_t *) ctx->iv,
						(ica_des_key_single_t *) pCtx->key, out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_DES_CIPHER, 
					IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
		}
	}

	return 1;
}				// end ibmca_des_cipher

static int ibmca_tdes_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
			     const unsigned char *in, size_t inlen)
{
	int mode = 0;
	int rv;
	unsigned int len;
	ICA_DES_CTX *pCtx = ctx->cipher_data;
	ica_des_vector_t pre_iv;

	if (inlen > UINT32_MAX) {
		IBMCAerr(IBMCA_F_IBMCA_TDES_CIPHER, IBMCA_R_OUTLEN_TO_LARGE);
		return 0;
	}
	len = inlen;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_CBC;
	} else if ((EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_CFB_MODE) &&
		   (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE)) {
		IBMCAerr(IBMCA_F_IBMCA_TDES_CIPHER, 
				IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			rv = p_ica_3des_cfb(in, out, len, pCtx->key,
					ctx->iv, 8, ICA_ENCRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_3des_ofb(in, out, len, pCtx->key,
					8, ctx->iv, ICA_ENCRYPT);
		} else {
			rv = p_ica_3des_encrypt(mode, len, (unsigned char *)in,
						(ica_des_vector_t *) ctx->iv,
						(ica_des_key_triple_t *) pCtx->key, out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_TDES_CIPHER, 
					IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv,
			       out + len - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
		}
	} else {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			/* Protect against decrypt in place */
			/* FIXME: Again, check if EVP_CIPHER_CTX_iv_length() should be used */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_3des_cfb(in, out, len, pCtx->key,
					ctx->iv, 8, ICA_DECRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_3des_ofb(in, out, len, pCtx->key,
					8, ctx->iv, ICA_DECRYPT);
		} else {
			/* Protect against decrypt in place */
			/* FIXME: Again, check if EVP_CIPHER_CTX_iv_length() should be used */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_3des_decrypt(mode, len, (unsigned char *)in,
						(ica_des_vector_t *) ctx->iv,
						(ica_des_key_triple_t *) pCtx->key, out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_TDES_CIPHER, 
					IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
		}
	}

	return 1;
}				// end ibmca_tdes_cipher

/* FIXME: a lot of common code between ica_aes_[128|192|256]_cipher() fncs */
static int ibmca_aes_128_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
				const unsigned char *in, size_t inlen)
{
	int mode = 0;
	int rv;
	unsigned int len;
	ICA_AES_128_CTX *pCtx = ctx->cipher_data;
	ica_aes_vector_t pre_iv;

	if (inlen > UINT32_MAX) {
		IBMCAerr(IBMCA_F_IBMCA_AES_128_CIPHER, IBMCA_R_OUTLEN_TO_LARGE);
		return 0;
	}
	len = inlen;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_CBC;
	} else if ((EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_CFB_MODE) &&
		   (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE)) {
		IBMCAerr(IBMCA_F_IBMCA_AES_128_CIPHER, 
			 IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			rv = p_ica_aes_cfb(in, out, len, pCtx->key,
					AES_KEY_LEN128, ctx->iv,
					AES_BLOCK_SIZE, ICA_ENCRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_aes_ofb(in, out, len, pCtx->key,
					AES_KEY_LEN128, ctx->iv,
					ICA_ENCRYPT);
		} else {
			rv = p_ica_aes_encrypt(mode, len, (unsigned char *)in,
						(ica_aes_vector_t *)ctx->iv,
						AES_KEY_LEN128,
						(unsigned char *)pCtx->key,
						out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_128_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv,
			       out + len - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
		}
	} else {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			/* Protect against decrypt in place */
			/* FIXME: Again, check if EVP_CIPHER_CTX_iv_length() should be used */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_aes_cfb(in, out, len, pCtx->key,
					AES_KEY_LEN128, ctx->iv,
					AES_BLOCK_SIZE, ICA_DECRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_aes_ofb(in, out, len, pCtx->key,
					AES_KEY_LEN128, ctx->iv,
					ICA_DECRYPT);
		} else {
			/* Protect against decrypt in place */
			/* FIXME: Again, check if EVP_CIPHER_CTX_iv_length() should be used */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_aes_decrypt(mode, len, (unsigned char *)in,
						(ica_aes_vector_t *)ctx->iv,
						AES_KEY_LEN128,
						(unsigned char *)pCtx->key,
						out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_128_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
		}
	}

	return 1;
}

static int ibmca_aes_192_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
				const unsigned char *in, size_t inlen)
{
	int mode = 0;
	int rv;
	unsigned int len;
	ICA_AES_192_CTX *pCtx = ctx->cipher_data;
	ica_aes_vector_t pre_iv;

	if (inlen > UINT32_MAX) {
		IBMCAerr(IBMCA_F_IBMCA_AES_192_CIPHER, IBMCA_R_OUTLEN_TO_LARGE);
		return 0;
	}
	len = inlen;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_CBC;
	} else if ((EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_CFB_MODE) &&
		   (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE)) {
		IBMCAerr(IBMCA_F_IBMCA_AES_192_CIPHER, 
			 IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			rv = p_ica_aes_cfb(in, out, len, pCtx->key,
					AES_KEY_LEN192, ctx->iv,
					AES_BLOCK_SIZE, ICA_ENCRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_aes_ofb(in, out, len, pCtx->key,
					AES_KEY_LEN192, ctx->iv,
					ICA_ENCRYPT);
		} else {
			rv = p_ica_aes_encrypt(mode, len, (unsigned char *)in,
						(ica_aes_vector_t *)ctx->iv,
						AES_KEY_LEN192,
						(unsigned char *)pCtx->key, out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_192_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv,
			       out + len - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
		}
	} else {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			/* Protect against decrypt in place */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_aes_cfb(in, out, len, pCtx->key,
					AES_KEY_LEN192, ctx->iv,
					AES_BLOCK_SIZE, ICA_DECRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_aes_ofb(in, out, len, pCtx->key,
					AES_KEY_LEN192, ctx->iv,
					ICA_DECRYPT);
		} else {
			/* Protect against decrypt in place */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_aes_decrypt(mode, len, (unsigned char *)in,
						(ica_aes_vector_t *)ctx->iv,
						AES_KEY_LEN192,
						(unsigned char *)pCtx->key, out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_192_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
		}
	}

	return 1;
}

static int ibmca_aes_256_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
				const unsigned char *in, size_t inlen)
{
	int mode = 0;
	int rv;
	unsigned int len;
	ICA_AES_256_CTX *pCtx = ctx->cipher_data;
	ica_aes_vector_t pre_iv;

	if (inlen > UINT32_MAX) {
		IBMCAerr(IBMCA_F_IBMCA_AES_256_CIPHER, IBMCA_R_OUTLEN_TO_LARGE);
		return 0;
	}
	len = inlen;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_CBC;
	} else if ((EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_CFB_MODE) &&
		   (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE)) {
		IBMCAerr(IBMCA_F_IBMCA_AES_256_CIPHER, 
			 IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			rv = p_ica_aes_cfb(in, out, len, pCtx->key,
					AES_KEY_LEN256, ctx->iv,
					AES_BLOCK_SIZE, ICA_ENCRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_aes_ofb(in, out, len, pCtx->key,
					AES_KEY_LEN256, ctx->iv,
					ICA_ENCRYPT);
		} else {
			rv = p_ica_aes_encrypt(mode, len, (unsigned char *)in,
						(ica_aes_vector_t *)ctx->iv,
						AES_KEY_LEN256,
						(unsigned char *)pCtx->key, out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_256_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv,
			       out + len - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
		}
	} else {
		if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CFB_MODE) {
			/* Protect against decrypt in place */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_aes_cfb(in, out, len, pCtx->key,
					AES_KEY_LEN256, ctx->iv,
					AES_BLOCK_SIZE, ICA_DECRYPT);
		} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_OFB_MODE) {
			rv = p_ica_aes_ofb(in, out, len, pCtx->key,
					AES_KEY_LEN256, ctx->iv,
					ICA_DECRYPT);
		} else {
			/* Protect against decrypt in place */
			memcpy(pre_iv, in + len - sizeof(pre_iv), sizeof(pre_iv));

			rv = p_ica_aes_decrypt(mode, len, (unsigned char *)in,
						(ica_aes_vector_t *)ctx->iv,
						AES_KEY_LEN256,
						(unsigned char *)pCtx->key, out);
		}

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_256_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_OFB_MODE) {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
		}
	}

	return 1;
}

static int ibmca_cipher_cleanup(EVP_CIPHER_CTX * ctx)
{
	return 1;
}

static int ibmca_engine_digests(ENGINE * e, const EVP_MD ** digest,
				const int **nids, int nid)
{
	if (!digest)
		return (ibmca_usable_digests(nids));

	switch (nid) {
#ifndef OPENSSL_NO_SHA1
	case NID_sha1:
		*digest = &ibmca_sha1;
		break;
#endif
#ifndef OPENSSL_NO_SHA256
	case NID_sha256:
		*digest = &ibmca_sha256;
		break;
#endif
	default:
		*digest = NULL;
		break;
	}
	return (*digest != NULL);
}

static int ibmca_usable_digests(const int **nids)
{
	*nids = digest_nids;
	return (sizeof(digest_nids) / sizeof(int));
}

#ifndef OPENSSL_NO_SHA1
static int ibmca_sha1_init(EVP_MD_CTX * ctx)
{
	IBMCA_SHA_CTX *ibmca_sha_ctx = ctx->md_data;
	memset((unsigned char *)ibmca_sha_ctx, 0, sizeof(*ibmca_sha_ctx));
	return 1;
}

static int ibmca_sha1_update(EVP_MD_CTX * ctx, const void *in_data,
			     unsigned long inlen)
{
	IBMCA_SHA_CTX *ibmca_sha_ctx = ctx->md_data;
	unsigned int message_part=SHA_MSG_PART_MIDDLE,
		fill_size=0;
	unsigned long in_data_len=inlen;
	unsigned char tmp_hash[SHA_HASH_LENGTH];

	if (in_data_len == 0)
		return 1;

	if( ibmca_sha_ctx->c.runningLength == 0 && ibmca_sha_ctx->tail_len == 0) {
		message_part = SHA_MSG_PART_FIRST;

		ibmca_sha_ctx->tail_len = in_data_len & 0x3f;
		if(ibmca_sha_ctx->tail_len) {
			in_data_len &= ~0x3f;
			memcpy(ibmca_sha_ctx->tail, in_data + in_data_len, ibmca_sha_ctx->tail_len);
		}
	}
	else if( ibmca_sha_ctx->c.runningLength == 0 && ibmca_sha_ctx->tail_len > 0 ) {

		/* Here we need to fill out the temporary tail buffer until
		 * it has 64 bytes in it, then call ica_sha1 on that buffer.
		 * If there weren't enough bytes passed in to fill it out,
		 * just copy in what we can and return success without calling
		 * ica_sha1. - KEY
		 */

		fill_size = SHA_BLOCK_SIZE - ibmca_sha_ctx->tail_len;
		if(fill_size < in_data_len) {
			memcpy(ibmca_sha_ctx->tail + ibmca_sha_ctx->tail_len, in_data, fill_size);

			/* Submit the filled out tail buffer */
			if( p_ica_sha1( (unsigned int)SHA_MSG_PART_FIRST,
					(unsigned int)SHA_BLOCK_SIZE, ibmca_sha_ctx->tail,
					&ibmca_sha_ctx->c,
					tmp_hash)) {

				IBMCAerr(IBMCA_F_IBMCA_SHA1_UPDATE, 
						IBMCA_R_REQUEST_FAILED);
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
		if(ibmca_sha_ctx->tail_len) {
			in_data_len &= ~0x3f;
			memcpy(ibmca_sha_ctx->tail,
				in_data + fill_size + in_data_len,
				ibmca_sha_ctx->tail_len);
			// fill_size is added to in_data down below
		}
	}
	else if( ibmca_sha_ctx->c.runningLength > 0 ) {
		if(ibmca_sha_ctx->tail_len) {
			fill_size = SHA_BLOCK_SIZE - ibmca_sha_ctx->tail_len;
			if(fill_size < in_data_len) {
				memcpy(ibmca_sha_ctx->tail + ibmca_sha_ctx->tail_len,
						in_data, fill_size);

				/* Submit the filled out save buffer */
				if( p_ica_sha1( message_part,
						(unsigned int)SHA_BLOCK_SIZE, ibmca_sha_ctx->tail,
						&ibmca_sha_ctx->c,
						tmp_hash)) {

					IBMCAerr(IBMCA_F_IBMCA_SHA1_UPDATE, 
							IBMCA_R_REQUEST_FAILED);
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
			if(ibmca_sha_ctx->tail_len) {
				in_data_len &= ~0x3f;
				memcpy(ibmca_sha_ctx->tail, 
					in_data + fill_size +in_data_len,
					ibmca_sha_ctx->tail_len);
			}
		} else {
			/* This is the odd case, where we need to go ahead and
			 * send the first X * 64 byte chunks in to be processed
			 * and copy the last <64 byte area into the tail. -KEY
			 */
			ibmca_sha_ctx->tail_len = in_data_len & 0x3f;
			if( ibmca_sha_ctx->tail_len) {
				in_data_len &= ~0x3f;
				memcpy(ibmca_sha_ctx->tail, in_data + in_data_len,
						ibmca_sha_ctx->tail_len);
			}
		}
	}

	/* If the data passed in was <64 bytes, in_data_len will be 0 */
        if( in_data_len && 
		p_ica_sha1(message_part,
			(unsigned int)in_data_len, (unsigned char *)(in_data + fill_size),
			&ibmca_sha_ctx->c,
			tmp_hash)) {

		IBMCAerr(IBMCA_F_IBMCA_SHA1_UPDATE, IBMCA_R_REQUEST_FAILED);
		return 0;
	}

	return 1;
}

static int ibmca_sha1_final(EVP_MD_CTX * ctx, unsigned char *md)
{
	IBMCA_SHA_CTX *ibmca_sha_ctx = ctx->md_data;
	unsigned int message_part = 0;

	if (ibmca_sha_ctx->c.runningLength)
		message_part = SHA_MSG_PART_FINAL;
	else
		message_part = SHA_MSG_PART_ONLY;

	if( p_ica_sha1(message_part,
		       ibmca_sha_ctx->tail_len,
		       (unsigned char *)ibmca_sha_ctx->tail,
		       &ibmca_sha_ctx->c, md)) {

		IBMCAerr(IBMCA_F_IBMCA_SHA1_FINAL, IBMCA_R_REQUEST_FAILED);
		return 0;
	}

	return 1;
}				// end ibmca_sha1_final

static int ibmca_sha1_cleanup(EVP_MD_CTX * ctx)
{
	return 1;
}				// end ibmca_sha1_cleanup

#endif // OPENSSL_NO_SHA1

#ifndef OPENSSL_NO_SHA256
static int ibmca_sha256_init(EVP_MD_CTX *ctx)
{
	IBMCA_SHA256_CTX *ibmca_sha256_ctx = ctx->md_data;
	memset((unsigned char *)ibmca_sha256_ctx, 0, sizeof(*ibmca_sha256_ctx));
	return 1;
}				// end ibmca_sha256_init                                                

static int
ibmca_sha256_update(EVP_MD_CTX *ctx, const void *in_data, unsigned long inlen)
{
	IBMCA_SHA256_CTX *ibmca_sha256_ctx = ctx->md_data;
	unsigned int message_part = SHA_MSG_PART_MIDDLE, fill_size = 0;
	unsigned long in_data_len = inlen;
	unsigned char tmp_hash[SHA256_HASH_LENGTH];

	if (in_data_len == 0)
		return 1;

	if (ibmca_sha256_ctx->c.runningLength == 0 
	    && ibmca_sha256_ctx->tail_len == 0) {
		message_part = SHA_MSG_PART_FIRST;

		ibmca_sha256_ctx->tail_len = in_data_len & 0x3f;
		if(ibmca_sha256_ctx->tail_len) {
			in_data_len &= ~0x3f;
			memcpy(ibmca_sha256_ctx->tail, in_data + in_data_len,
			       ibmca_sha256_ctx->tail_len);
		}
	} else if (ibmca_sha256_ctx->c.runningLength == 0
		   && ibmca_sha256_ctx->tail_len > 0 ) {
		/* Here we need to fill out the temporary tail buffer
		 * until it has 64 bytes in it, then call ica_sha256 on
		 * that buffer.  If there weren't enough bytes passed
		 * in to fill it out, just copy in what we can and
		 * return success without calling ica_sha256. - KEY */

		fill_size = SHA_BLOCK_SIZE - ibmca_sha256_ctx->tail_len;
		if (fill_size < in_data_len) {
			memcpy(ibmca_sha256_ctx->tail 
			       + ibmca_sha256_ctx->tail_len, in_data,
			       fill_size);

			/* Submit the filled out tail buffer */
			if (p_ica_sha256((unsigned int)SHA_MSG_PART_FIRST,
					(unsigned int)SHA_BLOCK_SIZE,
					ibmca_sha256_ctx->tail,
					&ibmca_sha256_ctx->c,
					tmp_hash)) {
				IBMCAerr(IBMCA_F_IBMCA_SHA256_UPDATE, 
					 IBMCA_R_REQUEST_FAILED);
				return 0;
			}
		} else {
			memcpy(ibmca_sha256_ctx->tail
			       + ibmca_sha256_ctx->tail_len, in_data,
			       in_data_len);
			ibmca_sha256_ctx->tail_len += in_data_len;
			return 1;
		}

		/* We had to use 'fill_size' bytes from in_data to fill out the
		 * empty part of save data, so adjust in_data_len */
		in_data_len -= fill_size;

		ibmca_sha256_ctx->tail_len = in_data_len & 0x3f;
		if(ibmca_sha256_ctx->tail_len) {
			in_data_len &= ~0x3f;
			memcpy(ibmca_sha256_ctx->tail,
			       in_data + fill_size + in_data_len,
			       ibmca_sha256_ctx->tail_len);
			/* fill_size is added to in_data down below */
		}
	} else if (ibmca_sha256_ctx->c.runningLength > 0) {
		if (ibmca_sha256_ctx->tail_len) {
			fill_size = SHA_BLOCK_SIZE - ibmca_sha256_ctx->tail_len;
			if (fill_size < in_data_len) {
				memcpy(ibmca_sha256_ctx->tail 
				       + ibmca_sha256_ctx->tail_len, in_data,
				       fill_size);

				/* Submit the filled out save buffer */
				if (p_ica_sha256(message_part,
						(unsigned int)SHA_BLOCK_SIZE,
						ibmca_sha256_ctx->tail,
						&ibmca_sha256_ctx->c,
						tmp_hash)) {
					IBMCAerr(IBMCA_F_IBMCA_SHA256_UPDATE, 
						 IBMCA_R_REQUEST_FAILED);
					return 0;
				}
			} else {
				memcpy(ibmca_sha256_ctx->tail
				       + ibmca_sha256_ctx->tail_len, in_data,
				       in_data_len);
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
				       in_data + in_data_len,
				       ibmca_sha256_ctx->tail_len);
			}
		}
	}

	/* If the data passed in was <64 bytes, in_data_len will be 0 */
        if (in_data_len && 
	    p_ica_sha256(message_part,
			(unsigned int)in_data_len, (unsigned char *)(in_data + fill_size),
			&ibmca_sha256_ctx->c,
			tmp_hash)) {
		IBMCAerr(IBMCA_F_IBMCA_SHA256_UPDATE, IBMCA_R_REQUEST_FAILED);
		return 0;
	}

	return 1;
}				// end ibmca_sha256_update                                                 

static int ibmca_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	IBMCA_SHA256_CTX *ibmca_sha256_ctx = ctx->md_data;
	unsigned int message_part = 0;

	if (ibmca_sha256_ctx->c.runningLength)
		message_part = SHA_MSG_PART_FINAL;
	else
		message_part = SHA_MSG_PART_ONLY;

	if (p_ica_sha256(message_part,
			ibmca_sha256_ctx->tail_len,
			(unsigned char *)ibmca_sha256_ctx->tail,
			&ibmca_sha256_ctx->c,
			md)) {
		IBMCAerr(IBMCA_F_IBMCA_SHA256_FINAL, IBMCA_R_REQUEST_FAILED);
		return 0;
	}

	return 1;
}				// end ibmca_sha256_final

static int ibmca_sha256_cleanup(EVP_MD_CTX *ctx)
{
	return 1;
}				// end ibmca_sha256_cleanup
#endif // OPENSSL_NO_SHA256

static int ibmca_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			 const BIGNUM *m, BN_CTX *ctx)
{
	/* r = (a^p) mod m
	                        r = output
	                        a = input
	                        p = exponent
	                        m = modulus
	*/

	unsigned char *input = NULL, *output =  NULL;
	ica_rsa_key_mod_expo_t *key = NULL;
	unsigned int rc;
	int plen, mlen, inputlen;

	if (!ibmca_dso) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_NOT_LOADED);
		goto err;
	}

	/*
	 make necessary memory allocations
	 FIXME: Would it be possible to minimize memory allocation overhead by either
                allocating it all at once or having a static storage?
	*/
	key = (ica_rsa_key_mod_expo_t *) calloc(1, sizeof(ica_rsa_key_mod_expo_t));
	if (key == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	key->key_length = mlen = BN_num_bytes(m);

	key->modulus = (unsigned char *) calloc(1, key->key_length);
	if (key->modulus == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	plen = BN_num_bytes(p);

	/* despite plen, key->exponent must be key->key_length in size */
	key->exponent = (unsigned char *) calloc(1, key->key_length);
	if (key->exponent == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	inputlen = BN_num_bytes(a);

	/* despite inputlen, input and output must be key->key_length in size */
	input = (unsigned char *) calloc(1, key->key_length);
	if (input == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	output = (unsigned char *) calloc(1, key->key_length);
	if (output == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	/* Now convert from BIGNUM representation.
	 * Everything must be right-justified
	 */
	BN_bn2bin(m, key->modulus);

	BN_bn2bin(p, key->exponent + key->key_length - plen);

	BN_bn2bin(a, input + key->key_length - inputlen);

	/* execute the ica mod_exp call */
	rc = p_ica_rsa_mod_expo(ibmca_handle, input, key, output);
	if (rc != 0) {
		goto err;
	}
	else {
		rc = 1;
	}

        /* Convert output to BIGNUM representation.
	 * right-justified output applies
	 */
	/* BN_bin2bn((unsigned char *) (output + key->key_length - inputlen), inputlen, r); */
	BN_bin2bn((unsigned char *) output, key->key_length, r);

	goto end;

err:
	rc = 0;    /* error condition */

end:
	free(key->exponent);
	free(key->modulus);
	free(key);
	free(input);
	free(output);

	return rc;
}

#ifndef OPENSSL_NO_RSA
static int ibmca_rsa_init(RSA *rsa)
{
	RSA_blinding_off(rsa);

	return 1;
}

static int ibmca_rsa_mod_exp(BIGNUM * r0, const BIGNUM * I, RSA * rsa,
                             BN_CTX *ctx)
{
	int to_return = 0;

	if (!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp) {
		if (!rsa->d || !rsa->n) {
			IBMCAerr(IBMCA_F_IBMCA_RSA_MOD_EXP,
				 IBMCA_R_MISSING_KEY_COMPONENTS);
			goto err;
		}
		to_return = ibmca_mod_exp(r0, I, rsa->d, rsa->n, ctx);
	} else {
		to_return =
		    ibmca_mod_exp_crt(r0, I, rsa->p, rsa->q, rsa->dmp1,
				      rsa->dmq1, rsa->iqmp, ctx);
	}
err:
	return to_return;
}
#endif

/* Ein kleines chinesisches "Restessen"  */
static int ibmca_mod_exp_crt(BIGNUM * r, const BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * q,
			     const BIGNUM * dmp1, const BIGNUM * dmq1,
			     const BIGNUM * iqmp, BN_CTX * ctx)
{
	/*
	r = output
	a = input
	p and q are themselves
	dmp1, dmq1 are dp and dq respectively
	iqmp is qInverse
	*/

	ica_rsa_key_crt_t *key = NULL;
	unsigned char *output = NULL, *input = NULL;
	int rc;
	int plen, qlen, dplen, dqlen, qInvlen;
	int inputlen;

	/*
	 make necessary memory allocations
	 FIXME: Would it be possible to minimize memory allocation overhead by either
                allocating it all at once or having a static storage?
	*/
	key = (ica_rsa_key_crt_t *) calloc(1, sizeof(ica_rsa_key_crt_t));
	if (key == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	/* buffers pointed by p, q, dp, dq and qInverse in struct
	 * ica_rsa_key_crt_t must be of size key_legth/2 or larger.
	 * p, dp and qInverse have an additional 8-byte padding. */

	plen = BN_num_bytes(p);
	qlen = BN_num_bytes(q);
	key->key_length = 2 * (plen > qlen ? plen : qlen);

	key->p = (unsigned char *) calloc(1, (key->key_length/2) + 8);
	if (key->p == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	dplen = BN_num_bytes(dmp1);
	key->dp = (unsigned char *) calloc(1, (key->key_length/2) + 8);
	if (key->dp == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	key->q = (unsigned char *) calloc(1, key->key_length/2);
	if (key->q == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	dqlen = BN_num_bytes(dmq1);
	key->dq = (unsigned char *) calloc(1, key->key_length/2);
	if (key->dq == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	qInvlen = BN_num_bytes(iqmp);
	key->qInverse = (unsigned char *) calloc(1, (key->key_length/2) + 8);
	if (key->qInverse == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	inputlen = BN_num_bytes(a);
	if (inputlen > key->key_length) {     /* input can't be larger than key */
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	/* allocate input to the size of key_length in bytes, and
	 * pad front with zero if inputlen < key->key_length */
	input = (unsigned char *) calloc(1, key->key_length);
	if (input == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}

	/* output must also be key_length in size */
	output = (unsigned char *) calloc(1, key->key_length);
	if (output == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}


	/* Now convert from BIGNUM representation.
	 * p, dp and qInverse have an additional 8-byte padding,
	 * and everything must be right-justified */
	BN_bn2bin(p, key->p + 8 + (key->key_length/2) - plen);

	BN_bn2bin(dmp1, key->dp + 8 + (key->key_length/2) - dplen);

	BN_bn2bin(q, key->q + (key->key_length/2) - qlen);

	BN_bn2bin(dmq1, key->dq + (key->key_length/2) - dqlen);

	BN_bn2bin(iqmp, key->qInverse + 8 + (key->key_length/2) - qInvlen);

	BN_bn2bin(a, input + key->key_length - inputlen);

	/* execute the ica crt call */

	rc = p_ica_rsa_crt(ibmca_handle, input, key, output);
	if (rc != 0) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	else {
		rc = 1;
	}

	/* Convert output to BIGNUM representation */
	/* BN_bin2bn((unsigned char *) (output + key->key_length - inputlen), inputlen, r); */
	BN_bin2bn((unsigned char *) output, key->key_length, r);


	goto end;

err:
	rc = 0;    /* error condition */

end:
	free(key->p);
	free(key->q);
	free(key->dp);
	free(key->dq);
	free(key->qInverse);
	free(key);
	free(input);
	free(output);

	return rc;
}

#ifndef OPENSSL_NO_DSA
/* This code was liberated and adapted from the commented-out code in
 * dsa_ossl.c. Because of the unoptimised form of the Ibmca acceleration
 * (it doesn't have a CRT form for RSA), this function means that an
 * Ibmca system running with a DSA server certificate can handshake
 * around 5 or 6 times faster/more than an equivalent system running with
 * RSA. Just check out the "signs" statistics from the RSA and DSA parts
 * of "openssl speed -engine ibmca dsa1024 rsa1024". */
static int ibmca_dsa_mod_exp(DSA * dsa, BIGNUM * rr, BIGNUM * a1,
			     BIGNUM * p1, BIGNUM * a2, BIGNUM * p2,
			     BIGNUM * m, BN_CTX * ctx,
			     BN_MONT_CTX * in_mont)
{
	BIGNUM t;
	int to_return = 0;

	BN_init(&t);
	/* let rr = a1 ^ p1 mod m */
	if (!ibmca_mod_exp(rr, a1, p1, m, ctx))
		goto end;
	/* let t = a2 ^ p2 mod m */
	if (!ibmca_mod_exp(&t, a2, p2, m, ctx))
		goto end;
	/* let rr = rr * t mod m */
	if (!BN_mod_mul(rr, rr, &t, m, ctx))
		goto end;
	to_return = 1;
end:
	BN_free(&t);
	return to_return;
}


static int ibmca_mod_exp_dsa(DSA * dsa, BIGNUM * r, BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * m,
			     BN_CTX * ctx, BN_MONT_CTX * m_ctx)
{
	return ibmca_mod_exp(r, a, p, m, ctx);
}
#endif

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int ibmca_mod_exp_mont(BIGNUM * r, const BIGNUM * a,
			      const BIGNUM * p, const BIGNUM * m,
			      BN_CTX * ctx, BN_MONT_CTX * m_ctx)
{
	return ibmca_mod_exp(r, a, p, m, ctx);
}

#ifndef OPENSSL_NO_DH
/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int ibmca_mod_exp_dh(DH const *dh, BIGNUM * r,
			    const BIGNUM * a, const BIGNUM * p,
			    const BIGNUM * m, BN_CTX * ctx,
			    BN_MONT_CTX * m_ctx)
{
	return ibmca_mod_exp(r, a, p, m, ctx);
}
#endif

/* Random bytes are good */
static int ibmca_rand_bytes(unsigned char *buf, int num)
{
	unsigned int rc;


	rc = p_ica_random_number_generate(num, buf);
	if (rc < 0) {
		IBMCAerr(IBMCA_F_IBMCA_RAND_BYTES, IBMCA_R_REQUEST_FAILED);
		return 0;
	}
	return 1;
}

static int ibmca_rand_status(void)
{
	return 1;
}

/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
static int bind_fn(ENGINE * e, const char *id)
{
	if (id && (strcmp(id, engine_ibmca_id) != 0))	/* WJH XXX */
		return 0;
	if (!bind_helper(e))
		return 0;
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

#endif				/* !OPENSSL_NO_HW_IBMCA */
#endif				/* !OPENSSL_NO_HW */
