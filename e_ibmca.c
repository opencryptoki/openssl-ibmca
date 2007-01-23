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
 *
 *
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_IBMCA

#include "ica_openssl_api.h"

#define IBMCA_LIB_NAME "ibmca engine"
#include "e_ibmca_err.c"

typedef struct ibmca_des_context {
	unsigned char key[sizeof(ICA_KEY_DES_TRIPLE)];
} ICA_DES_CTX;

typedef struct ibmca_aes_128_context {
	unsigned char key[AES_KEY_LEN128];
} ICA_AES_128_CTX;

typedef struct ibmca_aes_192_context {
	unsigned char key[AES_KEY_LEN192];
} ICA_AES_192_CTX;

typedef struct ibmca_aes_256_context {
	unsigned char key[AES_KEY_LEN256];
} ICA_AES_256_CTX;

#ifndef OPENSSL_NO_SHA1
typedef struct ibmca_sha1_ctx {
	ICA_SHA_CONTEXT c;
	unsigned char tail[SHA_BLOCK_SIZE];
	unsigned int tail_len;
} IBMCA_SHA_CTX;
#endif

#ifndef OPENSSL_NO_SHA256
typedef struct ibmca_sha256_ctx {
	ICA_SHA256_CONTEXT c;
	unsigned char tail[SHA256_BLOCK_SIZE];
	unsigned int tail_len;
} IBMCA_SHA256_CTX;
#endif

static int cipher_nids[] = { 
	NID_des_ecb,
	NID_des_cbc,
	NID_des_ede3_ecb,
	NID_des_ede3_cbc,
	NID_aes_128_ecb,
	NID_aes_128_cbc,
	NID_aes_192_ecb,
	NID_aes_192_cbc,
	NID_aes_256_ecb,
	NID_aes_256_cbc,
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

static const char *IBMCA_F1 = "icaOpenAdapter";
static const char *IBMCA_F2 = "icaCloseAdapter";
static const char *IBMCA_F3 = "icaRsaModExpo";
static const char *IBMCA_F4 = "icaRandomNumberGenerate";
static const char *IBMCA_F5 = "icaRsaCrt";
static const char *IBMCA_F6 = "icaSha1";
static const char *IBMCA_F7 = "icaDesEncrypt";
static const char *IBMCA_F8 = "icaDesDecrypt";
static const char *IBMCA_F9 = "icaTDesEncrypt";
static const char *IBMCA_F10 = "icaTDesDecrypt";
static const char *IBMCA_F11 = "icaAesEncrypt";
static const char *IBMCA_F12 = "icaAesDecrypt";
static const char *IBMCA_F13 = "icaSha256";

static ICA_ADAPTER_HANDLE ibmca_handle = 0;

/* BIGNUM stuff */
static int ibmca_mod_exp(BIGNUM * r, const BIGNUM * a, const BIGNUM * p,
			 const BIGNUM * m, BN_CTX * ctx);

static int ibmca_mod_exp_crt(BIGNUM * r, const BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * q,
			     const BIGNUM * dmp1, const BIGNUM * dmq1,
			     const BIGNUM * iqmp, BN_CTX * ctx);

#ifndef OPENSSL_NO_RSA
/* RSA stuff */
static int ibmca_rsa_mod_exp(BIGNUM * r0, const BIGNUM * I, RSA * rsa);

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
			    const unsigned char *in, unsigned int inlen);

static int ibmca_tdes_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
			     const unsigned char *in, unsigned int inlen);

static int ibmca_aes_128_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				const unsigned char *in, unsigned int inlen);

static int ibmca_aes_192_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				const unsigned char *in, unsigned int inlen);

static int ibmca_aes_256_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				const unsigned char *in, unsigned int inlen);

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
	"Ibmca RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	ibmca_rsa_mod_exp,
	ibmca_mod_exp_mont,
	ibmca_rsa_init,
	NULL,
	0,
	NULL,
	NULL,
	NULL
};
#endif

#ifndef OPENSSL_NO_DSA
/* Our internal DSA_METHOD that we provide pointers to */
static DSA_METHOD ibmca_dsa = {
	"Ibmca DSA method",
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
	"Ibmca DH method",
	NULL,
	NULL,
	ibmca_mod_exp_dh,
	NULL,
	NULL,
	0,
	NULL
};
#endif

static RAND_METHOD ibmca_rand = {
	/* "IBMCA RAND method", */
	NULL,
	ibmca_rand_bytes,
	NULL,
	NULL,
	ibmca_rand_bytes,
	ibmca_rand_status,
};

/* DES ECB EVP */
const EVP_CIPHER ibmca_des_ecb = {
	NID_des_ecb,
	sizeof(ICA_DES_VECTOR),
	sizeof(ICA_KEY_DES_SINGLE),
	sizeof(ICA_DES_VECTOR),
	EVP_CIPH_ECB_MODE,
	ibmca_init_key,
	ibmca_des_cipher,
	ibmca_cipher_cleanup,
	sizeof(struct ibmca_des_context),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

/* DES CBC EVP */
const EVP_CIPHER ibmca_des_cbc = {
	NID_des_cbc,
	sizeof(ICA_DES_VECTOR),
	sizeof(ICA_KEY_DES_SINGLE),
	sizeof(ICA_DES_VECTOR),
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

/* 3DES ECB EVP	*/
const EVP_CIPHER ibmca_tdes_ecb = {
	NID_des_ede3_ecb,
	sizeof(ICA_DES_VECTOR),
	sizeof(ICA_KEY_DES_TRIPLE),
	sizeof(ICA_DES_VECTOR),
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
	sizeof(ICA_DES_VECTOR),
	sizeof(ICA_KEY_DES_TRIPLE),
	sizeof(ICA_DES_VECTOR),
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

/* AES-128 ECB EVP */
const EVP_CIPHER ibmca_aes_128_ecb = {
	NID_aes_128_ecb,
	sizeof(ICA_AES_VECTOR),
	sizeof(ICA_KEY_AES_LEN128),
	sizeof(ICA_AES_VECTOR),
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
	sizeof(ICA_AES_VECTOR),
	sizeof(ICA_KEY_AES_LEN128),
	sizeof(ICA_AES_VECTOR),
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

/* AES-192 ECB EVP */
const EVP_CIPHER ibmca_aes_192_ecb = {
	NID_aes_192_ecb,
	sizeof(ICA_AES_VECTOR),
	sizeof(ICA_KEY_AES_LEN192),
	sizeof(ICA_AES_VECTOR),
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
	sizeof(ICA_AES_VECTOR),
	sizeof(ICA_KEY_AES_LEN192),
	sizeof(ICA_AES_VECTOR),
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

/* AES-256 ECB EVP */
const EVP_CIPHER ibmca_aes_256_ecb = {
	NID_aes_256_ecb,
	sizeof(ICA_AES_VECTOR),
	sizeof(ICA_KEY_AES_LEN256),
	sizeof(ICA_AES_VECTOR),
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
	sizeof(ICA_AES_VECTOR),
	sizeof(ICA_KEY_AES_LEN256),
	sizeof(ICA_AES_VECTOR),
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

#ifndef OPENSSL_NO_SHA1
static const EVP_MD ibmca_sha1 = {
	NID_sha1,
	NID_sha1WithRSAEncryption,
	LENGTH_SHA_HASH,
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
	LENGTH_SHA_HASH,
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

static unsigned int (ICA_CALL * p_icaOpenAdapter) ();
static unsigned int (ICA_CALL * p_icaCloseAdapter) ();
static unsigned int (ICA_CALL * p_icaRsaModExpo) ();
static unsigned int (ICA_CALL * p_icaRandomNumberGenerate) ();
static unsigned int (ICA_CALL * p_icaRsaCrt) ();
static unsigned int (ICA_CALL * p_icaSha1) ();
static unsigned int (ICA_CALL * p_icaDesEncrypt) ();
static unsigned int (ICA_CALL * p_icaDesDecrypt) ();
static unsigned int (ICA_CALL * p_icaTDesEncrypt) ();
static unsigned int (ICA_CALL * p_icaTDesDecrypt) ();
static unsigned int (ICA_CALL * p_icaAesEncrypt) ();
static unsigned int (ICA_CALL * p_icaAesDecrypt) ();
static unsigned int (ICA_CALL * p_icaSha256) ();

/* utility function to obtain a context */
static int get_context(ICA_ADAPTER_HANDLE * p_handle)
{
	unsigned int status = 0;

	status = p_icaOpenAdapter(0, p_handle);
	if (status != 0)
		return 0;
	return 1;
}

/* similarly to release one. */
static void release_context(ICA_ADAPTER_HANDLE i_handle)
{
	p_icaCloseAdapter(i_handle);
}

/* (de)initialisation functions. */
static int ibmca_init(ENGINE * e)
{

	void (*p1) ();
	void (*p2) ();
	void (*p3) ();
	void (*p4) ();
	void (*p5) ();
	void (*p6) ();
	void (*p7) ();
	void (*p8) ();
	void (*p9) ();
	void (*p10) ();
	void (*p11) ();
	void (*p12) ();
	void (*p13) ();

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

	if (!(p1 = DSO_bind_func(ibmca_dso, IBMCA_F1))
	    || !(p2 = DSO_bind_func(ibmca_dso, IBMCA_F2))
	    || !(p3 = DSO_bind_func(ibmca_dso, IBMCA_F3))
	    || !(p4 = DSO_bind_func(ibmca_dso, IBMCA_F4))
	    || !(p5 = DSO_bind_func(ibmca_dso, IBMCA_F5))
	    || !(p6 = DSO_bind_func(ibmca_dso, IBMCA_F6))
	    || !(p7 = DSO_bind_func(ibmca_dso, IBMCA_F7))
	    || !(p8 = DSO_bind_func(ibmca_dso, IBMCA_F8))
	    || !(p9 = DSO_bind_func(ibmca_dso, IBMCA_F9))
	    || !(p10 = DSO_bind_func(ibmca_dso, IBMCA_F10))
	    || !(p11 = DSO_bind_func(ibmca_dso, IBMCA_F11))
	    || !(p12 = DSO_bind_func(ibmca_dso, IBMCA_F12))
	    || !(p13 = DSO_bind_func(ibmca_dso, IBMCA_F13))) {
		IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_DSO_FAILURE);
		goto err;
	}

	/* Copy the pointers */

	p_icaOpenAdapter = (unsigned int (ICA_CALL *) ()) p1;
	p_icaCloseAdapter = (unsigned int (ICA_CALL *) ()) p2;
	p_icaRsaModExpo = (unsigned int (ICA_CALL *) ()) p3;
	p_icaRandomNumberGenerate = (unsigned int (ICA_CALL *) ()) p4;
	p_icaRsaCrt = (unsigned int (ICA_CALL *) ()) p5;
	p_icaSha1 = (unsigned int (ICA_CALL *) ()) p6;
	p_icaDesEncrypt = (unsigned int (ICA_CALL *) ()) p7;
	p_icaDesDecrypt = (unsigned int (ICA_CALL *) ()) p8;
	p_icaTDesEncrypt = (unsigned int (ICA_CALL *) ()) p9;
	p_icaTDesDecrypt = (unsigned int (ICA_CALL *) ()) p10;
	p_icaAesEncrypt = (unsigned int (ICA_CALL *) ()) p11;
	p_icaAesDecrypt = (unsigned int (ICA_CALL *) ()) p12;
	p_icaSha256 = (unsigned int (ICA_CALL *) ()) p13;

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

	p_icaOpenAdapter = NULL;
	p_icaCloseAdapter = NULL;
	p_icaRsaModExpo = NULL;
	p_icaRandomNumberGenerate = NULL;
	p_icaRsaCrt = NULL;
	p_icaSha1 = NULL;
	p_icaDesEncrypt = NULL;
	p_icaDesDecrypt = NULL;
	p_icaTDesEncrypt = NULL;
	p_icaTDesDecrypt = NULL;
	p_icaAesEncrypt = NULL;
	p_icaAesDecrypt = NULL;
	p_icaSha256 = NULL;

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
	case NID_des_ede3_ecb:
		*cipher = &ibmca_tdes_ecb;
		break;
	case NID_des_ede3_cbc:
		*cipher = &ibmca_tdes_cbc;
		break;
	case NID_aes_128_ecb:
		*cipher = &ibmca_aes_128_ecb;
		break;
	case NID_aes_128_cbc:
		*cipher = &ibmca_aes_128_cbc;
		break;
	case NID_aes_192_ecb:
		*cipher = &ibmca_aes_192_ecb;
		break;
	case NID_aes_192_cbc:
		*cipher = &ibmca_aes_192_cbc;
		break;
	case NID_aes_256_ecb:
		*cipher = &ibmca_aes_256_ecb;
		break;
	case NID_aes_256_cbc:
		*cipher = &ibmca_aes_256_cbc;
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
		*nids = cipher_nids;
	return (sizeof(cipher_nids) / sizeof(int));
}

static int ibmca_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
			  const unsigned char *iv, int enc)
{
	ICA_DES_CTX *pCtx = ctx->cipher_data;

	memcpy(pCtx->key, key, ctx->cipher->key_len);

	return 1;
}				// end ibmca_init_key

static int ibmca_des_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
			    const unsigned char *in, unsigned int inlen)
{
	int mode;
	int outlen = inlen;
	int rv;
	ICA_DES_CTX *pCtx = ctx->cipher_data;
	ICA_DES_VECTOR pre_iv;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_DES_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_DES_CBC;
	} else {
		IBMCAerr(IBMCA_F_IBMCA_DES_CIPHER, 
				IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		rv = p_icaDesEncrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				     mode,
				     inlen,
				     in,
				     (ICA_DES_VECTOR *) ctx->iv,
				     (ICA_KEY_DES_SINGLE *) pCtx->key,
				     &outlen, out);

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_DES_CIPHER, 
					IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv,
			       out + inlen - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
			return 1;
		}
	} else {
		/* Protect against decrypt in place */
		memcpy(pre_iv, in + inlen - sizeof(pre_iv), sizeof(pre_iv));
		rv = p_icaDesDecrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				     mode,
				     inlen,
				     in,
				     (ICA_DES_VECTOR *) ctx->iv,
				     (ICA_KEY_DES_SINGLE *) pCtx->key,
				     &outlen, out);

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_DES_CIPHER, 
					IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
#if 0
			memcpy(ctx->iv,
			       in + inlen - ctx->cipher->iv_len,
			       ctx->cipher->iv_len);
#endif
			return 1;
		}
	}
}				// end ibmca_des_cipher

static int ibmca_tdes_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
			     const unsigned char *in, unsigned int inlen)
{
	int mode;
	int outlen = inlen;
	int rv;
	ICA_DES_CTX *pCtx = ctx->cipher_data;
	ICA_DES_VECTOR pre_iv;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_DES_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_DES_CBC;
	} else {
		IBMCAerr(IBMCA_F_IBMCA_TDES_CIPHER, 
				IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		rv = p_icaTDesEncrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				      mode,
				      inlen,
				      in,
				      (ICA_DES_VECTOR *) ctx->iv,
				      (ICA_KEY_DES_TRIPLE *) pCtx->key,
				      &outlen, out);

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_TDES_CIPHER, 
					IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv,
			       out + inlen - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
			return 1;
		}
	} else {
		/* Protect against decrypt in place */
		memcpy(pre_iv, in + inlen - sizeof(pre_iv), sizeof(pre_iv));
		rv = p_icaTDesDecrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				      mode,
				      inlen,
				      in,
				      (ICA_DES_VECTOR *) ctx->iv,
				      (ICA_KEY_DES_TRIPLE *) pCtx->key,
				      &outlen, out);

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_TDES_CIPHER, 
					IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
#if 0
			memcpy(ctx->iv,
			       in + inlen - ctx->cipher->iv_len,
			       ctx->cipher->iv_len);
#endif
			return 1;
		}
	}
}				// end ibmca_tdes_cipher

static int ibmca_aes_128_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
				const unsigned char *in, unsigned int inlen)
{
	int mode;
	int outlen = inlen;
	int rv;
	ICA_AES_128_CTX *pCtx = ctx->cipher_data;
	ICA_AES_VECTOR pre_iv;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_AES_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_AES_CBC;
	} else {
		IBMCAerr(IBMCA_F_IBMCA_AES_128_CIPHER, 
			 IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		rv = p_icaAesEncrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				     mode,
				     inlen,
				     in,
				     (ICA_AES_VECTOR *)ctx->iv,
				     AES_KEY_LEN128,
				     (ICA_KEY_AES_LEN128 *)pCtx->key,
				     &outlen, out);
		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_128_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv,
			       out + inlen - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
			return 1;
		}
	} else {
		/* Protect against decrypt in place */
		memcpy(pre_iv, in + inlen - sizeof(pre_iv), sizeof(pre_iv));
		rv = p_icaAesDecrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				     mode,
				     inlen,
				     in,
				     (ICA_AES_VECTOR *)ctx->iv,
				     AES_KEY_LEN128,
				     (ICA_KEY_AES_LEN128 *)pCtx->key,
				     &outlen, out);

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_128_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
			return 1;
		}
	}
}

static int ibmca_aes_192_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
				const unsigned char *in, unsigned int inlen)
{
	int mode;
	int outlen = inlen;
	int rv;
	ICA_AES_192_CTX *pCtx = ctx->cipher_data;
	ICA_AES_VECTOR pre_iv;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_AES_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_AES_CBC;
	} else {
		IBMCAerr(IBMCA_F_IBMCA_AES_192_CIPHER, 
			 IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		rv = p_icaAesEncrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				     mode,
				     inlen,
				     in,
				     (ICA_AES_VECTOR *)ctx->iv,
				     AES_KEY_LEN192,
				     (ICA_KEY_AES_LEN192 *)pCtx->key,
				     &outlen, out);
		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_192_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv,
			       out + inlen - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
			return 1;
		}
	} else {
		/* Protect against decrypt in place */
		memcpy(pre_iv, in + inlen - sizeof(pre_iv), sizeof(pre_iv));
		rv = p_icaAesDecrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				     mode,
				     inlen,
				     in,
				     (ICA_AES_VECTOR *)ctx->iv,
				     AES_KEY_LEN192,
				     (ICA_KEY_AES_LEN192 *)pCtx->key,
				     &outlen, out);

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_192_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
			return 1;
		}
	}
}

static int ibmca_aes_256_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
				const unsigned char *in, unsigned int inlen)
{
	int mode;
	int outlen = inlen;
	int rv;
	ICA_AES_256_CTX *pCtx = ctx->cipher_data;
	ICA_AES_VECTOR pre_iv;

	if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
		mode = MODE_AES_ECB;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mode = MODE_AES_CBC;
	} else {
		IBMCAerr(IBMCA_F_IBMCA_AES_256_CIPHER, 
			 IBMCA_R_CIPHER_MODE_NOT_SUPPORTED);
		return 0;
	}

	if (ctx->encrypt) {
		rv = p_icaAesEncrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				     mode,
				     inlen,
				     in,
				     (ICA_AES_VECTOR *)ctx->iv,
				     AES_KEY_LEN256,
				     (ICA_KEY_AES_LEN256 *)pCtx->key,
				     &outlen, out);
		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_256_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv,
			       out + inlen - EVP_CIPHER_CTX_iv_length(ctx),
			       EVP_CIPHER_CTX_iv_length(ctx));
			return 1;
		}
	} else {
		/* Protect against decrypt in place */
		memcpy(pre_iv, in + inlen - sizeof(pre_iv), sizeof(pre_iv));
		rv = p_icaAesDecrypt((ICA_ADAPTER_HANDLE) ibmca_handle,
				     mode,
				     inlen,
				     in,
				     (ICA_AES_VECTOR *)ctx->iv,
				     AES_KEY_LEN256,
				     (ICA_KEY_AES_LEN256 *)pCtx->key,
				     &outlen, out);

		if (rv) {
			IBMCAerr(IBMCA_F_IBMCA_AES_256_CIPHER, 
				 IBMCA_R_REQUEST_FAILED);
			return 0;
		} else {
			memcpy(ctx->iv, pre_iv, EVP_CIPHER_CTX_iv_length(ctx));
			return 1;
		}
	}
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
}				// end ibmca_sha1_init                                                

static int ibmca_sha1_update(EVP_MD_CTX * ctx, const void *in_data,
			     unsigned long inlen)
{
	IBMCA_SHA_CTX *ibmca_sha_ctx = ctx->md_data;
	unsigned int message_part=SHA_MSG_PART_MIDDLE,
		fill_size=0,
		tmp_len=LENGTH_SHA_HASH;
	unsigned long in_data_len=inlen;
	unsigned char tmp_hash[LENGTH_SHA_HASH];

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
		 * it has 64 bytes in it, then call icaSha1 on that buffer.
		 * If there weren't enough bytes passed in to fill it out,
		 * just copy in what we can and return success without calling
		 * icaSha1. - KEY
		 */

		fill_size = SHA_BLOCK_SIZE - ibmca_sha_ctx->tail_len;
		if(fill_size < in_data_len) {
			memcpy(ibmca_sha_ctx->tail + ibmca_sha_ctx->tail_len, in_data, fill_size);

			/* Submit the filled out tail buffer */
			if( p_icaSha1(  ibmca_handle, (unsigned int)SHA_MSG_PART_FIRST,
					(unsigned int)SHA_BLOCK_SIZE, ibmca_sha_ctx->tail,
					(unsigned int)LENGTH_SHA_CONTEXT, &ibmca_sha_ctx->c,
					&tmp_len, tmp_hash)) {

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
				if( p_icaSha1(  ibmca_handle, message_part,
						(unsigned int)SHA_BLOCK_SIZE, ibmca_sha_ctx->tail,
						(unsigned int)LENGTH_SHA_CONTEXT, &ibmca_sha_ctx->c,
						&tmp_len, tmp_hash)) {

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
		p_icaSha1(ibmca_handle, message_part,
			(unsigned int)in_data_len, in_data + fill_size,
			(unsigned int)LENGTH_SHA_CONTEXT, &ibmca_sha_ctx->c,
			&tmp_len, tmp_hash)) {

		IBMCAerr(IBMCA_F_IBMCA_SHA1_UPDATE, IBMCA_R_REQUEST_FAILED);
		return 0;
	}

	return 1;
}				// end ibmca_sha1_update                                                 

static int ibmca_sha1_final(EVP_MD_CTX * ctx, unsigned char *md)
{
	IBMCA_SHA_CTX *ibmca_sha_ctx = ctx->md_data;
	unsigned int message_part = 0;
	int outlen = LENGTH_SHA_HASH;

	if (ibmca_sha_ctx->c.runningLength)
		message_part = SHA_MSG_PART_FINAL;
	else
		message_part = SHA_MSG_PART_ONLY;

	if( p_icaSha1(ibmca_handle,
		       message_part,
		       ibmca_sha_ctx->tail_len,
		       ibmca_sha_ctx->tail,
		       LENGTH_SHA_CONTEXT, &ibmca_sha_ctx->c, &outlen, md)) {
		
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
	unsigned int message_part = SHA_MSG_PART_MIDDLE, fill_size = 0,
		tmp_len = LENGTH_SHA256_HASH;
	unsigned long in_data_len = inlen;
	unsigned char tmp_hash[LENGTH_SHA256_HASH];

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
		 * until it has 64 bytes in it, then call icaSha256 on
		 * that buffer.  If there weren't enough bytes passed
		 * in to fill it out, just copy in what we can and
		 * return success without calling icaSha256. - KEY */

		fill_size = SHA_BLOCK_SIZE - ibmca_sha256_ctx->tail_len;
		if (fill_size < in_data_len) {
			memcpy(ibmca_sha256_ctx->tail 
			       + ibmca_sha256_ctx->tail_len, in_data,
			       fill_size);

			/* Submit the filled out tail buffer */
			if (p_icaSha256(ibmca_handle,
					(unsigned int)SHA_MSG_PART_FIRST,
					(unsigned int)SHA_BLOCK_SIZE,
					ibmca_sha256_ctx->tail,
					(unsigned int)LENGTH_SHA256_CONTEXT,
					&ibmca_sha256_ctx->c,
					&tmp_len, tmp_hash)) {
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
				if (p_icaSha256(ibmca_handle, message_part,
						(unsigned int)SHA_BLOCK_SIZE,
						ibmca_sha256_ctx->tail,
						(unsigned int)
						LENGTH_SHA256_CONTEXT,
						&ibmca_sha256_ctx->c,
						&tmp_len, tmp_hash)) {
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
	    p_icaSha256(ibmca_handle, message_part,
			(unsigned int)in_data_len, in_data + fill_size,
			(unsigned int)LENGTH_SHA256_CONTEXT,
			&ibmca_sha256_ctx->c,
			&tmp_len, tmp_hash)) {
		IBMCAerr(IBMCA_F_IBMCA_SHA256_UPDATE, IBMCA_R_REQUEST_FAILED);
		return 0;
	}

	return 1;
}				// end ibmca_sha256_update                                                 

static int ibmca_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	IBMCA_SHA256_CTX *ibmca_sha256_ctx = ctx->md_data;
	unsigned int message_part = 0;
	int outlen = LENGTH_SHA256_HASH;

	if (ibmca_sha256_ctx->c.runningLength)
		message_part = SHA_MSG_PART_FINAL;
	else
		message_part = SHA_MSG_PART_ONLY;

	if (p_icaSha256(ibmca_handle,
			message_part,
			ibmca_sha256_ctx->tail_len,
			ibmca_sha256_ctx->tail,
			LENGTH_SHA256_CONTEXT, &ibmca_sha256_ctx->c, &outlen,
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
	char *argument;
	char *result;
	char *key;
	ICA_KEY_RSA_MODEXPO *pubkey;
	int inLen, outLen, tmpLen;
	unsigned int rc;
	int to_return = 0; /* fail code set by default */

	if (!ibmca_dso) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_NOT_LOADED);
		goto err;
	}
	outLen = BN_num_bytes(m);
	argument = malloc(outLen);
	if (!argument) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	result = malloc(outLen);
	if (!result) {
		free(argument);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	key = malloc(sizeof(*pubkey));
	if (!key) {
		free(argument);
		free(result);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	pubkey = (ICA_KEY_RSA_MODEXPO *)key;
	memset(pubkey, 0, sizeof(*pubkey));
	pubkey->keyType = CORRECT_ENDIANNESS(ME_KEY_TYPE);
	pubkey->keyLength = CORRECT_ENDIANNESS(sizeof(ICA_KEY_RSA_MODEXPO));
	pubkey->expOffset = (char *)pubkey->keyRecord - (char *)pubkey;
#define IBMCA_MAX_EXP_LEN 256
	if (outLen > IBMCA_MAX_EXP_LEN) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_MEXP_LENGTH_TO_LARGE);
		goto err;
	}
	pubkey->expLength = pubkey->nLength = outLen;
	if (outLen < BN_num_bytes(p)) { /* Key record underflow check */
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_UNDERFLOW_KEYRECORD);
		goto err;
	}
	BN_bn2bin(p,
		  &pubkey->keyRecord[(pubkey->expLength - BN_num_bytes(p))]);
	BN_bn2bin(m, &pubkey->keyRecord[pubkey->expLength]);
	pubkey->modulusBitLength =  CORRECT_ENDIANNESS((pubkey->nLength * 8));
	pubkey->nOffset =
		CORRECT_ENDIANNESS((pubkey->expOffset + pubkey->expLength));
	pubkey->expOffset = CORRECT_ENDIANNESS(((char *)pubkey->keyRecord -
						(char *)pubkey));
	tmpLen = outLen;
	pubkey->expLength = pubkey->nLength = CORRECT_ENDIANNESS(tmpLen);
	memset(argument, 0, outLen);
	BN_bn2bin(a, ((unsigned char *)argument
		      + outLen
		      - BN_num_bytes(a)));
	inLen = outLen;
	if ((rc = p_icaRsaModExpo(ibmca_handle, inLen,
				  (unsigned char *)argument,
				  pubkey, &outLen,
				  (unsigned char *)result)) != 0) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	BN_bin2bn((unsigned char *)result, outLen, r);
	to_return = 1;
	free(argument);
	free(result);
	free(key);
err:
	return to_return;
}

#ifndef OPENSSL_NO_RSA
static int ibmca_rsa_init(RSA *rsa)
{
	RSA_blinding_off(rsa);

	return 1;
}

static int ibmca_rsa_mod_exp(BIGNUM * r0, const BIGNUM * I, RSA * rsa)
{
	BN_CTX *ctx;
	int to_return = 0;

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
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
	if (ctx)
		BN_CTX_free(ctx);
	return to_return;
}
#endif

/* Ein kleines chinesisches "Restessen"  */
static int ibmca_mod_exp_crt(BIGNUM * r, const BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * q,
			     const BIGNUM * dmp1, const BIGNUM * dmq1,
			     const BIGNUM * iqmp, BN_CTX * ctx)
{
	char *argument;
	char *result;
	char *key;
	unsigned char *pkey;
	ICA_KEY_RSA_CRT *privkey;
	int inLen, outLen;
	int rc;
	unsigned int offset, pSize, qSize;
	unsigned int keyRecordSize;
	unsigned int pbytes = BN_num_bytes(p);
	unsigned int qbytes = BN_num_bytes(q);
	unsigned int dmp1bytes = BN_num_bytes(dmp1);
	unsigned int dmq1bytes = BN_num_bytes(dmq1);
	unsigned int iqmpbytes = BN_num_bytes(iqmp);
	int to_return = 0;

	argument = malloc((pbytes + qbytes));
	if (!argument) {
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	result = malloc((pbytes + qbytes));
	if (!result) {
		free(argument);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	key = malloc(sizeof(*privkey));
	if (!key) {
		free(argument);
		free(result);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	privkey = (ICA_KEY_RSA_CRT *)key;
	keyRecordSize = (pbytes + qbytes + dmp1bytes + dmq1bytes + iqmpbytes);
	if (keyRecordSize > sizeof(privkey->keyRecord)) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP_CRT,
			 IBMCA_R_OPERANDS_TO_LARGE);
		goto err;
	}
	if ((qbytes + dmq1bytes) > 256) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP_CRT,
			 IBMCA_R_OPERANDS_TO_LARGE);
		goto err;
	}
	if (pbytes + dmp1bytes > 256) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP_CRT,
			 IBMCA_R_OPERANDS_TO_LARGE);
		goto err;
	}
	memset(privkey, 0, sizeof(*privkey));
	privkey->keyType = CORRECT_ENDIANNESS(CRT_KEY_TYPE);
	privkey->keyLength = CORRECT_ENDIANNESS(sizeof(ICA_KEY_RSA_CRT));
	privkey->modulusBitLength = CORRECT_ENDIANNESS(qbytes * 2 * 8);
	privkey->pLength = CORRECT_ENDIANNESS(pbytes + 8);
	privkey->qLength = CORRECT_ENDIANNESS(qbytes);
	privkey->dpLength = CORRECT_ENDIANNESS(dmp1bytes + 8);
	privkey->dqLength = CORRECT_ENDIANNESS(dmq1bytes);
	privkey->qInvLength = CORRECT_ENDIANNESS(iqmpbytes + 8);
	offset = ((char *)privkey->keyRecord - (char *)privkey);
	qSize = qbytes;
	pSize = (qSize + 8);	/*  1 QWORD larger */
	/* SAB  probably aittle redundant, but we'll verify that each 
	 * of the components which make up a key record sent ot the card 
	 * does not exceed the space that is allocated for it.  this 
	 * handles the case where even if the total length does not 
	 * exceed keyrecord zied, if the operands are funny sized they 
	 * could cause potential side affects on either the card or the 
	 * result
	 */
	if ((pbytes > pSize) || (dmp1bytes > pSize) ||
	    (iqmpbytes > pSize) || (qbytes > qSize) ||
	    (dmq1bytes > qSize)) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP_CRT,
			 IBMCA_R_OPERANDS_TO_LARGE);
		goto err;
	}
	privkey->dpOffset = CORRECT_ENDIANNESS(offset);
	offset += pSize;
	privkey->dqOffset = CORRECT_ENDIANNESS(offset);
	offset += qSize;
	privkey->pOffset = CORRECT_ENDIANNESS(offset);
	offset += pSize;
	privkey->qOffset = CORRECT_ENDIANNESS(offset);
	offset += qSize;
	privkey->qInvOffset = CORRECT_ENDIANNESS(offset);
	pkey = (char *)privkey->keyRecord;
	if (pSize < pbytes) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP_CRT,
			 IBMCA_R_UNDERFLOW_CONDITION);
		goto err;
	}
	pkey += pSize - dmp1bytes;
	BN_bn2bin(dmp1, pkey);
	pkey += dmp1bytes;
	BN_bn2bin(dmq1, pkey);
	pkey += qSize;
	pkey += pSize - pbytes; /* set up for zero padding of next field */
	BN_bn2bin(p, pkey);
	pkey += pbytes;
	BN_bn2bin(q, pkey);
	pkey += qSize;
	pkey += pSize - iqmpbytes; /* Adjust for padding */
	BN_bn2bin(iqmp, pkey);
	/* Prepare the argument and response */
	outLen = CORRECT_ENDIANNESS(privkey->qLength) * 2; /* Correct
							      endianess
							      is used
							      because
							      the
							      fields
							      were
							      converted
							      above */
	if (outLen > 256) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP_CRT,
			 IBMCA_R_OUTLEN_TO_LARGE);
		goto err;
	}
	/* SAB check for underflow here on the argeument */
	if (outLen < BN_num_bytes(a)) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP_CRT,
			 IBMCA_R_UNDERFLOW_CONDITION);
		goto err;
	}
	memset(argument, 0, pbytes + qbytes);
	BN_bn2bin(a, ((unsigned char *)argument
		      + outLen
		      - BN_num_bytes(a)));
	inLen = outLen;
	memset(result, 0, outLen);
	if ((rc = p_icaRsaCrt(ibmca_handle, inLen,
			      (unsigned char *)argument,
			      privkey, &outLen,
			      (unsigned char *)result)) != 0) {
		free(argument);
		free(result);
		free(key);
		IBMCAerr(IBMCA_F_IBMCA_MOD_EXP_CRT,
			 IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	BN_bin2bn((unsigned char *)result, outLen, r);
	to_return = 1;
	free(argument);
	free(result);
	free(key);
err:
	return to_return;
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
	int to_return = 0;	/* assume failure */
	unsigned int ret;


	if (ibmca_handle == 0) {
		IBMCAerr(IBMCA_F_IBMCA_RAND_BYTES,
			 IBMCA_R_NOT_INITIALISED);
		goto err;
	}

	ret = p_icaRandomNumberGenerate(ibmca_handle, num, buf);
	if (ret < 0) {
		IBMCAerr(IBMCA_F_IBMCA_RAND_BYTES, IBMCA_R_REQUEST_FAILED);
		goto err;
	}
	to_return = 1;
err:
	return to_return;
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
