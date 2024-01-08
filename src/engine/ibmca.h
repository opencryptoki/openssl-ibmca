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

#include <errno.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <ica_api.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
 #define OLDER_OPENSSL
#endif

/*
 * Here is a DEBUG_PRINTF macro which expands to nothing
 * at production level and is active only when the
 * ibmca build is configured with --enable-debug
 */
#ifdef DEBUG
#  define DEBUG_PRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
#  define DEBUG_PRINTF(...) do{} while(0)
#endif

/* COMPAT MACROS */
#ifdef OLDER_OPENSSL
 #define EVP_CIPHER_CTX_get_cipher_data(ctx)    ((ctx)->cipher_data)
 #define EVP_CIPHER_CTX_original_iv(ctx)        ((ctx)->oiv)
 #define EVP_CIPHER_CTX_iv_noconst(ctx)         ((ctx)->iv)
 #define EVP_CIPHER_CTX_encrypting(ctx)         ((ctx)->encrypt)
 #define EVP_CIPHER_CTX_buf_noconst(ctx)        ((ctx)->buf)
 #define EVP_CIPHER_CTX_key_length(ctx)         ((ctx)->cipher->key_len)
 #define EVP_MD_CTX_md_data(ctx)                ((ctx)->md_data)
#else
 #define EVP_CTRL_GCM_SET_IVLEN                 EVP_CTRL_AEAD_SET_IVLEN
 #define EVP_CTRL_GCM_SET_TAG                   EVP_CTRL_AEAD_SET_TAG
 #define EVP_CTRL_GCM_GET_TAG                   EVP_CTRL_AEAD_GET_TAG
#endif


#if !defined(NID_aes_128_gcm) || \
    !defined(NID_aes_192_gcm) || \
    !defined(NID_aes_256_gcm)
 #ifndef OPENSSL_NO_AES_GCM
  #define OPENSSL_NO_AES_GCM
 #endif
#endif
#ifndef EVP_AEAD_TLS1_AAD_LEN
 #define EVP_AEAD_TLS1_AAD_LEN              13
#endif
#ifndef EVP_MD_FLAG_PKEY_METHOD_SIGNATURE
 #define EVP_MD_FLAG_PKEY_METHOD_SIGNATURE  0
#endif


/******************************* Cipher stuff *********************************/
typedef struct ibmca_des_context {
    unsigned char key[sizeof(ica_des_key_triple_t)];
} ICA_DES_CTX;
typedef ICA_DES_CTX ICA_TDES_CTX;

#define AES_128_KEYLEN  AES_KEY_LEN128
typedef struct ibmca_aes_128_context {
    unsigned char key[sizeof(ica_aes_key_len_128_t)];
} ICA_AES_128_CTX;

#define AES_192_KEYLEN  AES_KEY_LEN192
typedef struct ibmca_aes_192_context {
    unsigned char key[sizeof(ica_aes_key_len_192_t)];
} ICA_AES_192_CTX;

#define AES_256_KEYLEN  AES_KEY_LEN256
typedef struct ibmca_aes_256_context {
    unsigned char key[sizeof(ica_aes_key_len_256_t)];
} ICA_AES_256_CTX;

typedef struct ibmca_aes_gcm_context {
    unsigned char key[32];
    int key_set;
    int iv_set;

    unsigned char tag[16];
    unsigned char subkey[16];
    unsigned char icb[16];
    unsigned char ucb[16];
    unsigned long long ptlen;
    unsigned long long aadlen;

    unsigned char *iv;
    int ivlen;
    int taglen;
    int iv_gen;
    int tls_aadlen;

} ICA_AES_GCM_CTX;

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

const EVP_CIPHER *ibmca_des_ecb();
const EVP_CIPHER *ibmca_des_cbc();
const EVP_CIPHER *ibmca_des_ofb();
const EVP_CIPHER *ibmca_des_cfb();
const EVP_CIPHER *ibmca_tdes_ecb();
const EVP_CIPHER *ibmca_tdes_cbc();
const EVP_CIPHER *ibmca_tdes_ofb();
const EVP_CIPHER *ibmca_tdes_cfb();
const EVP_CIPHER *ibmca_aes_128_ecb();
const EVP_CIPHER *ibmca_aes_128_cbc();
const EVP_CIPHER *ibmca_aes_128_ofb();
const EVP_CIPHER *ibmca_aes_128_cfb();
const EVP_CIPHER *ibmca_aes_192_ecb();
const EVP_CIPHER *ibmca_aes_192_cbc();
const EVP_CIPHER *ibmca_aes_192_ofb();
const EVP_CIPHER *ibmca_aes_192_cfb();
const EVP_CIPHER *ibmca_aes_256_ecb();
const EVP_CIPHER *ibmca_aes_256_cbc();
const EVP_CIPHER *ibmca_aes_256_ofb();
const EVP_CIPHER *ibmca_aes_256_cfb();
#ifndef OPENSSL_NO_AES_GCM
const EVP_CIPHER *ibmca_aes_128_gcm();
const EVP_CIPHER *ibmca_aes_192_gcm();
const EVP_CIPHER *ibmca_aes_256_gcm();
#endif

#ifndef OLDER_OPENSSL
void ibmca_des_ecb_destroy();
void ibmca_des_cbc_destroy();
void ibmca_des_ofb_destroy();
void ibmca_des_cfb_destroy();
void ibmca_tdes_ecb_destroy();
void ibmca_tdes_cbc_destroy();
void ibmca_tdes_ofb_destroy();
void ibmca_tdes_cfb_destroy();
void ibmca_aes_128_ecb_destroy();
void ibmca_aes_128_cbc_destroy();
void ibmca_aes_128_ofb_destroy();
void ibmca_aes_128_cfb_destroy();
void ibmca_aes_192_ecb_destroy();
void ibmca_aes_192_cbc_destroy();
void ibmca_aes_192_ofb_destroy();
void ibmca_aes_192_cfb_destroy();
void ibmca_aes_256_ecb_destroy();
void ibmca_aes_256_cbc_destroy();
void ibmca_aes_256_ofb_destroy();
void ibmca_aes_256_cfb_destroy();
void ibmca_aes_128_gcm_destroy();
void ibmca_aes_192_gcm_destroy();
void ibmca_aes_256_gcm_destroy();
#endif

/******************************* Digest stuff *********************************/
#ifndef OPENSSL_NO_SHA1
#define SHA_BLOCK_SIZE 64
typedef struct ibmca_sha1_ctx {
    sha_context_t c;
    unsigned char tail[SHA_BLOCK_SIZE];
    unsigned int tail_len;
} IBMCA_SHA_CTX;

const EVP_MD *ibmca_sha1();

#ifndef OLDER_OPENSSL
void ibmca_sha1_destroy();
#endif
#endif

#ifndef OPENSSL_NO_SHA256
#define SHA256_BLOCK_SIZE 64
typedef struct ibmca_sha256_ctx {
    sha256_context_t c;
    unsigned char tail[SHA256_BLOCK_SIZE];
    unsigned int tail_len;
} IBMCA_SHA256_CTX;

const EVP_MD *ibmca_sha256();

#ifndef OLDER_OPENSSL
void ibmca_sha256_destroy();
#endif
#endif

#ifndef OPENSSL_NO_SHA512
#define SHA512_BLOCK_SIZE 128
typedef struct ibmca_sha512_ctx {
    sha512_context_t c;
    unsigned char tail[SHA512_BLOCK_SIZE];
    unsigned int tail_len;
} IBMCA_SHA512_CTX;

const EVP_MD *ibmca_sha512();

#ifndef OLDER_OPENSSL
void ibmca_sha512_destroy();
#endif
#endif

/******************************** BIGNUM stuff ********************************/
int ibmca_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                  const BIGNUM *m, BN_CTX *ctx);


/********************************* RSA stuff **********************************/
#ifndef OPENSSL_NO_RSA
RSA_METHOD *ibmca_rsa();
#ifndef OLDER_OPENSSL
void ibmca_rsa_destroy(void);
#endif
#endif

extern ica_adapter_handle_t ibmca_handle;



/********************************* DSA stuff **********************************/
#ifndef OPENSSL_NO_DSA
DSA_METHOD *ibmca_dsa();
#ifndef OLDER_OPENSSL
void ibmca_dsa_destroy(void);
#endif
#endif



/********************************** DH stuff **********************************/
#ifndef OPENSSL_NO_DH
DH_METHOD *ibmca_dh();
#ifndef OLDER_OPENSSL
void ibmca_dh_destroy(void);
#endif
#endif


/********************************** EC stuff **********************************/

/* Either enable or disable ALL ECC */
#ifndef OPENSSL_NO_EC
 #if defined(OPENSSL_NO_ECDH) || defined(OPENSSL_NO_ECDSA)
  #define OPENSSL_NO_EC
 #endif
#endif

#define IBMCA_EC_MAX_D_LEN	66
#define IBMCA_EC_MAX_Q_LEN	(2 * IBMCA_EC_MAX_D_LEN)
#define IBMCA_EC_MAX_SIG_LEN	IBMCA_EC_MAX_Q_LEN
#define IBMCA_EC_MAX_Z_LEN	IBMCA_EC_MAX_D_LEN

#ifndef OPENSSL_NO_EC
int ibmca_ec_init(void);
void ibmca_ec_destroy(void);

int ibmca_ecdh_compute_key(unsigned char **pout, size_t *poutlen,
			   const EC_POINT *pub_key, const EC_KEY *ecdh);
ECDSA_SIG *ibmca_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
				const BIGNUM *in_kinv, const BIGNUM *in_r,
				EC_KEY *eckey);
int ibmca_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
			   const ECDSA_SIG *sig, EC_KEY *eckey);
 #ifdef OLDER_OPENSSL
extern ECDSA_METHOD *ibmca_ecdsa;
extern ECDH_METHOD *ibmca_ecdh;
extern const ECDSA_METHOD *ossl_ecdsa;
extern const ECDH_METHOD *ossl_ecdh;

int ibmca_older_ecdh_compute_key(void *out, size_t len,
				 const EC_POINT *pub_key,
				 EC_KEY *ecdh,
				 void *(*KDF)(const void *in, size_t inlen,
					      void *out, size_t *outlen));
ECDSA_SIG *ibmca_older_ecdsa_do_sign(const unsigned char *dgst, int dlen,
				     const BIGNUM *, const BIGNUM *,
				     EC_KEY *eckey);
int ibmca_older_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
				const ECDSA_SIG *sig, EC_KEY *eckey);

/*
 * APIs which are missing in openssl 1.0.2.
 */
ECDH_METHOD *ECDH_METHOD_new(const ECDH_METHOD *meth);
void ECDH_METHOD_set_compute_key(ECDH_METHOD *meth,
				 int (*compute_key)(void *out, size_t len,
						    const EC_POINT *pub_key,
						    EC_KEY *ecdh,
						    void *(*KDF)(const void *in,
								 size_t inlen,
								 void *out,
								 size_t *outlen)));
void ECDH_METHOD_get_compute_key(const ECDH_METHOD *meth,
                                 int (**compute_key)(void *out, size_t len,
                                                     const EC_POINT *pub_key,
                                                     EC_KEY *ecdh,
                                                     void *(*KDF)(const void *in,
                                                                  size_t inlen,
                                                                  void *out,
                                                                  size_t *outlen)));
void ECDH_METHOD_set_name(ECDH_METHOD *meth, char *name);
void ECDH_METHOD_free(ECDH_METHOD *meth);

void ECDSA_METHOD_get_sign(const ECDSA_METHOD *meth,
                           int (**psign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                               BIGNUM **kinvp, BIGNUM **rp),
                           ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
                                                    int dgst_len,
                                                    const BIGNUM *in_kinv,
                                                    const BIGNUM *in_r,
                                                    EC_KEY *eckey));

void ECDSA_METHOD_get_verify(const ECDSA_METHOD *meth,
                             int (**pverify_sig)(const unsigned char *dgst,
                                                 int dgst_len,
                                                 const ECDSA_SIG *sig,
                                                 EC_KEY *eckey));

 #else
extern EC_KEY_METHOD *ibmca_ec;
extern const EC_KEY_METHOD *ossl_ec;

int ibmca_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
		     unsigned char *sig_array, unsigned int *siglen,
		     const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
int ibmca_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
		       const unsigned char *sigbuf, int sig_len,
		       EC_KEY *eckey);
 #endif
#endif

const EVP_PKEY_METHOD *ibmca_x25519(void);
const EVP_PKEY_METHOD *ibmca_x448(void);
const EVP_PKEY_METHOD *ibmca_ed25519(void);
const EVP_PKEY_METHOD *ibmca_ed448(void);
void ibmca_x25519_destroy(void);
void ibmca_x448_destroy(void);
void ibmca_ed25519_destroy(void);
void ibmca_ed448_destroy(void);

/******************************* Libica stuff *********************************/
/*
 * These are the function pointers that are (un)set when the library has
 * successfully (un)loaded.
 */
typedef unsigned int (*ica_get_functionlist_t)(libica_func_list_element *,
                                               unsigned int *);
typedef void         (*ica_set_fallback_mode_t)(int);
typedef unsigned int (*ica_open_adapter_t)(ica_adapter_handle_t *);
typedef unsigned int (*ica_close_adapter_t)(ica_adapter_handle_t);
typedef unsigned int (*ica_rsa_mod_expo_t)(ica_adapter_handle_t,
                                           unsigned char *,
                                           ica_rsa_key_mod_expo_t *,
                                           unsigned char *);
typedef unsigned int (*ica_rsa_crt_t)(ica_adapter_handle_t, unsigned char *,
                                      ica_rsa_key_crt_t *, unsigned char *);
typedef unsigned int (*ica_random_number_generate_t)(unsigned int,
                                                     unsigned char *);
typedef unsigned int (*ica_sha1_t)(unsigned int, unsigned int, unsigned char *,
                                   sha_context_t *, unsigned char *);
typedef unsigned int (*ica_sha256_t)(unsigned int, unsigned int,
                                     unsigned char *, sha256_context_t *,
                                     unsigned char *);
typedef unsigned int (*ica_sha512_t)(unsigned int, unsigned int,
                                     unsigned char *, sha512_context_t *,
                                     unsigned char *);
typedef unsigned int (*ica_des_ecb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      unsigned char *key,
                                      unsigned int direction);
typedef unsigned int (*ica_des_cbc_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      unsigned char *key,
                                      unsigned char *iv,
                                      unsigned int direction);
typedef unsigned int (*ica_des_cfb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      const unsigned char *key,
                                      unsigned char *iv,
                                      unsigned int lcfb,
                                      unsigned int direction);
typedef unsigned int (*ica_des_ofb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      const unsigned char *key,
                                      unsigned char *iv,
                                      unsigned int direction);
typedef unsigned int (*ica_3des_ecb_t)(const unsigned char *in_data,
                                       unsigned char *out_data,
                                       unsigned long data_length,
                                       unsigned char *key,
                                       unsigned int direction);
typedef unsigned int (*ica_3des_cbc_t)(const unsigned char *in_data,
                                       unsigned char *out_data,
                                       unsigned long data_length,
                                       unsigned char *key,
                                       unsigned char *iv,
                                       unsigned int direction);
typedef unsigned int (*ica_3des_cfb_t)(const unsigned char *, unsigned char *,
                                       unsigned long, const unsigned char *,
                                       unsigned char *, unsigned int,
                                       unsigned int);
typedef unsigned int (*ica_3des_ofb_t)(const unsigned char *in_data,
                                       unsigned char *out_data,
                                       unsigned long data_length,
                                       const unsigned char *key,
                                       unsigned char *iv,
                                       unsigned int direction);
typedef unsigned int (*ica_aes_ecb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      unsigned char *key,
                                      unsigned int key_length,
                                      unsigned int direction);
typedef unsigned int (*ica_aes_cbc_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      unsigned char *key,
                                      unsigned int key_length,
                                      unsigned char *iv,
                                      unsigned int direction);
typedef unsigned int (*ica_aes_ofb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      const unsigned char *key,
                                      unsigned int key_length,
                                      unsigned char *iv,
                                      unsigned int direction);
typedef unsigned int (*ica_aes_cfb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      const unsigned char *key,
                                      unsigned int key_length,
                                      unsigned char *iv, unsigned int lcfb,
                                      unsigned int direction);
typedef unsigned int (*ica_aes_gcm_initialize_t)(const unsigned char *iv,
                                                 unsigned int iv_length,
                                                 unsigned char *key,
                                                 unsigned int key_length,
                                                 unsigned char *icb,
                                                 unsigned char *ucb,
                                                 unsigned char *subkey,
                                                 unsigned int direction);
typedef unsigned int (*ica_aes_gcm_intermediate_t)(unsigned char *plaintext,
                                                   unsigned long
                                                            plaintext_length,
                                                   unsigned char *ciphertext,
                                                   unsigned char *ucb,
                                                   unsigned char *aad,
                                                   unsigned long aad_length,
                                                   unsigned char *tag,
                                                   unsigned int tag_length,
                                                   unsigned char *key,
                                                   unsigned int key_length,
                                                   unsigned char *subkey,
                                                   unsigned int direction);
typedef unsigned int (*ica_aes_gcm_last_t)(unsigned char *icb,
                                           unsigned long aad_length,
                                           unsigned long ciph_length,
                                           unsigned char *tag,
                                           unsigned char *final_tag,
                                           unsigned int final_tag_length,
                                           unsigned char *key,
                                           unsigned int key_length,
                                           unsigned char *subkey,
                                           unsigned int direction);

#ifndef OPENSSL_NO_EC
typedef ICA_EC_KEY* (*ica_ec_key_new_t)(unsigned int nid,
					unsigned int *privlen);
typedef int (*ica_ec_key_init_t)(const unsigned char *X,
				 const unsigned char *Y,
				 const unsigned char *D, ICA_EC_KEY *key);
typedef int (*ica_ec_key_generate_t)(ica_adapter_handle_t adapter_handle,
				     ICA_EC_KEY *key);
typedef int (*ica_ecdh_derive_secret_t)(ica_adapter_handle_t adapter_handle,
					const ICA_EC_KEY *privkey_A,
					const ICA_EC_KEY *pubkey_B,
					unsigned char *z,
					unsigned int z_length);
typedef int (*ica_ecdsa_sign_t)(ica_adapter_handle_t adapter_handle,
				const ICA_EC_KEY *privkey,
				const unsigned char *hash,
				unsigned int hash_length,
				unsigned char *signature,
				unsigned int signature_length);
typedef int (*ica_ecdsa_verify_t)(ica_adapter_handle_t adapter_handle,
				  const ICA_EC_KEY *pubkey,
				  const unsigned char *hash,
				  unsigned int hash_length,
				  const unsigned char *signature,
				  unsigned int signature_length);
typedef int (*ica_ec_key_get_public_key_t)(ICA_EC_KEY *key, unsigned char *q,
					   unsigned int *q_len);
typedef int (*ica_ec_key_get_private_key_t)(ICA_EC_KEY *key, unsigned char *d,
					    unsigned int *d_len);
typedef void (*ica_ec_key_free_t)(ICA_EC_KEY *key);
#endif

typedef
int (*ica_x25519_ctx_new_t)(ICA_X25519_CTX **ctx);
typedef
int (*ica_x448_ctx_new_t)(ICA_X448_CTX **ctx);
typedef
int (*ica_ed25519_ctx_new_t)(ICA_ED25519_CTX **ctx);
typedef
int (*ica_ed448_ctx_new_t)(ICA_ED448_CTX **ctx);
typedef
int (*ica_x25519_key_set_t)(ICA_X25519_CTX *ctx, const unsigned char priv[32],
		       const unsigned char pub[32]);
typedef
int (*ica_x448_key_set_t)(ICA_X448_CTX *ctx, const unsigned char priv[56],
		     const unsigned char pub[56]);
typedef
int (*ica_ed25519_key_set_t)(ICA_ED25519_CTX *ctx, const unsigned char priv[32],
			const unsigned char pub[32]);
typedef
int (*ica_ed448_key_set_t)(ICA_ED448_CTX *ctx, const unsigned char priv[56],
		      const unsigned char pub[56]);
typedef
int (*ica_x25519_key_get_t)(ICA_X25519_CTX *ctx, unsigned char priv[32],
		       unsigned char pub[32]);
typedef
int (*ica_x448_key_get_t)(ICA_X448_CTX *ctx, unsigned char priv[56],
		     unsigned char pub[56]);
typedef
int (*ica_ed25519_key_get_t)(ICA_ED25519_CTX *ctx, unsigned char priv[32],
			unsigned char pub[32]);
typedef
int (*ica_ed448_key_get_t)(ICA_ED448_CTX *ctx, unsigned char priv[57],
		      unsigned char pub[57]);
typedef
int (*ica_x25519_key_gen_t)(ICA_X25519_CTX *ctx);
typedef
int (*ica_x448_key_gen_t)(ICA_X448_CTX *ctx);
typedef
int (*ica_ed25519_key_gen_t)(ICA_ED25519_CTX *ctx);
typedef
int (*ica_ed448_key_gen_t)(ICA_ED448_CTX *ctx);
typedef
int (*ica_x25519_derive_t)(ICA_X25519_CTX *ctx,
		      unsigned char shared_secret[32],
		      const unsigned char peer_pub[32]);
typedef
int (*ica_x448_derive_t)(ICA_X448_CTX *ctx,
		    unsigned char shared_secret[56],
		    const unsigned char peer_pub[56]);
typedef
int (*ica_ed25519_sign_t)(ICA_ED25519_CTX *ctx, unsigned char sig[64],
		     const unsigned char *msg, size_t msglen);
typedef
int (*ica_ed448_sign_t)(ICA_ED448_CTX *ctx, unsigned char sig[114],
		   const unsigned char *msg, size_t msglen);
typedef
int (*ica_ed25519_verify_t)(ICA_ED25519_CTX *ctx, const unsigned char sig[64],
		       const unsigned char *msg, size_t msglen);
typedef
int (*ica_ed448_verify_t)(ICA_ED448_CTX *ctx, const unsigned char sig[114],
		     const unsigned char *msg, size_t msglen);
typedef
int (*ica_x25519_ctx_del_t)(ICA_X25519_CTX **ctx);
typedef
int (*ica_x448_ctx_del_t)(ICA_X448_CTX **ctx);
typedef
int (*ica_ed25519_ctx_del_t)(ICA_ED25519_CTX **ctx);
typedef
int (*ica_ed448_ctx_del_t)(ICA_ED448_CTX **ctx);

typedef void (*ica_cleanup_t)(void);
typedef void (*ica_allow_external_gcm_iv_in_fips_mode_t)(int allow);

/* entry points into libica, filled out at DSO load time */
extern ica_get_functionlist_t           p_ica_get_functionlist;
extern ica_set_fallback_mode_t          p_ica_set_fallback_mode;
extern ica_open_adapter_t               p_ica_open_adapter;
extern ica_close_adapter_t              p_ica_close_adapter;
extern ica_rsa_mod_expo_t               p_ica_rsa_mod_expo;
extern ica_random_number_generate_t     p_ica_random_number_generate;
extern ica_rsa_crt_t                    p_ica_rsa_crt;
extern ica_sha1_t                       p_ica_sha1;
extern ica_sha256_t                     p_ica_sha256;
extern ica_sha512_t                     p_ica_sha512;
extern ica_des_ecb_t                    p_ica_des_ecb;
extern ica_des_cbc_t                    p_ica_des_cbc;
extern ica_des_ofb_t                    p_ica_des_ofb;
extern ica_des_cfb_t                    p_ica_des_cfb;
extern ica_3des_ecb_t                   p_ica_3des_ecb;
extern ica_3des_cbc_t                   p_ica_3des_cbc;
extern ica_3des_cfb_t                   p_ica_3des_cfb;
extern ica_3des_ofb_t                   p_ica_3des_ofb;
extern ica_aes_ecb_t                    p_ica_aes_ecb;
extern ica_aes_cbc_t                    p_ica_aes_cbc;
extern ica_aes_ofb_t                    p_ica_aes_ofb;
extern ica_aes_cfb_t                    p_ica_aes_cfb;
#ifndef OPENSSL_NO_AES_GCM
extern ica_aes_gcm_initialize_t         p_ica_aes_gcm_initialize;
extern ica_aes_gcm_intermediate_t       p_ica_aes_gcm_intermediate;
extern ica_aes_gcm_last_t               p_ica_aes_gcm_last;
#endif
#ifndef OPENSSL_NO_EC
extern ica_ec_key_new_t			p_ica_ec_key_new;
extern ica_ec_key_init_t		p_ica_ec_key_init;
extern ica_ec_key_generate_t		p_ica_ec_key_generate;
extern ica_ecdh_derive_secret_t		p_ica_ecdh_derive_secret;
extern ica_ecdsa_sign_t			p_ica_ecdsa_sign;
extern ica_ecdsa_verify_t		p_ica_ecdsa_verify;
extern ica_ec_key_get_public_key_t	p_ica_ec_key_get_public_key;
extern ica_ec_key_get_private_key_t	p_ica_ec_key_get_private_key;
extern ica_ec_key_free_t		p_ica_ec_key_free;
#endif
extern ica_x25519_ctx_new_t		p_ica_x25519_ctx_new;
extern ica_x448_ctx_new_t		p_ica_x448_ctx_new;
extern ica_ed25519_ctx_new_t		p_ica_ed25519_ctx_new;
extern ica_ed448_ctx_new_t		p_ica_ed448_ctx_new;
extern ica_x25519_key_set_t		p_ica_x25519_key_set;
extern ica_x448_key_set_t		p_ica_x448_key_set;
extern ica_ed25519_key_set_t		p_ica_ed25519_key_set;
extern ica_ed448_key_set_t		p_ica_ed448_key_set;
extern ica_x25519_key_get_t		p_ica_x25519_key_get;
extern ica_x448_key_get_t		p_ica_x448_key_get;
extern ica_ed25519_key_get_t		p_ica_ed25519_key_get;
extern ica_ed448_key_get_t		p_ica_ed448_key_get;
extern ica_x25519_key_gen_t		p_ica_x25519_key_gen;
extern ica_x448_key_gen_t		p_ica_x448_key_gen;
extern ica_ed25519_key_gen_t		p_ica_ed25519_key_gen;
extern ica_ed448_key_gen_t		p_ica_ed448_key_gen;
extern ica_x25519_derive_t		p_ica_x25519_derive;
extern ica_x448_derive_t		p_ica_x448_derive;
extern ica_ed25519_sign_t		p_ica_ed25519_sign;
extern ica_ed448_sign_t			p_ica_ed448_sign;
extern ica_ed25519_verify_t		p_ica_ed25519_verify;
extern ica_ed448_verify_t		p_ica_ed448_verify;
extern ica_x25519_ctx_del_t		p_ica_x25519_ctx_del;
extern ica_x448_ctx_del_t		p_ica_x448_ctx_del;
extern ica_ed25519_ctx_del_t		p_ica_ed25519_ctx_del;
extern ica_ed448_ctx_del_t		p_ica_ed448_ctx_del;
extern ica_cleanup_t            p_ica_cleanup;
