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

/*
 * Digest and Cipher support added by Robert H Burroughs (burrough@us.ibm.com).
 *
 * DES/3DES/AES-CFB/OFB support added by Kent Yoder (yoder1@us.ibm.com)
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/aes.h>

#include <ica_api.h>
#include "ibmca.h"
#include "e_ibmca_err.h"

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_IBMCA

#define IBMCA_LIB_NAME "ibmca engine"

#define AP_PATH "/sys/devices/ap"

/*
 * The default library name.  The macro LIBICA_SHARED_LIB is provided
 * via configure at the command line.
 */
static const char *LIBICA_NAME = LIBICA_SHARED_LIB;
/*
 * If a ctrl command is used to set libica name, we have to strdup the
 * argument since the config parser will free and clear the element at
 * the end of parsing.  If the engine is not loaded during
 * configuration, we will not be able to use the string provided by
 * the ctrl command since it is cleared.  Remember if we strdup'ed the
 * string such that we free it at the end.
 */
static int LIBICA_NAME_allocated;

/* Constants used when creating the ENGINE */
static const char *engine_ibmca_id = "ibmca";
static const char *engine_ibmca_name = "Ibmca hardware engine support";

/* This is a process-global DSO handle used for loading and unloading
 * the Ibmca library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */
void *ibmca_dso = NULL;

ica_adapter_handle_t ibmca_handle = DRIVER_NOT_LOADED;

/* entry points into libica, filled out at DSO load time */
ica_get_functionlist_t          p_ica_get_functionlist;
ica_set_fallback_mode_t         p_ica_set_fallback_mode;
ica_open_adapter_t              p_ica_open_adapter;
ica_close_adapter_t             p_ica_close_adapter;
ica_rsa_mod_expo_t              p_ica_rsa_mod_expo;
ica_random_number_generate_t    p_ica_random_number_generate;
ica_rsa_crt_t                   p_ica_rsa_crt;
ica_sha1_t                      p_ica_sha1;
ica_sha256_t                    p_ica_sha256;
ica_sha512_t                    p_ica_sha512;
ica_des_ecb_t                   p_ica_des_ecb;
ica_des_cbc_t                   p_ica_des_cbc;
ica_des_ofb_t                   p_ica_des_ofb;
ica_des_cfb_t                   p_ica_des_cfb;
ica_3des_ecb_t                  p_ica_3des_ecb;
ica_3des_cbc_t                  p_ica_3des_cbc;
ica_3des_cfb_t                  p_ica_3des_cfb;
ica_3des_ofb_t                  p_ica_3des_ofb;
ica_aes_ecb_t                   p_ica_aes_ecb;
ica_aes_cbc_t                   p_ica_aes_cbc;
ica_aes_ofb_t                   p_ica_aes_ofb;
ica_aes_cfb_t                   p_ica_aes_cfb;
#ifndef OPENSSL_NO_AES_GCM
ica_aes_gcm_initialize_t        p_ica_aes_gcm_initialize;
ica_aes_gcm_intermediate_t      p_ica_aes_gcm_intermediate;
ica_aes_gcm_last_t              p_ica_aes_gcm_last;
#endif
ica_cleanup_t                   p_ica_cleanup;

/* save libcrypto's default ec methods */
#ifndef NO_EC
 #ifdef OLDER_OPENSSL
    const ECDSA_METHOD *ossl_ecdsa;
    const ECDH_METHOD *ossl_ecdh;
 #else
    const EC_KEY_METHOD *ossl_ec;
 #endif
#endif

/*
 * ibmca_crypto_algos lists the supported crypto algos by ibmca.
 * This list is matched against all algo support by libica. Only if
 * the algo is in this list it is activated in ibmca.
 * The defines can be found in the libica header file.
 */
static int ibmca_crypto_algos[] = {
    SHA1,
    SHA256,
    SHA512,
    P_RNG,
    RSA_ME,
    RSA_CRT,
    DES_ECB,
    DES_CBC,
    DES_OFB,
    DES_CFB,
    DES3_ECB,
    DES3_CBC,
    DES3_OFB,
    DES3_CFB,
    DES3_CTR,
    AES_ECB,
    AES_CBC,
    AES_OFB,
    AES_CFB,
    AES_GCM_KMA,
    EC_KGEN,
    EC_DSA_SIGN,
    EC_DSA_VERIFY,
    EC_DH,
    ED25519_KEYGEN,
    ED25519_SIGN,
    ED25519_VERIFY,
    ED448_KEYGEN,
    ED448_SIGN,
    ED448_VERIFY,
    X25519_KEYGEN,
    X25519_DERIVE,
    X448_KEYGEN,
    X448_DERIVE,
    0
};

#define MAX_CIPHER_NIDS sizeof(ibmca_crypto_algos)

/*
 * This struct maps one NID to one crypto algo.
 * So we can tell OpenSSL this NID maps to this function.
 */
struct crypto_pair {
    int nids[MAX_CIPHER_NIDS];
    const void *crypto_meths[MAX_CIPHER_NIDS];
};

/* We can not say how much crypto algos are
 * supported by libica. We can only say the
 * size is not greater as the supported
 * crypto algos by ibmca.
 * The actual number of supported crypto algos
 * is saved to the size_****_nid variabes
 */
static size_t size_cipher_list = 0;
static size_t size_digest_list = 0;
static size_t size_pkey_meths_list = 0;

static struct registration_helper {
    int rsa_enabled;
    int ec_enabled;
    int ec_kgen_switch;
    int ec_dh_switch;
    int ec_dsa_sign_switch;
    int ec_dsa_verify_switch;
    int x25519_keygen_switch;
    int x25519_derive_switch;
    int x448_keygen_switch;
    int x448_derive_switch;
    int ed25519_keygen_switch;
    int ed25519_sign_switch;
    int ed25519_verify_switch;
    int ed448_keygen_switch;
    int ed448_sign_switch;
    int ed448_verify_switch;
    int x25519_switch;
    int x448_switch;
    int ed25519_switch;
    int ed448_switch;
} ibmca_registration;

static CRYPTO_ONCE bindcountlockinitonce = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *bindcountlock = NULL;
static int bindcount = 0;

static struct crypto_pair ibmca_cipher_lists;
static struct crypto_pair ibmca_digest_lists;
static struct crypto_pair ibmca_pkey_meths_lists;

static int ibmca_usable_ciphers(const int **nids);
static int ibmca_engine_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
                                const int **nids, int nid);
static int ibmca_usable_digests(const int **nids);
static int ibmca_engine_digests(ENGINE * e, const EVP_MD ** digest,
                                const int **nids, int nid);
static int ibmca_engine_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                                   const int **nids, int nid);
static int ibmca_usable_pkey_meths(const int **nids);

static void bindcountlockinit(void)
{
    bindcountlock = CRYPTO_THREAD_lock_new();
}

/* RAND stuff */
static int ibmca_rand_bytes(unsigned char *buf, int num);
static int ibmca_rand_status(void);

static RAND_METHOD ibmca_rand = {
    /* "IBMCA RAND method", */
    NULL,                       /* seed */
    ibmca_rand_bytes,           /* bytes */
    NULL,                       /* cleanup */
    NULL,                       /* add */
    ibmca_rand_bytes,           /* pseudorand */
    ibmca_rand_status,          /* status */
};


/* The definitions for control commands specific to this engine */
#define IBMCA_CMD_SO_PATH		ENGINE_CMD_BASE
#define IBMCA_CMD_LIBICA        (ENGINE_CMD_BASE + 1)
static const ENGINE_CMD_DEFN ibmca_cmd_defns[] = {
    {IBMCA_CMD_SO_PATH,
     "SO_PATH",
     "Specifies the path to the 'ibmca' shared library",
     ENGINE_CMD_FLAG_STRING},
    {IBMCA_CMD_LIBICA,
     "libica",
     "Specifies the path to the 'libica' shared library",
     ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

/* Destructor (complements the "ENGINE_ibmca()" constructor) */
static int ibmca_destroy(ENGINE *e)
{
    int newbindcount;
    CRYPTO_atomic_add(&bindcount, -1, &newbindcount, bindcountlock);
    if (newbindcount)
        return 1;
    /* Unload the ibmca error strings so any error state including our
     * functs or reasons won't lead to a segfault (they simply get displayed
     * without corresponding string data because none will be found).
     */
    ERR_unload_IBMCA_strings();
    return 1;
}

inline static int set_RSA_prop(ENGINE *e)
{
    if (ibmca_registration.rsa_enabled) {
        return 1;
    }
    if (
#ifndef OPENSSL_NO_RSA
        !ENGINE_set_RSA(e, ibmca_rsa()) ||
#endif
#ifndef OPENSSL_NO_DSA
        !ENGINE_set_DSA(e, ibmca_dsa()) ||
#endif
#ifndef OPENSSL_NO_DH
        !ENGINE_set_DH(e, ibmca_dh())
#endif
        )
        return 0;

    ibmca_registration.rsa_enabled = 1;

    return 1;
}

#ifndef OPENSSL_NO_EC
static int set_EC_prop(ENGINE *e)
{
    if (ibmca_registration.ec_enabled) {
        return 1;
    }

 #ifdef OLDER_OPENSSL
    ossl_ecdh = ECDH_get_default_method();
    ossl_ecdsa = ECDSA_get_default_method();

    ibmca_ecdh = ECDH_METHOD_new(NULL);
    ibmca_ecdsa = ECDSA_METHOD_new(NULL);

    ECDSA_METHOD_set_name(ibmca_ecdsa, "Ibmca ECDSA method");
    ECDSA_METHOD_set_sign(ibmca_ecdsa, ibmca_older_ecdsa_do_sign);
    ECDSA_METHOD_set_verify(ibmca_ecdsa, ibmca_older_ecdsa_do_verify);
  #ifdef ECDSA_FLAG_FIPS_METHOD
    ECDSA_METHOD_set_flags(ibmca_ecdsa, ECDSA_FLAG_FIPS_METHOD);
  #endif

    ECDH_METHOD_set_name(ibmca_ecdh, "Ibmca ECDH method");
    ECDH_METHOD_set_compute_key(ibmca_ecdh, ibmca_older_ecdh_compute_key);
  #ifdef ECDH_FLAG_FIPS_METHOD
    ECDH_METHOD_set_flags(ibmca_ecdh, ECDH_FLAG_FIPS_METHOD);
  #endif

    if (!ENGINE_set_ECDH(e, ibmca_ecdh))
        return 0;
    if (!ENGINE_set_ECDSA(e, ibmca_ecdsa))
        return 0;
 #else
    ossl_ec = EC_KEY_get_default_method();

    ibmca_ec = EC_KEY_METHOD_new(ibmca_ec);
    EC_KEY_METHOD_set_keygen(ibmca_ec, ibmca_ec_key_gen);
    EC_KEY_METHOD_set_compute_key(ibmca_ec, ibmca_ecdh_compute_key);
    EC_KEY_METHOD_set_sign(ibmca_ec, ibmca_ecdsa_sign, ECDSA_sign_setup,
                           ibmca_ecdsa_sign_sig);
    EC_KEY_METHOD_set_verify(ibmca_ec, ibmca_ecdsa_verify,
                             ibmca_ecdsa_verify_sig);

    if (!ENGINE_set_EC(e, ibmca_ec))
        return 0;
 #endif

    ibmca_registration.ec_enabled = 1;

    return 1;
}
#endif

/*
 * dig_nid_cnt and ciph_nid_cnt count the number of enabled crypt mechanims.
 * dig_nid_cnt and ciph_nid_cnt needs to be pointer, because only
 * set_engine_prop knows about how much digest or cipher will be set per call.
 * To count the number of cipher and digest outside of the function is not
 * feasible
 */
inline static int set_engine_prop(ENGINE *e, int algo_id, int *dig_nid_cnt,
                                  int *ciph_nid_cnt, int *pkey_nid_cnt)
{
    switch (algo_id) {
    case P_RNG:
        if (!ENGINE_set_RAND(e, &ibmca_rand))
            return 0;
        break;
    /*
     * RSA will be enabled if one of this is set. OpenSSL does not distinguish
     * between RSA_ME and RSA_CRT. It is not the task of ibmca to route one ME
     * call to CRT or vice versa.
     */
    case RSA_ME:
    case RSA_CRT:
        if (!set_RSA_prop(e))
            return 0;
        break;
#ifndef OPENSSL_NO_SHA1
    case SHA1:
        ibmca_digest_lists.nids[*dig_nid_cnt] = NID_sha1;
        ibmca_digest_lists.crypto_meths[(*dig_nid_cnt)++] = ibmca_sha1();
        break;
#endif
#ifndef OPENSSL_NO_SHA256
    case SHA256:
        ibmca_digest_lists.nids[*dig_nid_cnt] = NID_sha256;
        ibmca_digest_lists.crypto_meths[(*dig_nid_cnt)++] = ibmca_sha256();
        break;
#endif
#ifndef OPENSSL_NO_SHA512
    case SHA512:
        ibmca_digest_lists.nids[*dig_nid_cnt] = NID_sha512;
        ibmca_digest_lists.crypto_meths[(*dig_nid_cnt)++] = ibmca_sha512();
        break;
#endif
    case DES_ECB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_des_ecb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_des_ecb();
        break;
    case DES_CBC:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_des_cbc;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_des_cbc();
        break;
    case DES_OFB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_des_ofb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_des_ofb();
        break;
    case DES_CFB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_des_cfb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_des_cfb();
        break;
    case DES3_ECB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_des_ede3_ecb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_tdes_ecb();
        break;
    case DES3_CBC:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_des_ede3_cbc;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_tdes_cbc();
        break;
    case DES3_OFB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_des_ede3_ofb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_tdes_ofb();
        break;
    case DES3_CFB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_des_ede3_cfb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_tdes_cfb();
        break;
    case AES_ECB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_ecb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_128_ecb();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_ecb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_192_ecb();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_ecb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_256_ecb();
        break;
    case AES_CBC:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_cbc;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_128_cbc();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_cbc;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_192_cbc();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_cbc;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_256_cbc();
        break;
    case AES_OFB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_ofb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_128_ofb();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_ofb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_192_ofb();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_ofb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_256_ofb();
        break;
    case AES_CFB:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_cfb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_128_cfb();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_cfb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_192_cfb();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_cfb;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_256_cfb();
        break;
#ifndef OPENSSL_NO_AES_GCM
    case AES_GCM_KMA:
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_gcm;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_128_gcm();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_gcm;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_192_gcm();
        ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_gcm;
        ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] =
            ibmca_aes_256_gcm();
        break;
#endif
#ifndef OPENSSL_NO_EC
    case EC_KGEN:
        ibmca_registration.ec_kgen_switch = 1;
        break;
    case EC_DH:
        ibmca_registration.ec_dh_switch = 1;
        break;
    case EC_DSA_SIGN:
        ibmca_registration.ec_dsa_sign_switch = 1;
        break;
    case EC_DSA_VERIFY:
        ibmca_registration.ec_dsa_verify_switch = 1;
        break;
#endif
    case ED25519_KEYGEN:
        ibmca_registration.ed25519_keygen_switch = 1;
        break;
    case ED25519_SIGN:
        ibmca_registration.ed25519_sign_switch = 1;
        break;
    case ED25519_VERIFY:
        ibmca_registration.ed25519_verify_switch = 1;
        break;
    case ED448_KEYGEN:
        ibmca_registration.ed448_keygen_switch = 1;
        break;
    case ED448_SIGN:
        ibmca_registration.ed448_sign_switch = 1;
        break;
    case ED448_VERIFY:
        ibmca_registration.ed448_verify_switch = 1;
        break;
    case X25519_KEYGEN:
        ibmca_registration.x25519_keygen_switch = 1;
        break;
    case X25519_DERIVE:
        ibmca_registration.x25519_derive_switch = 1;
        break;
    case X448_KEYGEN:
        ibmca_registration.x448_keygen_switch = 1;
        break;
    case X448_DERIVE:
        ibmca_registration.x448_derive_switch = 1;
        break;
    default:
        break;                  /* do nothing */
    }

#ifndef OPENSSL_NO_EC
    if (ibmca_registration.ec_kgen_switch && ibmca_registration.ec_dh_switch
        && ibmca_registration.ec_dsa_sign_switch
        && ibmca_registration.ec_dsa_verify_switch) {
        if (!set_EC_prop(e))
            return 0;
    }
#endif

    if (ibmca_registration.x25519_keygen_switch
        && ibmca_registration.x25519_derive_switch
        && !ibmca_registration.x25519_switch) {
        ibmca_registration.x25519_switch = 1;
        ibmca_pkey_meths_lists.nids[*pkey_nid_cnt] = NID_X25519;
        ibmca_pkey_meths_lists.crypto_meths[(*pkey_nid_cnt)++]
          = ibmca_x25519();
    }
    if (ibmca_registration.x448_keygen_switch
        && ibmca_registration.x448_derive_switch
        && !ibmca_registration.x448_switch) {
        ibmca_registration.x448_switch = 1;
        ibmca_pkey_meths_lists.nids[*pkey_nid_cnt] = NID_X448;
        ibmca_pkey_meths_lists.crypto_meths[(*pkey_nid_cnt)++]
          = ibmca_x448();
    }
    if (ibmca_registration.ed25519_keygen_switch
        && ibmca_registration.ed25519_sign_switch
        && ibmca_registration.ed25519_verify_switch
        && !ibmca_registration.ed25519_switch) {
        ibmca_registration.ed25519_switch = 1;
        ibmca_pkey_meths_lists.nids[*pkey_nid_cnt] = NID_ED25519;
        ibmca_pkey_meths_lists.crypto_meths[(*pkey_nid_cnt)++]
          = ibmca_ed25519();
    }
    if (ibmca_registration.ed448_keygen_switch
        && ibmca_registration.ed448_sign_switch
        && ibmca_registration.ed448_verify_switch
        && !ibmca_registration.ed448_switch) {
        ibmca_registration.ed448_switch = 1;
        ibmca_pkey_meths_lists.nids[*pkey_nid_cnt] = NID_ED448;
        ibmca_pkey_meths_lists.crypto_meths[(*pkey_nid_cnt)++]
          = ibmca_ed448();
    }

    size_cipher_list = *ciph_nid_cnt;
    size_digest_list = *dig_nid_cnt;
    size_pkey_meths_list = *pkey_nid_cnt;
    return 1;
}

static int set_supported_meths(ENGINE *e)
{
    int i, j;
    unsigned int mech_len;
    libica_func_list_element *pmech_list;
    int rc = 0;
    int dig_nid_cnt = 0;
    int ciph_nid_cnt = 0;
    int pkey_nid_cnt = 0;

    if (p_ica_get_functionlist(NULL, &mech_len))
        return 0;

    pmech_list = malloc(sizeof(libica_func_list_element) * mech_len);
    if (!pmech_list)
        return 0;

    if (p_ica_get_functionlist(pmech_list, &mech_len))
        goto out;

    for (i = 0; i < mech_len; i++) {

        libica_func_list_element *f = &pmech_list[i];

        /* Disable crypto algorithm if not supported in hardware */
        if (!(f->flags & (ICA_FLAG_SHW | ICA_FLAG_DHW)))
            continue;

        /* Check if this crypto algorithm is supported by ibmca */
        for (j = 0; ibmca_crypto_algos[j]; j++)
            if (ibmca_crypto_algos[j] == f->mech_mode_id)
                break;
        if (!ibmca_crypto_algos[j])
            continue;
        /*
         * This algorith is supported by ibmca and libica
         * Set NID, ibmca struct and the info for the ENGINE struct
         */
        if (!set_engine_prop(e, ibmca_crypto_algos[j],
                             &dig_nid_cnt, &ciph_nid_cnt, &pkey_nid_cnt))
            goto out;
    }

    if (dig_nid_cnt > 0)
        if (!ENGINE_set_digests(e, ibmca_engine_digests))
            goto out;

    if (ciph_nid_cnt > 0)
        if (!ENGINE_set_ciphers(e, ibmca_engine_ciphers))
            goto out;

    if (pkey_nid_cnt > 0)
        if (!ENGINE_set_pkey_meths(e, ibmca_engine_pkey_meths))
            goto out;

    rc = 1;
out:
    free(pmech_list);

    return rc;
}

__attribute__((constructor))
static void ibmca_constructor(void)
{
    DEBUG_PRINTF(">%s\n", __func__);
}

__attribute__((destructor))
static void ibmca_destructor(void)
{
    if (bindcountlock)
        CRYPTO_THREAD_lock_free(bindcountlock);
    if (LIBICA_NAME_allocated)
        free((void *)LIBICA_NAME);
}

static void do_ica_cleanup(void)
{
    if (p_ica_cleanup)
        p_ica_cleanup();
    if (ibmca_dso && dlclose(ibmca_dso)) {
        IBMCAerr(IBMCA_F_IBMCA_FINISH, IBMCA_R_DSO_FAILURE);
        return;
    }

    ibmca_dso = NULL;

    p_ica_open_adapter = NULL;
    p_ica_close_adapter = NULL;

    p_ica_rsa_mod_expo = NULL;
    p_ica_rsa_crt = NULL;
#ifndef OPENSSL_NO_EC
    p_ica_ec_key_new = NULL;
    p_ica_ec_key_init = NULL;
    p_ica_ec_key_generate = NULL;
    p_ica_ecdh_derive_secret = NULL;
    p_ica_ecdsa_sign = NULL;
    p_ica_ecdsa_verify = NULL;
    p_ica_ec_key_get_public_key = NULL;
    p_ica_ec_key_get_private_key = NULL;
    p_ica_ec_key_free = NULL;
#endif

    p_ica_random_number_generate = NULL;
    p_ica_sha1 = NULL;
    p_ica_sha256 = NULL;
    p_ica_sha512 = NULL;
    p_ica_aes_ecb = NULL;
    p_ica_des_ecb = NULL;
    p_ica_3des_ecb = NULL;
    p_ica_aes_cbc = NULL;
    p_ica_des_cbc = NULL;
    p_ica_3des_cbc = NULL;
    p_ica_aes_ofb = NULL;
    p_ica_des_ofb = NULL;
    p_ica_3des_ofb = NULL;
    p_ica_aes_cfb = NULL;
    p_ica_des_cfb = NULL;
    p_ica_3des_cfb = NULL;
#ifndef OPENSSL_NO_AES_GCM
    p_ica_aes_gcm_initialize = NULL;
    p_ica_aes_gcm_intermediate = NULL;
    p_ica_aes_gcm_last = NULL;
#endif
    p_ica_x25519_ctx_new = NULL;
    p_ica_x448_ctx_new = NULL;
    p_ica_ed25519_ctx_new = NULL;
    p_ica_ed448_ctx_new = NULL;
    p_ica_x25519_key_set = NULL;
    p_ica_x448_key_set = NULL;
    p_ica_ed25519_key_set = NULL;
    p_ica_ed448_key_set = NULL;
    p_ica_x25519_key_get = NULL;
    p_ica_x448_key_get = NULL;
    p_ica_ed25519_key_get = NULL;
    p_ica_ed448_key_get = NULL;
    p_ica_x25519_key_gen = NULL;
    p_ica_x448_key_gen = NULL;
    p_ica_ed25519_key_gen = NULL;
    p_ica_ed448_key_gen = NULL;
    p_ica_x25519_derive = NULL;
    p_ica_x448_derive = NULL;
    p_ica_ed25519_sign = NULL;
    p_ica_ed448_sign = NULL;
    p_ica_ed25519_verify = NULL;
    p_ica_ed448_verify = NULL;
    p_ica_x25519_ctx_del = NULL;
    p_ica_x448_ctx_del = NULL;
    p_ica_ed25519_ctx_del = NULL;
    p_ica_ed448_ctx_del = NULL;
    p_ica_cleanup = NULL;
}

static int ibmca_init(ENGINE *e)
{
    ibmca_dso = dlopen(LIBICA_NAME, RTLD_NOW);
    if (ibmca_dso == NULL) {
        DEBUG_PRINTF("%s: dlopen(%s) failed\n", __func__, LIBICA_NAME);
        IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_DSO_FAILURE);
        goto err;
    }

#define BIND(dso, sym)	(p_##sym = (sym##_t)dlsym(dso, #sym))

    if (!BIND(ibmca_dso, ica_open_adapter)
        || !BIND(ibmca_dso, ica_close_adapter)
        || !BIND(ibmca_dso, ica_get_functionlist)) {
        IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_DSO_FAILURE);
        DEBUG_PRINTF("%s: function bind failed\n", __func__);
        goto err;
    }
    BIND(ibmca_dso, ica_rsa_mod_expo);
    BIND(ibmca_dso, ica_rsa_crt);
    BIND(ibmca_dso, ica_random_number_generate);
    BIND(ibmca_dso, ica_sha1);
    BIND(ibmca_dso, ica_sha256);
    BIND(ibmca_dso, ica_sha512);
    BIND(ibmca_dso, ica_aes_ecb);
    BIND(ibmca_dso, ica_des_ecb);
    BIND(ibmca_dso, ica_3des_ecb);
    BIND(ibmca_dso, ica_aes_cbc);
    BIND(ibmca_dso, ica_des_cbc);
    BIND(ibmca_dso, ica_3des_cbc);
    BIND(ibmca_dso, ica_aes_ofb);
    BIND(ibmca_dso, ica_des_ofb);
    BIND(ibmca_dso, ica_3des_ofb);
    BIND(ibmca_dso, ica_aes_cfb);
    BIND(ibmca_dso, ica_des_cfb);
    BIND(ibmca_dso, ica_3des_cfb);
#ifndef OPENSSL_NO_AES_GCM
    BIND(ibmca_dso, ica_aes_gcm_initialize);
    BIND(ibmca_dso, ica_aes_gcm_intermediate);
    BIND(ibmca_dso, ica_aes_gcm_last);
#endif
#ifndef OPENSSL_NO_EC
    BIND(ibmca_dso, ica_ec_key_new);
    BIND(ibmca_dso, ica_ec_key_init);
    BIND(ibmca_dso, ica_ec_key_generate);
    BIND(ibmca_dso, ica_ecdh_derive_secret);
    BIND(ibmca_dso, ica_ecdsa_sign);
    BIND(ibmca_dso, ica_ecdsa_verify);
    BIND(ibmca_dso, ica_ec_key_get_public_key);
    BIND(ibmca_dso, ica_ec_key_get_private_key);
    BIND(ibmca_dso, ica_ec_key_free);
#endif
    BIND(ibmca_dso, ica_x25519_ctx_new);
    BIND(ibmca_dso, ica_x448_ctx_new);
    BIND(ibmca_dso, ica_ed25519_ctx_new);
    BIND(ibmca_dso, ica_ed448_ctx_new);
    BIND(ibmca_dso, ica_x25519_key_set);
    BIND(ibmca_dso, ica_x448_key_set);
    BIND(ibmca_dso, ica_ed25519_key_set);
    BIND(ibmca_dso, ica_ed448_key_set);
    BIND(ibmca_dso, ica_x25519_key_get);
    BIND(ibmca_dso, ica_x448_key_get);
    BIND(ibmca_dso, ica_ed25519_key_get);
    BIND(ibmca_dso, ica_ed448_key_get);
    BIND(ibmca_dso, ica_x25519_key_gen);
    BIND(ibmca_dso, ica_x448_key_gen);
    BIND(ibmca_dso, ica_ed25519_key_gen);
    BIND(ibmca_dso, ica_ed448_key_gen);
    BIND(ibmca_dso, ica_x25519_derive);
    BIND(ibmca_dso, ica_x448_derive);
    BIND(ibmca_dso, ica_ed25519_sign);
    BIND(ibmca_dso, ica_ed448_sign);
    BIND(ibmca_dso, ica_ed25519_verify);
    BIND(ibmca_dso, ica_ed448_verify);
    BIND(ibmca_dso, ica_x25519_ctx_del);
    BIND(ibmca_dso, ica_x448_ctx_del);
    BIND(ibmca_dso, ica_ed25519_ctx_del);
    BIND(ibmca_dso, ica_ed448_ctx_del);

    /* ica_cleanup is not always present and only needed for newer libraries */
    p_ica_cleanup = (ica_cleanup_t)dlsym(ibmca_dso, "ica_cleanup");

    /* disable fallbacks on Libica */
    if (BIND(ibmca_dso, ica_set_fallback_mode))
        p_ica_set_fallback_mode(0);

    if (p_ica_open_adapter(&ibmca_handle)) {
        IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_UNIT_FAILURE);
        goto err;
    }

    if (!set_supported_meths(e))
        goto err;

    return 1;

err:
    do_ica_cleanup();
    return 0;
}

static int ibmca_finish(ENGINE *e)
{
#ifndef OLDER_OPENSSL
    ibmca_des_ecb_destroy();
    ibmca_des_cbc_destroy();
    ibmca_des_ofb_destroy();
    ibmca_des_cfb_destroy();
    ibmca_tdes_ecb_destroy();
    ibmca_tdes_cbc_destroy();
    ibmca_tdes_ofb_destroy();
    ibmca_tdes_cfb_destroy();

    ibmca_aes_128_ecb_destroy();
    ibmca_aes_128_cbc_destroy();
    ibmca_aes_128_ofb_destroy();
    ibmca_aes_128_cfb_destroy();
    ibmca_aes_192_ecb_destroy();
    ibmca_aes_192_cbc_destroy();
    ibmca_aes_192_ofb_destroy();
    ibmca_aes_192_cfb_destroy();
    ibmca_aes_256_ecb_destroy();
    ibmca_aes_256_cbc_destroy();
    ibmca_aes_256_ofb_destroy();
    ibmca_aes_256_cfb_destroy();

#ifndef OPENSSL_NO_AES_GCM
    ibmca_aes_128_gcm_destroy();
    ibmca_aes_192_gcm_destroy();
    ibmca_aes_256_gcm_destroy();
#endif

#ifndef OPENSSL_NO_SHA1
    ibmca_sha1_destroy();
#endif
#ifndef OPENSSL_NO_SHA256
    ibmca_sha256_destroy();
#endif
#ifndef OPENSSL_NO_SHA512
    ibmca_sha512_destroy();
#endif
#ifndef OPENSSL_NO_RSA
    ibmca_rsa_destroy();
#endif
#ifndef OPENSSL_NO_DSA
    ibmca_dsa_destroy();
#endif
#ifndef OPENSSL_NO_DH
    ibmca_dh_destroy();
#endif

#endif /* !OLDER_OPENSSL */

#ifndef NO_EC
    ibmca_ec_destroy();
#endif

    if (p_ica_close_adapter)
        p_ica_close_adapter(ibmca_handle);

    do_ica_cleanup();
    memset(&ibmca_registration, 0, sizeof(ibmca_registration));
    return 1;
}

static int ibmca_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) ())
{
    char *tmp;
    int initialised = ((ibmca_dso == NULL) ? 0 : 1);
    switch (cmd) {
    case IBMCA_CMD_SO_PATH:
        if (p == NULL) {
            IBMCAerr(IBMCA_F_IBMCA_CTRL, ERR_R_PASSED_NULL_PARAMETER);
            return 0;
        }
        if (initialised) {
            IBMCAerr(IBMCA_F_IBMCA_CTRL, IBMCA_R_ALREADY_LOADED);
            return 0;
        }
        return 1;
    case IBMCA_CMD_LIBICA:
        if (p == NULL) {
            IBMCAerr(IBMCA_F_IBMCA_CTRL, ERR_R_PASSED_NULL_PARAMETER);
            return 0;
        }
        if (initialised) {
            IBMCAerr(IBMCA_F_IBMCA_CTRL, IBMCA_R_ALREADY_LOADED);
            return 0;
        }
        tmp = strdup((const char *) p);
        if (!tmp) {
            IBMCAerr(IBMCA_F_IBMCA_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (LIBICA_NAME_allocated)
            free((void *)LIBICA_NAME);
        LIBICA_NAME = tmp;
        LIBICA_NAME_allocated = 1;
        return 1;
    default:
        break;
    }
    IBMCAerr(IBMCA_F_IBMCA_CTRL, IBMCA_R_CTRL_COMMAND_NOT_IMPLEMENTED);

    return 0;
}

/*
 * This internal function is used by ENGINE_ibmca()
 * and possibly by the "dynamic" ENGINE support too
 */
static int bind_helper(ENGINE *e)
{
    int ignored;

    CRYPTO_THREAD_run_once(&bindcountlockinitonce, bindcountlockinit);
    
    CRYPTO_atomic_add(&bindcount, 1, &ignored, bindcountlock);
    ERR_load_IBMCA_strings();

    if (!ENGINE_set_id(e, engine_ibmca_id) ||
        !ENGINE_set_name(e, engine_ibmca_name) ||
        !ENGINE_set_destroy_function(e, ibmca_destroy) ||
        !ENGINE_set_init_function(e, ibmca_init) ||
        !ENGINE_set_finish_function(e, ibmca_finish) ||
        !ENGINE_set_ctrl_function(e, ibmca_ctrl) ||
        !ENGINE_set_cmd_defns(e, ibmca_cmd_defns))
        return 0;

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

/*
 * ENGINE calls this to find out how to deal with
 * a particular NID in the ENGINE.
 */
static int ibmca_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                                const int **nids, int nid)
{
    int i;
    if (!cipher)
        return (ibmca_usable_ciphers(nids));

    *cipher = NULL;
    for (i = 0; i < size_cipher_list; i++)
        if (nid == ibmca_cipher_lists.nids[i]) {
            *cipher = (EVP_CIPHER *) ibmca_cipher_lists.crypto_meths[i];
            break;
        }

    /* Check: how can *cipher be NULL? */
    return (*cipher != NULL);
}

static int ibmca_usable_ciphers(const int **nids)
{
    if (nids)
        *nids = ibmca_cipher_lists.nids;

    return size_cipher_list;
}

static int ibmca_engine_digests(ENGINE *e, const EVP_MD **digest,
                                const int **nids, int nid)
{
    int i;
    if (!digest)
        return (ibmca_usable_digests(nids));

    *digest = NULL;
    for (i = 0; i < size_digest_list; i++)
        if (nid == ibmca_digest_lists.nids[i]) {
            *digest = (EVP_MD *) ibmca_digest_lists.crypto_meths[i];
            break;
        }


    return (*digest != NULL);
}

static int ibmca_usable_digests(const int **nids)
{
    if (nids)
        *nids = ibmca_digest_lists.nids;

    return size_digest_list;
}

static int ibmca_engine_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                                   const int **nids, int nid)
{
    int i;

    if (!pmeth)
        return (ibmca_usable_pkey_meths(nids));

    *pmeth = NULL;
    for (i = 0; i < size_pkey_meths_list; i++) {
        if (nid == ibmca_pkey_meths_lists.nids[i]) {
            *pmeth = (EVP_PKEY_METHOD *)ibmca_pkey_meths_lists.crypto_meths[i];
            break;
        }
    }

    return (*pmeth != NULL);
}

static int ibmca_usable_pkey_meths(const int **nids)
{
    if (nids)
        *nids = ibmca_pkey_meths_lists.nids;

    return size_pkey_meths_list;
}

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

/*
 * This stuff is needed if this ENGINE is being
 * compiled into a self-contained shared-library.
 */
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_ibmca_id) != 0)) {
        fprintf(stderr, "wrong engine id\n");
        return 0;
    }
    if (!bind_helper(e)) {
        fprintf(stderr, "bind failed\n");
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif                          /* !OPENSSL_NO_HW_IBMCA */
#endif                          /* !OPENSSL_NO_HW */
