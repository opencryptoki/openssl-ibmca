/*
 * Copyright [2005-2017] International Business Machines Corp.
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
#define LIBICA_SHARED_LIB "libica.so"

#define AP_PATH "/sys/devices/ap"

static const char *LIBICA_NAME = "ica";

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
        0
};

#define MAX_CIPHER_NIDS sizeof(ibmca_crypto_algos)

/*
 * This struct maps one NID to one crypto algo.
 * So we can tell OpenSSL this NID maps to this function.
 */
struct crypto_pair
{
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

static struct crypto_pair ibmca_cipher_lists;
static struct crypto_pair ibmca_digest_lists;

static int ibmca_destroy(ENGINE * e);
static int ibmca_init(ENGINE * e);
static int ibmca_finish(ENGINE * e);
static int ibmca_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ());

ica_adapter_handle_t ibmca_handle = 0;

#ifndef OPENSSL_NO_DSA
/* DSA stuff */
#ifdef OLDER_OPENSSL
static int ibmca_dsa_mod_exp(DSA * dsa, BIGNUM * rr, BIGNUM * a1,
			     BIGNUM * p1, BIGNUM * a2, BIGNUM * p2,
			     BIGNUM * m, BN_CTX * ctx,
			     BN_MONT_CTX * in_mont);
static int ibmca_mod_exp_dsa(DSA * dsa, BIGNUM * r, BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * m,
			     BN_CTX * ctx, BN_MONT_CTX * m_ctx);
#else
static int ibmca_dsa_mod_exp(DSA * dsa, BIGNUM * rr, const BIGNUM * a1,
			     const BIGNUM * p1, const BIGNUM * a2,
			     const BIGNUM * p2, const BIGNUM * m,
			     BN_CTX * ctx, BN_MONT_CTX * in_mont);
static int ibmca_mod_exp_dsa(DSA * dsa, BIGNUM * r, const BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * m,
			     BN_CTX * ctx, BN_MONT_CTX * m_ctx);
#endif
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

static int ibmca_usable_ciphers(const int **nids);

static int ibmca_engine_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
				const int **nids, int nid);

static int ibmca_usable_digests(const int **nids);

static int ibmca_engine_digests(ENGINE * e, const EVP_MD ** digest,
				const int **nids, int nid);

/* WJH - check for more commands, like in nuron */

/* The definitions for control commands specific to this engine */
#define IBMCA_CMD_SO_PATH		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN ibmca_cmd_defns[] = {
	{IBMCA_CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the 'ibmca' shared library",
	 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};

#ifndef OPENSSL_NO_DSA
/* Our internal DSA_METHOD that we provide pointers to */
#ifdef OLDER_OPENSSL
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
#else
static DSA_METHOD *ibmca_dsa = NULL;
#endif
#endif

#ifndef OPENSSL_NO_DH
/* Our internal DH_METHOD that we provide pointers to */
#ifdef OLDER_OPENSSL
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
#else
static DH_METHOD *ibmca_dh = NULL;
#endif
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

/* Constants used when creating the ENGINE */
static const char *engine_ibmca_id = "ibmca";
static const char *engine_ibmca_name = "Ibmca hardware engine support";


inline static int set_RSA_prop(ENGINE *e)
{
	static int rsa_enabled = 0;
#ifndef OPENSSL_NO_DSA
	const DSA_METHOD *meth2;
#ifndef OLDER_OPENSSL
	ibmca_dsa = DSA_meth_new("Ibmca DSA method", 0);
#endif
#endif
#ifndef OPENSSL_NO_DH
	const DH_METHOD *meth3;
#ifndef OLDER_OPENSSL
	ibmca_dh = DH_meth_new("Ibmca DH method", 0);
#endif
#endif

	if(rsa_enabled){
		return 1;
	}
        if(
#ifndef OPENSSL_NO_RSA
	   !ENGINE_set_RSA(e, ibmca_rsa()) ||
#endif
#ifndef OPENSSL_NO_DSA
#ifdef OLDER_OPENSSL
	   !ENGINE_set_DSA(e, &ibmca_dsa) ||
#else
	   !ENGINE_set_DSA(e, ibmca_dsa) ||
#endif
#endif
#ifndef OPENSSL_NO_DH
#ifdef OLDER_OPENSSL
	   !ENGINE_set_DH(e, &ibmca_dh)
#else
	   !ENGINE_set_DH(e, ibmca_dh)
#endif
	  )
#endif
		return 0;
#ifndef OPENSSL_NO_DSA
	meth2 = DSA_OpenSSL();
#ifdef OLDER_OPENSSL
        ibmca_dsa.dsa_do_sign = meth2->dsa_do_sign;
        ibmca_dsa.dsa_sign_setup = meth2->dsa_sign_setup;
        ibmca_dsa.dsa_do_verify = meth2->dsa_do_verify;
#else
	if (   !DSA_meth_set_sign(ibmca_dsa, DSA_meth_get_sign(meth2))
	    || !DSA_meth_set_verify(ibmca_dsa, DSA_meth_get_verify(meth2))
	    || !DSA_meth_set_mod_exp(ibmca_dsa, ibmca_dsa_mod_exp)
	    || !DSA_meth_set_bn_mod_exp(ibmca_dsa, ibmca_mod_exp_dsa) )
		return 0;
#endif
#endif
#ifndef OPENSSL_NO_DH
        /* Much the same for Diffie-Hellman */
        meth3 = DH_OpenSSL();
#ifdef OLDER_OPENSSL
        ibmca_dh.generate_key = meth3->generate_key;
        ibmca_dh.compute_key = meth3->compute_key;
#else
	if (   !DH_meth_set_generate_key(ibmca_dh, DH_meth_get_generate_key(meth3))
	    || !DH_meth_set_compute_key(ibmca_dh, DH_meth_get_compute_key(meth3))
	    || !DH_meth_set_bn_mod_exp(ibmca_dh, ibmca_mod_exp_dh) )
		return 0;
#endif
#endif
	rsa_enabled = 1;
	return 1;
}


/*
 * dig_nid_cnt and ciph_nid_cnt count the number of enabled crypt mechanims.
 * dig_nid_cnt and ciph_nid_cnt needs to be pointer, because only set_engine_prop
 * knows about how much digest or cipher will be set per call. To count the number of
 * cipher and digest outside of the function is not feasible
 */
inline static int set_engine_prop(ENGINE *e, int algo_id, int *dig_nid_cnt, int *ciph_nid_cnt)
{
        switch(algo_id) {
                case P_RNG:
                        if(!ENGINE_set_RAND(e, &ibmca_rand))
                                return 0;
                        break;
		/*
		 * RSA will be enabled if one of this is set. OpenSSL does not distinguish
		 * between RSA_ME and RSA_CRT. It is not the task of ibmca to route one ME
		 * call to CRT or vice versa.
		 */
                case RSA_ME:
                case RSA_CRT:
                        if(!set_RSA_prop(e))
                                return 0;
			break;
#ifndef OPENSSL_NO_SHA1
		case SHA1:
			ibmca_digest_lists.nids[*dig_nid_cnt] = NID_sha1;
			ibmca_digest_lists.crypto_meths[(*dig_nid_cnt)++]=  ibmca_sha1();
			break;
#endif
#ifndef OPENSSL_NO_SHA256
                case SHA256:
                        ibmca_digest_lists.nids[*dig_nid_cnt] = NID_sha256;
			ibmca_digest_lists.crypto_meths[(*dig_nid_cnt)++] =  ibmca_sha256();
			break;
#endif
#ifndef OPENSSL_NO_SHA512
                case SHA512:
                        ibmca_digest_lists.nids[*dig_nid_cnt] = NID_sha512;
			ibmca_digest_lists.crypto_meths[(*dig_nid_cnt)++] =  ibmca_sha512();
			break;
#endif
                case DES_ECB:
			ibmca_cipher_lists.nids[*ciph_nid_cnt]  = NID_des_ecb;
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
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_128_ecb();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_ecb;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_192_ecb();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_ecb;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_256_ecb();
			break;
		case AES_CBC:
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_cbc;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_128_cbc();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_cbc;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_192_cbc();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_cbc;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_256_cbc();
			break;
		case AES_OFB:
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_ofb;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_128_ofb();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_ofb;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_192_ofb();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_ofb;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_256_ofb();
			break;
		case AES_CFB:
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_cfb;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_128_cfb();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_cfb;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_192_cfb();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_cfb;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_256_cfb();
			break;
#ifndef OPENSSL_NO_AES_GCM
		case AES_GCM_KMA:
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_128_gcm;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_128_gcm();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_192_gcm;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_192_gcm();
			ibmca_cipher_lists.nids[*ciph_nid_cnt] = NID_aes_256_gcm;
			ibmca_cipher_lists.crypto_meths[(*ciph_nid_cnt)++] = ibmca_aes_256_gcm();
			break;
#endif
		default:
			break;	/* do nothing */
	}

	size_cipher_list = *ciph_nid_cnt;
	size_digest_list = *dig_nid_cnt;
	return 1;
}

int is_crypto_card_loaded()
{
	DIR* sysDir;
	FILE *file;
	char dev[PATH_MAX] = AP_PATH;
	struct dirent *direntp;
	char *type = NULL;
	size_t size;
	char c;

	if ((sysDir = opendir(dev)) == NULL )
		return 0;

	while((direntp = readdir(sysDir)) != NULL){
		if(strstr(direntp->d_name, "card") != 0){
			snprintf(dev, PATH_MAX, "%s/%s/type", AP_PATH,
				direntp->d_name);

			if ((file = fopen(dev, "r")) == NULL){
	                        closedir(sysDir);
                                return 0;
			}

			if (getline(&type, &size, file) == -1){
				fclose(file);
				closedir(sysDir);
				return 0;
			}

			/* ignore \n
			 * looking for CEX??A and CEX??C
			 * Skip type CEX??P cards
			 */
			if (type[strlen(type)-2] == 'P'){
				free(type);
				type = NULL;
				fclose(file);
				continue;
			}
			free(type);
			type = NULL;
			fclose(file);

			snprintf(dev, PATH_MAX, "%s/%s/online", AP_PATH,
				direntp->d_name);
			if ((file = fopen(dev, "r")) == NULL){
				closedir(sysDir);
				return 0;
			}
			if((c = fgetc(file)) == '1'){
				fclose(file);
				return 1;
			}
			fclose(file);
		}
	}
	closedir(sysDir);
	return 0;
}

static int set_supported_meths(ENGINE *e)
{
	int i, j;
	unsigned int mech_len;
	libica_func_list_element *pmech_list;
	int rc = 0;
	int dig_nid_cnt = 0;
	int ciph_nid_cnt = 0;
	int card_loaded;

	if (p_ica_get_functionlist(NULL, &mech_len))
		return 0;

	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (!pmech_list)
		return 0;

	if (p_ica_get_functionlist(pmech_list, &mech_len))
		goto out;

	card_loaded = is_crypto_card_loaded();

	for (i = 0; i < mech_len; i++) {
		libica_func_list_element *f = &pmech_list[i];
		/* Disable crypto algorithm if not supported in hardware */
		if (!(f->flags & (ICA_FLAG_SHW | ICA_FLAG_DHW)))
			continue;
		/*
		 * If no crypto card is available, disable crypto algos that can
		 * only operate on HW on card
		 */
		if ((f->flags & ICA_FLAG_DHW) && !card_loaded)
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
							 &dig_nid_cnt, &ciph_nid_cnt))
			goto out;
	}

	if(dig_nid_cnt > 0)
		if(!ENGINE_set_digests(e, ibmca_engine_digests))
			goto out;

	if(ciph_nid_cnt > 0)
		if(!ENGINE_set_ciphers(e, ibmca_engine_ciphers))
			goto out;

	rc = 1;
out:
	free(pmech_list);
	return rc;
}


/* This internal function is used by ENGINE_ibmca() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE * e)
{
	if (!ENGINE_set_id(e, engine_ibmca_id) ||
	    !ENGINE_set_name(e, engine_ibmca_name) ||
	    !ENGINE_set_destroy_function(e, ibmca_destroy) ||
	    !ENGINE_set_init_function(e, ibmca_init) ||
	    !ENGINE_set_finish_function(e, ibmca_finish) ||
	    !ENGINE_set_ctrl_function(e, ibmca_ctrl) ||
	    !ENGINE_set_cmd_defns(e, ibmca_cmd_defns))
		return 0;

	/* Ensure the ibmca error handling is set up */
	ERR_load_IBMCA_strings();
	/* initialize the engine implizit */
	ibmca_init(e);
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

# ifndef OPENSSL_NO_AES_GCM
	ibmca_aes_128_gcm_destroy();
	ibmca_aes_192_gcm_destroy();
	ibmca_aes_256_gcm_destroy();
# endif

# ifndef OPENSSL_NO_SHA1
	ibmca_sha1_destroy();
# endif
# ifndef OPENSSL_NO_SHA256
	ibmca_sha256_destroy();
# endif
# ifndef OPENSSL_NO_SHA512
	ibmca_sha512_destroy();
# endif

#endif
	ERR_unload_IBMCA_strings();
	return 1;
}

/* This is a process-global DSO handle used for loading and unloading
 * the Ibmca library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */

void *ibmca_dso = NULL;

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

/* initialisation functions. */
#define BIND(dso, sym)	(p_##sym = (sym##_t)dlsym(dso, #sym))
static int ibmca_init(ENGINE * e)
{
	static int init = 0;

	if (init)	/* Engine already loaded. */
		return 1;
	init++;

	DEBUG_PRINTF(">%s\n", __func__);

	/* Attempt to load libica.so. Needs to be
	 * changed unfortunately because the Ibmca drivers don't have
	 * standard library names that can be platform-translated well. */
	/* TODO: Work out how to actually map to the names the Ibmca
	 * drivers really use - for now a symbollic link needs to be
	 * created on the host system from libica.so to ica.so on
	 * unix variants. */

	/* WJH XXX check name translation */

	ibmca_dso = dlopen(LIBICA_SHARED_LIB, RTLD_NOW);
	if (ibmca_dso == NULL) {
		DEBUG_PRINTF("%s: dlopen(%s) failed\n", __func__, LIBICA_SHARED_LIB);
		IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_DSO_FAILURE);
		goto err;
	}

	if (!BIND(ibmca_dso, ica_open_adapter)
	    || !BIND(ibmca_dso, ica_close_adapter)
	    || !BIND(ibmca_dso, ica_rsa_mod_expo)
	    || !BIND(ibmca_dso, ica_rsa_crt)
	    || !BIND(ibmca_dso, ica_random_number_generate)
	    || !BIND(ibmca_dso, ica_sha1)
	    || !BIND(ibmca_dso, ica_sha256)
	    || !BIND(ibmca_dso, ica_sha512)
	    || !BIND(ibmca_dso, ica_aes_ecb)
	    || !BIND(ibmca_dso, ica_des_ecb)
	    || !BIND(ibmca_dso, ica_3des_ecb)
	    || !BIND(ibmca_dso, ica_aes_cbc)
	    || !BIND(ibmca_dso, ica_des_cbc)
	    || !BIND(ibmca_dso, ica_3des_cbc)
	    || !BIND(ibmca_dso, ica_aes_ofb)
	    || !BIND(ibmca_dso, ica_des_ofb)
	    || !BIND(ibmca_dso, ica_3des_ofb)
	    || !BIND(ibmca_dso, ica_aes_cfb)
	    || !BIND(ibmca_dso, ica_des_cfb)
	    || !BIND(ibmca_dso, ica_3des_cfb)
	    || !BIND(ibmca_dso, ica_get_functionlist)
#ifndef OPENSSL_NO_AES_GCM
	    || !BIND(ibmca_dso, ica_aes_gcm_initialize)
	    || !BIND(ibmca_dso, ica_aes_gcm_intermediate)
	    || !BIND(ibmca_dso, ica_aes_gcm_last)
#endif
	   ) {
		IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_DSO_FAILURE);
		DEBUG_PRINTF("%s: function bind failed\n", __func__);
		goto err;
	}

	// disable fallbacks on Libica
	if (BIND(ibmca_dso, ica_set_fallback_mode))
		p_ica_set_fallback_mode(0);

        if(!set_supported_meths(e))
                goto err;

	if (!get_context(&ibmca_handle)) {
		IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_UNIT_FAILURE);
		goto err;
	}

	DEBUG_PRINTF("<%s success\n", __func__);
	return 1;
err:
	if (ibmca_dso) {
		dlclose(ibmca_dso);
		ibmca_dso = NULL;
	}
	p_ica_open_adapter = NULL;
	p_ica_close_adapter = NULL;
	p_ica_rsa_mod_expo = NULL;
	p_ica_random_number_generate = NULL;
	p_ica_rsa_crt = NULL;
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
	return 0;
}

static int ibmca_finish(ENGINE * e)
{
	if (ibmca_dso == NULL) {
		IBMCAerr(IBMCA_F_IBMCA_FINISH, IBMCA_R_NOT_LOADED);
		return 0;
	}
	release_context(ibmca_handle);
	if (dlclose(ibmca_dso)) {
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
		LIBICA_NAME = (const char *) p;
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
        int i;
	if (!cipher)
		return (ibmca_usable_ciphers(nids));

        *cipher = NULL;
        for(i = 0; i < size_cipher_list;i++)
                if(nid == ibmca_cipher_lists.nids[i]){
                        *cipher = (EVP_CIPHER*) ibmca_cipher_lists.crypto_meths [i];
                        break;
		}
        /* Check: how can *cipher be NULL? */
	return (*cipher != NULL);
}

static int ibmca_usable_ciphers(const int **nids)
{

        if(nids)
	        *nids = ibmca_cipher_lists.nids;
	return size_cipher_list;
}

static int ibmca_engine_digests(ENGINE * e, const EVP_MD ** digest,
				const int **nids, int nid)
{
	int i;
	if (!digest)
		return (ibmca_usable_digests(nids));

        *digest = NULL;
        for(i = 0; i < size_digest_list;i++)
                if(nid == ibmca_digest_lists.nids[i]){
                        *digest = (EVP_MD*) ibmca_digest_lists.crypto_meths[i];
                        break;
		}


	return (*digest != NULL);
}

static int ibmca_usable_digests(const int **nids)
{
        if(nids)
		*nids = ibmca_digest_lists.nids;
	return size_digest_list;
}

#ifndef OPENSSL_NO_DSA
/* This code was liberated and adapted from the commented-out code in
 * dsa_ossl.c. Because of the unoptimised form of the Ibmca acceleration
 * (it doesn't have a CRT form for RSA), this function means that an
 * Ibmca system running with a DSA server certificate can handshake
 * around 5 or 6 times faster/more than an equivalent system running with
 * RSA. Just check out the "signs" statistics from the RSA and DSA parts
 * of "openssl speed -engine ibmca dsa1024 rsa1024". */
#ifdef OLDER_OPENSSL
static int ibmca_dsa_mod_exp(DSA * dsa, BIGNUM * rr, BIGNUM * a1,
			     BIGNUM * p1, BIGNUM * a2, BIGNUM * p2,
			     BIGNUM * m, BN_CTX * ctx,
			     BN_MONT_CTX * in_mont)
#else
static int ibmca_dsa_mod_exp(DSA * dsa, BIGNUM * rr, const BIGNUM * a1,
			     const BIGNUM * p1, const BIGNUM * a2,
			     const BIGNUM * p2, const BIGNUM * m,
			     BN_CTX * ctx, BN_MONT_CTX * in_mont)
#endif
{
	BIGNUM *t;
	int to_return = 0;

	t = BN_new();
	/* let rr = a1 ^ p1 mod m */
	if (!ibmca_mod_exp(rr, a1, p1, m, ctx))
		goto end;
	/* let t = a2 ^ p2 mod m */
	if (!ibmca_mod_exp(t, a2, p2, m, ctx))
		goto end;
	/* let rr = rr * t mod m */
	if (!BN_mod_mul(rr, rr, t, m, ctx))
		goto end;
	to_return = 1;
end:
	BN_free(t);
	return to_return;
}

#ifdef OLDER_OPENSSL
static int ibmca_mod_exp_dsa(DSA * dsa, BIGNUM * r, BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * m,
			     BN_CTX * ctx, BN_MONT_CTX * m_ctx)
#else
static int ibmca_mod_exp_dsa(DSA * dsa, BIGNUM * r, const BIGNUM * a,
			     const BIGNUM * p, const BIGNUM * m,
			     BN_CTX * ctx, BN_MONT_CTX * m_ctx)
#endif
{
	return ibmca_mod_exp(r, a, p, m, ctx);
}
#endif

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
