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

#include <stdlib.h>
#include <pthread.h>
#include "ibmca.h"
#include "e_ibmca_err.h"

#ifndef OPENSSL_NO_EC

ica_ec_key_new_t		p_ica_ec_key_new;
ica_ec_key_init_t		p_ica_ec_key_init;
ica_ec_key_generate_t		p_ica_ec_key_generate;
ica_ecdh_derive_secret_t        p_ica_ecdh_derive_secret;
ica_ecdsa_sign_t		p_ica_ecdsa_sign;
ica_ecdsa_verify_t		p_ica_ecdsa_verify;
ica_ec_key_get_public_key_t	p_ica_ec_key_get_public_key;
ica_ec_key_get_private_key_t	p_ica_ec_key_get_private_key;
ica_ec_key_free_t		p_ica_ec_key_free;

int ec_ex_data_index = -1;
pthread_mutex_t ec_ex_data_mutex = PTHREAD_MUTEX_INITIALIZER;

struct ibmca_ec_ex_data {
    ICA_EC_KEY *ica_key;
    int nid;
    unsigned int privlen;
};

void ibmca_ec_ex_data_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp)
{
    struct ibmca_ec_ex_data *data = ptr;

    if (data == NULL)
        return;

    p_ica_ec_key_free(data->ica_key);
    OPENSSL_free(data);
}

int ibmca_ec_ex_data_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
#ifdef OPENSSL_VERSION_PREREQ
                         void **pptr, int idx, long argl, void *argp)
#else
                         void *from_d, int idx, long argl, void *argp)
#endif
{
#ifndef OPENSSL_VERSION_PREREQ
    void **pptr = (void **)from_d;
#endif
    struct ibmca_ec_ex_data *from_data;
    struct ibmca_ec_ex_data *to_data;
    unsigned char Q[2 * IBMCA_EC_MAX_D_LEN];
    unsigned char D[IBMCA_EC_MAX_D_LEN];
    unsigned int len;
    int rc;

    if (pptr == NULL)
        return 0;

    from_data = (struct ibmca_ec_ex_data *)*pptr;
    if (from_data == NULL)
        return 0;

    to_data = OPENSSL_zalloc(sizeof(*to_data));
    if (to_data == NULL) {
       return 0;
    }

    to_data->nid = from_data->nid;
    to_data->ica_key = p_ica_ec_key_new(to_data->nid, &to_data->privlen);
    if (to_data->ica_key == NULL) {
        IBMCAerr(IBMCA_F_ICA_EC_KEY_NEW, IBMCA_R_EC_ICA_EC_KEY_INIT);
        goto error;
    }

    if (p_ica_ec_key_get_private_key(from_data->ica_key, D, &len) == 0) {
        rc = p_ica_ec_key_init(NULL, NULL, D, to_data->ica_key);
        if (rc != 0) {
            IBMCAerr(IBMCA_F_ICA_EC_KEY_INIT, rc);
            goto error;
        }
    }

    if (p_ica_ec_key_get_public_key(from_data->ica_key, Q, &len) == 0) {
        rc = p_ica_ec_key_init(Q, Q + to_data->privlen, NULL, to_data->ica_key);
        if (rc != 0) {
            IBMCAerr(IBMCA_F_ICA_EC_KEY_INIT, rc);
            goto error;
        }
    }

    *pptr = to_data;

    return 1;

error:
    if (to_data->ica_key != NULL)
        p_ica_ec_key_free(to_data->ica_key);
    OPENSSL_free(to_data);

    return 0;
}

static ICA_EC_KEY *ibmca_ec_make_ica_key(EC_KEY *ec_key, int *nid,
                                         unsigned int *privlen)
{
    ICA_EC_KEY *icakey;
    const EC_GROUP *group;
    const EC_POINT *q;
    const BIGNUM *bn_d;
    BIGNUM *bn_x = NULL, *bn_y = NULL;
    unsigned char D[IBMCA_EC_MAX_D_LEN];
    unsigned char X[IBMCA_EC_MAX_D_LEN];
    unsigned char Y[IBMCA_EC_MAX_D_LEN];
    int rc, n;

    /* Get group */
    if ((group = EC_KEY_get0_group(ec_key)) == NULL) {
        IBMCAerr(IBMCA_F_ICA_EC_KEY_NEW, IBMCA_R_EC_INVALID_PARM);
        return NULL;
    }

    /* Get curve nid */
    *nid = EC_GROUP_get_curve_name(group);
    if (*nid <= 0) {
        IBMCAerr(IBMCA_F_ICA_EC_KEY_NEW, IBMCA_R_EC_UNSUPPORTED_CURVE);
        return NULL;
    }

    /* Create ICA_EC_KEY object */
    icakey = p_ica_ec_key_new(*nid, privlen);
    if (icakey == NULL) {
        IBMCAerr(IBMCA_F_ICA_EC_KEY_NEW, IBMCA_R_EC_ICA_EC_KEY_INIT);
        return NULL;
    }

    /* Get private (D) value from EC_KEY (if available) */
    bn_d = EC_KEY_get0_private_key(ec_key);
    if (bn_d != NULL) {
        /* Format (D) as char array, with leading zeros if necessary */
        n = *privlen - BN_num_bytes(bn_d);
        memset(D, 0, n);
        BN_bn2bin(bn_d, &(D[n]));

        /* Initialize private ICA_EC_KEY */
        rc = p_ica_ec_key_init(NULL, NULL, D, icakey);
        if (rc != 0) {
            IBMCAerr(IBMCA_F_ICA_EC_KEY_INIT, rc);
            goto error;
        }
    }

    /* Get public (X and Y) values from EC_KEY (if available) */
    q = EC_KEY_get0_public_key(ec_key);
    if (q != NULL) {
        /* Provide public key (X,Y) */
        bn_x = BN_new();
        bn_y = BN_new();
        if (!EC_POINT_get_affine_coordinates_GFp(group, q, bn_x, bn_y, NULL)) {
            IBMCAerr(IBMCA_F_ICA_EC_KEY_NEW, IBMCA_R_EC_INTERNAL_ERROR);
            goto error;
        }

        /* Format (X) as char array with leading nulls if necessary */
        n = *privlen - BN_num_bytes(bn_x);
        memset(X, 0, n);
        BN_bn2bin(bn_x, &X[n]);

        /* Format (Y) as char array with leading nulls if necessary */
        n = *privlen - BN_num_bytes(bn_y);
        memset(Y, 0, n);
        BN_bn2bin(bn_y, &Y[n]);

        /* Initialize public ICA_EC_KEY */
        rc = p_ica_ec_key_init(X, Y, NULL, icakey);
        if (rc != 0) {
            IBMCAerr(IBMCA_F_ICA_EC_KEY_INIT, rc);
            goto error;
        }
    }

out:
    BN_clear_free(bn_x);
    BN_clear_free(bn_y);

    return icakey;

error:
    p_ica_ec_key_free(icakey);
    icakey = NULL;
    goto out;
}

static ICA_EC_KEY *ibmca_ec_make_and_cache_ica_key(EC_KEY *ec_key,
                                                   unsigned int *privlen)
{
    struct ibmca_ec_ex_data *data, *data2;

    data = OPENSSL_zalloc(sizeof(*data));
    if (data == NULL)
        return NULL;

    data->ica_key = ibmca_ec_make_ica_key(ec_key, &data->nid, &data->privlen);
    if (data->ica_key == NULL) {
        OPENSSL_free(data);
        return NULL;
    }

    /*
     * Note that another thread could have allocated and set the ex_data for
     * that key after the caller of this function has checked if there is
     * already ex_data available for the key. So once we have the lock, we
     * check again, and if there now is ex_data available, we return the
     * ICA key from the ex_data, and free the one just created.
     */
    if (pthread_mutex_lock(&ec_ex_data_mutex) != 0) {
        IBMCAerr(IBMCA_F_ICA_EC_KEY_NEW, IBMCA_R_EC_INTERNAL_ERROR);
        return NULL;
    }

    data2 = EC_KEY_get_ex_data(ec_key, ec_ex_data_index);
    if (data2 != NULL) {
        pthread_mutex_unlock(&ec_ex_data_mutex);

        p_ica_ec_key_free(data->ica_key);
        OPENSSL_free(data);

        *privlen = data2->privlen;

        return data2->ica_key;
    }

    if (EC_KEY_set_ex_data(ec_key, ec_ex_data_index, data) != 1) {
        IBMCAerr(IBMCA_F_ICA_EC_KEY_NEW, IBMCA_R_EC_INTERNAL_ERROR);
        pthread_mutex_unlock(&ec_ex_data_mutex);
        OPENSSL_free(data);
        return NULL;
    }

    pthread_mutex_unlock(&ec_ex_data_mutex);

    *privlen = data->privlen;

    return data->ica_key;
}

int ibmca_ec_init(void)
{
#ifdef OLDER_OPENSSL
    return 0;
#else
    ec_ex_data_index = EC_KEY_get_ex_new_index(0, NULL, NULL,
                                               ibmca_ec_ex_data_dup,
                                               ibmca_ec_ex_data_free);
    if (ec_ex_data_index < 0) {
        IBMCAerr(IBMCA_F_IBMCA_INIT, IBMCA_R_EC_INTERNAL_ERROR);
        return 0;
    }

    return 1;
#endif
}

void ibmca_ec_destroy(void)
{
 #ifdef OLDER_OPENSSL
    if (ibmca_ecdh)
        ECDH_METHOD_free(ibmca_ecdh);
    if (ibmca_ecdh)
        ECDSA_METHOD_free(ibmca_ecdsa);
 #else
    if (ec_ex_data_index >= 0) {
        CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY, ec_ex_data_index);
        ec_ex_data_index = -1;
    }
    if (ibmca_ec)
        EC_KEY_METHOD_free(ibmca_ec);
 #endif
}

/**
 * ECDH key derivation method, replaces ossl_ecdh_compute_key.
 *
 * @return 1 success
 *         0 error
 */
int ibmca_ecdh_compute_key(unsigned char **pout, size_t *poutlen,
                           const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    ICA_EC_KEY *ica_pubkey = NULL, *ica_privkey = NULL;
    const EC_GROUP *group;
    BIGNUM *bn_x = NULL, *bn_y = NULL;
    unsigned int n, privlen;
    unsigned char X[IBMCA_EC_MAX_D_LEN];
    unsigned char Y[IBMCA_EC_MAX_D_LEN];
    unsigned char *z_buf = NULL;
    int rc, ret = 0, nid;
 #ifndef OLDER_OPENSSL
    int (*compute_key_sw)(unsigned char **pout, size_t *poutlen,
                          const EC_POINT *pub_key, const EC_KEY *ecdh) = NULL;
 #endif
    struct ibmca_ec_ex_data *data = EC_KEY_get_ex_data(ecdh, ec_ex_data_index);

    /* Get group from EC_KEY */
    if ((group = EC_KEY_get0_group(ecdh)) == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ECDH_COMPUTE_KEY, IBMCA_R_EC_INVALID_PARM);
        return 0;
    }

    /* Determine curve nid */
    nid = EC_GROUP_get_curve_name(group);
    if (nid <= 0) {
        IBMCAerr(IBMCA_F_IBMCA_ECDH_COMPUTE_KEY, IBMCA_R_EC_UNSUPPORTED_CURVE);
        return 0;
    }

    if (data != NULL) {
        ica_privkey = data->ica_key;
        privlen = data->privlen;
        goto do_derive;
    }

    /* Create ICA_EC_KEY object for private key */
    ica_privkey = ibmca_ec_make_and_cache_ica_key((EC_KEY*)ecdh, &privlen);
    if (ica_privkey == NULL) {
        /* This curve is not supported by libica. */
    #ifdef OLDER_OPENSSL
        return 0;
    #else
        /*
         * EC_KEY_METHOD_get_compute_key misses the const-qualifier of the
         * parameter in some openssl versions.
         */
        EC_KEY_METHOD_get_compute_key((EC_KEY_METHOD *)ossl_ec,
                                      &compute_key_sw);
        if (compute_key_sw == NULL) {
            IBMCAerr(IBMCA_F_IBMCA_ECDH_COMPUTE_KEY,
                     IBMCA_R_EC_INTERNAL_ERROR);
            return 0;
        }

        return compute_key_sw(pout, poutlen, pub_key, ecdh);
    #endif
    }

do_derive:
    /* Create ICA_EC_KEY object for public key */
    ica_pubkey = p_ica_ec_key_new(nid, &privlen);
    if (ica_pubkey == NULL) {
        /* This curve is not supported by libica. */
 #ifdef OLDER_OPENSSL
        return 0;
 #else
        /*
         * EC_KEY_METHOD_get_compute_key misses the const-qualifier of the
         * parameter in some openssl versions.
         */
        EC_KEY_METHOD_get_compute_key((EC_KEY_METHOD *)ossl_ec,
                                      &compute_key_sw);
        if (compute_key_sw == NULL) {
            IBMCAerr(IBMCA_F_IBMCA_ECDH_COMPUTE_KEY,
                     IBMCA_R_EC_INTERNAL_ERROR);
            return 0;
        }

        return compute_key_sw(pout, poutlen, pub_key, ecdh);
 #endif
    }

    /* Get (X,Y) from EC_POINT */
    bn_x = BN_new();
    bn_y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, pub_key, bn_x, bn_y, NULL)) {
        IBMCAerr(IBMCA_F_IBMCA_ECDH_COMPUTE_KEY, IBMCA_R_EC_INTERNAL_ERROR);
        goto end;
    }

    /* Format (X) as char array, with leading zeros if necessary */
    n = privlen - BN_num_bytes(bn_x);
    memset(X, 0, n);
    BN_bn2bin(bn_x, &(X[n]));

    /* Format (Y) as char array, with leading zeros if necessary */
    n = privlen - BN_num_bytes(bn_y);
    memset(Y, 0, n);
    BN_bn2bin(bn_y, &(Y[n]));

    /* Initialize public ICA_EC_KEY with (X,Y) */
    rc = p_ica_ec_key_init(X, Y, NULL, ica_pubkey);
    if (rc != 0) {
        IBMCAerr(IBMCA_F_ICA_EC_KEY_INIT, rc);
        goto end;
    }

    /* Allocate memory for shared secret z, will be freed by caller */
    if ((z_buf = OPENSSL_malloc(privlen)) == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ECDH_COMPUTE_KEY, IBMCA_R_EC_INTERNAL_ERROR);
        goto end;
    }

    /* Calculate shared secret z */
    rc = p_ica_ecdh_derive_secret(ibmca_handle, ica_privkey, ica_pubkey, z_buf,
                                  privlen);
    if (rc != 0) {
        /* Possibly no suitable adapter. */
        OPENSSL_free(z_buf);

 #ifdef OLDER_OPENSSL
        goto end;
 #else
        /*
         * EC_KEY_METHOD_get_compute_key misses the const-qualifier of the
         * parameter in some openssl versions.
         */
        EC_KEY_METHOD_get_compute_key((EC_KEY_METHOD *)ossl_ec,
                                      &compute_key_sw);
        if (compute_key_sw == NULL) {
            IBMCAerr(IBMCA_F_ICA_ECDH_DERIVE_SECRET, rc);
            goto end;
        }

        ret = compute_key_sw(pout, poutlen, pub_key, ecdh);
        goto end;
 #endif
    }

    *pout = z_buf;
    *poutlen = privlen;

    ret = 1;

end:
    p_ica_ec_key_free(ica_pubkey);
    BN_clear_free(bn_x);
    BN_clear_free(bn_y);
    return ret;
}

/**
 * ECDSA signing method (replaces ossl_ecdsa_sign_sig).
 *
 * @return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
ECDSA_SIG *ibmca_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
                const BIGNUM *in_kinv, const BIGNUM *in_r,
                EC_KEY *eckey)
{
    ECDSA_SIG *sig = NULL;
    ICA_EC_KEY *icakey = NULL;
    unsigned int privlen;
    BIGNUM *r, *s, *kinv;
    unsigned char sigret[IBMCA_EC_MAX_SIG_LEN];
    int rc;
 #ifndef OLDER_OPENSSL
    int (*sign_sw)(int type, const unsigned char *dgst, int dlen,
                    unsigned char *sig, unsigned int *siglen,
                    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey) = NULL;
 #endif
    int (*sign_setup_sw)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                         BIGNUM **rp) = NULL;
    ECDSA_SIG *(*sign_sig_sw)(const unsigned char *dgst, int dgst_len,
                              const BIGNUM *in_kinv, const BIGNUM *in_r,
                              EC_KEY *eckey) = NULL;
    BN_CTX *ctx;
    struct ibmca_ec_ex_data *data = EC_KEY_get_ex_data(eckey, ec_ex_data_index);

    /* Check parms: precomputed (k,r) are not supported by ibmca */
    if (in_kinv != NULL || in_r != NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ECDSA_SIGN_SIG, IBMCA_R_EC_INVALID_PARM);
        return NULL;
    }

    /* Check if key usable */
 #ifndef OLDER_OPENSSL
    if (!EC_KEY_can_sign(eckey)) {
        IBMCAerr(IBMCA_F_IBMCA_ECDSA_SIGN_SIG,
                 IBMCA_R_EC_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return NULL;
    }
 #endif

    if (data != NULL) {
        icakey = data->ica_key;
        privlen = data->privlen;
        goto do_sign;
    }

    /* Create ICA_EC_KEY object */
    icakey = ibmca_ec_make_and_cache_ica_key(eckey, &privlen);
    if (icakey == NULL) {
        /* This curve is not supported by libica. */
 #ifdef OLDER_OPENSSL
        ECDSA_METHOD_get_sign(ossl_ecdsa, &sign_setup_sw, &sign_sig_sw);
 #else
        /*
         * EC_KEY_METHOD_get_sign misses the const-qualifier of the
         * parameter in some openssl versions.
         */
        EC_KEY_METHOD_get_sign((EC_KEY_METHOD *)ossl_ec, &sign_sw,
                               &sign_setup_sw, &sign_sig_sw);
 #endif
        if (sign_sig_sw == NULL || sign_setup_sw == NULL) {
            IBMCAerr(IBMCA_F_IBMCA_ECDSA_SIGN_SIG,
                     IBMCA_R_EC_INTERNAL_ERROR);
            return NULL;
        }

        kinv = NULL;
        r = NULL;
        ctx = BN_CTX_new();
        sign_setup_sw(eckey, ctx, &kinv, &r);
        BN_CTX_free(ctx);
        sig = sign_sig_sw(dgst, dgst_len, kinv, r, eckey);
        BN_clear_free(kinv);
        BN_clear_free(r);
        return sig;
    }

do_sign:
    /* Call libica signing routine */
    rc = p_ica_ecdsa_sign(ibmca_handle, icakey, dgst, dgst_len, sigret,
                          sizeof(sigret));
    if (rc != 0) {
        /* Possibly no adapter. */
 #ifdef OLDER_OPENSSL
        ECDSA_METHOD_get_sign(ossl_ecdsa, &sign_setup_sw, &sign_sig_sw);
 #else
        /*
         * EC_KEY_METHOD_get_sign misses the const-qualifier of the
         * parameter in some openssl versions.
         */
        EC_KEY_METHOD_get_sign((EC_KEY_METHOD *)ossl_ec, &sign_sw,
                               &sign_setup_sw, &sign_sig_sw);
 #endif
        if (sign_sig_sw == NULL || sign_setup_sw == NULL) {
            IBMCAerr(IBMCA_F_IBMCA_ECDSA_SIGN_SIG,
                     IBMCA_R_EC_INTERNAL_ERROR);
            return NULL;
        }

        kinv = NULL;
        r = NULL;
        ctx = BN_CTX_new();
        sign_setup_sw(eckey, ctx, &kinv, &r);
        BN_CTX_free(ctx);
        sig = sign_sig_sw(dgst, dgst_len, kinv, r, eckey);
        BN_clear_free(kinv);
        BN_clear_free(r);
        goto end2;
    }

    /* Construct ECDSA_SIG object from char array */
    r = BN_bin2bn(sigret, privlen, NULL);
    s = BN_bin2bn(sigret + privlen, privlen, NULL);
    sig = ECDSA_SIG_new();

 #ifndef OLDER_OPENSSL
    if (sig)
        ECDSA_SIG_set0(sig, r, s);
 #else
    if (sig) {
        BN_free(sig->r);
        sig->r = r;
        BN_free(sig->s);
        sig->s = s;
    }
 #endif

end2:
    return sig;
}

/**
 * ECDSA verify method (replaces ossl_ecdsa_verify_sig).
 *
 * @return
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ibmca_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
                           const ECDSA_SIG *sig, EC_KEY *eckey)
{
    unsigned char sig_array[IBMCA_EC_MAX_Q_LEN];
    BIGNUM *bn_x = NULL, *bn_y = NULL;
    const BIGNUM *bn_r, *bn_s;
    unsigned int privlen;
    ICA_EC_KEY *icakey = NULL;
    int rc, n;
    int ret = -1;
#ifndef OLDER_OPENSSL
    int (*verify_sw)(int type, const unsigned char *dgst, int dgst_len,
                     const unsigned char *sigbuf, int sig_len, EC_KEY *eckey) = NULL;
#endif
    int (*verify_sig_sw)(const unsigned char *dgst, int dgst_len,
                         const ECDSA_SIG *sig, EC_KEY *eckey) = NULL;
    struct ibmca_ec_ex_data *data = EC_KEY_get_ex_data(eckey, ec_ex_data_index);

    /* Check parms */
    if (eckey == NULL || sig == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ECDSA_VERIFY_SIG, EC_R_MISSING_PARAMETERS);
        return ret;
    }

    /* Check if key usable */
#ifndef OLDER_OPENSSL
    if (!EC_KEY_can_sign(eckey)) {
        IBMCAerr(IBMCA_F_IBMCA_ECDSA_VERIFY_SIG, IBMCA_R_EC_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return ret;
    }
 #endif

    if (data != NULL) {
        icakey = data->ica_key;
        privlen = data->privlen;
        goto do_verify;
    }

    /* Create ICA_EC_KEY object */
    icakey = ibmca_ec_make_and_cache_ica_key(eckey, &privlen);
    if (icakey == NULL) {
        /* This curve is not supported by libica. */
 #ifdef OLDER_OPENSSL
        ECDSA_METHOD_get_verify(ossl_ecdsa, &verify_sig_sw);
 #else
        /*
         * EC_KEY_METHOD_get_verify misses the const-qualifier of the
         * parameter in some openssl versions.
         */
        EC_KEY_METHOD_get_verify((EC_KEY_METHOD *)ossl_ec, &verify_sw,
                                 &verify_sig_sw);
 #endif
        if (verify_sig_sw == NULL) {
            IBMCAerr(IBMCA_F_IBMCA_ECDSA_VERIFY_SIG,
                     IBMCA_R_EC_INTERNAL_ERROR);
            return ret;
        }

        return verify_sig_sw(dgst, dgst_len, sig, eckey);
    }

do_verify:
    /* Get (r,s) from ECDSA_SIG */
 #ifdef OLDER_OPENSSL
    bn_r = sig->r;
    bn_s = sig->s;
 #else
    ECDSA_SIG_get0(sig, &bn_r, &bn_s);
 #endif

    /* Format r as byte array with leading 0x00's if necessary */
    n = privlen - BN_num_bytes(bn_r);
    memset(sig_array, 0, n);
    BN_bn2bin(bn_r, &(sig_array[n]));

    /* Format s as byte array with leading 0x00's if necessary */
    n = privlen - BN_num_bytes(bn_s);
    memset(&(sig_array[privlen]), 0, n);
    BN_bn2bin(bn_s, &(sig_array[privlen+n]));

    /* Call libica verify routine */
    rc = p_ica_ecdsa_verify(ibmca_handle, icakey, dgst, dgst_len, sig_array,
                            2 * privlen);
    switch (rc) {
    case 0:
        ret = 1; /* signature valid */
        break;
    case EFAULT:
        ret = 0; /* signature invalid */
        break;
    default:
        /* Possibly no suitable adapter. */
 #ifdef OLDER_OPENSSL
        ECDSA_METHOD_get_verify(ossl_ecdsa, &verify_sig_sw);
 #else
        /*
         * EC_KEY_METHOD_get_verify misses the const-qualifier of the
         * parameter in some openssl versions.
         */
        EC_KEY_METHOD_get_verify((EC_KEY_METHOD *)ossl_ec, &verify_sw,
                                 &verify_sig_sw);
 #endif
        if (verify_sig_sw == NULL) {
            IBMCAerr(IBMCA_F_IBMCA_ECDSA_VERIFY_SIG,
                     IBMCA_R_EC_INTERNAL_ERROR);
            goto end;
        }

        ret = verify_sig_sw(dgst, dgst_len, sig, eckey);
        break;
    }

end:
    BN_clear_free(bn_x);
    BN_clear_free(bn_y);

    return ret;
}

/* --- OLDER_OPENSSL section --- */
 #ifdef OLDER_OPENSSL

ECDSA_METHOD *ibmca_ecdsa = NULL;
ECDH_METHOD *ibmca_ecdh = NULL;

/*
 * This structure is opaque in openssl. However, get/set methods are missing
 * so we copy its definition and write our own.
 */
struct ecdh_method {
    const char *name;
    int (*compute_key)(void *out, size_t len, const EC_POINT *pub_key,
                       EC_KEY *ecdh, void *(*KDF)(const void *in,
                                                  size_t inlen, void *out,
                                                  size_t *outlen));
    int flags;
    void *app_data;
};

struct ecdsa_method {
    const char *name;
    ECDSA_SIG *(*sign_sig)(const unsigned char *dgst, int dgst_len,
                           const BIGNUM *inv, const BIGNUM *rp,
                           EC_KEY *eckey);
    int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                      BIGNUM **r);
    int (*verify_sig)(const unsigned char *dgst, int dgst_len,
                      const ECDSA_SIG *sig, EC_KEY *eckey);
    int flags;
    void *app_data;
};

/**
 * ECDH key derivation method, replaces ossl_ecdh_compute_key for older openssl.
 *
 * @return 1 success
 *         0 error
 */
int ibmca_older_ecdh_compute_key(void *out, size_t outlen,
                                 const EC_POINT *pub_key,
                                 EC_KEY *ecdh, void *(*KDF) (const void *in,
                                                             size_t inlen,
                                                             void *out,
                                                             size_t *outlen))
{
    int rc = 0;
    unsigned char *temp_p = NULL;
    size_t temp_len = 0;
    int (*compute_key_sw)(void *out, size_t len, const EC_POINT *pub_key,
                          EC_KEY *ecdh, void *(*KDF)(const void *in,
                                                     size_t inlen,
                                                     void *out,
                                                     size_t *outlen)) = NULL;

    rc = ibmca_ecdh_compute_key(&temp_p, &temp_len, pub_key, ecdh);
    if (!rc) {
        ECDH_METHOD_get_compute_key(ossl_ecdh, &compute_key_sw);
        rc = compute_key_sw == NULL ? 0 : compute_key_sw(out, outlen, pub_key,
                                                         ecdh, KDF);
        goto end;
    }

    if (outlen < temp_len) {
        rc = 0;
        goto end;
    }

    if (KDF != NULL) {
        if (KDF(temp_p, temp_len, out, &outlen) == NULL) {
            rc = 0;
            goto end;
        }
        rc = outlen;
    } else {
        if (outlen > temp_len)
            outlen = temp_len;
        memcpy(out, temp_p, outlen);
        rc = outlen;
    }

end:
    OPENSSL_free(temp_p);
    return rc;
}

/**
 * ECDSA sign method, replaces ecdsa_do_sign for older openssl.
 */
ECDSA_SIG *ibmca_older_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                                     const BIGNUM *in_kinv, const BIGNUM *in_r,
                                     EC_KEY *eckey)
{
    if (in_kinv != NULL || in_r != NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ECDSA_DO_SIGN, IBMCA_R_EC_INVALID_PARM);
        return NULL;
    }

    return ibmca_ecdsa_sign_sig(dgst, dgst_len, NULL, NULL, eckey);
}

/**
 * ECDSA verify method, replaces ecdsa_do_verify for older openssl.
 *
 * @return 1 success
 *         0 error
 */
int ibmca_older_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                                const ECDSA_SIG *sig, EC_KEY *eckey)
{
    return ibmca_ecdsa_verify_sig(dgst, dgst_len, sig, eckey);
}

/*
 * APIs which are missing in openssl 1.0.2.
 */
ECDH_METHOD *ECDH_METHOD_new(const ECDH_METHOD *meth)
{
    ECDH_METHOD *out;

    out = OPENSSL_malloc(sizeof(*out));
    if (out == NULL)
        return NULL;

    if (meth)
        memcpy(out, meth, sizeof(*out));
    else
        memset(out, 0, sizeof(*out));

    return out;
}

void ECDH_METHOD_set_compute_key(ECDH_METHOD *meth,
                                 int (*compute_key)(void *out, size_t len,
                                                    const EC_POINT *pub_key,
                                                    EC_KEY *ecdh,
                                                    void *(*KDF)(const void *in,
                                                                 size_t inlen,
                                                                 void *out,
                                                                 size_t *outlen)))
{
    meth->compute_key = compute_key;
}

void ECDH_METHOD_get_compute_key(const ECDH_METHOD *meth,
                                 int (**compute_key)(void *out, size_t len,
                                                     const EC_POINT *pub_key,
                                                     EC_KEY *ecdh,
                                                     void *(*KDF)(const void *in,
                                                                  size_t inlen,
                                                                  void *out,
                                                                  size_t *outlen)))
{
    if (compute_key != NULL)
        *compute_key = meth->compute_key;
}

void ECDH_METHOD_set_name(ECDH_METHOD *meth, char *name)
{
    meth->name = name;
}

void ECDH_METHOD_free(ECDH_METHOD *meth)
{
    OPENSSL_free(meth);
}

void ECDSA_METHOD_get_sign(const ECDSA_METHOD *meth,
                           int (**psign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                               BIGNUM **kinvp, BIGNUM **rp),
                           ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
                                                    int dgst_len,
                                                    const BIGNUM *in_kinv,
                                                    const BIGNUM *in_r,
                                                    EC_KEY *eckey))
{
    if (psign_setup != NULL)
        *psign_setup = meth->sign_setup;
    if (psign_sig != NULL)
        *psign_sig = meth->sign_sig;
}

void ECDSA_METHOD_get_verify(const ECDSA_METHOD *meth,
                             int (**pverify_sig)(const unsigned char *dgst,
                                                 int dgst_len,
                                                 const ECDSA_SIG *sig,
                                                 EC_KEY *eckey))
{
    if (pverify_sig != NULL)
        *pverify_sig = meth->verify_sig;
}

/* --- !OLDER_OPENSSL section --- */
 #else

EC_KEY_METHOD *ibmca_ec = NULL;

/**
 * ECDSA signing method (replaces ossl_ecdsa_sign).
 *
 * returns 1 if success
 *         0 if error
 */
int ibmca_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
             unsigned char *sig_array, unsigned int *siglen,
             const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *sig;
    const BIGNUM *bn_r, *bn_s;
    const EC_GROUP *group;
    int n, r_len, rc;

    /* Check parms: precomputed (k,r) are not supported by ibmca */
    if (kinv != NULL || r != NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ECDSA_SIGN, IBMCA_R_EC_INVALID_PARM);
        return 0;
    }

    /* Create signature */
    sig = ibmca_ecdsa_sign_sig(dgst, dlen, NULL, NULL, eckey);
    if (sig == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ECDSA_SIGN, IBMCA_R_EC_INTERNAL_ERROR);
        *siglen = 0;
        return 0;
    }

    /* Determine r-length */
    if ((group = EC_KEY_get0_group(eckey)) == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_ECDSA_SIGN, IBMCA_R_EC_INTERNAL_ERROR);
        rc = 0;
        goto ret;
    }
    r_len = (EC_GROUP_get_degree(group) + 7) / 8;

    /* Get (r,s) from ECDSA_SIG */
    ECDSA_SIG_get0(sig, &bn_r, &bn_s);

    /* Format r as byte array with leading 0x00's if necessary */
    n = r_len - BN_num_bytes(bn_r);
    memset(sig_array, 0, n);
    BN_bn2bin(bn_r, &(sig_array[n]));

    /* Format s as byte array with leading 0x00's if necessary */
    n = r_len - BN_num_bytes(bn_s);
    memset(&(sig_array[r_len]), 0, n);
    BN_bn2bin(bn_s, &(sig_array[r_len + n]));

    /* Create DER encoding */
    *siglen = i2d_ECDSA_SIG(sig, &sig_array);

    rc = 1;
ret:
    ECDSA_SIG_free(sig);
    return rc;
}

/**
 * ECDSA verify method (replaces ossl_ecdsa_verify). Just create an ECDSA_SIG object
 * from given byte array and call ibmca_ecdsa_verify_sig.
 *
 * @return
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ibmca_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                       const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL)
        return ret;

    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto err;

    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen) != 0)
        goto err;

    ret = ibmca_ecdsa_verify_sig(dgst, dgst_len, s, eckey);

err:
    OPENSSL_clear_free(der, derlen);
    ECDSA_SIG_free(s);

    return ret;
}

 #endif

#else

/* non-empty compilation unit */
static void *variable = &variable;

#endif
