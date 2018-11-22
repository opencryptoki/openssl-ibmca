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

#include <openssl/rsa.h>
#include "ibmca.h"
#include "e_ibmca_err.h"

/*
 * Define compat functions for older OpenSSL versions
 */
#ifdef OLDER_OPENSSL
void RSA_get0_key(const RSA *rsa, const BIGNUM **n,
                  const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = rsa->n;
    if (e != NULL)
        *e = rsa->e;
    if (d != NULL)
        *d = rsa->d;
}

void RSA_get0_factors(const RSA *rsa, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = rsa->p;
    if (q != NULL)
        *q = rsa->q;
}

void RSA_get0_crt_params(const RSA *rsa, const BIGNUM **dmp1,
                         const BIGNUM **dmq1, const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = rsa->dmp1;
    if (dmq1 != NULL)
        *dmq1 = rsa->dmq1;
    if (iqmp != NULL)
        *iqmp = rsa->iqmp;
}
#endif


int ibmca_mod_exp(BIGNUM * r, const BIGNUM * a, const BIGNUM * p,
                  const BIGNUM * m, BN_CTX * ctx)
{
    /* r = (a^p) mod m
     * r = output
     * a = input
     * p = exponent
     * m = modulus
     */

    unsigned char *input = NULL, *output = NULL;
    ica_rsa_key_mod_expo_t *key = NULL;
    unsigned int rc;
    int plen, mlen, inputlen;

    /*
     * make necessary memory allocations
     * FIXME: Would it be possible to minimize memory allocation overhead by
     * either allocating it all at once or having a static storage?
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
    } else {
        rc = 1;
    }

    /* Convert output to BIGNUM representation.
     * right-justified output applies
     */
    /* BN_bin2bn((unsigned char *) (output + key->key_length - inputlen),
     *           inputlen, r); */
    BN_bin2bn((unsigned char *) output, key->key_length, r);

    goto end;

err:
    rc = 0;                     /* error condition */

end:
    free(key->exponent);
    free(key->modulus);
    free(key);
    free(input);
    free(output);

    return rc;
}

#ifndef OPENSSL_NO_RSA

static int ibmca_mod_exp_crt(BIGNUM * r, const BIGNUM * a,
                             const BIGNUM * p, const BIGNUM * q,
                             const BIGNUM * dmp1, const BIGNUM * dmq1,
                             const BIGNUM * iqmp, BN_CTX * ctx)
{
    /*
     * r = output
     * a = input
     * p and q are themselves
     * dmp1, dmq1 are dp and dq respectively
     * iqmp is qInverse
     */

    ica_rsa_key_crt_t *key = NULL;
    unsigned char *output = NULL, *input = NULL;
    int rc;
    int plen, qlen, dplen, dqlen, qInvlen;
    int inputlen;

    /*
     * make necessary memory allocations
     * FIXME: Would it be possible to minimize memory allocation overhead by
     * either allocating it all at once or having a static storage?
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

    key->p = (unsigned char *) calloc(1, (key->key_length / 2) + 8);
    if (key->p == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
        goto err;
    }
    dplen = BN_num_bytes(dmp1);
    key->dp = (unsigned char *) calloc(1, (key->key_length / 2) + 8);
    if (key->dp == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
        goto err;
    }

    key->q = (unsigned char *) calloc(1, key->key_length / 2);
    if (key->q == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
        goto err;
    }

    dqlen = BN_num_bytes(dmq1);
    key->dq = (unsigned char *) calloc(1, key->key_length / 2);
    if (key->dq == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
        goto err;
    }

    qInvlen = BN_num_bytes(iqmp);
    key->qInverse = (unsigned char *) calloc(1, (key->key_length / 2) + 8);
    if (key->qInverse == NULL) {
        IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
        goto err;
    }
    inputlen = BN_num_bytes(a);
    if (inputlen > key->key_length) {   /* input can't be larger than key */
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
    BN_bn2bin(p, key->p + 8 + (key->key_length / 2) - plen);

    BN_bn2bin(dmp1, key->dp + 8 + (key->key_length / 2) - dplen);

    BN_bn2bin(q, key->q + (key->key_length / 2) - qlen);

    BN_bn2bin(dmq1, key->dq + (key->key_length / 2) - dqlen);

    BN_bn2bin(iqmp, key->qInverse + 8 + (key->key_length / 2) - qInvlen);

    BN_bn2bin(a, input + key->key_length - inputlen);

    /* execute the ica crt call */

    rc = p_ica_rsa_crt(ibmca_handle, input, key, output);
    if (rc != 0) {
        IBMCAerr(IBMCA_F_IBMCA_MOD_EXP, IBMCA_R_REQUEST_FAILED);
        goto err;
    } else {
        rc = 1;
    }

    /* Convert output to BIGNUM representation */
    /* BN_bin2bn((unsigned char *) (output + key->key_length - inputlen),
     *           inputlen, r); */
    BN_bin2bn((unsigned char *) output, key->key_length, r);

    goto end;

err:
    rc = 0;                     /* error condition */

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

static int ibmca_rsa_init(RSA * rsa)
{
    RSA_blinding_off(rsa);

    return 1;
}

static int ibmca_rsa_mod_exp(BIGNUM * r0, const BIGNUM * I, RSA * rsa,
                             BN_CTX * ctx)
{
    int to_return = 0;
    const BIGNUM *d, *n, *p, *q, *dmp1, *dmq1, *iqmp;

    RSA_get0_key(rsa, &n, NULL, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    if (!p || !q || !dmp1 || !dmq1 || !iqmp) {
        if (!d || !n) {
            IBMCAerr(IBMCA_F_IBMCA_RSA_MOD_EXP, IBMCA_R_MISSING_KEY_COMPONENTS);
            goto err;
        }
        to_return = ibmca_mod_exp(r0, I, d, n, ctx);
    } else {
        to_return = ibmca_mod_exp_crt(r0, I, p, q, dmp1, dmq1, iqmp, ctx);
    }

err:
    return to_return;
}

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int ibmca_mod_exp_mont(BIGNUM * r, const BIGNUM * a,
                              const BIGNUM * p, const BIGNUM * m,
                              BN_CTX * ctx, BN_MONT_CTX * m_ctx)
{
    return ibmca_mod_exp(r, a, p, m, ctx);
}

#ifdef OLDER_OPENSSL
static RSA_METHOD rsa_m = {
    "Ibmca RSA method",         /* name */
    NULL,                       /* rsa_pub_enc */
    NULL,                       /* rsa_pub_dec */
    NULL,                       /* rsa_priv_enc */
    NULL,                       /* rsa_priv_dec */
    ibmca_rsa_mod_exp,          /* rsa_mod_exp */
    ibmca_mod_exp_mont,         /* bn_mod_exp */
    ibmca_rsa_init,             /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* rsa_sign */
    NULL,                       /* rsa_verify */
    NULL                        /* rsa_keygen */
};

RSA_METHOD *ibmca_rsa(void)
{
    /* We know that the "PKCS1_SSLeay()" functions hook properly
     * to the ibmca-specific mod_exp and mod_exp_crt so we use
     * those functions. NB: We don't use ENGINE_openssl() or
     * anything "more generic" because something like the RSAref
     * code may not hook properly, and if you own one of these here
     * cards then you have the right to do RSA operations on it
     * anyway! */
    const RSA_METHOD *meth1 = RSA_PKCS1_SSLeay();

    rsa_m.rsa_pub_enc = meth1->rsa_pub_enc;
    rsa_m.rsa_pub_dec = meth1->rsa_pub_dec;
    rsa_m.rsa_priv_enc = meth1->rsa_priv_enc;
    rsa_m.rsa_priv_dec = meth1->rsa_priv_dec;

    return &rsa_m;
}

#else
static RSA_METHOD *rsa_m = NULL;
RSA_METHOD *ibmca_rsa(void)
{
    const RSA_METHOD *meth1;
    RSA_METHOD *method;

    if (rsa_m != NULL)
        goto done;

    if ((method = RSA_meth_new("Ibmca RSA method", 0)) == NULL
        || (meth1 = RSA_PKCS1_OpenSSL()) == NULL
        || !RSA_meth_set_pub_enc(method, RSA_meth_get_pub_enc(meth1))
        || !RSA_meth_set_pub_dec(method, RSA_meth_get_pub_dec(meth1))
        || !RSA_meth_set_priv_enc(method, RSA_meth_get_priv_enc(meth1))
        || !RSA_meth_set_priv_dec(method, RSA_meth_get_priv_dec(meth1))
        || !RSA_meth_set_mod_exp(method, ibmca_rsa_mod_exp)
        || !RSA_meth_set_bn_mod_exp(method, ibmca_mod_exp_mont)
        || !RSA_meth_set_init(method, ibmca_rsa_init)) {
        RSA_meth_free(method);
        method = NULL;
        meth1 = NULL;
    }

    rsa_m = method;

done:
    return rsa_m;
}

void ibmca_rsa_destroy(void)
{
    RSA_meth_free(rsa_m);
}
#endif

#endif                          /* endif OPENSSL_NO_RSA */
