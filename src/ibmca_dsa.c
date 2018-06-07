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

#include <openssl/dsa.h>
#include "ibmca.h"

#ifndef OPENSSL_NO_DSA

/* This code was liberated and adapted from the commented-out code in
 * dsa_ossl.c. Because of the unoptimised form of the Ibmca acceleration
 * (it doesn't have a CRT form for RSA), this function means that an
 * Ibmca system running with a DSA server certificate can handshake
 * around 5 or 6 times faster/more than an equivalent system running with
 * RSA. Just check out the "signs" statistics from the RSA and DSA parts
 * of "openssl speed -engine ibmca dsa1024 rsa1024". */
#ifdef OLDER_OPENSSL
static int ibmca_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
                             BIGNUM *p1, BIGNUM *a2, BIGNUM *p2,
                             BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
#else
static int ibmca_dsa_mod_exp(DSA *dsa, BIGNUM *rr, const BIGNUM *a1,
                             const BIGNUM *p1, const BIGNUM *a2,
                             const BIGNUM *p2, const BIGNUM *m,
                             BN_CTX *ctx, BN_MONT_CTX *in_mont)
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
static int ibmca_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
                             const BIGNUM *p, const BIGNUM *m,
                             BN_CTX *ctx, BN_MONT_CTX *m_ctx)
#else
static int ibmca_mod_exp_dsa(DSA *dsa, BIGNUM *r, const BIGNUM *a,
                             const BIGNUM *p, const BIGNUM *m,
                             BN_CTX *ctx, BN_MONT_CTX *m_ctx)
#endif
{
    return ibmca_mod_exp(r, a, p, m, ctx);
}


#ifdef OLDER_OPENSSL
static DSA_METHOD dsa_m = {
    "Ibmca DSA method",         /* name */
    NULL,                       /* dsa_do_sign */
    NULL,                       /* dsa_sign_setup */
    NULL,                       /* dsa_do_verify */
    ibmca_dsa_mod_exp,          /* dsa_mod_exp */
    ibmca_mod_exp_dsa,          /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL                        /* app_data */
};

DSA_METHOD *ibmca_dsa(void)
{
    const DSA_METHOD *meth1 = DSA_OpenSSL();

    dsa_m.dsa_do_sign = meth1->dsa_do_sign;
    dsa_m.dsa_sign_setup = meth1->dsa_sign_setup;
    dsa_m.dsa_do_verify = meth1->dsa_do_verify;

    return &dsa_m;
}

#else
static DSA_METHOD *dsa_m = NULL;
DSA_METHOD *ibmca_dsa(void)
{
    const DSA_METHOD *meth1;
    DSA_METHOD *method;

    if (dsa_m != NULL)
        goto done;

    if ((method = DSA_meth_new("Ibmca DSA method", 0)) == NULL
        || (meth1 = DSA_OpenSSL()) == NULL
        || !DSA_meth_set_sign(method, DSA_meth_get_sign(meth1))
        || !DSA_meth_set_sign_setup(method, DSA_meth_get_sign_setup(meth1))
        || !DSA_meth_set_verify(method, DSA_meth_get_verify(meth1))
        || !DSA_meth_set_mod_exp(method, ibmca_dsa_mod_exp)
        || !DSA_meth_set_bn_mod_exp(method, ibmca_mod_exp_dsa)) {
        DSA_meth_free(method);
        method = NULL;
        meth1 = NULL;
    }

    dsa_m = method;

done:
    return dsa_m;
}

void ibmca_dsa_destroy(void)
{
    DSA_meth_free(dsa_m);
}
#endif
#endif                          /* endif OPENSSL_NO_DSA */
