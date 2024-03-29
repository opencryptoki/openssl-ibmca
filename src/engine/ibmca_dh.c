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

#include <openssl/dh.h>
#include "ibmca.h"
#include <stdio.h>

#ifndef OPENSSL_NO_DH

static int (*ibmca_mod_exp_dh_backup)(DH const *dh, BIGNUM *r,
                                      const BIGNUM *a, const BIGNUM *p,
                                      const BIGNUM *m, BN_CTX *ctx,
                                      BN_MONT_CTX *m_ctx);

/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int ibmca_mod_exp_dh(DH const *dh, BIGNUM *r,
                            const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
	if (!ibmca_mod_exp(r, a, p, m, ctx) && ibmca_mod_exp_dh_backup)
		return ibmca_mod_exp_dh_backup(dh, r, a, p, m, ctx, m_ctx);
	return 1;
}


#ifdef OLDER_OPENSSL
static DH_METHOD dh_m = {
    "Ibmca DH method",          /* name */
    NULL,                       /* generate_key */
    NULL,                       /* compute_key */
    ibmca_mod_exp_dh,           /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    DH_FLAG_FIPS_METHOD,        /* flags */
    NULL                        /* app_data */
};

DH_METHOD *ibmca_dh(void)
{
    const DH_METHOD *meth1 = DH_OpenSSL();

    ibmca_mod_exp_dh_backup = meth1->bn_mod_exp;
    dh_m.generate_key = meth1->generate_key;
    dh_m.compute_key = meth1->compute_key;

    return &dh_m;
}

#else
static DH_METHOD *dh_m = NULL;
DH_METHOD *ibmca_dh(void)
{
    const DH_METHOD *meth1;
    DH_METHOD *method;

    if (dh_m != NULL)
        goto done;

    if ((method = DH_meth_new("Ibmca DH method", 0)) == NULL
        || (meth1 = DH_OpenSSL()) == NULL
	    || (ibmca_mod_exp_dh_backup = DH_meth_get_bn_mod_exp(meth1)) == NULL
        || !DH_meth_set_generate_key(method, DH_meth_get_generate_key(meth1))
        || !DH_meth_set_compute_key(method, DH_meth_get_compute_key(meth1))
        || !DH_meth_set_bn_mod_exp(method, ibmca_mod_exp_dh)
        || !DH_meth_set_flags(method, DH_FLAG_FIPS_METHOD)) {
        DH_meth_free(method);
        method = NULL;
        meth1 = NULL;
    }

    dh_m = method;

done:
    return dh_m;
}

void ibmca_dh_destroy(void)
{
    DH_meth_free(dh_m);
}
#endif

#endif                          /* end OPENSSL_NO_DH */
