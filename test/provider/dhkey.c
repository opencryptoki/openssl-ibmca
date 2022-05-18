/*
 * Copyright [2021-2022] International Business Machines Corp.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include <ica_api.h>

#define UNUSED(var)                             ((void)(var))

void setup(void)
{
    OPENSSL_load_builtin_modules();

    CONF_modules_load_file(NULL, NULL,
                           CONF_MFLAGS_DEFAULT_SECTION|
                           CONF_MFLAGS_IGNORE_MISSING_FILE);
}

int check_dhkey(int nid, const char *name, const char *algo)
{
    int            ret = 0;
    EVP_PKEY_CTX  *ctx = NULL;
    EVP_PKEY      *dh_pkey = NULL;
    EVP_PKEY      *peer_pkey = NULL;
    size_t         keylen1, keylen2;
    unsigned char  keybuf1[1024], keybuf2[1024];
    const OSSL_PROVIDER *provider;
    const char *provname;

    /* Keygen with IBMCA provider */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
        goto out;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        goto out;
    }

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        goto out;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, "ibmca") != 0) {
        fprintf(stderr, "Context is not using the IBMCA provider, but '%s'\n",
               provname);
        goto out;
    }

    if (EVP_PKEY_CTX_set_dh_nid(ctx, nid) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_dh_nid failed\n");
        goto out;
    }

    if (EVP_PKEY_keygen(ctx, &dh_pkey) <= 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == 7) {
            /* curve not supported => test passed */
            fprintf(stderr, "Group %s not supported by OpenSSL\n", name);
            ret = 1;
        } else {
            fprintf(stderr, "EVP_PKEY_keygen failed\n");
        }
        goto out;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Keygen with IBMCA provider (using dh_pkey as template) */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_pkey, "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        goto out;
    }

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        goto out;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, "ibmca") != 0) {
        fprintf(stderr, "Context is not using the IBMCA provider, but '%s'\n",
               provname);
        goto out;
    }

    if (EVP_PKEY_keygen(ctx, &peer_pkey) <= 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == 7) {
            /* curve not supported => test passed */
            fprintf(stderr, "Group %s not supported by OpenSSL\n", name);
            ret = 1;
        } else {
            fprintf(stderr, "EVP_PKEY_keygen failed\n");
        }

        goto out;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Derive with IBMCA provider (no KDF) */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_pkey, "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed\n");
        goto out;
    }

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        goto out;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, "ibmca") != 0) {
        fprintf(stderr, "Context is not using the IBMCA provider, but '%s'\n",
               provname);
        goto out;
    }

    if (EVP_PKEY_derive_set_peer_ex(ctx, peer_pkey, 1) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer_ex failed\n");
        goto out;
    }

    keylen1 = sizeof(keybuf1);
    if (EVP_PKEY_derive(ctx, keybuf1, &keylen1) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed\n");
        goto out;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Derive with default provider (no KDF) */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_pkey, "provider=default");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed\n");
        goto out;
    }

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        goto out;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, "default") != 0) {
        fprintf(stderr, "Context is not using the default provider, but '%s'\n",
               provname);
        goto out;
    }

    if (EVP_PKEY_derive_set_peer_ex(ctx, peer_pkey, 1) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer_ex failed\n");
        goto out;
    }

    keylen2 = sizeof(keybuf2);
    if (EVP_PKEY_derive(ctx, keybuf2, &keylen2) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed\n");
        goto out;
    }

    if (keylen1 != keylen2 || memcmp(keybuf1, keybuf2, keylen1) != 0) {
        fprintf(stderr, "Derived keys are not equal\n");
        goto out;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Derive with IBMCA provider (X9_63 KDF) */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_pkey, "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed\n");
        goto out;
    }

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        goto out;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, "ibmca") != 0) {
        fprintf(stderr, "Context is not using the IBMCA provider, but '%s'\n",
               provname);
        goto out;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_type(ctx, EVP_PKEY_DH_KDF_X9_42) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_type failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_md(ctx, EVP_get_digestbyname("SHA256")) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_md failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, OBJ_nid2obj(NID_id_aes256_wrap)) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set0_dh_kdf_oid failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, sizeof(keybuf1)) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_outlen failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_set_peer_ex(ctx, peer_pkey, 1) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer_ex failed\n");
        goto out;
    }

    keylen1 = sizeof(keybuf1);
    if (EVP_PKEY_derive(ctx, keybuf1, &keylen1) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed\n");
        goto out;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Derive with default provider (X9_63 KDF) */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_pkey, "provider=default");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed\n");
        goto out;
    }

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        goto out;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, "default") != 0) {
        fprintf(stderr, "Context is not using the default provider, but '%s'\n",
               provname);
        goto out;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_type(ctx, EVP_PKEY_DH_KDF_X9_42) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_type failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_md(ctx, EVP_get_digestbyname("SHA256")) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_md failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, OBJ_nid2obj(NID_id_aes256_wrap)) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set0_dh_kdf_oid failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, sizeof(keybuf2)) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_dh_kdf_outlen failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_set_peer_ex(ctx, peer_pkey, 1) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer_ex failed\n");
        goto out;
    }

    keylen2 = sizeof(keybuf2);
    if (EVP_PKEY_derive(ctx, keybuf2, &keylen2) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed\n");
        goto out;
    }

    if (keylen1 != keylen2 || memcmp(keybuf1, keybuf2, keylen1) != 0) {
        fprintf(stderr, "Derived keys are not equal\n");
        goto out;
    }

    ret = 1;

 out:
    if (peer_pkey)
       EVP_PKEY_free(peer_pkey);
    if (dh_pkey)
       EVP_PKEY_free(dh_pkey);
    if (ctx)
       EVP_PKEY_CTX_free(ctx);

    ERR_print_errors_fp(stderr);

    return ret;
}

static const unsigned int required_ica_mechs[] = { RSA_ME };
static const unsigned int required_ica_mechs_len =
                        sizeof(required_ica_mechs) / sizeof(unsigned int);

int check_libica()
{
    unsigned int mech_len, i, k, found = 0;
    libica_func_list_element *mech_list = NULL;
    int rc;

    rc = ica_get_functionlist(NULL, &mech_len);
    if (rc != 0) {
        fprintf(stderr, "Failed to get function list from libica!\n");
        return 77;
    }

    mech_list = calloc(sizeof(libica_func_list_element), mech_len);
    if (mech_list == NULL) {
        fprintf(stderr, "Failed to allocate memory for function list!\n");
        return 77;
    }

    rc = ica_get_functionlist(mech_list, &mech_len);
    if (rc != 0) {
        fprintf(stderr, "Failed to get function list from libica!\n");
        free(mech_list);
        return 77;
    }

    for (i = 0; i < mech_len; i++) {
        for (k = 0; k < required_ica_mechs_len; k++) {
            if (mech_list[i].mech_mode_id == required_ica_mechs[k]) {
                if (mech_list[i].flags &
                    (ICA_FLAG_SW | ICA_FLAG_SHW | ICA_FLAG_DHW))
                    found++;
            }
        }
    }

    free(mech_list);

    if (found < required_ica_mechs_len) {
        fprintf(stderr,
               "Libica does not support the required algorithms, skipping.\n");
        return 77;
    }

    return 0;
}

int main(int argc, char **argv)
{
    static const struct testparams {
        int         nid;
        const char *name;
    } params[] = {
                {NID_ffdhe2048,        "NID_ffdhe2048"},
                {NID_ffdhe3072,        "NID_ffdhe3072"},
                {NID_ffdhe4096,        "NID_ffdhe4096"},
                {NID_ffdhe6144,        "NID_ffdhe6144"},
                {NID_ffdhe8192,        "NID_ffdhe8192"},
                {NID_modp_1536,        "NID_modp_1536"},
                {NID_modp_2048,        "NID_modp_2048"},
                {NID_modp_3072,        "NID_modp_3072"},
                {NID_modp_4096,        "NID_modp_4096"},
                {NID_modp_6144,        "NID_modp_6144"},
                {NID_modp_8192,        "NID_modp_8192"},
    };

    UNUSED(argc);
    UNUSED(argv);

    int ret = 0, i;
    /* First fix the environment */
    char *testcnf = getenv("IBMCA_OPENSSL_TEST_CONF");
    char *testpath = getenv("IBMCA_TEST_PATH");

    /* Do not overwrite a user-provided OPENSSL_CONF in the
       environment.  This allows us to execute this test also on an
       installation with a user-provided engine configuration. */
    if (testcnf && setenv("OPENSSL_CONF", testcnf, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_CONF environment variable!\n");
        return 77;
    }
    
    if (testpath && setenv("OPENSSL_MODULES", testpath, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_MODULES environment variable!\n");
        return 77;
    }

    ret = check_libica();
    if (ret != 0)
        return ret;

    setup();
    for (i = 0; i < (int)(sizeof(params) / sizeof(struct testparams)); ++i) {
        if (!check_dhkey(params[i].nid, params[i].name, "DH")) {
            fprintf(stderr, "Failure for %s (DH)\n", params[i].name);
            ret = 99;
        }
        if (!check_dhkey(params[i].nid, params[i].name, "DHX")) {
            fprintf(stderr, "Failure for %s (DHX)\n", params[i].name);
            ret = 99;
        }
    }
    return ret;
}
