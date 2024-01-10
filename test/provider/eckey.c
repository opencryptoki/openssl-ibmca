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
#include <dlfcn.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
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

int check_eckey(int nid, const char *name)
{
    int            ret = 0;
    size_t         siglen;
    unsigned char  sigbuf[1024];
    EVP_PKEY_CTX  *ctx = NULL;
    EVP_PKEY      *ec_pkey = NULL;
    EVP_PKEY      *peer_pkey = NULL;
    size_t         keylen1, keylen2;
    unsigned char  keybuf1[512], keybuf2[512];
    EVP_MD_CTX     *md_ctx = NULL;
    unsigned char  digest[32];
    const OSSL_PROVIDER *provider;
    const char *provname;

    memset(digest, 0, sizeof(digest));

    /* Keygen with IBMCA provider */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "?provider=ibmca");
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

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == 7) {
            /* curve not supported => test passed */
            fprintf(stderr, "Curve %s not supported by OpenSSL\n", name);
            ret = 1;
        } else {
            fprintf(stderr, "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed\n");
        }
        goto out;
    }

    if (EVP_PKEY_keygen(ctx, &ec_pkey) <= 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == 7) {
            /* curve not supported => test passed */
            fprintf(stderr, "Curve %s not supported by OpenSSL\n", name);
            ret = 1;
        } else {
            fprintf(stderr, "EVP_PKEY_keygen failed\n");
        }
        goto out;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Sign with IBMCA provider */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_init failed\n");
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

    siglen = sizeof(sigbuf);
    if (EVP_PKEY_sign(ctx, sigbuf, &siglen, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign failed\n");
        goto out;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Verify with default provider */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, "provider=default");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_init failed\n");
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

    ret = EVP_PKEY_verify(ctx, sigbuf, siglen, digest, sizeof(digest));
    if (ret == -1) {
        /* error */
        fprintf(stderr, "Failed to verify signature with %s (default provider)\n", name);
        goto out;
    } else if (ret == 0) {
        /* incorrect signature */
        fprintf(stderr, "Signature incorrect with %s (default provider)\n", name);
        goto out;
    } else {
        /* signature ok */
        printf("Signature correct with %s (default provider)\n", name);
        ret = 0;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Verify with IBMCA provider */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_init failed\n");
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

    ret = EVP_PKEY_verify(ctx, sigbuf, siglen, digest, sizeof(digest));
    if (ret == -1) {
        /* error */
        fprintf(stderr, "Failed to verify signature with %s (ibmca provider)\n", name);
        goto out;
    } else if (ret == 0) {
        /* incorrect signature */
        fprintf(stderr, "Signature incorrect with %s (ibmca provider)\n", name);
        goto out;
    } else {
        /* signature ok */
        printf("Signature correct with %s (ibmca provider)\n", name);
        ret = 0;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Digest-Sign with IBMCA provider */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto out;
    }

    if (EVP_DigestSignInit_ex(md_ctx, &ctx, "SHA256", NULL,
                               "?provider=ibmca", ec_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed\n");
        ctx = NULL;
        goto out;
    }

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        ctx = NULL;
        goto out;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, "ibmca") != 0) {
        fprintf(stderr, "Context is not using the IBMCA provider, but '%s'\n",
               provname);
        goto out;
    }

    if (EVP_DigestSignUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestSignUpdate (1) failed\n");
        ctx = NULL;
        goto out;
    }

    if (EVP_DigestSignUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestSignUpdate (2) failed\n");
        ctx = NULL;
        goto out;
    }

    siglen = sizeof(sigbuf);
    if (EVP_DigestSignFinal(md_ctx, sigbuf, &siglen) <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal failed\n");
        ctx = NULL;
        goto out;
    }

    EVP_MD_CTX_free(md_ctx);
    ctx = NULL;

    /* Digest-Verify with default provider */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto out;
    }

    if (EVP_DigestVerifyInit_ex(md_ctx, &ctx, "SHA256", NULL,
                                "provider=default", ec_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        ctx = NULL;
        goto out;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (1) failed\n");
        ctx = NULL;
        goto out;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (2) failed\n");
        ctx = NULL;
        goto out;
    }

    ret = EVP_DigestVerifyFinal(md_ctx, sigbuf, siglen);
    if (ret == -1) {
        /* error */
        fprintf(stderr, "Failed to digest-verify signature with %s (default provider)\n", name);
        ctx = NULL;
        goto out;
    } else if (ret == 0) {
        /* incorrect signature */
        fprintf(stderr, "Digest-Signature incorrect with %s (default provider)\n", name);
        ctx = NULL;
        goto out;
    } else {
        /* signature ok */
        printf("Digest-Signature correct with %s (default provider)\n", name);
        ret = 0;
    }

    EVP_MD_CTX_free(md_ctx);
    ctx = NULL;

    /* Digest-Verify with IBMCA provider */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto out;
    }

    if (EVP_DigestVerifyInit_ex(md_ctx, &ctx, "SHA256", NULL,
                                "?provider=ibmca", ec_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        ctx = NULL;
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

    if (EVP_DigestVerifyUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (1) failed\n");
        ctx = NULL;
        goto out;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (2) failed\n");
        ctx = NULL;
        goto out;
    }

    ret = EVP_DigestVerifyFinal(md_ctx, sigbuf, siglen);
    if (ret == -1) {
        /* error */
        fprintf(stderr, "Failed to digest-verify signature with %s (IBMCA provider)\n", name);
        ctx = NULL;
        goto out;
    } else if (ret == 0) {
        /* incorrect signature */
        fprintf(stderr, "Digest-Signature incorrect with %s (IBMCA provider)\n", name);
        ctx = NULL;
        goto out;
    } else {
        /* signature ok */
        printf("Digest-Signature correct with %s (IBMCA provider)\n", name);
        ret = 0;
    }

    EVP_MD_CTX_free(md_ctx);
    ctx = NULL;

    /* Digest-Sign with default provider */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto out;
    }

    if (EVP_DigestSignInit_ex(md_ctx, &ctx, "SHA256", NULL,
                               "provider=default", ec_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed\n");
        ctx = NULL;
        goto out;
    }

    provider = EVP_PKEY_CTX_get0_provider(ctx);
    if (provider == NULL) {
        fprintf(stderr, "Context is not a provider-context\n");
        ctx = NULL;
        goto out;
    }

    provname = OSSL_PROVIDER_get0_name(provider);
    if (strcmp(provname, "default") != 0) {
        fprintf(stderr, "Context is not using the default provider, but '%s'\n",
               provname);
        goto out;
    }

    if (EVP_DigestSignUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestSignUpdate (1) failed\n");
        ctx = NULL;
        goto out;
    }

    if (EVP_DigestSignUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestSignUpdate (2) failed\n");
        ctx = NULL;
        goto out;
    }

    siglen = sizeof(sigbuf);
    if (EVP_DigestSignFinal(md_ctx, sigbuf, &siglen) <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal failed\n");
        ctx = NULL;
        goto out;
    }

    EVP_MD_CTX_free(md_ctx);
    ctx = NULL;

    /* Digest-Verify with default provider */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto out;
    }

    if (EVP_DigestVerifyInit_ex(md_ctx, &ctx, "SHA256", NULL,
                                "provider=default", ec_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        ctx = NULL;
        goto out;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (1) failed\n");
        ctx = NULL;
        goto out;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (2) failed\n");
        ctx = NULL;
        goto out;
    }

    ret = EVP_DigestVerifyFinal(md_ctx, sigbuf, siglen);
    if (ret == -1) {
        /* error */
        fprintf(stderr, "Failed to digest-verify signature with %s (default provider)\n", name);
        ctx = NULL;
        goto out;
    } else if (ret == 0) {
        /* incorrect signature */
        fprintf(stderr, "Digest-Signature incorrect with %s (default provider)\n", name);
        ctx = NULL;
        goto out;
    } else {
        /* signature ok */
        printf("Digest-Signature correct with %s (default provider)\n", name);
        ret = 0;
    }

    EVP_MD_CTX_free(md_ctx);
    ctx = NULL;

    /* Digest-Verify with IBMCA provider */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto out;
    }

    if (EVP_DigestVerifyInit_ex(md_ctx, &ctx, "SHA256", NULL,
                                "?provider=ibmca", ec_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        ctx = NULL;
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

    if (EVP_DigestVerifyUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (1) failed\n");
        ctx = NULL;
        goto out;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate (2) failed\n");
        ctx = NULL;
        goto out;
    }

    ret = EVP_DigestVerifyFinal(md_ctx, sigbuf, siglen);
    if (ret == -1) {
        /* error */
        fprintf(stderr, "Failed to digest-verify signature with %s (IBMCA provider)\n", name);
        ctx = NULL;
        goto out;
    } else if (ret == 0) {
        /* incorrect signature */
        fprintf(stderr, "Digest-Signature incorrect with %s (IBMCA provider)\n", name);
        ctx = NULL;
        goto out;
    } else {
        /* signature ok */
        printf("Digest-Signature correct with %s (IBMCA provider)\n", name);
        ret  =0;
    }

    ctx = NULL;

    /* Keygen with IBMCA provider (using ec_pkey as template) */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, "?provider=ibmca");
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
            fprintf(stderr, "Curve %s not supported by OpenSSL\n", name);
            ret = 1;
        } else {
            fprintf(stderr, "EVP_PKEY_keygen failed\n");
        }
        goto out;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Derive with IBMCA provider (no KDF) */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, "?provider=ibmca");
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
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, "provider=default");
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
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, "?provider=ibmca");
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

    if (EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_X9_63) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_type failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, EVP_get_digestbyname("SHA256")) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_md failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, sizeof(keybuf1)) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_outlen failed\n");
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
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ec_pkey, "provider=default");
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

    if (EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_X9_63) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_type failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, EVP_get_digestbyname("SHA256")) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_md failed\n");
        goto out;
    }

    if (EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, sizeof(keybuf2)) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_ecdh_kdf_outlen failed\n");
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
    if (ec_pkey)
       EVP_PKEY_free(ec_pkey);
    if (ctx)
       EVP_PKEY_CTX_free(ctx);
    if (md_ctx)
        EVP_MD_CTX_free(md_ctx);

    ERR_print_errors_fp(stderr);

    return ret;
}

static const unsigned int required_ica_mechs[] = { EC_DH, EC_DSA_SIGN,
                                                   EC_DSA_VERIFY, EC_KGEN, };
static const unsigned int required_ica_mechs_len =
                        sizeof(required_ica_mechs) / sizeof(unsigned int);

typedef unsigned int (*ica_get_functionlist_t)(libica_func_list_element *,
                                               unsigned int *);

int check_libica()
{
    unsigned int mech_len, i, k, found = 0;
    libica_func_list_element *mech_list = NULL;
    void *ibmca_dso;
    ica_get_functionlist_t p_ica_get_functionlist;
    int rc;

    ibmca_dso = dlopen(LIBICA_NAME, RTLD_NOW);
    if (ibmca_dso == NULL) {
        fprintf(stderr, "Failed to load libica '%s'!\n", LIBICA_NAME);
        return 77;
    }

    p_ica_get_functionlist =
            (ica_get_functionlist_t)dlsym(ibmca_dso, "ica_get_functionlist");
    if (p_ica_get_functionlist == NULL) {
        fprintf(stderr, "Failed to get ica_get_functionlist from '%s'!\n",
                LIBICA_NAME);
        return 77;
    }

    rc = p_ica_get_functionlist(NULL, &mech_len);
    if (rc != 0) {
        fprintf(stderr, "Failed to get function list from libica!\n");
        return 77;
    }

    mech_list = calloc(sizeof(libica_func_list_element), mech_len);
    if (mech_list == NULL) {
        fprintf(stderr, "Failed to allocate memory for function list!\n");
        return 77;
    }

    rc = p_ica_get_functionlist(mech_list, &mech_len);
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
                {NID_X9_62_prime192v1, "NID_X9_62_prime192v1"},
                {NID_secp224r1,        "NID_secp224r1"},
                {NID_X9_62_prime256v1, "NID_X9_62_prime256v1"},
                {NID_secp384r1,        "NID_secp384r1"},
                {NID_secp521r1,        "NID_secp521r1"},
                {NID_brainpoolP160r1,  "NID_brainpoolP160r1"},
                {NID_brainpoolP192r1,  "NID_brainpoolP192r1"},
                {NID_brainpoolP224r1,  "NID_brainpoolP224r1"},
                {NID_brainpoolP256r1,  "NID_brainpoolP256r1"},
                {NID_brainpoolP320r1,  "NID_brainpoolP320r1"},
                {NID_brainpoolP384r1,  "NID_brainpoolP384r1"},
                {NID_brainpoolP512r1,  "NID_brainpoolP512r1"}
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
        if (!check_eckey(params[i].nid, params[i].name)) {
            fprintf(stderr, "Failure for %s\n", params[i].name);
            ret = 99;
        }
    }
    return ret;
}
