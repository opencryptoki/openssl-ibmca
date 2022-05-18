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
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
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

int check_rsakey(int bits, const char *algo, const char *name)
{
    int            ret = 0;
    size_t         siglen;
    unsigned char  sigbuf[1024];
    EVP_PKEY_CTX   *ctx = NULL;
    EVP_PKEY       *rsa_pkey = NULL;
    EVP_MD_CTX     *md_ctx = NULL;
    unsigned char  digest[32];
    const OSSL_PROVIDER *provider;
    const char *provname;

    memset(digest, 0, sizeof(digest));

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

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits failed\n");
        goto out;
    }

    if (strcmp(algo, "RSA-PSS") == 0) {
        /* generate a PSS restricted RSA-PSS key */
        if (EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, "SHA256", NULL) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_keygen_md_name failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, "SHA256") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen failed\n");
            goto out;
        }
    }

    if (EVP_PKEY_keygen(ctx, &rsa_pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed\n");
        goto out;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Sign with IBMCA provider */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_init failed\n");
        goto out;
    }

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "?provider=ibmca") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            goto out;
        }
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
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, "provider=default");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_init failed\n");
        goto out;
    }

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "provider=default") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            goto out;
        }
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
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rsa_pkey, "?provider=ibmca");
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
        goto out;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_verify_init failed\n");
        goto out;
    }

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "provider=default") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            goto out;
        }
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
                               "?provider=ibmca", rsa_pkey, NULL) == 0) {
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

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "?provider=ibmca") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            ctx = NULL;
            goto out;
        }
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
                                "provider=default", rsa_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        ctx = NULL;
        goto out;
    }

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "?provider=ibmca") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            ctx = NULL;
            goto out;
        }
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
                                "?provider=ibmca", rsa_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        ctx = NULL;
        goto out;
    }

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "?provider=ibmca") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            ctx = NULL;
            goto out;
        }
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
                               "provider=default", rsa_pkey, NULL) == 0) {
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

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "?provider=ibmca") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            ctx = NULL;
            goto out;
        }
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
                                "provider=default", rsa_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        ctx = NULL;
        goto out;
    }

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "?provider=ibmca") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            ctx = NULL;
            goto out;
        }
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
                                "?provider=ibmca", rsa_pkey, NULL) == 0) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        ctx = NULL;
        goto out;
    }

    if (strcmp(algo, "RSA-PSS") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256",
                                              "?provider=ibmca") <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md_name failed\n");
            ctx = NULL;
            goto out;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 24) <= 0) {
            fprintf(stderr, "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
            ctx = NULL;
            goto out;
        }
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

    ctx = NULL;

    ret = 1;

 out:
    if (rsa_pkey)
       EVP_PKEY_free(rsa_pkey);
    if (ctx)
       EVP_PKEY_CTX_free(ctx);
    if (md_ctx)
        EVP_MD_CTX_free(md_ctx);

    ERR_print_errors_fp(stderr);

    return ret;
}

static const unsigned int required_ica_mechs[] = { RSA_ME,  RSA_CRT };
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
        int         bits;
        const char *algo;
        const char *name;
    } params[] = {
                {512, "RSA", "RSA-512"},
                {1024, "RSA", "RSA-1024"},
                {2048, "RSA", "RSA-2048"},
                {4096, "RSA", "RSA-4096"},
                {512, "RSA-PSS", "RSA-PSS-512"},
                {1024, "RSA-PSS", "RSA-PSS-1024"},
                {2048, "RSA-PSS", "RSA-PSS-2048"},
                {4096, "RSA-PSS", "RSA-PSS-4096"},
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
        if (!check_rsakey(params[i].bits, params[i].algo, params[i].name)) {
            fprintf(stderr, "Failure for %s\n", params[i].name);
            ret = 99;
        }
    }
    return ret;
}
