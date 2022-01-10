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

#define _GNU_SOURCE
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/err.h>

/* This is just a random number of threads to stimulate provider configuration. */
#define DEFAULT_MAX_THREADS 20


void setup(void)
{
    OPENSSL_load_builtin_modules();

    CONF_modules_load_file(NULL, NULL,
                           CONF_MFLAGS_DEFAULT_SECTION|
                           CONF_MFLAGS_IGNORE_MISSING_FILE);
}

static int do_sign_verify(EVP_PKEY *eckey)
{
    int            ret = 0, i;
    EVP_PKEY_CTX  *pctx = NULL;
    size_t         siglen;
    unsigned char  sigbuf[1024];
    unsigned char  digest[32];

    memset(digest, 0, sizeof(digest));

    for (i = 0; i < 100; i++) {

        /* Sign with IBMCA provider */
        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, eckey, "?provider=ibmca");
        if (pctx == NULL) {
            fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
            goto out;
        }

        if (EVP_PKEY_sign_init(pctx) <= 0) {
            fprintf(stderr, "EVP_PKEY_sign_init failed\n");
            goto out;
        }

        siglen = sizeof(sigbuf);
        if (EVP_PKEY_sign(pctx, sigbuf, &siglen, digest, sizeof(digest)) <= 0) {
            fprintf(stderr, "EVP_PKEY_sign failed\n");
            goto out;
        }

        EVP_PKEY_CTX_free(pctx);

        /* Verify with IBMCA provider */
        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, eckey, "?provider=ibmca");
        if (pctx == NULL) {
            fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed\n");
            goto out;
        }

        if (EVP_PKEY_verify_init(pctx) <= 0) {
            fprintf(stderr, "EVP_PKEY_verify_init failed\n");
            goto out;
        }

        ret = EVP_PKEY_verify(pctx, sigbuf, siglen, digest, sizeof(digest));
        if (ret == -1) {
            /* error */
            fprintf(stderr, "Failed to verify signature\n");
            ret = 0;
        } else if (ret == 0) {
            /* incorrect signature */
            fprintf(stderr, "Signature incorrect\n");
            ret = 0;
        } else {
            /* signature ok */
            ret = 1;
        }

        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;
    }

 out:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);

    ERR_print_errors_fp(stderr);
    return ret;
}

static void *threadfn(void *arg) {
    unsigned long res = 0;
    EVP_PKEY *eckey = arg;
    if (do_sign_verify(eckey) != 1) {
        res = 1;
    }
    return (void *)res;
}

int main(int argc, char **argv)
{
    pthread_t *threads;
    unsigned long int i, maxthreads = 0, errors = 0;
    int c;
    pthread_t me;
    EVP_PKEY *eckey = NULL;
    EVP_PKEY_CTX *pctx = NULL;

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

    // arg parse
    while (1) {
        int option_index;
        static struct option long_options[] = {
            { "threads", required_argument, 0, 't'},
            { 0,         0,                 0, 0  }
        };

        c = getopt_long(argc, argv, "t:", long_options, &option_index);
        if (c == -1) {
            break;
        } else if (c == 't') {
            maxthreads = strtoul(optarg, NULL, 0);
        } else {
            fprintf(stderr, "USAGE: %s [-t|--threads <num>]\n", argv[0]);
            fprintf(stderr, "where\t<num> specifies the number of threads to use (default: 20)\n");
            return 1;
        }
    }

    setup();

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "?provider=ibmca");
    if (pctx == NULL) {
        fprintf(stderr, "Failed to create PKEY_CTX\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    /*
     * Generate an EC key with a curve that libica does not support, so that
     * it uses SW-fallbacks, and thus stresses the fallback pkey cache
     */
    if (EVP_PKEY_keygen_init(pctx) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) != 1 ||
        EVP_PKEY_keygen(pctx, &eckey) != 1) {
        fprintf(stderr, "keygen initialization failed\n");
        EVP_PKEY_CTX_free(pctx);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (eckey == NULL) {
        /* error */
        fprintf(stderr, "Failed to create ec key for NID_secp256k1\n");
        EVP_PKEY_CTX_free(pctx);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    EVP_PKEY_CTX_free(pctx);

    if (maxthreads == 0)
        maxthreads = DEFAULT_MAX_THREADS;
    threads = calloc(sizeof(pthread_t), maxthreads);
    if (threads == NULL) {
        fprintf(stderr, "Thread array allocation failed!\n");
        return 1;
    }

    me = pthread_self();
    // Start threads
    for (i = 0; i < maxthreads; ++i) {
        int s = pthread_create(&threads[i], NULL, &threadfn, eckey);
        if (s != 0) {
            fprintf(stderr, "Failed to create thread %lu: %s\n", i, strerror(s));
            threads[i] = me;
        }
    }
    // Now join threads
    for (i = 0; i < maxthreads; ++i) {
        if (!pthread_equal(threads[i], me)) {
            void *retval;
            int s = pthread_join(threads[i], &retval);
            if (s != 0) {
                fprintf(stderr, "Failed to join thread %lu: %s\n", i, strerror(s));
            } else if ((unsigned long)retval != 0) {
                fprintf(stderr, "Error in thread %lu\n", i);
                ++errors;
            }
        }
    }
    free(threads);
    EVP_PKEY_free(eckey);
    return errors ? 99 : 0;
}
