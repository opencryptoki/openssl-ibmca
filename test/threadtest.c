#define _GNU_SOURCE
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

/* This is just a random number of threads to stimulate engine configuration. */
#define DEFAULT_MAX_THREADS 20

static int setup()
{
    ENGINE        *engine;
    EVP_PKEY_CTX  *pctx = NULL;

    OPENSSL_load_builtin_modules();

    ENGINE_load_builtin_engines();

    /* CONF_MFLAGS_DEFAULT_SECTION introduced some time between 0.9.8b and
       0.9.8e */
#ifndef CONF_MFLAGS_DEFAULT_SECTION
#define CONF_MFLAGS_DEFAULT_SECTION 0x0
#endif

    CONF_modules_load_file(NULL, NULL,
                           CONF_MFLAGS_DEFAULT_SECTION|
                           CONF_MFLAGS_IGNORE_MISSING_FILE);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) &&  \
    !defined(LIBRESSL_VERSION_NUMBER)
    /* OpenSSL 1.1.0+ takes care of initialization itself */
#else
    OpenSSL_add_all_algorithms();
#endif

    engine = ENGINE_by_id("ibmca");
    pctx = EVP_PKEY_CTX_new_id(NID_X25519, engine);
    if (pctx == NULL) {
        return 0;
    }
    EVP_PKEY_CTX_free(pctx);

    return 1;
}

static int check_globals()
{
    int            ret = 0;
    EVP_PKEY      *eckey = NULL;
    ENGINE        *engine;
    EVP_PKEY_CTX  *pctx = NULL;

    engine = ENGINE_by_id("ibmca");
    if (engine == NULL) {
        fprintf(stderr, "Failed to retrieve ibmca engine\n");
        goto out;
    }
    pctx = EVP_PKEY_CTX_new_id(NID_X25519, engine);
    if (pctx == NULL) {
        fprintf(stderr, "Failed to create PKEY_CTX\n");
        return 0;
    }
    if (EVP_PKEY_keygen_init(pctx) != 1 ||
        EVP_PKEY_keygen(pctx, &eckey) != 1) {
        fprintf(stderr, "keygen initialization failed\n");
        goto out;
    }
    if (eckey == NULL) {
        /* error */
        fprintf(stderr, "Failed to create ec key for X25519\n");
        goto out;
    }
    ret = 1;
 out:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (eckey)
        EVP_PKEY_free(eckey);
    return ret;
}

static void *threadfn(void *arg) {
    unsigned long res = 0;
    (void) arg;
    if (check_globals() != 1) {
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
    
    /* First fix the environment */
    char *testcnf = getenv("IBMCA_OPENSSL_TEST_CONF");

    /* Do not overwrite a user-provided OPENSSL_CONF in the
       environment.  This allows us to execute this test also on an
       installation with a user-provided engine configuration. */
    if (testcnf && setenv("OPENSSL_CONF", testcnf, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_CONF environment variable!\n");
        return 77;
    }

    // arg parse
    while (1) {
        int option_index;
        static struct option long_options[] =
            {
             {"threads", required_argument, 0, 't'},
             {0,         0,                 0, 0  }
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

    if (maxthreads == 0)
        maxthreads = DEFAULT_MAX_THREADS;
    threads = calloc(sizeof(pthread_t), maxthreads);
    if (threads == NULL) {
        fprintf(stderr, "Thread array allocation failed!\n");
        return 1;
    }

    if (setup() != 1) {
        fprintf(stderr, "Failed to set up test.  Skipping...\n");
        return 77;
    }
    
    me = pthread_self();
    // Start threads
    for (i = 0; i < maxthreads; ++i) {
        int s = pthread_create(&threads[i], NULL, &threadfn, NULL);
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
    return errors ? 99 : 0;
}
