#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/engine.h>

void setup(void)
{
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
}

int initwithlib(ENGINE *e, const char *lib, int checkexists, int expectedinitval)
{
    void *hdl;

    if (checkexists) {
        hdl = dlopen(lib, RTLD_LAZY);
        if (hdl == NULL) {
            fprintf(stderr, "Skipping initialization with non-existent library \"%s\"\n", lib);
            return 1;
        }
        dlclose(hdl);
    }
    if (ENGINE_ctrl_cmd_string(e, "libica", lib, 0) != 1) {
        fprintf(stderr, "\"libica\" ctrl failed to set \"%s\" on un-initialized ibmca!\n", lib);
        return 0;
    }
    if (ENGINE_init(e) != expectedinitval) {
        fprintf(stderr, "ibmca unexpted initialization result for libica=%s (expected: %d)!\n",
                lib, expectedinitval);
        return 0;
    }
    ENGINE_finish(e);
    return 1;
}

int testctrl(void)
{
    ENGINE *engine;
    int ret = 99, i;
    static const struct testparams {
        const char *lib;
        int checkexists;
        int expectedinitval;
    } params[] = {
                  {"doesnotexist",    0, 0},
                  {"libica.so.4",     1, 1},
                  {"libica-cex.so.4", 1, 1}
    };

    engine = ENGINE_by_id("ibmca");
    if (engine == NULL) {
        fprintf(stderr, "ibmca engine not loaded!  Skipping...\n");
        return 77;
    }
    if (!ENGINE_init(engine)) {
        fprintf(stderr, "ibmca engine initialization failed!\n");
        goto out;
    }
    /* Engine ctrl "libica" only works if engine is not initialized. */
    if (ENGINE_ctrl_cmd_string(engine, "libica", "doesnotexist", 0) == 1) {
        fprintf(stderr, "\"libica\" ctrl succeeded despite initialized ibmca!\n");
        goto out;
    }
    ENGINE_finish(engine);
    ret = 0;
    for (i = 0; i < sizeof(params) / sizeof(struct testparams); ++i) {
        if (!initwithlib(engine, params[i].lib, params[i].checkexists, params[i].expectedinitval))
            ret = 99;
    }
    /* We have to restore the correct libica and init ibmca here to
       restore the double free above.  This might leak resources, but
       should be okay for a test. */
    ENGINE_ctrl_cmd_string(engine, "libica", LIBICA_SHARED_LIB, 0);
    ENGINE_init(engine);
 out:
    ENGINE_free(engine);
    return ret;
}

int main(int argc, char **argv)
{
    /* First fix the environment */
    char *testcnf = getenv("IBMCA_OPENSSL_TEST_NOINIT_CONF");

    /* Do not overwrite a user-provided OPENSSL_CONF in the
       environment.  This allows us to execute this test also on an
       installation with a user-provided engine configuration. */
    if (testcnf && setenv("OPENSSL_CONF", testcnf, 0)) {
        fprintf(stderr, "Failed to set OPENSSL_CONF environment variable!\n");
        return 77;
    }
    
    setup();
    return testctrl();
}
