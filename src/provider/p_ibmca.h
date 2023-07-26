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
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>

#include <ica_api.h>

#include <openssl/provider.h>
#include <openssl/ec.h>

/* Environment variable name to enable debug */
#define IBMCA_DEBUG_ENVVAR          "IBMCA_DEBUG"
#define IBMCA_DEBUG_PATH_ENVVAR     "IBMCA_DEBUG_PATH"

/* IBMCA provider configuration key words */
#define IBMCA_CONF_DEBUG            "debug"
#define IBMCA_CONF_DEBUG_PATH       "debug-path"
#define IBMCA_CONF_ALGORITHMS       "algorithms"
#define IBMCA_CONF_FIPS             "fips"
#define IBMCA_CONF_FALLBACK_PROPS   "fallback-properties"

/* IBMCA provider configuration key words for algorithms */
#define IBMCA_CONFIG_ALGO_ALL       "ALL"
#define IBMCA_CONFIG_ALGO_RSA       "RSA"
#define IBMCA_CONFIG_ALGO_EC        "EC"
#define IBMCA_CONFIG_ALGO_DH        "DH"

/* IBMCA provider context */
struct ibmca_prov_ctx {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    const char *name;
    const char *openssl_version;
    const char *module_filename;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
    OSSL_FUNC_core_new_error_fn *c_new_error;
    OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
    OSSL_FUNC_core_vset_error_fn *c_vset_error;
    OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
    OSSL_FUNC_core_get_params_fn *c_get_params;
    OSSL_FUNC_CRYPTO_zalloc_fn *c_zalloc;
    OSSL_FUNC_CRYPTO_malloc_fn *c_malloc;
    OSSL_FUNC_CRYPTO_realloc_fn *c_realloc;
    OSSL_FUNC_CRYPTO_free_fn *c_free;
    OSSL_FUNC_CRYPTO_clear_free_fn *c_clear_free;
    OSSL_FUNC_CRYPTO_secure_malloc_fn *c_secure_malloc;
    OSSL_FUNC_CRYPTO_secure_zalloc_fn *c_secure_zalloc;
    OSSL_FUNC_CRYPTO_secure_free_fn *c_secure_free;
    OSSL_FUNC_CRYPTO_secure_clear_free_fn *c_secure_clear_free;
    OSSL_FUNC_OPENSSL_cleanse_fn *c_cleanse;
    bool debug;
    const char *debug_path;
    FILE *debug_file;
    pid_t debug_pid;
    pthread_mutex_t debug_mutex;
    bool fips;
    bool fips_configured;
    bool *algo_enabled;
    char *property_def;
    const char *fallback_props_conf;
    char *fallback_property_query;
    ica_adapter_handle_t ica_adapter;
    int ica_fips_status;
    OSSL_ALGORITHM *algorithms[OSSL_OP__HIGHEST + 1];
};

/* IBMCA provider key */

struct ibmca_pss_params {
     int digest_nid;
     int mgf_nid;
     int mgf_digest_nid;
     int saltlen;
     bool restricted;
};

struct ibmca_ffc_params {
    int group_nid;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g; /* DHX only */
    BIGNUM *cofactor; /* DHX only */
    int length;
    unsigned char *seed;
    size_t seed_len;
    int gindex;
    int pcounter;
    int hindex;
    unsigned int validate_pq : 1;
    unsigned int validate_g : 1;
    unsigned int validate_legacy : 1;
    const char *mdname;
    const char *mdprops;
};

struct ibmca_key {
    const struct ibmca_prov_ctx *provctx;
    unsigned int ref_count;
    int type; /* EVP_PKEY_xxx types */
    void (*free_cb)(struct ibmca_key *key);
    int (*dup_cb)(const struct ibmca_key *key, struct ibmca_key *new_key);
    size_t (*get_max_param_size)(const struct ibmca_key *key);
    OSSL_FUNC_keymgmt_export_fn *export;
    OSSL_FUNC_keymgmt_import_fn *import;
    OSSL_FUNC_keymgmt_has_fn *has;
    OSSL_FUNC_keymgmt_match_fn *match;
    const char *algorithm;
    EVP_PKEY *fallback_pkey_cache;
    pthread_rwlock_t fallback_pkey_cache_lock;
    union {
        struct {
            size_t bits;
            size_t keylength;
            ica_rsa_key_crt_t private_crt;
            ica_rsa_key_mod_expo_t private_me;
            ica_rsa_key_mod_expo_t public;
            struct ibmca_pss_params pss; /* For type EVP_PKEY_RSA_PSS only */
            BN_BLINDING *blinding;
            BN_BLINDING *mt_blinding;
            pthread_rwlock_t blinding_lock;
            BN_MONT_CTX *blinding_mont_ctx;
            BN_ULONG blinding_mont_ctx_n0;
        } rsa; /* For type EVP_PKEY_RSA and EVP_PKEY_RSA_PSS */
        struct {
            int curve_nid;
            point_conversion_form_t format;
            bool include_pub;
            size_t prime_size;
            ICA_EC_KEY *key;
            struct {
                BIGNUM *x;
                BIGNUM *y;
                BIGNUM *d;
            } fallback;
        } ec; /* For type EVP_PKEY_EC */
        struct {
            BIGNUM *pub;
            BIGNUM *priv;
            struct ibmca_ffc_params ffc_params;
        } dh; /* For type EVP_PKEY_DH and EVP_PKEY_DHX */
    };
};

void ibmca_keymgmt_upref(struct ibmca_key *key);
unsigned int ibmca_keymgmt_downref(struct ibmca_key *key);
struct ibmca_key *ibmca_keymgmt_new(const struct ibmca_prov_ctx *provctx,
                                    int type, const char *algorithm,
                                    void (*free_cb)(struct ibmca_key *key),
                                    int (*dup_cb)(const struct ibmca_key *key,
                                                  struct ibmca_key *new_key),
                                    size_t (*get_max_param_size)(
                                                const struct ibmca_key *key),
                                    OSSL_FUNC_keymgmt_export_fn *export,
                                    OSSL_FUNC_keymgmt_import_fn *import,
                                    OSSL_FUNC_keymgmt_has_fn *has,
                                    OSSL_FUNC_keymgmt_match_fn *match);
int ibmca_keymgmt_match(const struct ibmca_key *key1,
                        const struct ibmca_key *key2);
struct ibmca_op_ctx *ibmca_keymgmt_gen_init(
                                    const struct ibmca_prov_ctx *provctx,
                                    int type,
                                    void (*free_cb)
                                        (struct ibmca_op_ctx *ctx),
                                    int (*dup_cb)
                                        (const struct ibmca_op_ctx *ctx,
                                         struct ibmca_op_ctx *new_ctx));
bool ibmca_keymgmt_rsa_pub_valid(const ica_rsa_key_mod_expo_t *public);
bool ibmca_keymgmt_rsa_priv_crt_valid(const ica_rsa_key_crt_t *private_crt);
bool ibmca_keymgmt_rsa_priv_me_valid(const ica_rsa_key_mod_expo_t *private_me);

OSSL_FUNC_keymgmt_free_fn ibmca_keymgmt_free;
OSSL_FUNC_keymgmt_dup_fn ibmca_keymgmt_dup;
OSSL_FUNC_keymgmt_gen_cleanup_fn ibmca_keymgmt_gen_cleanup;
OSSL_FUNC_keymgmt_load_fn ibmca_keymgmt_load;

/* IBMCA provider operation context */
struct ibmca_op_ctx {
    const struct ibmca_prov_ctx *provctx;
    int type; /* EVP_PKEY_xxx types */
    const char *propq;
    struct ibmca_key *key;
    int operation;
    void (*free_cb)(struct ibmca_op_ctx *ctx);
    int (*dup_cb)(const struct ibmca_op_ctx *ctx, struct ibmca_op_ctx *new_ctx);
    unsigned char *tbuf;
    size_t tbuf_len;
    union {
        union {
            struct {
                size_t bits;
                BIGNUM *pub_exp;
                struct ibmca_pss_params pss; /* For EVP_PKEY_RSA_PSS only */
            } gen; /* For operation EVP_PKEY_OP_KEYGEN */
            struct {
                int pad_mode;
                EVP_MD *mgf1_md;
                EVP_MD *oaep_md;
                unsigned char *oaep_label;
                size_t oaep_labellen;
                unsigned int tls_clnt_version;
                unsigned int tls_alt_version;
                unsigned int implicit_rejection;
            } cipher; /* For operation EVP_PKEY_OP_ENCRYPT/DECRYPT */
            struct {
                int pad_mode;
                EVP_MD *md;
                bool set_md_allowed;
                EVP_MD *mgf1_md;
                int saltlen;
                struct ibmca_pss_params pss;
                EVP_MD_CTX *md_ctx;
            } signature; /* For operation EVP_PKEY_OP_SIGN/VERIFY */
        } rsa; /* For type EVP_PKEY_RSA and EVP_PKEY_RSA_PSS */
        union {
            struct {
                int selection;
                int curve_nid;
                point_conversion_form_t format;
            } gen; /* For operation EVP_PKEY_OP_KEYGEN */
            struct {
                EVP_MD *md;
                bool set_md_allowed;
                size_t md_size;
                EVP_MD_CTX *md_ctx;
            } signature; /* For operation EVP_PKEY_OP_SIGN/VERIFY */
            struct {
                struct ibmca_key *peer_key;
                int kdf_type; /* EVP_PKEY_ECDH_KDF_xxx */
                EVP_MD *kdf_md;
                size_t kdf_outlen;
                unsigned char *kdf_ukm;
                size_t kdf_ukmlen;
            } derive;/* For operation EVP_PKEY_OP_DERIVE */
        } ec; /* For type EVP_PKEY_EC */
        union {
            struct {
                EVP_PKEY_CTX *pctx;
                int selection;
                int priv_len;
            } gen; /* For operation EVP_PKEY_OP_KEYGEN */
            struct {
                struct ibmca_key *peer_key;
                bool pad;
                int kdf_type; /* EVP_PKEY_DH_KDF_xxx */
                EVP_MD *kdf_md;
                size_t kdf_outlen;
                unsigned char *kdf_ukm;
                size_t kdf_ukmlen;
                char *kdf_cekalg;
            } derive;/* For operation EVP_PKEY_OP_DERIVE */
        } dh; /* For type EVP_PKEY_DH and EVP_PKEY_DHX */
    };
};

struct ibmca_op_ctx *ibmca_op_newctx(const struct ibmca_prov_ctx *provctx,
                                     const char *propq, int type,
                                     void (*free_cb)(struct ibmca_op_ctx *ctx),
                                     int (*dup_cb)
                                               (const struct ibmca_op_ctx *ctx,
                                                struct ibmca_op_ctx *new_ctx));
int ibmca_op_init(struct ibmca_op_ctx *ctx, struct ibmca_key *key,
                  int operation);
int ibmca_op_alloc_tbuf(struct ibmca_op_ctx *ctx, size_t tbuf_len);

int ibmca_digest_signverify_update(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                                   const unsigned char *data, size_t datalen);
int ibmca_digest_sign_final(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                            OSSL_FUNC_signature_sign_fn *sign_func,
                            unsigned char *sig, size_t *siglen, size_t sigsize);
int ibmca_digest_verify_final(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                              OSSL_FUNC_signature_verify_fn *verify_func,
                              const unsigned char *sig, size_t siglen);
int ibmca_get_ctx_md_params(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                            OSSL_PARAM *params);
int ibmca_set_ctx_md_params(struct ibmca_op_ctx *ctx, EVP_MD_CTX *md_ctx,
                            const OSSL_PARAM params[]);
const OSSL_PARAM *ibmca_gettable_ctx_md_params(const struct ibmca_op_ctx *ctx,
                                               const EVP_MD *md);
const OSSL_PARAM *ibmca_settable_ctx_md_params(const struct ibmca_op_ctx *ctx,
                                               const EVP_MD *md);

OSSL_FUNC_asym_cipher_freectx_fn ibmca_op_freectx;
OSSL_FUNC_asym_cipher_dupctx_fn ibmca_op_dupctx;

/* Macros for calling core functions */
#define P_ZALLOC(prov_ctx, size)                    \
        (prov_ctx)->c_zalloc((size), __FILE__ , __LINE__)
#define P_MALLOC(prov_ctx, size)                    \
        (prov_ctx)->c_malloc((size), __FILE__ , __LINE__)
#define P_REALLOC(prov_ctx, ptr, size)              \
        (prov_ctx)->c_realloc((ptr), (size), __FILE__ , __LINE__)
#define P_FREE(prov_ctx, ptr)                       \
        (prov_ctx)->c_free((ptr), __FILE__ , __LINE__)
#define P_CLEAR_FREE(prov_ctx, ptr, size)           \
        (prov_ctx)->c_clear_free((ptr), (size), __FILE__ , __LINE__)
#define P_SECURE_MALLOC(prov_ctx, size)             \
        (prov_ctx)->c_secure_malloc((size), __FILE__ , __LINE__)
#define P_SECURE_ZALLOC(prov_ctx, size)             \
        (prov_ctx)->c_secure_zalloc((size), __FILE__ , __LINE__)
#define P_SECURE_FREE(prov_ctx, ptr)                \
        (prov_ctx)->c_secure_free((ptr), __FILE__ , __LINE__)
#define P_SECURE_CLEAR_FREE(prov_ctx, ptr, size)    \
        (prov_ctx)->c_secure_clear_free((ptr), (size), __FILE__ , __LINE__)
#define P_CLEANSE(prov_ctx, ptr, size)              \
        (prov_ctx)->c_cleanse((ptr), (size))
#define P_STRDUP(prov_ctx, str)                     \
        ibmca_strdup((prov_ctx), (str), __FILE__ , __LINE__)
#define P_MEMDUP(prov_ctx, data, size)              \
        ibmca_memdup((prov_ctx), (data), (size), __FILE__ , __LINE__)
#define P_SECURE_MEMDUP(prov_ctx, data, size)       \
        ibmca_secure_memdup((prov_ctx), (data), (size), __FILE__ , __LINE__)

char *ibmca_strdup(const struct ibmca_prov_ctx *provctx, const char *str,
                   const char* file, int line);
void *ibmca_memdup(const struct ibmca_prov_ctx *provctx, const void *data,
                   size_t size, const char* file, int line);
void *ibmca_secure_memdup(const struct ibmca_prov_ctx *provctx,
                          const void *data, size_t size,
                          const char* file, int line);

EVP_PKEY_CTX *ibmca_new_fallback_pkey_ctx(const struct ibmca_prov_ctx *provctx,
                                          EVP_PKEY *pkey,
                                          const char *algorithm);
EVP_PKEY *ibmca_new_fallback_pkey(struct ibmca_key *key);
void ibmca_clean_fallback_pkey_cache(struct ibmca_key *key);
int ibmca_import_from_fallback_pkey(struct ibmca_key *key, const EVP_PKEY *pkey,
                                    int selection);
int ibmca_check_fallback_provider(const struct ibmca_prov_ctx *provctx,
                                  EVP_PKEY_CTX *pctx);

struct ibmca_keygen_cb_data {
    OSSL_CALLBACK *osslcb;
    void *cbarg;
};

int ibmca_keygen_cb(EVP_PKEY_CTX *ctx);

int ibmca_param_build_set_bn(const struct ibmca_prov_ctx *provctx,
                             OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                             const char *key, const BIGNUM *bn);
int ibmca_param_build_set_int(const struct ibmca_prov_ctx *provctx,
                              OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                              const char *key, int val);
int ibmca_param_build_set_uint(const struct ibmca_prov_ctx *provctx,
                               OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                               const char *key, unsigned int val);
int ibmca_param_build_set_utf8(const struct ibmca_prov_ctx *provctx,
                               OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                               const char *key, const char *str);
int ibmca_param_build_set_octet_ptr(const struct ibmca_prov_ctx *provctx,
                                    OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                    const char *key, const void *val,
                                    size_t len);
int ibmca_param_build_set_size_t(const struct ibmca_prov_ctx *provctx,
                                 OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                 const char *key, size_t val);
int ibmca_param_get_bn(const struct ibmca_prov_ctx *provctx,
                       const OSSL_PARAM params[], const char *key, BIGNUM **bn);
int ibmca_param_get_int(const struct ibmca_prov_ctx *provctx,
                        const OSSL_PARAM params[], const char *key, int *val);
int ibmca_param_get_uint(const struct ibmca_prov_ctx *provctx,
                         const OSSL_PARAM params[], const char *key,
                         unsigned int *val);
int ibmca_param_get_size_t(const struct ibmca_prov_ctx *provctx,
                           const OSSL_PARAM params[], const char *key,
                           size_t *val);
int ibmca_param_get_utf8(const struct ibmca_prov_ctx *provctx,
                         const OSSL_PARAM params[], const char *key,
                         const char **str);
int ibmca_param_get_octet_string(const struct ibmca_prov_ctx *provctx,
                                 const OSSL_PARAM params[], const char *key,
                                 void **val, size_t *len);

/* Debug and error handling functions and macros */
void ibmca_debug_print(struct ibmca_prov_ctx *provctx, const char *func,
                       const char *fmt, ...);

#define ibmca_debug(ctx, fmt...)                                       \
        do {                                                           \
            if ((ctx)->debug)                                          \
                ibmca_debug_print((struct ibmca_prov_ctx*)(ctx),       \
                                  __func__, fmt);                      \
        } while (0)

#define ibmca_debug_ctx(ctx, fmt...)    ibmca_debug((ctx), fmt)
#define ibmca_debug_key(key, fmt...)    ibmca_debug((key)->provctx, fmt)
#define ibmca_debug_op_ctx(ctx, fmt...) ibmca_debug((ctx)->provctx, fmt)

void ibmca_put_error(const struct ibmca_prov_ctx *provctx, int err,
                     const char *file, int line, const char *func,
                     char *fmt, ...);

#define put_error_ctx(ctx, err, fmt...)             \
        do {                                        \
            ibmca_debug_ctx((ctx), "ERROR: "fmt);   \
            ibmca_put_error((ctx), (err), __FILE__, \
                __LINE__, __func__, fmt);           \
        } while (0)
#define put_error_key(key, err, fmt...)             \
        put_error_ctx((key)->provctx, (err), fmt)
#define put_error_op_ctx(ctx, err, fmt...)          \
        put_error_ctx((ctx)->provctx, (err), fmt)

#define IBMCA_ERR_INTERNAL_ERROR                1
#define IBMCA_ERR_MALLOC_FAILED                 2
#define IBMCA_ERR_INVALID_PARAM                 3
#define IBMCA_ERR_CONFIGURATION                 4
#define IBMCA_ERR_LIBICA_FAILED                 5
#define IBMCA_ERR_SIGNATURE_BAD                 6
#define IBMCA_ERR_EC_CURVE_NOT_SUPPORTED        7

#define UNUSED(var)                             ((void)(var))

/* Algorithm support definitions */

struct ibmca_mech_capability {
    const char *capability;
    const OSSL_PARAM **details;
};

extern const OSSL_ALGORITHM ibmca_rsa_keymgmt[];
extern const OSSL_ALGORITHM ibmca_rsa_asym_cipher[];
extern const OSSL_ALGORITHM ibmca_rsa_signature[];

#define IBMCA_RSA_DEFAULT_BITS              2048
#define IBMCA_RSA_DEFAULT_PUB_EXP           65537L
#define IBMCA_RSA_DEFAULT_DIGEST            NID_sha256
#define IBMCA_RSA_PSS_DEFAULT_DIGEST        NID_sha1
#define IBMCA_RSA_PSS_DEFAULT_MGF           NID_mgf1
#define IBMCA_RSA_PSS_DEFAULT_MGF_DIGEST    NID_sha1
#define IBMCA_RSA_PSS_DEFAULT_SALTLEN       20
#define IBMCA_RSA_OAEP_DEFAULT_DIGEST       NID_sha1
#define IBMCA_RSA_DEFAULT_PADDING           RSA_PKCS1_PADDING
#define IBMCA_RSA_MIN_MODULUS_BITS          512
#define IBMCA_SSL_MAX_MASTER_KEY_LENGTH     48

#define IBMCA_RSA_PSS_DEFAULTS   { IBMCA_RSA_PSS_DEFAULT_DIGEST,        \
                                   IBMCA_RSA_PSS_DEFAULT_MGF,           \
                                   IBMCA_RSA_PSS_DEFAULT_MGF_DIGEST,    \
                                   IBMCA_RSA_PSS_DEFAULT_SALTLEN,       \
                                   false                                \
                                 }

#define MAX_DIGINFO_SIZE                    128

extern const OSSL_ITEM ibmca_rsa_padding_table[];

int ibmca_rsa_build_digest_info(const struct ibmca_prov_ctx *provctx,
                                const EVP_MD *md, const unsigned char *data,
                                size_t data_len, unsigned char *out,
                                size_t outsize, size_t *outlen);
int ibmca_rsa_add_pkcs1_padding(const struct ibmca_prov_ctx *provctx, int type,
                                const unsigned char *in, size_t inlen,
                                unsigned char *out, size_t outlen);
int ibmca_rsa_check_pkcs1_padding_type1(const struct ibmca_prov_ctx *provctx,
                                        const unsigned char *in, size_t inlen,
                                        unsigned char *out, size_t outsize,
                                        unsigned char **outptr, size_t *outlen);
int ibmca_rsa_check_pkcs1_padding_type2(const struct ibmca_prov_ctx *provctx,
                                        const unsigned char *in, size_t inlen,
                                        unsigned char *out, size_t outsize,
                                        size_t *outlen,
                                        const unsigned char *kdk,
                                        size_t kdklen);
int ibmca_rsa_add_oaep_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                    const unsigned char *in, size_t inlen,
                                    unsigned char *out, size_t outlen,
                                    const EVP_MD *oaep_md,
                                    const EVP_MD *mgf1_md,
                                    const unsigned char *label,
                                    size_t label_len);
int ibmca_rsa_check_oaep_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                      const unsigned char *in, size_t inlen,
                                      unsigned char *out, size_t outsize,
                                      size_t *outlen,
                                      const EVP_MD *oaep_md,
                                      const EVP_MD *mgf1_md,
                                      const unsigned char *label,
                                      size_t label_len);
int ibmca_rsa_check_pkcs1_tls_padding(const struct ibmca_prov_ctx *provctx,
                                      unsigned int client_version,
                                      unsigned int alt_version,
                                      const unsigned char *in, size_t inlen,
                                      unsigned char *out, size_t outsize,
                                      size_t *outlen);
int ibmca_rsa_add_x931_padding(const struct ibmca_prov_ctx *provctx,
                               const unsigned char *in, size_t inlen,
                               unsigned char *out, size_t outlen,
                               int digest_nid);
int ibmca_rsa_check_X931_padding(const struct ibmca_prov_ctx *provctx,
                                 const unsigned char *in, int inlen,
                                 unsigned char *out, size_t outsize,
                                 unsigned char **outptr, size_t *outlen,
                                 int digest_nid);
int ibmca_rsa_add_pss_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                   const unsigned char *in, size_t inlen,
                                   unsigned char *out, size_t outlen,
                                   const EVP_MD *pss_md, const EVP_MD *mgf1_md,
                                   int saltlen);
int ibmca_rsa_check_pss_mgf1_padding(const struct ibmca_prov_ctx *provctx,
                                     const unsigned char *in, size_t inlen,
                                     const unsigned char *data, size_t datalen,
                                     const EVP_MD *pss_md,
                                     const EVP_MD *mgf1_md,
                                     int saltlen);

int ibmca_keymgmt_rsa_derive_kdk(struct ibmca_key *key,
                                 const unsigned char *in, size_t inlen,
                                 unsigned char *kdk, size_t kdklen);

int ibmca_keymgmt_rsa_pub_as_bn(struct ibmca_key *key, BIGNUM **n, BIGNUM **e);

int ibmca_rsa_priv_with_blinding(struct ibmca_key *key, const unsigned char *in,
                                 unsigned char *out, size_t rsa_size);

int ossl_bn_rsa_do_unblind(const unsigned char *intermediate,
                           const BIGNUM *unblind,
                           const unsigned char *to_mod,
                           unsigned char *buf, int num,
                           BN_MONT_CTX *m_ctx, BN_ULONG n0);

extern const OSSL_ALGORITHM ibmca_ec_keymgmt[];
extern const OSSL_ALGORITHM ibmca_ec_signature[];
extern const OSSL_ALGORITHM ibmca_ec_keyexch[];
extern const struct ibmca_mech_capability ibmca_ec_capabilities[];

#define IBMCA_EC_DEFAULT_DIGEST             NID_sha256

extern const OSSL_ALGORITHM ibmca_dh_keymgmt[];
extern const OSSL_ALGORITHM ibmca_dh_keyexch[];
extern const struct ibmca_mech_capability ibmca_dh_capabilities[];
