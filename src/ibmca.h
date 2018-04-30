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

#include <ica_api.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
 #define OLDER_OPENSSL
#endif

/*
 * Here is a DEBUG_PRINTF macro which expands to nothing
 * at production level and is active only when the
 * ibmca build is configured with --enable-debug
 */
#ifdef DEBUG
 #define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
 #define DEBUG_PRINTF(...) do{} while(0)
#endif

/*
 * These are the function pointers that are (un)set when the library has
 * successfully (un)loaded.
 */
typedef unsigned int (*ica_get_functionlist_t)(libica_func_list_element *,
                                               unsigned int *);
typedef void         (*ica_set_fallback_mode_t)(int);
typedef unsigned int (*ica_open_adapter_t)(ica_adapter_handle_t *);
typedef unsigned int (*ica_close_adapter_t)(ica_adapter_handle_t);
typedef unsigned int (*ica_rsa_mod_expo_t)(ica_adapter_handle_t,
                      unsigned char *,
                      ica_rsa_key_mod_expo_t *,
                      unsigned char *);
typedef unsigned int (*ica_rsa_crt_t)(ica_adapter_handle_t, unsigned char *,
                      ica_rsa_key_crt_t *, unsigned char *);
typedef unsigned int (*ica_random_number_generate_t)(unsigned int,
                                                     unsigned char *);
typedef unsigned int (*ica_sha1_t)(unsigned int, unsigned int, unsigned char *,
                                   sha_context_t *, unsigned char *);
typedef unsigned int (*ica_sha256_t)(unsigned int, unsigned int,
                                     unsigned char *, sha256_context_t *,
                                     unsigned char *);
typedef unsigned int (*ica_sha512_t)(unsigned int, unsigned int,
                                     unsigned char *, sha512_context_t *,
                                     unsigned char *);
typedef unsigned int (*ica_des_ecb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      unsigned char *key,
                                      unsigned int direction);
typedef unsigned int (*ica_des_cbc_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      unsigned char *key,
                                      unsigned char *iv,
                                      unsigned int direction);
typedef unsigned int (*ica_des_cfb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      const unsigned char *key,
                                      unsigned char *iv,
                                      unsigned int lcfb,
                                      unsigned int direction);
typedef unsigned int (*ica_des_ofb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      const unsigned char *key,
                                      unsigned char *iv,
                                      unsigned int direction);
typedef unsigned int (*ica_3des_ecb_t)(const unsigned char *in_data,
                                       unsigned char *out_data,
                                       unsigned long data_length,
                                       unsigned char *key,
                                       unsigned int direction);
typedef unsigned int (*ica_3des_cbc_t)(const unsigned char *in_data,
                                       unsigned char *out_data,
                                       unsigned long data_length,
                                       unsigned char *key,
                                       unsigned char *iv,
                                       unsigned int direction);
typedef unsigned int (*ica_3des_cfb_t)(const unsigned char *, unsigned char *,
                                       unsigned long, const unsigned char *,
                                       unsigned char *, unsigned int,
                                       unsigned int);
typedef unsigned int (*ica_3des_ofb_t)(const unsigned char *in_data,
                                       unsigned char *out_data,
                                       unsigned long data_length,
                                       const unsigned char *key,
                                       unsigned char *iv,
                                       unsigned int direction);
typedef unsigned int (*ica_aes_ecb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      unsigned char *key,
                                      unsigned int key_length,
                                      unsigned int direction);
typedef unsigned int (*ica_aes_cbc_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      unsigned char *key,
                                      unsigned int key_length,
                                      unsigned char *iv,
                                      unsigned int direction);
typedef unsigned int (*ica_aes_ofb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      const unsigned char *key,
                                      unsigned int key_length,
                                      unsigned char *iv,
                                      unsigned int direction);
typedef unsigned int (*ica_aes_cfb_t)(const unsigned char *in_data,
                                      unsigned char *out_data,
                                      unsigned long data_length,
                                      const unsigned char *key,
                                      unsigned int key_length,
                                      unsigned char *iv, unsigned int lcfb,
                                      unsigned int direction);
typedef unsigned int (*ica_aes_gcm_initialize_t)(const unsigned char *iv,
                                                 unsigned int iv_length,
                                                 unsigned char *key,
                                                 unsigned int key_length,
                                                 unsigned char *icb,
                                                 unsigned char *ucb,
                                                 unsigned char *subkey,
                                                 unsigned int direction);
typedef unsigned int (*ica_aes_gcm_intermediate_t)(unsigned char *plaintext,
                                                   unsigned long
                                                            plaintext_length,
                                                   unsigned char *ciphertext,
                                                   unsigned char *ucb,
                                                   unsigned char *aad,
                                                   unsigned long aad_length,
                                                   unsigned char *tag,
                                                   unsigned int tag_length,
                                                   unsigned char *key,
                                                   unsigned int key_length,
                                                   unsigned char *subkey,
                                                   unsigned int direction);
typedef unsigned int (*ica_aes_gcm_last_t)(unsigned char *icb,
                                           unsigned long aad_length,
                                           unsigned long ciph_length,
                                           unsigned char *tag,
                                           unsigned char *final_tag,
                                           unsigned int final_tag_length,
                                           unsigned char *key,
                                           unsigned int key_length,
                                           unsigned char *subkey,
                                           unsigned int direction);

/* entry points into libica, filled out at DSO load time */
extern ica_get_functionlist_t           p_ica_get_functionlist;
extern ica_set_fallback_mode_t          p_ica_set_fallback_mode;
extern ica_open_adapter_t               p_ica_open_adapter;
extern ica_close_adapter_t              p_ica_close_adapter;
extern ica_rsa_mod_expo_t               p_ica_rsa_mod_expo;
extern ica_random_number_generate_t     p_ica_random_number_generate;
extern ica_rsa_crt_t                    p_ica_rsa_crt;
extern ica_sha1_t                       p_ica_sha1;
extern ica_sha256_t                     p_ica_sha256;
extern ica_sha512_t                     p_ica_sha512;
extern ica_des_ecb_t                    p_ica_des_ecb;
extern ica_des_cbc_t                    p_ica_des_cbc;
extern ica_des_ofb_t                    p_ica_des_ofb;
extern ica_des_cfb_t                    p_ica_des_cfb;
extern ica_3des_ecb_t                   p_ica_3des_ecb;
extern ica_3des_cbc_t                   p_ica_3des_cbc;
extern ica_3des_cfb_t                   p_ica_3des_cfb;
extern ica_3des_ofb_t                   p_ica_3des_ofb;
extern ica_aes_ecb_t                    p_ica_aes_ecb;
extern ica_aes_cbc_t                    p_ica_aes_cbc;
extern ica_aes_ofb_t                    p_ica_aes_ofb;
extern ica_aes_cfb_t                    p_ica_aes_cfb;
#ifndef OPENSSL_NO_AES_GCM
extern ica_aes_gcm_initialize_t         p_ica_aes_gcm_initialize;
extern ica_aes_gcm_intermediate_t       p_ica_aes_gcm_intermediate;
extern ica_aes_gcm_last_t               p_ica_aes_gcm_last;
#endif
