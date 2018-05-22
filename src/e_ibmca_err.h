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

#ifndef HEADER_IBMCA_ERR_H
#define HEADER_IBMCA_ERR_H

/* BEGIN ERROR CODES */
void ERR_load_IBMCA_strings(void);
void ERR_unload_IBMCA_strings(void);
void ERR_IBMCA_error(int function, int reason, char *file, int line);
#define IBMCAerr(f,r) ERR_IBMCA_error((f),(r),__FILE__,__LINE__)

/* Error codes for the IBMCA functions. */

/* Function codes. */
#define IBMCA_F_IBMCA_CTRL              100
#define IBMCA_F_IBMCA_FINISH            101
#define IBMCA_F_IBMCA_INIT              102
#define IBMCA_F_IBMCA_MOD_EXP           103
#define IBMCA_F_IBMCA_MOD_EXP_CRT       104
#define IBMCA_F_IBMCA_RAND_BYTES        105
#define IBMCA_F_IBMCA_RSA_MOD_EXP       106
#define IBMCA_F_IBMCA_DES_CIPHER        107
#define IBMCA_F_IBMCA_TDES_CIPHER       108
#define IBMCA_F_IBMCA_SHA1_UPDATE       109
#define IBMCA_F_IBMCA_SHA1_FINAL        110
#define IBMCA_F_IBMCA_AES_128_CIPHER    111
#define IBMCA_F_IBMCA_AES_192_CIPHER    112
#define IBMCA_F_IBMCA_AES_256_CIPHER    113
#define IBMCA_F_IBMCA_SHA256_UPDATE     114
#define IBMCA_F_IBMCA_SHA256_FINAL      115
#define IBMCA_F_IBMCA_SHA512_UPDATE     116
#define IBMCA_F_IBMCA_SHA512_FINAL      117
#define IBMCA_F_IBMCA_EC_KEY_GEN	120
#define IBMCA_F_IBMCA_ECDH_COMPUTE_KEY	121
#define IBMCA_F_IBMCA_ECDSA_SIGN	122
#define IBMCA_F_IBMCA_ECDSA_SIGN_SIG	123
#define IBMCA_F_IBMCA_ECDSA_DO_SIGN	124
#define IBMCA_F_IBMCA_ECDSA_VERIFY	125
#define IBMCA_F_IBMCA_ECDSA_VERIFY_SIG	126
#define IBMCA_F_ICA_EC_KEY_NEW		127
#define IBMCA_F_ICA_EC_KEY_INIT		128
#define IBMCA_F_ICA_EC_KEY_GENERATE	129
#define IBMCA_F_ICA_EC_KEY_GET_PUBLIC_KEY	130
#define IBMCA_F_ICA_EC_KEY_GET_PRIVATE_KEY	131
#define IBMCA_F_ICA_ECDH_DERIVE_SECRET	132
#define IBMCA_F_ICA_ECDSA_SIGN		133
#define IBMCA_F_ICA_ECDSA_VERIFY	134

/* Reason codes. */
#define IBMCA_R_ALREADY_LOADED                  100
#define IBMCA_R_BN_CTX_FULL                     101
#define IBMCA_R_BN_EXPAND_FAIL                  102
#define IBMCA_R_CTRL_COMMAND_NOT_IMPLEMENTED    103
#define IBMCA_R_DSO_FAILURE                     104
#define IBMCA_R_MEXP_LENGTH_TO_LARGE            110
#define IBMCA_R_MISSING_KEY_COMPONENTS          105
#define IBMCA_R_NOT_INITIALISED                 106
#define IBMCA_R_NOT_LOADED                      107
#define IBMCA_R_OPERANDS_TO_LARGE               111
#define IBMCA_R_OUTLEN_TO_LARGE                 112
#define IBMCA_R_REQUEST_FAILED                  108
#define IBMCA_R_UNDERFLOW_CONDITION             113
#define IBMCA_R_UNDERFLOW_KEYRECORD             114
#define IBMCA_R_UNIT_FAILURE                    109
#define IBMCA_R_CIPHER_MODE_NOT_SUPPORTED       115
#define IBMCA_R_EC_INVALID_PARM			120
#define IBMCA_R_EC_UNSUPPORTED_CURVE		121
#define IBMCA_R_EC_INTERNAL_ERROR		122
#define IBMCA_R_EC_ICA_EC_KEY_INIT		123
#define IBMCA_R_EC_CURVE_DOES_NOT_SUPPORT_SIGNING	159

#endif
