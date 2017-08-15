/*
 * Copyright [2015-2017] International Business Machines Corp.
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

#include <openssl/engine.h>
#include <ica_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>
#include <dirent.h>
#include <string.h>
#include <stdbool.h>

#define CIPH 1
#define DIG  2
#define SET 1
#define UNSET 0


typedef struct{
	int nid;
	int ica_id;
	int dig_ciph;
} id_map;

#define AP_PATH  "/sys/devices/ap"
#define IBMCA_PATH "/usr/lib64/openssl/engines/libibmca.so"


id_map ica_to_ssl_map[] = {
#ifndef OPENSSL_NO_SHA1
	{NID_sha1, SHA1, DIG},
#endif
#ifndef OPENSSL_NO_SHA256
        {NID_sha256, SHA256, DIG},
#endif
#ifndef OPENSSL_NO_SHA512
	{NID_sha512, SHA512, DIG},
#endif
        {NID_des_ecb, DES_ECB, CIPH},
        {NID_des_cbc, DES_CBC, CIPH},
        {NID_des_ofb64, DES_OFB, CIPH},
        {NID_des_cfb64, DES_CFB, CIPH},
        {NID_des_ede3_ecb, DES3_ECB, CIPH},
        {NID_des_ede3_cbc, DES3_CBC, CIPH},
        {NID_des_ede3_ofb64, DES3_OFB, CIPH},
        {NID_des_ede3_cfb64, DES3_CFB, CIPH},
        {NID_aes_128_ecb, AES_ECB, CIPH},
        {NID_aes_192_ecb, AES_ECB, CIPH},
        {NID_aes_256_ecb, AES_ECB, CIPH},
        {NID_aes_128_cbc, AES_CBC, CIPH},
        {NID_aes_192_cbc, AES_CBC, CIPH},
        {NID_aes_256_cbc, AES_CBC, CIPH},
        {NID_aes_128_ofb128, AES_OFB, CIPH},
        {NID_aes_192_ofb128, AES_OFB, CIPH},
        {NID_aes_256_ofb128, AES_OFB, CIPH},
        {NID_aes_128_cfb128, AES_CFB, CIPH},
        {NID_aes_192_cfb128, AES_CFB, CIPH},
        {NID_aes_256_cfb128, AES_CFB, CIPH},
        {0, 0, 0}
};

ENGINE *eng;
int failure = 0;

int init_engine(char *id)
{
	ENGINE_load_builtin_engines();
        eng = ENGINE_by_id("dynamic");
	if(!eng){
		return 1;
	return 1;
	}
        if(!ENGINE_ctrl_cmd_string(eng, "SO_PATH", id, 0)){
                return 1;
        }
        if (!ENGINE_ctrl_cmd_string(eng, "LOAD", NULL, 0)){
                return 1;
        }
        if (!ENGINE_init(eng)){
                return 1;
	}
	if(!ENGINE_set_default_RSA(eng))
		return 1;
        ENGINE_set_default_DSA(eng);
	ENGINE_set_default_RAND(eng);
	ENGINE_set_default_DH(eng);
        ENGINE_set_default_ciphers(eng);
        ENGINE_set_default_digests(eng);

	return 0;
}

void exit_engine()
{
        /* Release the functional reference from ENGINE_init() */
        ENGINE_finish(eng);
        /* Release the structural reference from ENGINE_by_id() */
        ENGINE_free(eng);
}

void nid_failure(int nid, int set)
{
	failure++;
	if(set == SET){
		fprintf(stderr, "ERROR: NID %d not set in Engine!\n", nid);
	} else if(set == UNSET)
		fprintf(stderr, "ERROR: NID %d set despite missing hardware support!", nid);
}

int is_crypto_card_loaded()
{
        DIR* sysDir;
        FILE *file;
        char dev[PATH_MAX] = AP_PATH;
        struct dirent *direntp;
        char *type = NULL;
        size_t size;
        char c;

        if ((sysDir = opendir(dev)) == NULL )
                return 0;

        while((direntp = readdir(sysDir)) != NULL){
                if(strstr(direntp->d_name, "card") != 0){
                        snprintf(dev, PATH_MAX, "%s/%s/type", AP_PATH,
                                 direntp->d_name);

                        if ((file = fopen(dev, "r")) == NULL){
                                closedir(sysDir);
                                return 0;
                        }

                        if (getline(&type, &size, file) == -1){
                                fclose(file);
                                closedir(sysDir);
                                return 0;
                        }

                        /* ignore \n
                         * looking for CEX??A and CEX??C
                         * Skip type CEX??P cards
                         */
                        if (type[strlen(type)-2] == 'P'){
                                free(type);
                                type = NULL;
                                fclose(file);
                                continue;
                        }
                        free(type);
                        type = NULL;
                        fclose(file);

                        snprintf(dev, PATH_MAX, "%s/%s/online", AP_PATH,
                                direntp->d_name);

                        if ((file = fopen(dev, "r")) == NULL){
                                closedir(sysDir);
                                return 0;
                        }
                        if((c = fgetc(file)) == '1'){
                                fclose(file);
                                return 1;
                        }
                        fclose(file);
                }
        }
        closedir(sysDir);
        return 0;
}

void check_mech(int i, int j, libica_func_list_element *pmech_list)
{
	if(!(pmech_list[j].flags & (ICA_FLAG_SHW))){
		if(ica_to_ssl_map[i].dig_ciph == CIPH){
			if(ENGINE_get_cipher_engine(ica_to_ssl_map[i].nid)){
				nid_failure(ica_to_ssl_map[i].nid, UNSET);
			} else{
				printf("NID %d not found! SUCCESS\n",
				       ica_to_ssl_map[i].nid);
			}
		} else{
			if(ENGINE_get_digest_engine(ica_to_ssl_map[i].nid)){
				nid_failure(ica_to_ssl_map[i].nid, UNSET);
			} else{
				printf("NID %d not found! SUCCESS\n",
				       ica_to_ssl_map[i].nid);
			}
		}
        } else{
		if(ica_to_ssl_map[i].dig_ciph == CIPH){
			if(!ENGINE_get_cipher_engine(ica_to_ssl_map[i].nid)){
				nid_failure(ica_to_ssl_map[i].nid, SET);
			} else{
				printf("NID %d found! SUCCESS %d\n",
				       ica_to_ssl_map[i].nid, j);
			}
		} else{
			if(!ENGINE_get_digest_engine(ica_to_ssl_map[i].nid)){
				nid_failure(ica_to_ssl_map[i].nid, SET);
			} else{
				printf("NID %d found! SUCCESS %d\n",
                                       ica_to_ssl_map[i].nid, j);
			}
		}
	}
}

int main (int argc, char *argv[])
{
	int i, j, opt, option_index = 0;
	int card_loaded;
	unsigned int mech_len;
	bool found = false;
	libica_func_list_element *pmech_list = NULL;
	char *engine_id = IBMCA_PATH;
	struct option long_options[] = {
                   {"help", no_argument, 0, 'h'},
		   {"file", required_argument, 0, 'f'},
		   {0 ,0 ,0, 0}
	};

	while ((opt = getopt_long(argc, argv, "hf:",
				long_options, &option_index)) != -1) {
               switch (opt) {
               case 'f':
                   engine_id = optarg;
                   break;
               case 'h':
			printf("This test checks with the engine API of libcrypto if a\n"
                          "crypto mechanism is enabled or not.\n"
                          "If one mechanism is not found the NID is returned.\n"
                          "The NID can be mapped to a name in the file \n"
                          "/usr/include/openssl/obj_mac.h\n");

                   printf("Usage: %s [-f | --file ibmca.so] [-h | --help]\n",
                           argv[0]);
			exit(EXIT_SUCCESS);
               default: /* '?' */
                   fprintf(stderr, "Usage: %s [-t nsecs] [-n] name\n",
                           argv[0]);
                   exit(EXIT_FAILURE);
               }
	}

	printf("This test checks with the engine API of libcrypto if a\n"
	       "crypto mechanism is enabled or not.\n"
	       "If one mechanism is not found the NID is returned.\n"
	       "The NID can be mapped to a name in the file \n"
	       "/usr/include/openssl/obj_mac.h\n");
	printf("IBMCA path: %s\n", engine_id);
	printf("--------------------------------------------------------------\n\n");

	if(init_engine(engine_id)){
		fprintf(stderr, "Could not initialize Ibmca engine\n");
		return EXIT_FAILURE;
	}
	if (ica_get_functionlist(NULL, &mech_len) != 0){
		perror("get_functionlist");
		return EXIT_FAILURE;
	}
	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (ica_get_functionlist(pmech_list, &mech_len) != 0){
		perror("get_functionlist");
		free(pmech_list);
		return EXIT_FAILURE;
	}

	card_loaded = is_crypto_card_loaded();
        for(i=0;ica_to_ssl_map[i].nid;i++){
		for(j=0;j<mech_len;j++){

                        if(ica_to_ssl_map[i].ica_id == pmech_list[j].mech_mode_id){
				found=true;
				check_mech(i, j, pmech_list);
				break;
			}
		}
			assert(found);
			found = false;

	}

	for(i=0;i<mech_len;i++){
		if(pmech_list[i].mech_mode_id == P_RNG){
			if(pmech_list[i].flags & (ICA_FLAG_SHW)){
				if(!ENGINE_get_default_RAND()){
					failure++;
					fprintf(stderr, "ERROR: Engine has no enabled PRNG support!\n");
				} else{
					printf("PRNG Support found! SUCCESS\n");
				}
			} else{
                               if(ENGINE_get_default_RAND()){
                                        failure++;
                                        fprintf(stderr, "ERROR: Engine has enabled PRNG support"
							", despite no hardware support!\n");
                                } else{
					printf("PRNG Support not found! SUCCESS\n");
				}
			}

		}
		if(pmech_list[i].mech_mode_id == RSA_ME){
			if(card_loaded){
				if(!ENGINE_get_default_RSA()){
					failure++;
					fprintf(stderr, "ERROR: Engine has no enabeled RSA support!\n");
				} else{
					printf("RSA Support found! SUCCESS\n");
				}
				if(!ENGINE_get_default_DSA()){
					failure++;
					fprintf(stderr, "ERROR: Engine has no enabled DSA support!\n");
				} else{
					printf("DSA Support found! SUCCESS\n");
				}
                                if(!ENGINE_get_default_DH()){
                                        failure++;
                                        fprintf(stderr, "ERROR: Engine has no enabled DH support!\n");
                                } else{
					printf("DH Support found! SUCCESS\n");
				}

			} else{
				if(ENGINE_get_default_RSA()){
                                        failure++;
                                        fprintf(stderr, "ERROR: Engine has enabled RSA support,"
							"despite no hardware support!\n");
                                } else{
                                        printf("RSA Support not found! SUCCESS\n");
                                }
                                if(ENGINE_get_default_DSA()){
                                        failure++;
                                        fprintf(stderr, "ERROR: Engine has no enabled DSA support,"
							"despite no hardware support!\n");
                                } else{
                                        printf("DSA Support not found! SUCCESS\n");
                                }
                                if(ENGINE_get_default_DH()){
                                        failure++;
                                        fprintf(stderr, "ERROR: Engine has no enabled DH support,"
                                                        "despite no hardware support!\n");
                                } else{
                                        printf("DH Support not found! SUCCESS\n");
                                }
			}
		}
	}

	printf("\n\n--------------------------------------------------------------\n");
	printf("TEST Summary:\n"
	       "Failure Counter:  %d\n", failure);
	if(failure)
		return EXIT_FAILURE;
	else
		return EXIT_SUCCESS;
}
