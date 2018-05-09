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
