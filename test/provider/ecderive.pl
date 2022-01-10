#!/usr/bin/env perl

#
# Copyright [2021-2022] International Business Machines Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

use strict;
use warnings;
use test;

test::ecderive("prime192v1", 2);
test::ecderivekdf("prime192v1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("secp224r1", 2);
test::ecderivekdf("secp224r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("prime256v1", 2);
test::ecderivekdf("prime256v1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("secp384r1", 2);
test::ecderivekdf("secp384r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("secp521r1", 2);
test::ecderivekdf("secp521r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("brainpoolP160r1", 2);
test::ecderivekdf("brainpoolP160r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("brainpoolP192r1", 2);
test::ecderivekdf("brainpoolP192r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("brainpoolP224r1", 2);
test::ecderivekdf("brainpoolP224r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("brainpoolP256r1", 2);
test::ecderivekdf("brainpoolP256r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("brainpoolP320r1", 2);
test::ecderivekdf("brainpoolP320r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("brainpoolP384r1", 2);
test::ecderivekdf("brainpoolP384r1", 2, 200, "X963KDF", "SHA-256");
test::ecderive("brainpoolP512r1", 2);
test::ecderivekdf("brainpoolP512r1", 2, 200, "X963KDF", "SHA-256");

