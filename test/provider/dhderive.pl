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

test::dhderive("ffdhe2048", 2);
test::dhderivekdf("ffdhe2048", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("ffdhe3072", 2);
test::dhderivekdf("ffdhe3072", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("ffdhe4096", 2);
test::dhderivekdf("ffdhe4096", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("ffdhe6144", 2);
test::dhderivekdf("ffdhe6144", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("ffdhe8192", 2);
test::dhderivekdf("ffdhe8192", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("modp_1536", 2);
test::dhderivekdf("modp_1536", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("modp_2048", 2);
test::dhderivekdf("modp_2048", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("modp_3072", 2);
test::dhderivekdf("modp_3072", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("modp_4096", 2);
test::dhderivekdf("modp_4096", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("modp_6144", 2);
test::dhderivekdf("modp_6144", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");
test::dhderive("modp_8192", 2);
test::dhderivekdf("modp_8192", 2, 200, "X942KDF-ASN1", "SHA-256", "id-aes256-wrap");

