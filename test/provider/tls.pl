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
use FindBin;

# TLS 1.3 with RSA signatures
test::tls(10001, "$FindBin::Bin/server-key-rsa.pem", "$FindBin::Bin/server-cert-rsa.pem", "ALL", "TLS_AES_256_GCM_SHA384", "-tls1_3");
# TLS 1.3 with EC signatures
test::tls(10002, "$FindBin::Bin/server-key-ec.pem", "$FindBin::Bin/server-cert-ec.pem", "ALL", "TLS_AES_256_GCM_SHA384", "-tls1_3");
# TLS 1.2 with RSA signatures and ECDH key exchange
test::tls(10003, "$FindBin::Bin/server-key-rsa.pem", "$FindBin::Bin/server-cert-rsa.pem", "ECDHE-RSA-AES256-GCM-SHA384", "\"\"", "-no_tls1_3");
# TLS 1.2 with ECDSA signatures and ECDH key exchange
test::tls(10004, "$FindBin::Bin/server-key-ec.pem", "$FindBin::Bin/server-cert-ec.pem", "ECDHE-ECDSA-AES256-GCM-SHA384", "\"\"", "-no_tls1_3");
# TLS 1.2 with RSA signatures and DH key exchange
test::tls(10005, "$FindBin::Bin/server-key-rsa.pem", "$FindBin::Bin/server-cert-rsa.pem", "DHE-RSA-AES256-GCM-SHA384", "\"\"", "-no_tls1_3");
# TLS 1.2 with RSA signatures and RSA key exchange
test::tls(10006, "$FindBin::Bin/server-key-rsa.pem", "$FindBin::Bin/server-cert-rsa.pem", "AES256-GCM-SHA384", "\"\"", "-no_tls1_3");

