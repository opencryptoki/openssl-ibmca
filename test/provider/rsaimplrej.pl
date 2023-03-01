#!/usr/bin/env perl

#
# Copyright [2023-2023] International Business Machines Corp.
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

# RSA implicit rejection - random positive test case
test::rsaimplrej("$FindBin::Bin/rsa-implrej-key.pem", "$FindBin::Bin/rsa-implrej-good-in.bin", "$FindBin::Bin/rsa-implrej-good-out.bin");
# RSA implicit rejection - random negative test case decrypting to empty
test::rsaimplrej("$FindBin::Bin/rsa-implrej-key.pem", "$FindBin::Bin/rsa-implrej-bad-empty-in.bin", "$FindBin::Bin/rsa-implrej-bad-empty-out.bin");
# RSA implicit rejection - invalid decrypting to max length message
test::rsaimplrej("$FindBin::Bin/rsa-implrej-key.pem", "$FindBin::Bin/rsa-implrej-bad-max-in.bin", "$FindBin::Bin/rsa-implrej-bad-max-out.bin");
# RSA implicit rejection - invalid decrypting to message with length specified by second to last value from PRF
test::rsaimplrej("$FindBin::Bin/rsa-implrej-key.pem", "$FindBin::Bin/rsa-implrej-bad-prf-in.bin", "$FindBin::Bin/rsa-implrej-bad-prf-out.bin");


