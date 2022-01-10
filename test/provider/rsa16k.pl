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

test::rsaencdec("16384", 2, 2037);
test::rsaoaepencdec("16384", 2, 200, "SHA-256");
test::rsasignverify("16384", 2, 64);
test::rsapsssignverify("16384", 2, 100, "SHA-256", 25);
test::rsax931signverify("16384", 2, 100, "SHA-256");

