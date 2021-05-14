#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::rsaencdec("8k", 10, 1013);
test::rsasignverify("8k", 10, 1013);
