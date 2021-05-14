#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::rsaencdec("4k", 50, 501);
test::rsasignverify("4k", 50, 501);

