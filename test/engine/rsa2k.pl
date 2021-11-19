#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::rsaencdec("2k", 50, 245);
test::rsasignverify("2k", 50, 245);
