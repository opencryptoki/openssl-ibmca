#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::cipher("des-ede3-cfb", 24, 8);
