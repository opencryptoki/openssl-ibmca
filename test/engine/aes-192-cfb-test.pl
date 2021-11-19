#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::cipher("aes-192-cfb", 24, 16);
