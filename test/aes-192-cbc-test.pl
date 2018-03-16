#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::cipher("aes-192-cbc", 24, 16);
