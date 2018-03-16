#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::cipher("aes-128-cbc", 16, 16);
