#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::cipher("aes-256-cbc", 32, 16);
