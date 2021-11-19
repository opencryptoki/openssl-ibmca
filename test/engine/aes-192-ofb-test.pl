#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::cipher("aes-192-ofb", 24, 16);
