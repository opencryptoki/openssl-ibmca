#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::cipher("aes-256-ofb", 32, 16);
