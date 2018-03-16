#!/usr/bin/env perl

use strict;
use warnings;
use test;

test::cipher("aes-128-ofb", 16, 16);
