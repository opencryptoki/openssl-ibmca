#!/usr/bin/env perl

use strict;
use warnings;
use test;

# No iv needed, but openssl app version 3 somehow requires one...
test::cipher("des-ede3", 24, test::osslversion3 ? 8 : 0);
