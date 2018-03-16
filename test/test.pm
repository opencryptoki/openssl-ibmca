#!/usr/bin/env perl

use strict;
use warnings;

package test;

sub cipher {
	my $tests = 50;
	my $max_file_size = 1024;
	my $eng = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF}";
	my @hex = ("a".."f", "0".."9");

	my ($cipher,$keylen,$ivlen) = @_;

	# skip if engine not loaded
	exit(77) unless (`$eng openssl engine -c` =~ m/ibmca/);

	for my $i (1..$tests) {
		my $bytes = 1 + int(rand($max_file_size));
		my $key = "";
		$key .= $hex[rand(@hex)] for (1..$keylen);
		my $iv = "";
		if ($ivlen > 0) {
			$iv .= $hex[rand(@hex)] for (1..$ivlen);
			$iv = "-iv $iv";
		}

		# engine enc, no-engine dec
		`openssl rand $bytes > data.in`;
		`$eng openssl $cipher -e -K $key $iv -in data.in -out data.enc`;
		`openssl $cipher -d -K $key $iv -in data.enc -out data.dec`;
		`cmp data.in data.dec`;
		exit(1) if ($?);

		# no-engine enc, engine dec
		`openssl rand $bytes > data.in`;
		`openssl $cipher -e -K $key $iv -in data.in -out data.enc`;
		`$eng openssl $cipher -d -K $key $iv -in data.enc -out data.dec`;
		`cmp data.in data.dec`;
		exit(1) if ($?);
	}

	`rm -f data.in data.enc data.dec`;
}

1;
