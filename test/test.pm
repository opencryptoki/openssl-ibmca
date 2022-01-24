#!/usr/bin/env perl

use strict;
use warnings;

package test;

sub osslversion1 {
    my $vstr = `openssl version -v`;

    return $vstr =~ /OpenSSL 1\..*/;
}

sub osslversion3 {
    my $vstr = `openssl version -v`;

    return $vstr =~ /OpenSSL 3\..*/;
}

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
		`openssl rand $bytes > ${cipher}.${i}.data.in`;
		`$eng openssl $cipher -e -K $key $iv -in ${cipher}.${i}.data.in -out ${cipher}.${i}.data.enc`;
		`openssl $cipher -d -K $key $iv -in ${cipher}.${i}.data.enc -out ${cipher}.${i}.data.dec`;
		`cmp ${cipher}.${i}.data.in ${cipher}.${i}.data.dec`;
		exit(99) if ($?);
		`rm -f ${cipher}.${i}.data.in ${cipher}.${i}.data.enc ${cipher}.${i}.data.dec`;

		# no-engine enc, engine dec
		`openssl rand $bytes > ${cipher}.${i}.data.in`;
		`openssl $cipher -e -K $key $iv -in ${cipher}.${i}.data.in -out ${cipher}.${i}.data.enc`;
		`$eng openssl $cipher -d -K $key $iv -in ${cipher}.${i}.data.enc -out ${cipher}.${i}.data.dec`;
		`cmp ${cipher}.${i}.data.in ${cipher}.${i}.data.dec`;
		exit(99) if ($?);
		`rm -f ${cipher}.${i}.data.in ${cipher}.${i}.data.enc ${cipher}.${i}.data.dec`;
	}
}

sub rsaencdec {
	my $eng = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF}";
	my @hex = ("a".."f", "0".."9");

	my ($keylen, $tests, $max_file_size) = @_;

	# skip if engine not loaded
	exit(77) unless (`$eng openssl engine -c` =~ m/ibmca/);

	for my $i (1..$tests) {
		my $bytes = 1 + int(rand($max_file_size));
		# engine enc, no-engine dec
		`openssl rand $bytes > rsaencdec.${i}.${keylen}.data.in`;
		`$eng openssl rsautl -encrypt -inkey rsa$keylen.key -in rsaencdec.${i}.${keylen}.data.in -out rsaencdec.${i}.${keylen}.data.out`;
		`openssl rsautl -decrypt -inkey rsa$keylen.key -in rsaencdec.${i}.${keylen}.data.out -out rsaencdec.${i}.${keylen}.data.dec`;
		`cmp rsaencdec.${i}.${keylen}.data.in rsaencdec.${i}.${keylen}.data.dec`;
		exit(99) if ($?);
		`rm -f rsaencdec.${i}.${keylen}.data.in rsaencdec.${i}.${keylen}.out rsaencdec.${i}.${keylen}.dec`;

		# no-engine enc, engine dec
		`openssl rand $bytes > rsaencdec.${i}.${keylen}.data.in`;
		`openssl rsautl -encrypt -inkey rsa$keylen.key -in rsaencdec.${i}.${keylen}.data.in -out rsaencdec.${i}.${keylen}.data.out`;
		`$eng openssl rsautl -decrypt -inkey rsa$keylen.key -in rsaencdec.${i}.${keylen}.data.out -out rsaencdec.${i}.${keylen}.data.dec`;
		`cmp rsaencdec.${i}.${keylen}.data.in rsaencdec.${i}.${keylen}.data.dec`;
		exit(99) if ($?);
		`rm -f rsaencdec.${i}.${keylen}.data.in rsaencdec.${i}.${keylen}.out rsaencdec.${i}.${keylen}.dec`;
	}
}

sub rsasignverify {
	my $eng = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF}";
	my @hex = ("a".."f", "0".."9");

	my ($keylen, $tests, $max_file_size) = @_;

	# skip if engine not loaded
	exit(77) unless (`$eng openssl engine -c` =~ m/ibmca/);

	for my $i (1..$tests) {
		my $bytes = 1 + int(rand($max_file_size));
		my $key = "";
		$key .= $hex[rand(@hex)] for (1..$keylen);
		# engine sign, no-engine verify
		`openssl rand $bytes > rsasignverify.${i}.${keylen}.data.in`;
		`$eng openssl rsautl -sign -inkey rsa$keylen.key -in rsasignverify.${i}.${keylen}.data.in -out rsasignverify.${i}.${keylen}.data.out`;
		`openssl rsautl -verify -inkey rsa$keylen.key -in rsasignverify.${i}.${keylen}.data.out -out rsasignverify.${i}.${keylen}.data.rec`;
		`cmp rsasignverify.${i}.${keylen}.data.in rsasignverify.${i}.${keylen}.data.rec`;
		exit(99) if ($?);
		`rm -f rsasignverify.${i}.${keylen}.data.in rsasignverify.${i}.${keylen}.data.out rsasignverify.${i}.${keylen}.data.rec`;

		# no-engine sign, engine verify
		`openssl rand $bytes > rsasignverify.${i}.${keylen}.data.in`;
		`openssl rsautl -sign -inkey rsa$keylen.key -in rsasignverify.${i}.${keylen}.data.in -out rsasignverify.${i}.${keylen}.data.out`;
		`$eng openssl rsautl -verify -inkey rsa$keylen.key -in rsasignverify.${i}.${keylen}.data.out -out rsasignverify.${i}.${keylen}.data.rec`;
		`cmp rsasignverify.${i}.${keylen}.data.in rsasignverify.${i}.${keylen}.data.rec`;
		exit(99) if ($?);
		`rm -f rsasignverify.${i}.${keylen}.data.in rsasignverify.${i}.${keylen}.data.out rsasignverify.${i}.${keylen}.data.rec`;
	}
}

sub dsasignverify {
	my $tests = 50;
	my $max_file_size = 1024;
	my $eng = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF}";
	my @hex = ("a".."f", "0".."9");

	my ($keylen) = @_;

	# skip if engine not loaded
	exit(77) unless (`$eng openssl engine -c` =~ m/ibmca/);

	for my $i (1..$tests) {
		my $bytes = 1 + int(rand($max_file_size));
		# engine sign, no-engine verify
		`openssl rand $bytes > dsa.${i}.${keylen}.data.in`;
		`$eng openssl dgst -sign dsa$keylen.key -out dsa.${i}.${keylen}.data.out dsa.${i}.${keylen}.data.in`;
		`openssl dgst -verify dsa${keylen}_pub.key -signature dsa.${i}.${keylen}.data.out dsa.${i}.${keylen}.data.in`;
		exit(99) if ($?);
		`rm -f dsa.${i}.${keylen}.data.in dsa.${i}.${keylen}.data.out`;

		# no-engine sign, engine verify
		`openssl rand $bytes > dsa.${i}.${keylen}.data.in`;
		`openssl dgst -sign dsa$keylen.key -out dsa.${i}.${keylen}.data.out dsa.${i}.${keylen}.data.in`;
		`$eng openssl dgst -verify dsa${keylen}_pub.key -signature dsa.${i}.${keylen}.data.out dsa.${i}.${keylen}.data.in`;
		exit(99) if ($?);
		`rm -f dsa.${i}.${keylen}.data.in dsa.${i}.${keylen}.data.out`;
	}
}

1;
