#!/usr/bin/env perl

#
# Copyright [2021-2022] International Business Machines Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

use strict;
use warnings;

package test;

sub rsaencdec {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($keylen, $tests, $max_file_size) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    `$prov openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$keylen -out rsa$keylen.key`;
    `$prov openssl rsa -in rsa$keylen.key -check -pubout -out rsa$keylen.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        my $bytes = 1 + int(rand($max_file_size));
        # provider enc, no-provider dec
        `openssl rand $bytes > rsaencdec.${i}.${keylen}.data.in`;
        `$prov openssl pkeyutl -encrypt -pubin -inkey rsa$keylen.pub -in rsaencdec.${i}.${keylen}.data.in -out rsaencdec.${i}.${keylen}.data.out`;
        `openssl pkeyutl -decrypt -inkey rsa$keylen.key -in rsaencdec.${i}.${keylen}.data.out -out rsaencdec.${i}.${keylen}.data.dec`;
        `cmp rsaencdec.${i}.${keylen}.data.in rsaencdec.${i}.${keylen}.data.dec`;
        exit(99) if ($?);
        `rm -f rsaencdec.${i}.${keylen}.data.in rsaencdec.${i}.${keylen}.data.out rsaencdec.${i}.${keylen}.data.dec`;

        # no-provider enc, provider dec
        `openssl rand $bytes > rsaencdec.${i}.${keylen}.data.in`;
        `openssl pkeyutl -encrypt -pubin -inkey rsa$keylen.pub -in rsaencdec.${i}.${keylen}.data.in -out rsaencdec.${i}.${keylen}.data.out`;
        `$prov openssl pkeyutl -decrypt -inkey rsa$keylen.key -in rsaencdec.${i}.${keylen}.data.out -out rsaencdec.${i}.${keylen}.data.dec`;
        `cmp rsaencdec.${i}.${keylen}.data.in rsaencdec.${i}.${keylen}.data.dec`;
        exit(99) if ($?);
        `rm -f rsaencdec.${i}.${keylen}.data.in rsaencdec.${i}.${keylen}.data.out rsaencdec.${i}.${keylen}.data.dec`;
    }

    `rm -f rsa$keylen.key rsa$keylen.pub`;
}

sub rsaoaepencdec {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($keylen, $tests, $max_file_size, $md) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    `$prov openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$keylen -out rsa$keylen.key`;
    `$prov openssl rsa -in rsa$keylen.key -check -pubout -out rsa$keylen.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        my $bytes = 1 + int(rand($max_file_size));
        # provider enc, no-provider dec
        `openssl rand $bytes > rsaoaepencdec.${i}.${keylen}.data.in`;
        `$prov openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$md -pubin -inkey rsa$keylen.pub -in rsaoaepencdec.${i}.${keylen}.data.in -out rsaoaepencdec.${i}.${keylen}.data.out`;
        `openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$md -inkey rsa$keylen.key -in rsaoaepencdec.${i}.${keylen}.data.out -out rsaoaepencdec.${i}.${keylen}.data.dec`;
        `cmp rsaoaepencdec.${i}.${keylen}.data.in rsaoaepencdec.${i}.${keylen}.data.dec`;
        exit(99) if ($?);
        `rm -f rsaoaepencdec.${i}.${keylen}.data.in rsaoaepencdec.${i}.${keylen}.data.out rsaoaepencdec.${i}.${keylen}.data.dec`;

        # no-provider enc, provider dec
        `openssl rand $bytes > rsaoaepencdec.${i}.${keylen}.data.in`;
        `openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$md -pubin -inkey rsa$keylen.pub -in rsaoaepencdec.${i}.${keylen}.data.in -out rsaoaepencdec.${i}.${keylen}.data.out`;
        `$prov openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$md -inkey rsa$keylen.key -in rsaoaepencdec.${i}.${keylen}.data.out -out rsaoaepencdec.${i}.${keylen}.data.dec`;
        `cmp rsaoaepencdec.${i}.${keylen}.data.in rsaoaepencdec.${i}.${keylen}.data.dec`;
        exit(99) if ($?);
        `rm -f rsaoaepencdec.${i}.${keylen}.data.in rsaoaepencdec.${i}.${keylen}.data.out rsaoaepencdec.${i}.${keylen}.data.dec`;
    }

    `rm -f rsa$keylen.key rsa$keylen.pub`;
}

sub rsasignverify {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($keylen, $tests, $input_size) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    `$prov openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$keylen -out rsa$keylen.key`;
    `$prov openssl rsa -in rsa$keylen.key -check -pubout -out rsa$keylen.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        my $bytes = 1 + int(rand($input_size));
        # provider sign, no-provider verify
        `openssl rand $bytes > rsasignverify.${i}.${keylen}.data.in`;
        `$prov openssl pkeyutl -sign -inkey rsa$keylen.key -in rsasignverify.${i}.${keylen}.data.in -out rsasignverify.${i}.${keylen}.data.out`;
        `openssl pkeyutl -verifyrecover -pubin -inkey rsa$keylen.pub -in rsasignverify.${i}.${keylen}.data.out -out rsasignverify.${i}.${keylen}.data.rec`;
        `cmp rsasignverify.${i}.${keylen}.data.in rsasignverify.${i}.${keylen}.data.rec`;
        exit(99) if ($?);
        `rm -f rsasignverify.${i}.${keylen}.data.in rsasignverify.${i}.${keylen}.data.out rsasignverify.${i}.${keylen}.data.rec`;

        # no-provider sign, provider verify
        `openssl rand $bytes > rsasignverify.${i}.${keylen}.data.in`;
        `openssl pkeyutl -sign -inkey rsa$keylen.key -in rsasignverify.${i}.${keylen}.data.in -out rsasignverify.${i}.${keylen}.data.out`;
        `$prov openssl pkeyutl -verifyrecover -pubin -inkey rsa$keylen.pub -in rsasignverify.${i}.${keylen}.data.out -out rsasignverify.${i}.${keylen}.data.rec`;
        `cmp rsasignverify.${i}.${keylen}.data.in rsasignverify.${i}.${keylen}.data.rec`;
        exit(99) if ($?);
        `rm -f rsasignverify.${i}.${keylen}.data.in rsasignverify.${i}.${keylen}.data.out rsasignverify.${i}.${keylen}.data.rec`;
    }

    `rm -f rsa$keylen.key rsa$keylen.pub`;
}

sub rsapsssignverify {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($keylen, $tests, $input_size, $md, $saltlen) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    `$prov openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:$keylen -pkeyopt rsa_pss_keygen_md:$md -pkeyopt rsa_pss_keygen_mgf1_md:$md -pkeyopt rsa_pss_keygen_saltlen:$saltlen -out rsapss$keylen.key`;
    # bug in OpenSSL 3.0: `$prov openssl rsa -in rsapss$keylen.key -check -pubout -out rsapss$keylen.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        my $bytes = 1 + int(rand($input_size));
        # provider sign, no-provider verify
        `openssl rand $bytes > rsapsssignverify.${i}.${keylen}.data.in`;
        `$prov openssl pkeyutl -sign -digest $md -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$saltlen -pkeyopt rsa_mgf1_md:$md -inkey rsapss$keylen.key -rawin -in rsapsssignverify.${i}.${keylen}.data.in -out rsapsssignverify.${i}.${keylen}.data.out`;
        # use pub key: `openssl pkeyutl -verify -digest $md -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$saltlen -pkeyopt rsa_mgf1_md:$md -pubin -inkey rsapss$keylen.pub -rawin -in rsapsssignverify.${i}.${keylen}.data.in -sigfile rsapsssignverify.${i}.${keylen}.data.out`;
        `openssl pkeyutl -verify -digest $md -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$saltlen -pkeyopt rsa_mgf1_md:$md -inkey rsapss$keylen.key -rawin -in rsapsssignverify.${i}.${keylen}.data.in -sigfile rsapsssignverify.${i}.${keylen}.data.out`;
        exit(99) if ($?);
        `rm -f rsapsssignverify.${i}.${keylen}.data.in rsapsssignverify.${i}.${keylen}.data.out`;

        # no-provider sign, provider verify
        `openssl rand $bytes > rsapsssignverify.${i}.${keylen}.data.in`;
        `openssl pkeyutl -sign -digest $md -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$saltlen -pkeyopt rsa_mgf1_md:$md -inkey rsapss$keylen.key -rawin -in rsapsssignverify.${i}.${keylen}.data.in -out rsapsssignverify.${i}.${keylen}.data.out`;
        # use pub key: `$prov openssl pkeyutl -verify -digest $md -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$saltlen -pkeyopt rsa_mgf1_md:$md -pubin -inkey rsapss$keylen.pub -rawin -in rsapsssignverify.${i}.${keylen}.data.in -sigfile rsapsssignverify.${i}.${keylen}.data.out`;
        `$prov openssl pkeyutl -verify -digest $md -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$saltlen -pkeyopt rsa_mgf1_md:$md -inkey rsapss$keylen.key -rawin -in rsapsssignverify.${i}.${keylen}.data.in -sigfile rsapsssignverify.${i}.${keylen}.data.out`;
        exit(99) if ($?);
        `rm -f rsapsssignverify.${i}.${keylen}.data.in rsapsssignverify.${i}.${keylen}.data.out`;
    }

    `rm -f rsapss$keylen.key rsapss$keylen.pub`;
}

sub rsax931signverify {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($keylen, $tests, $input_size, $md) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    `$prov openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$keylen -out rsa$keylen.key`;
    `$prov openssl rsa -in rsa$keylen.key -check -pubout -out rsa$keylen.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        my $bytes = 1 + int(rand($input_size));
        # provider sign, no-provider verify
        `openssl rand $bytes > rsax931signverify.${i}.${keylen}.data.in`;
        `$prov openssl pkeyutl -sign -digest $md -pkeyopt rsa_padding_mode:x931 -inkey rsa$keylen.key -rawin -in rsax931signverify.${i}.${keylen}.data.in -out rsax931signverify.${i}.${keylen}.data.out`;
        `openssl pkeyutl -verify -digest $md -pkeyopt rsa_padding_mode:x931 -pubin -inkey rsa$keylen.pub -rawin -in rsax931signverify.${i}.${keylen}.data.in -sigfile rsax931signverify.${i}.${keylen}.data.out`;
        exit(99) if ($?);
        `rm -f rsax931signverify.${i}.${keylen}.data.in rsax931signverify.${i}.${keylen}.data.out`;

        # no-provider sign, provider verify
        `openssl rand $bytes > rsax931signverify.${i}.${keylen}.data.in`;
        `openssl pkeyutl -sign -digest $md -pkeyopt rsa_padding_mode:x931 -inkey rsa$keylen.key -rawin -in rsax931signverify.${i}.${keylen}.data.in -out rsax931signverify.${i}.${keylen}.data.out`;
        `$prov openssl pkeyutl -verify -digest $md -pkeyopt rsa_padding_mode:x931 -pubin -inkey rsa$keylen.pub -rawin -in rsax931signverify.${i}.${keylen}.data.in -sigfile rsax931signverify.${i}.${keylen}.data.out`;
        exit(99) if ($?);
        `rm -f rsax931signverify.${i}.${keylen}.data.in rsax931signverify.${i}.${keylen}.data.out`;
    }

    `rm -f rsa$keylen.key rsa$keylen.pub`;
}

sub ecsignverify {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($curve, $tests, $input_size, $md) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    # skip if OpenSSL does not support the curve
    `openssl ecparam -list_curves | grep $curve`;
    return if ($?);

    `$prov openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve -out ec$curve.key`;
    `$prov openssl ec -in ec$curve.key -check -pubout -out ec$curve.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        my $bytes = 1 + int(rand($input_size));
        # provider sign, no-provider verify
        `openssl rand $bytes > ecsignverify.${i}.${curve}.data.in`;
        `$prov openssl pkeyutl -sign -digest $md -inkey ec$curve.key -rawin -in ecsignverify.${i}.${curve}.data.in -out ecsignverify.${i}.${curve}.data.out`;
        `openssl pkeyutl -verify -digest $md -pubin -inkey ec$curve.pub -rawin -in ecsignverify.${i}.${curve}.data.in -sigfile ecsignverify.${i}.${curve}.data.out`;
        exit(99) if ($?);
        `rm -f ecsignverify.${i}.${curve}.data.in ecsignverify.${i}.${curve}.data.out`;

        # no-provider sign, provider verify
        `openssl rand $bytes > ecsignverify.${i}.${curve}.data.in`;
        `openssl pkeyutl -sign -digest $md -inkey ec$curve.key -rawin -in ecsignverify.${i}.${curve}.data.in -out ecsignverify.${i}.${curve}.data.out`;
        `$prov openssl pkeyutl -verify -digest $md -pubin -inkey ec$curve.pub -rawin -in ecsignverify.${i}.${curve}.data.in -sigfile ecsignverify.${i}.${curve}.data.out`;
        exit(99) if ($?);
        `rm -f ecsignverify.${i}.${curve}.data.in ecsignverify.${i}.${curve}.data.out`;
    }

    `rm -f ec$curve.key ec$curve.pub`;
}

sub ecderive {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($curve, $tests) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    # skip if OpenSSL does not support the curve
    `openssl ecparam -list_curves | grep $curve`;
    return if ($?);

    `$prov openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve -out ec$curve.key`;
    `$prov openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve -out peer$curve.key`;
    `$prov openssl ec -in peer$curve.key -check -pubout -out peer$curve.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        `$prov openssl pkeyutl -derive -inkey ec$curve.key -peerkey peer$curve.pub -out ecderive.${i}.${curve}.data.out1`;
        `openssl pkeyutl -derive -inkey ec$curve.key -peerkey peer$curve.pub -out ecderive.${i}.${curve}.data.out2`;
        `cmp ecderive.${i}.${curve}.data.out1 ecderive.${i}.${curve}.data.out2`;
        exit(99) if ($?);
        `rm -f ecderive.${i}.${curve}.data.out1 ecderive.${i}.${curve}.data.out2`;
    }

    `rm -f ec$curve.key peer$curve.key peer$curve.pub`;
}

sub ecderivekdf {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($curve, $tests, $outlen, $kdf, $md) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    # skip if OpenSSL does not support the curve
    `openssl ecparam -list_curves | grep $curve`;
    return if ($?);

    `$prov openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve -out ec$curve.key`;
    `$prov openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve -out peer$curve.key`;
    `$prov openssl ec -in peer$curve.key -check -pubout -out peer$curve.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        `$prov openssl pkeyutl -derive -inkey ec$curve.key -peerkey peer$curve.pub -pkeyopt kdf-type:$kdf -pkeyopt kdf-outlen:$outlen -pkeyopt kdf-digest:$md -out ecderive.${i}.${curve}.data.out1`;
        `openssl pkeyutl -derive -inkey ec$curve.key -peerkey peer$curve.pub -pkeyopt kdf-type:$kdf -pkeyopt kdf-outlen:$outlen -pkeyopt kdf-digest:$md -out ecderive.${i}.${curve}.data.out2`;
        `cmp ecderive.${i}.${curve}.data.out1 ecderive.${i}.${curve}.data.out2`;
        exit(99) if ($?);
        `rm -f ecderive.${i}.${curve}.data.out1 ecderive.${i}.${curve}.data.out2`;
    }

    `rm -f ec$curve.key peer$curve.key peer$curve.pub`;
}

sub dhderive {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($group, $tests) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    `$prov openssl genpkey -algorithm DH -pkeyopt group:$group -out dh$group.key`;
    `$prov openssl genpkey -algorithm DH -pkeyopt group:$group -out peer$group.key`;
    `$prov openssl pkey -in peer$group.key -check -pubout -out peer$group.pub`;
    exit(99) if ($?);

    for my $i (1..$tests) {
        `$prov openssl pkeyutl -derive -inkey dh$group.key -peerkey peer$group.pub -out dhderive.${i}.${group}.data.out1`;
        `openssl pkeyutl -derive -inkey dh$group.key -peerkey peer$group.pub -out dhderive.${i}.${group}.data.out2`;
        `cmp dhderive.${i}.${group}.data.out1 dhderive.${i}.${group}.data.out2`;
        exit(99) if ($?);
        `rm -f dhderive.${i}.${group}.data.out1 dhderive.${i}.${group}.data.out2`;
    }

    `rm -f dh$group.key peer$group.key peer$group.pub`;
}

sub dhderivekdf {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($group, $tests, $outlen, $kdf, $md, $cekalg) = @_;

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    `$prov openssl genpkey -algorithm DH -pkeyopt group:$group -out dh$group.key`;
    `$prov openssl genpkey -algorithm DH -pkeyopt group:$group -out peer$group.key`;
    `$prov openssl pkey -in peer$group.key -check -pubout -out peer$group.pub`;
    exit(99) if ($?);


    for my $i (1..$tests) {
        `$prov openssl pkeyutl -derive -inkey dh$group.key -peerkey peer$group.pub -pkeyopt kdf-type:$kdf -pkeyopt kdf-outlen:$outlen -pkeyopt kdf-digest:$md -pkeyopt cekalg:$cekalg -out dhderive.${i}.${group}.data.out1`;
        `openssl pkeyutl -derive -inkey dh$group.key -peerkey peer$group.pub -pkeyopt kdf-type:$kdf -pkeyopt kdf-outlen:$outlen -pkeyopt kdf-digest:$md  -pkeyopt cekalg:$cekalg -out dhderive.${i}.${group}.data.out2`;
        `cmp dhderive.${i}.${group}.data.out1 dhderive.${i}.${group}.data.out2`;
        exit(99) if ($?);
        `rm -f dhderive.${i}.${group}.data.out1 dhderive.${i}.${group}.data.out2`;
    }

    `rm -f dh$group.key peer$group.key peer$group.pub`;
}

sub tls {
    my $prov = "OPENSSL_CONF=$ENV{IBMCA_OPENSSL_TEST_CONF} OPENSSL_MODULES=$ENV{IBMCA_TEST_PATH}";

    my ($port, $privkey, $cert, $cipher, $ciphersuites, $opts) = @_;
    my ($pid, $ret);

    `$prov openssl list -providers | grep "name: ibmca"`;
    exit(99) if ($?);

    `$prov openssl s_server -accept $port -naccept 1 -brief -cert $cert -key $privkey -cipher $cipher -ciphersuites $ciphersuites $opts 1>server-$port.out 2>&1 &`;
    sleep 1;
    `echo "Hello World" | $prov openssl s_client -connect localhost:$port -cipher $cipher -ciphersuites $ciphersuites $opts`;
    $ret = $?;
    sleep 1;
   `killall openssl`;
    exit(99) if ($ret);

   `rm -f server-$port.out`;
}

`bash -c unset OPENSSL_CONF`;
`bash -c unset OPENSSL_MODULES`;

1;
