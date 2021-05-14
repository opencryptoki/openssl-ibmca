#!/usr/bin/perl

#
# Generate sample openssl.cnfs from the system config file.
#
# Generated configs:
# - openssl.cnf.defaultlibica
#    Use engine with default library (as configured during configure)
# - openssl.cnf.libica
#    Use engine with libica from system path
# - openssl.cnf.libica-cex
#    Use engine with libica-cex from system path
#

sub printall($$$$)
{
    my ($oh1, $oh2, $oh3, $line) = @_;

    print $oh1 "$line";
    print $oh2 "$line";
    print $oh3 "$line";
}

sub generate($)
{
    my $libdir = shift;
    my $osslconfpath = "N/A";
    my ($tmp, $ih, $line, $oh1, $oh2, $oh3, $defaultcnfsect);

    $tmp = `openssl version -d`;
    if ($tmp =~/OPENSSLDIR: \"([^\"]*)\"/) {
	$osslconfpath = $1;
    }
    if ($osslconfpath eq "N/A") {
	die("Could not retrieve OpenSSL configuration");
    }

    open($ih, "<", "$osslconfpath/openssl.cnf") or die "Cannot open $osslconfpath/openssl.cnf";
    open($oh1, ">", "openssl.cnf.defaultlibica") or die "Cannot open openssl.cnf.defaultlibica";
    open($oh2, ">", "openssl.cnf.libica") or die "Cannot open openssl.cnf.libica";
    open($oh3, ">", "openssl.cnf.libica-cex") or die "Cannot open openssl.cnf.libica-cex";

    $defaultcnfsect = undef;
    while ($line = <$ih>) {
	if ($line =~ /openssl_conf\s*=\s*(.*)/) {
	    $defaultcnfsect = $1;
	}
	printall($oh1, $oh2, $oh3, "$line");
	if (defined($defaultcnfsect) && $line =~ /\[\s*$defaultcnfsect\s*\]/) {
	    printall($oh1, $oh2, $oh3, "\nengines = engine_section\n");
	}
    }
    printall($oh1, $oh2, $oh3, qq|
[engine_section]
ibmca = ibmca_section

[ibmca_section]
# The openssl engine path for ibmca.so.
# Set the dynamic_path to where the ibmca.so engine
# resides on the system.
dynamic_path = $libdir/ibmca.so
engine_id = ibmca
|);
    
    print $oh2 "libica = libica.so.3";
    print $oh3 "libica = libica-cex.so.3";
    printall($oh1, $oh2, $oh3, qq|
init = 1

#
# The following ibmca algorithms will be enabled by these parameters
# to the default_algorithms line. Any combination of these is valid,
# with "ALL" denoting the same as all of them in a comma separated
# list.
#
# RSA
# - RSA encrypt, decrypt, sign and verify, key lengths 512-4096
#
# DH
# - DH key exchange
#
# DSA
# - DSA sign and verify
#
# RAND
# - Hardware random number generation
#
# ECDSA (OpenSSL < 1.1.0)
# - Elliptic Curve DSA sign and verify
#
# ECDH (OpenSSL < 1.1.0)
# - Elliptic Curve DH key exchange
#
# EC (OpenSSL >= 1.1.0)
# - Elliptic Curve DSA sign and verify, Elliptic Curve DH key exchange
#
# CIPHERS
# - DES-ECB, DES-CBC, DES-CFB, DES-OFB,
#   DES-EDE3, DES-EDE3-CBC, DES-EDE3-CFB, DES-EDE3-OFB,
#   AES-128-ECB, AES-128-CBC, AES-128-CFB, AES-128-OFB, id-aes128-GCM,
#   AES-192-ECB, AES-192-CBC, AES-192-CFB, AES-192-OFB, id-aes192-GCM,
#   AES-256-ECB, AES-256-CBC, AES-256-CFB, AES-256-OFB, id-aes256-GCM ciphers
#
# DIGESTS
# - SHA1, SHA256, SHA512 digests
#
# PKEY_CRYPTO
# - X25519, X448, ED25519, ED448
#default_algorithms = ALL
default_algorithms = PKEY_CRYPTO,RAND,RSA,DH,DSA,EC
|);
    close($ih);
    close($oh1);
    close($oh2);
    close($oh3);
}

generate($ARGV[0]);
