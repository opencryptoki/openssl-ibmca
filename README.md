# OpenSSL-ibmca

OpenSSL engine and provider that uses the libica library under s390x to
accelerate cryptographic operations.


## Requirements

The build requirements are:
 * openssl-devel >= 0.9.8
 * openssl-devel >= 3.0.0 for building the IBMCA provider
 * libica-devel >= 3.3.0
 * libica-devel >= 3.6.0 or >= 4.0.1 for building the IBMCA provider
 * autoconf
 * automake
 * libtool
 * openssl
 * perl

The runtime requirements are:
 * openssl >= 0.9.8
 * openssl-devel >= 3.0.0 for using the IBMCA provider
 * libica >= 3.3.0
 * libica >= 3.6.0 or >= 4.0.1 for using the IBMCA provider


## Installing

```
$ ./configure [--enable-debug] [--disable-engine] [--disable-provider]
$ make
$ sudo make install
```

This will configure, build and install the package in a default location,
which is `/usr/local/lib`. It means that the engine ibmca.so and the provider
ibmca-provider.so will be installed in `/usr/local/lib/` by default.
If you want to install it anywhere else, run "configure" passing the new
location via prefix argument, for example:

```
$ ./configure --prefix=/usr --disable-provider --libdir=/usr/lib64/openssl/engines
```

or

```
$ ./configure --prefix=/usr --disable-engine --libdir=/usr/lib64/ossl-modules
```

Additionally, at configure time, you can specify to build the engine against the
libica-cex version via the `--with-libica-cex` feature switch.  If
this switch is not specified, the engine will use the full version of
libica by default.

To specify the version of libica for the engine, use
`--with-libica-version=<version>`.  The default version is version 4
of libica.  To build the engine against version 3 of libica, specify
`--with-libica-version=3` at configure time.

The provider uses the libica-cex version of libica by default. To build
the provider against the full version of libica specify the
`--with-provider-libica-full` feature switch. There is no functional
difference when the provider is built against the full version of libica.
The provider requires libica version 4, it can not be built with an older
libica version.

The provider requires OpenSSL 3.0 or later to be built. If OpenSSL 3.0 is
not availale, then the provider is automatically disabled.
When OpenSSL 3.0 is available, by default both, the engine as well as the
provider are built. You can disable the engine or the provider with the
`----disable-engine` or `----disable-provider` switch.

There are 2 RPM spec files contained in this package:
`openssl-ibmca.spec` and `openssl-ibmca-provider.spec`. The first one builds
only the engine and installs it into OpenSSL's engine directory. The second
one builds only the provider and install it into OpenSSL's modules directory.

We leave it to the distributions to produce an RPM that contains both, engine
and provider, if wanted. You can only specify one installation directory with
the `--libdir` configure option, but providers and engines need to be installed
into different locations. To achieve this, the engine and provider shared objects
must be moved by subsequent commands to the correct location after
`make install` has been performed.


## Enabling IBMCA

Apps with compiled-in OpenSSL config support can enable the engine or provider
via an OpenSSL configuration file. Refer to config(5). Sample OpenSSL
configuration files (`openssl.cnf.sample` and `openssl.cnf.provider.sample`)
are included in this package.

If the engine is configured properly, the command below should return the
IBMCA engine and all the supported cryptographic methods.

```
$ openssl engine -c
(dynamic) Dynamic engine loading support
(ibmca) Ibmca hardware engine support
[RAND, DES-ECB, DES-CBC, DES-OFB, DES-CFB, DES-EDE3, DES-EDE3-CBC, DES-EDE3-OFB,
 DES-EDE3-CFB, AES-128-ECB, AES-192-ECB, AES-256-ECB, AES-128-CBC, AES-192-CBC,
 AES-256-CBC, AES-128-OFB, AES-192-OFB, AES-256-OFB, AES-128-CFB, AES-192-CFB,
 AES-256-CFB, id-aes128-GCM, id-aes192-GCM, id-aes256-GCM, SHA1, SHA256, SHA512]
$
```

If the provider is configured properly, the command below should return the
IBMCA provider.

```
$ openssl list -providers
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.1.0
    status: active
  ibmca
    name: ibmca
    version: 1.1.0
    status: active
$
```

You can list the cryptographic methods implemented by the activated providers
as follows:

```
$ openssl list -key-managers
...
  Name: IBMCA RSA implementation
    Type: Provider Algorithm
    IDs: { 1.2.840.113549.1.1.1, 2.5.8.1.1, RSA, rsaEncryption } @ ibmca
  Name: IBMCA DH implementation
    Type: Provider Algorithm
    IDs: { 1.2.840.113549.1.3.1, DH, dhKeyAgreement } @ ibmca
  Name: IBMCA EC implementation
    Type: Provider Algorithm
    IDs: { 1.2.840.10045.2.1, EC, id-ecPublicKey } @ ibmca
  Name: IBMCA RSA-PSS implementation
    Type: Provider Algorithm
    IDs: { 1.2.840.113549.1.1.10, RSA-PSS, RSASSA-PSS, rsassaPss } @ ibmca
  Name: IBMCA DHX implementation
    Type: Provider Algorithm
    IDs: { 1.2.840.10046.2.1, dhpublicnumber, DHX, X9.42 DH } @ ibmca
...
$ openssl list -signature-algorithms
...
  { 1.2.840.113549.1.1.1, 2.5.8.1.1, RSA, rsaEncryption } @ ibmca
  ECDSA @ ibmca
...
$ openssl list -asymcipher-algorithms
...
  { 1.2.840.113549.1.1.1, 2.5.8.1.1, RSA, rsaEncryption } @ ibmca
...
$ openssl list -key-exchange-algorithms
...
  { 1.2.840.113549.1.3.1, DH, dhKeyAgreement } @ ibmca
  ECDH @ ibmca
....
$
```

## Configuring OpenSSL-ibmca

Since libica 3.8.0, libica provides two libraries.  The basic
libica.so.3 contains all the features listed above and is the default
library unless the `configure` switch `--with-libica-cex` is provided.
In that case, libica-cex.so.4 becomes the default library.  If both
versions of the library are installed on a system, OpenSSL-ibmca can
be configured to use either of these two.  To use `libica.so.4`, with
OpenSSL-ibmca, simply add the directive `libica = libica.so.4` to your
OpenSSL configuration file in the engine section before `init = 1`.
Similarly, to use `libica-cex.so.4`, add the line
`libica = libica-cex.so.4`.

The build process of OpenSSL-ibmca will produce the scripts
`ibmca-engine-opensslconfig` and `ibmca-provider-opensslconfig` which can be
used to update an existing OpenSSL configuration to enable the OpenSSL-ibmca
engine or provider.  By default, these scripts are not installed.  We leave it
to the distributions to find the correct place for these scripts (or not use
them at all).

## Support

To report a bug please submit a
 [ticket](https://github.com/opencryptoki/openssl-ibmca/issues) including the
 following information in the issue description:

* bug description
* distro release
* openssl-ibmca package version
* libica package version
* OpenSSL package version
* steps to reproduce the bug

Regarding technical or usage questions, also submit a
 [ticket](https://github.com/opencryptoki/openssl-ibmca/issues).

## Limitations

The ibmca engine's cipher and digest implementations do not
support the processing of messages in arbitrary chunk sizes.
All chunks, except the final one, are required to be a multiple
of the primitive's block size.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
