# OpenSSL-ibmca

OpenSSL engine that uses the libica library under s390x to accelerate
cryptographic operations.


## Requirements

The build requirements are:
 * openssl-devel >= 0.9.8
 * libica-devel >= 3.3.0
 * autoconf
 * automake
 * libtool

The runtime requirements are:
 * openssl >= 0.9.8
 * libica >= 3.3.0


## Installing

```
$ ./configure [--enable-debug]
$ make
$ sudo make install
```

This will configure, build and install the package in a default location,
which is `/usr/local/lib`. It means that the ibmca.so will be installed in
`/usr/local/lib/ibmca.so` by default. If you want to install it anywhere
else, run "configure" passing the new location via prefix argument, for
example:

```
$ ./configure --prefix=/usr --libdir=/usr/lib64/openssl/engines
```

## Enabling IBMCA

Apps with compiled-in OpenSSL config support can enable the engine via
an OpenSSL configuration file. Refer to config(5). A sample OpenSSL
configuration file (`openssl.cnf.sample`) is included in this package.

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


## Support

To report a bug please submit a
 [ticket](https://github.com/opencryptoki/openssl-ibmca/issues) including the
 following information in the issue description:

* bug description
* distro release
* openssl-ibmca package version
* libica package version
* steps to reproduce the bug

Regarding technical or usage questions, send email to
 [opencryptoki-tech](
    https://sourceforge.net/p/opencryptoki/mailman/opencryptoki-tech) or
 [opencryptoki-users](
    https://sourceforge.net/p/opencryptoki/mailman/opencryptoki-users)
 mailing list respectively.


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
