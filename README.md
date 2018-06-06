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

Included in this package there is a sample `openssl.cnf` file
(`openssl.cnf.sample`), which can be used to turn on use of the IBMCA engine in
apps where OpenSSL config support is compiled in.

In order to enable IBMCA, use the following instructions to apply the
configurations from `openssl.cnf.sample` to the `openssl.cnf` file installed
in the host by the OpenSSL package. **WARNING:** you may want to save the
original `openssl.cnf` file before changing it.

In `openssl.cnf.sample`, the *dynamic_path* variable is set to the default
location, which is `/usr/local/lib/ibmca.so` by default. However, if the
ibmca.so library has been installed anywhere else, then update the
*dynamic_path* variable.

Locate where the `openssl.cnf` file has been installed in the host and append
the content of the `openssl.cnf.sample` file to it.

```
$ rpm -ql openssl | grep openssl.cnf
$ cat openssl.cnf.sample >> /path/to/openssl.cnf
```

In `openssl.cnf` file, move the *openssl_conf* variable from the bottom to the
top of the file, such as in the example below:

```
HOME = .
RANDFILE = $ENV::HOME/.rnd
openssl_conf = openssl_def
```

Finally, check if the IBMCA is now enabled. The command below should return the
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
