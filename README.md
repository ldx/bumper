Bumper
======

[![Build Status](https://travis-ci.org/ldx/bumper.svg?branch=master)](https://travis-ci.org/ldx/bumper)

Introduction
------------

Bumper is a simple HTTP proxy with SSL/TLS man-in-the-middle capabilities.

The main use case is to make any caching proxy be able to cache HTTPS requests via terminating the SSL/TLS connection in Bumper, and sending the plain non-encrypted request to a parent proxy. Bumper will generate new SSL certificates for websites on the fly when the first HTTPS request for that URL is received. Since generating certificates is a CPU-heavy task, certificates will be cached in a directory, and when Bumper is restarted, it will read in certificate/private key pairs from this directory.

Another use case is if you want to study the requests going to a particular website from your browser. Since Bumper terminates the SSL/TLS connection browsers start via HTTP CONNECT, all requests and responses wrapped inside the CONNECT tunnel will be observable. Bumper will log each request/response to standard output. In this case, you don't need a parent proxy, Bumper will take care of performing requests.

Options
-------
- `-d, --certdir=<directory>`    Directory where generated certificates are stored. When Bumper is restarted, it will read in certificate/private key pairs from this directory. Filenames are always `<Website FQDN>.crt` for certificates, and `<Website FQDN>.key` for private keys.
- `-c, --cacert=<file>`          CA certificate file for generating certificates. This certificate will be used to sign website certificates created by Bumper. If you want to avoid browser warnings, you will need to import this certificate into your browser as a trusted CA certificate.
- `-k, --cakey=<file>`           CA private key file for generating and signing website certificates.
- `-p, --proxy=<host:port>`      HTTP parent proxy to use for all requests (both HTTP and HTTPS). This is probably a caching proxy. Optional, if not specified, Bumper will take care of performing requests without a parent proxy.
- `-n, --skipverify`             If set, BumperProxy will not verify the certificate of HTTPS websites. (default: false)
- `-l, --listen=<host:port>`     Host and port where Bumperproxy will be listening. (default: localhost:9718)
- `-x, --addxoriguri`            If set, BumperProxy will add an X-Orig-Uri header with the original URI to requests. This is mostly useful when using Varnish, see below. (default: false)
- `-v, --verbose`                Enable verbose logging.

Examples
--------

Using Bumper to log requests, even when HTTPS is used:

    $ ./bumper -c cybervillains.crt -k cybervillains.key -d ~/.bumper

The files `cybervillains.crt` and `cybervillains.key` are a self-signed CA private key and certificate. You may want to import `cybervillains.crt` into your browser to prevent security warnings about untrusted sites and certificates.

Forward all requests to an upstream proxy, adding an X-Orig-Uri header with the original URL in the request and disabling website certificate verification:

    $ ./bumper -d /tmp/certs/ -c cybervillains.crt -k cybervillains.key -x -p localhost:6081 -n
