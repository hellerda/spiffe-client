# Overview

```spiffe-client``` is a simple SPIRE Workload API client that provides similar functionality to the SPIRE Agent ```api fetch``` command.  It can fetch an x509 or JWT SVID and display the results to stdout or write the individual artifacts to disk.  It can also display a summary of the workload's assigned Spiffe ID and x509 cert chain.  It works by retrieving a ```JWTSource``` or ```X509Source``` from the Workload API and performing the fetch operations directly.  You can deploy the tool wherever you need a simple SPIRE test tool, or need to fetch SVIDs and bundles for a workload to consume.  The project builds the single binary ```spiffe-client``` , and can build a simple Docker container to run it.

Based on the SPIFFE [go-spiffe (v2) Examples](https://github.com/spiffe/go-spiffe/tree/main/v2/examples).


# Usage
```
$ spiffe-client -help
Usage of spiffe-client:
  -audience string
        The audience to pass to the the JWT claim (default "CI")
  -dumpbundle
        for x509 SVID: Dump Bundle cert(s) to stdout
  -dumpcert string
        for x509 SVID: Dump specified cert(s) to stdout
  -dumpjwthdr
        for JWT SVID: Dump the token header to stdout
  -dumpjwtpay
        for JWT SVID: Dump the token payload to stdout
  -dumpjwtsig
        for JWT SVID: Dump the (binary) token signature to stdout
  -dumpkey
        for x509 SVID: Dump privkey to stdout
  -fetch string
        Fetch an x509 or JWT SVID from SPIRE (default "x509")
  -outform string
        Output PEM or DER format for -dumpcert (default "PEM")
  -socketAddr string
        TCP address to connect to the SPIRE Agent API, in the form of "IP:PORT"
  -socketPath string
        Path to the SPIRE Agent API socket (default: "/tmp/spire-agent/public/api.sock")
  -v    Show more details (verbose)
```


# Build

To build the binary:
```
make
```

### Other build options
```
make stripped
make static
make static-and-stripped
```

### Remove the binary
```
make clean
```

### Build Docker container
```
make image
```


# Examples

## Helpful examples

**Example:** Running ```spiffe-client``` with no options will display a summary of the workload's assigned Spiffe ID and x509 cert chain:
```
$ spiffe-client
- SPIFFE ID = spiffe://example.org/myworkload
- TrustDomain = example.org
- Cert[0] Subject = O=SPIRE,C=US
- Cert[0] Issuer = OU=DOWNSTREAM-2,O=SPIFFE,C=US
- Cert[1] Subject = OU=DOWNSTREAM-2,O=SPIFFE,C=US
- Cert[1] Issuer = O=SPIFFE,C=US
- Cert[2] Subject = O=SPIFFE,C=US
- Cert[2] Issuer = CN=upstream-authority.example.org
```

**Example:** To dump the JSON header and payload of your workload's SPIRE-issued JWT token:
```
$ spiffe-client -fetch JWT -audience "blah" -dumpjwthdr
{"alg":"RS256","kid":"WQyuxjnLRYaIpAqUMKdKVPFkPRxNQBhF","typ":"JWT"}

$ spiffe-client -fetch JWT -audience "blah" -dumpjwtpay
{"aud":["blah"],"exp":1666115709,"iat":1666115409,"iss":"https://oidc.spire.mydomain.com","sub":"spiffe://example.org/nestedc-workload-ec2"}
```

**Example:** Display a text summary of each cert in your workload's cert chain:
```
$ spiffe-client -fetch x509 -dumpcert 0 -outform pem | openssl x509 -noout -text | egrep "[[:upper:]]"
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=SPIFFE, OU=DOWNSTREAM-2
        Validity
            Not Before: Oct 18 17:42:55 2022 GMT
            Not After : Oct 18 18:18:19 2022 GMT
        Subject: C=US, O=SPIRE
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Key Agreement
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                1A:6A:AF:1C:F1:DC:6E:42:7C:48:98:85:A9:44:F7:22:03:C9:2B:C2
            X509v3 Authority Key Identifier:
                keyid:84:31:64:C0:2F:98:91:07:73:76:FB:E7:5B:CE:C3:8F:33:6E:F4:45
            X509v3 Subject Alternative Name:
                URI:spiffe://example.org/nestedc-workload-ec2
    Signature Algorithm: sha256WithRSAEncryption

$ spiffe-client -fetch x509 -dumpcert 1 -outform pem | openssl x509 -noout -text | egrep "[[:upper:]]"
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=SPIFFE
        Validity
            Not Before: Oct 18 17:18:09 2022 GMT
            Not After : Oct 18 18:18:19 2022 GMT
        Subject: C=US, O=SPIFFE, OU=DOWNSTREAM-2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                84:31:64:C0:2F:98:91:07:73:76:FB:E7:5B:CE:C3:8F:33:6E:F4:45
            X509v3 Authority Key Identifier:
                keyid:78:FD:3C:E0:BD:DC:93:42:A9:31:2B:31:56:94:80:DF:AE:36:7E:F3
            X509v3 Subject Alternative Name:
                URI:spiffe://example.org
    Signature Algorithm: ecdsa-with-SHA256

$ spiffe-client -fetch x509 -dumpcert 2 -outform pem | openssl x509 -noout -text | egrep "[[:upper:]]"
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=upstream-authority.example.org
        Validity
            Not Before: Oct 17 23:44:22 2022 GMT
            Not After : Oct 18 23:44:32 2022 GMT
        Subject: C=US, O=SPIFFE
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                78:FD:3C:E0:BD:DC:93:42:A9:31:2B:31:56:94:80:DF:AE:36:7E:F3
            X509v3 Authority Key Identifier:
                keyid:76:7F:4A:4E:38:98:0B:2D:5A:FC:BF:5C:27:C4:F0:B2:F0:A3:D1:95
            X509v3 Subject Alternative Name:
                URI:spiffe://example.org
    Signature Algorithm: ecdsa-with-SHA256
```

**Example:** Likewise for the workload's top-level, root certificate:
```
$ spiffe-client -fetch x509 -dumpbundle -outform pem | openssl x509 -noout -text | egrep "[[:upper:]]"
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=upstream-authority.example.org
        Validity
            Not Before: Jun 30 23:44:15 2022 GMT
            Not After : Jun 27 23:44:15 2032 GMT
        Subject: CN=upstream-authority.example.org
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                76:7F:4A:4E:38:98:0B:2D:5A:FC:BF:5C:27:C4:F0:B2:F0:A3:D1:95
            X509v3 Authority Key Identifier:
                keyid:76:7F:4A:4E:38:98:0B:2D:5A:FC:BF:5C:27:C4:F0:B2:F0:A3:D1:95
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Alternative Name:
                URI:spiffe://example.org
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
    Signature Algorithm: ecdsa-with-SHA256
```

## Other command-line examples

**Example:** To dump the full x509 SVID cert chain and root CA cert in PEM format (the default):
```
$ spiffe-client -fetch x509 -dumpcert all
$ spiffe-client -fetch x509 -dumpbundle
```

**Example:** To dump the SVID key in PEM or DER format:
```
$ spiffe-client -fetch x509 -dumpkey
$ spiffe-client -fetch x509 -dumpkey -outform der
```

**Example:** The equivalent of a ```spire-agent api fetch x509``` command:
```
$ spiffe-client -fetch x509 -dumpkey > svid.0.key
$ spiffe-client -fetch x509 -dumpcert all > svid.0.pem
$ spiffe-client -fetch x509 -dumpbundle > bundle.0.pem
```

**Example:** Dump the base64-encoded JWT SVID to stdout:
```
$ spiffe-client -fetch JWT
```

**Example:** Dump the JWT SVID components individually to stdout.  Note the signature is in binary:
```
$ spiffe-client -fetch JWT -dumpjwthdr
$ spiffe-client -fetch JWT -dumpjwtpay
$ spiffe-client -fetch JWT -dumpjwtsig | xxd -p
```

# Accessing the SPIRE Agent socket

The workload typically accesses the SPIRE Agent socket over a Unix domain socket (UDS).  The default path is ```/tmp/spire-agent/public/api.sock```.  To access the socket over a different path:
```
$ spiffe-client -socketPath /run/spire/sockets/agent.sock
```

In cases where the UDS cannot be made directly available to the workload (e.g. to a container in a different process namespace), the workload can alternately access the SPIRE Agent over a TCP socket, using the ```-socketAddr``` option to access the address.  The address is of the form "IP:PORT", where the IP is optional and defaults to "127.0.0.1", and the PORT is required (no default).  The following forms are valid:

```
$ spiffe-client -socketAddr 127.0.0.1:1234
$ spiffe-client -socketAddr :1234
```

If this option is specified it overrides the ```-socketPath``` option.

The SPIRE Agent is not able to host a TCP port directly; to do this you must front the UDS with a TCP proxy:  To use an SSH tunnel:
```
$ ssh -R 1234:/tmp/spire-agent/public/api.sock user@localhost
```

To use ```socat```:
```
$ socat TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/tmp/spire-agent/public/api.sock
```
Note this method does not perform true workload attestation; the attested process will always be the local proxy, not the end workload.  This should only be done on an isolated network where the intended workload will be the only process able to access the agent TCP port.


# Limitations

1. Does not handle multiple SVIDs assigned to a workload
2. Does not support federated bundles
