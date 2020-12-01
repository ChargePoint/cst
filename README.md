# Chargepoint Modifications to NXP CST for CloudHSM Support

This repository contains a tarball dump of the NXP Code Signer Tool (v3.3.1),
and modifications to support AWS CloudHSM integration.

## Summary of Changes

### Modifications to back end engine

The source in "code/back_end-engine" was modified to read a certificate and
"fake" private key directly from the filesystem in PEM format prior to signing.
It is expected that the certificate and "fake" private key files will be
generated from CloudHSM prior to running the CST.

Additional Documentation on the CST "back_end-engine":

https://www.nxp.com/docs/en/application-note/AN12812.pdf

### Specify Directory of keys

An environment variable ("KEY_DIR) was added to allow the root directory of keys
to be specified.  If not set any signing attempt will fail.

## Build CST for CloudHSM

```bash
cd ${GITROOT}/code/cst && \
        OSTYPE=linux64 make rel_bin
cd ${GITROOT} && \
        mkdir -p linux64/lib && \
        cp -a code/cst/code/obj.linux64/libfrontend.a \
                linux64/lib/libfrontend.a
cd ${GITROOT}/code/back_end-engine/src && make
```

## CST Usage Example

```bash
KEY_DIR=/keys/uboot/exampleboard /opt/local/bin/cst \
        -i /keys/uboot/exampleboard/u-boot-srk1.csf \
        -o /artifacts/u-boot.csf.signed
```
