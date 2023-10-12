/*
   Copyright 2022 NXP
   SPDX-License-Identifier: BSD-3-Clause

   ===========================================================================

   @file    pkcs11_backend.h

   ===========================================================================
 */
#ifndef PKCS11_BACKEND_H
#define PKCS11_BACKEND_H

#include <adapt_layer.h>

int32_t
pkcs11_gen_sig_data(const char *in_file, const char *cert_ref,
                    hash_alg_t hash_alg, sig_fmt_t sig_fmt,
                    uint8_t *sig_buf, size_t *sig_buf_bytes,
                    func_mode_t mode);

X509*
pkcs11_read_certificate(const char *cert_ref);

#endif /* PKCS11_BACKEND_H */
