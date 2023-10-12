/*
   Copyright 2022 NXP
   SPDX-License-Identifier: BSD-3-Clause

   ===========================================================================

   @file    ssl_backend.h

   ===========================================================================
 */
#include <adapt_layer.h>

int32_t
ssl_gen_sig_data(const char *in_file,
                 const char *cert_file,
                 hash_alg_t hash_alg,
                 sig_fmt_t sig_fmt,
                 uint8_t *sig_buf,
                 size_t *sig_buf_bytes,
                 func_mode_t mode);

X509*
ssl_read_certificate(const char* filename);
