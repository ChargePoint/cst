// SPDX-License-Identifier: BSD-3-Clause
/*===========================================================================*/
/**
    @file    eng_backend.c

    @brief   An engine backend for Code-Signing Tool.

@verbatim
=============================================================================

    Copyright 2021 NXP

=============================================================================
@endverbatim */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/

/* Standard includes */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <adapt_layer.h>

/* Library Openssl includes */
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/engine.h>

#include "openssl_helper.h"
#include "eng_backend.h"

/*=======================================================================+
 LOCAL FUNCTION IMPLEMENTATIONS
 =======================================================================*/

/*--------------------------
 ctx_new
 ---------------------------*/
ENGINE_CTX *ctx_new()
{
    ENGINE_CTX *ctx;
    ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
    return ctx;
}

/*--------------------------
 ctx_destroy
 ---------------------------*/
int32_t ctx_destroy(ENGINE_CTX *ctx)
{
    if (ctx) {
        ENGINE_free(ctx->engine);
        OPENSSL_free(ctx);
    }
    return 1;
}

/*--------------------------
 ctx_init
 ---------------------------*/
int32_t ctx_init(ENGINE_CTX *ctx)
{
    /* OpenSSL Initialization */
#if OPENSSL_VERSION_NUMBER>=0x10100000
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
        | OPENSSL_INIT_ADD_ALL_DIGESTS \
        | OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
    OPENSSL_config(NULL);
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();
#endif

    ERR_clear_error();

    ENGINE_load_builtin_engines();

    ctx->engine = ENGINE_by_id("pkcs11");

    if(ctx->engine == NULL)
        return 0;

#ifdef DEBUG
    ENGINE_ctrl_cmd_string(ctx->engine, "VERBOSE", NULL, 0);
#endif

    if (!ENGINE_init(ctx->engine)) {
        ENGINE_free(ctx->engine);
        return 0;
    }
    return 1;
}

/*--------------------------
 ctx_finish
 ---------------------------*/
int32_t ctx_finish(ENGINE_CTX *ctx)
{
    if (ctx) {
        ENGINE_finish(ctx->engine);
    }
    return 1;
}

/*--------------------------
 ENGINE_load_certificate
 ---------------------------*/
X509 *ENGINE_load_certificate (ENGINE * e, const char *cert_ref)
{
    struct {
        const char *s_slot_cert_id;
        X509 *cert;
    } params = {0};

    params.s_slot_cert_id = cert_ref;
    params.cert = NULL;
    if (!ENGINE_ctrl_cmd (e, "LOAD_CERT_CTRL", 0, &params, NULL, 1)) {
        ERR_print_errors_fp (stderr);
        return NULL;
    }

  return params.cert;
}
