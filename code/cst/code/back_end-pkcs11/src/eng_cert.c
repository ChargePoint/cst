// SPDX-License-Identifier: BSD-3-Clause
/*===========================================================================*/
/**
    @file    eng_cert.c

    @brief   Provide functions to read certificate from token.

@verbatim
=============================================================================

    Copyright 2021-2022 NXP

=============================================================================
@endverbatim */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdint.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "openssl_helper.h"
#include "pkcs11_backend.h"
#include "eng_backend.h"

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
  pkcs11_read_certificate
---------------------------*/
X509*
pkcs11_read_certificate(const char* cert_ref)
{
    /* Engine configuration */
    ENGINE_CTX *ctx = NULL;

    /* Certificate */
    X509 *cert = NULL;

     /* Operation completed successfully */
    int32_t error = CAL_SUCCESS;

    /* Check for valid arguments */
    if (!cert_ref) {
       return NULL;
    }

    /* Allocate new context */
    ctx = ctx_new();

    if(!ctx){
        error = CAL_CRYPTO_API_ERROR;
        goto out;
    }

    /* Initialize the context */
    if(!ctx_init(ctx)){
        error = CAL_CRYPTO_API_ERROR;
        goto out;
    }

    cert = ENGINE_load_certificate (ctx->engine, cert_ref);
    if (!cert)
    {
        error = CAL_CRYPTO_API_ERROR;
        goto out;
    }

#ifdef DEBUG
    X509_print_fp(stdout, cert);
#endif

out:
    if(ctx) {

   /* Destroy the context: ctx_finish is not called here since
	* ENGINE_finish cleanups the engine instance. Calling ctx_destroy
	* next will lead to null pointer dereference. */
        ctx_destroy(ctx);
    }

    if (error)
        ERR_print_errors_fp(stderr);

    return cert;
}
