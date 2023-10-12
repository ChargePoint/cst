/*===========================================================================*/
/**
    @file    cert.c

    @brief   Implements certificate content reading API.
    The implementation of this API can be overloaded to read certificate
    from a Hardware Security Module (HSM).

@verbatim
=============================================================================

              Freescale Semiconductor
        (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.
		Copyright 2020, 2022 NXP

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=============================================================================
@endverbatim */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl_helper.h"

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
  ssl_read_certificate
---------------------------*/
X509*
ssl_read_certificate(const char* filename)
{
    BIO  *bio_cert = NULL; /**< OpenSSL BIO ptr */
    X509 *cert = NULL;     /**< X.509 certificate data structure */
    FILE *fp = NULL;       /**< File pointer for DER encoded file */
    /** Points to expected location of ".pem" filename extension */
    const char *temp = filename + strlen(filename) -
                       PEM_FILE_EXTENSION_BYTES;

    bio_cert = BIO_new(BIO_s_file());
    if (bio_cert == NULL)
    {
        return NULL;
    }

    /* PEM encoded */
    if (!strncasecmp(temp, PEM_FILE_EXTENSION, PEM_FILE_EXTENSION_BYTES))
    {
        if (BIO_read_filename(bio_cert, filename) <= 0)
        {
            BIO_free(bio_cert);
            return NULL;
        }

        cert = PEM_read_bio_X509(bio_cert, NULL, 0, NULL);
    }
    /* DER encoded */
    else
    {
        /* Open the DER file and load it into a X509 object */
        fp = fopen(filename, "rb");
        if (NULL == fp) return NULL;
        cert = d2i_X509_fp(fp, NULL);
        fclose(fp);
    }

    BIO_free(bio_cert);
    return cert;
}
