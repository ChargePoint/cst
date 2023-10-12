// SPDX-License-Identifier: BSD-3-Clause
/*===========================================================================*/
/**
    @file    eng_cms.c

    @brief  Provide misc. functions to handle Cryptographic Message
	        Syntax

@verbatim
=============================================================================

    Copyright 2021 NXP

=============================================================================
@endverbatim */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdint.h>
#include <openssl/cms.h>
#include "eng_backend.h"

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
 cms_to_buf
 ---------------------------*/
int32_t
cms_to_buf (CMS_ContentInfo * cms, BIO * bio_in, uint8_t * data_buffer,
            size_t * data_buffer_size, int32_t flags)
{
    int32_t err_value = CAL_SUCCESS;
    BIO *bio_out = NULL;
    BUF_MEM *buffer_memory;    /**< Used with BIO functions */

    buffer_memory = BUF_MEM_new ();
    buffer_memory->length = 0;
    buffer_memory->data = (char *) data_buffer;
    buffer_memory->max = *data_buffer_size;

    do {
        if (!(bio_out = BIO_new (BIO_s_mem ()))) {
            fprintf (stderr,
                     "Unable to allocate CMS signature result memory\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        BIO_set_mem_buf (bio_out, buffer_memory, BIO_NOCLOSE);

        /* Convert cms to der format */
        if (!i2d_CMS_bio_stream (bio_out, cms, bio_in, flags)) {
            fprintf (stderr,
                     "Unable to convert CMS signature to DER format\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Get the size of bio out in data_buffer_size */
        *data_buffer_size = BIO_ctrl_pending (bio_out);
    } while (0);

    if (bio_out)
        BIO_free (bio_out);
    return err_value;
}
