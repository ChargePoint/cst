// SPDX-License-Identifier: BSD-3-Clause
/*===========================================================================*/
/**
    @file    eng_dek.c

    @brief   Provide functions to manage data encryption keys.

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

/* Library Openssl includes */
#include <openssl/cms.h>
#include "eng_backend.h"

#define MAX_CMS_DATA          4096   /**< Max bytes in CMS_ContentInfo */

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
 generate_dek_key
 ---------------------------*/
int32_t
generate_dek_key (uint8_t * key, int32_t len)
{
    if (gen_random_bytes (key, len) != CAL_SUCCESS) {
        return CAL_CRYPTO_API_ERROR;
    }

  return CAL_SUCCESS;
}

/*--------------------------
 write_plaintext_dek_key
 ---------------------------*/
int32_t
write_plaintext_dek_key (uint8_t * key, size_t key_bytes,
                 const char *cert_file, const char *enc_file)
{
    int32_t err_value = CAL_SUCCESS; /**< Return value */
    char err_str[MAX_ERR_STR_BYTES]; /**< Used in preparing error msg */
    FILE *fh = NULL;     /**< File handle used with file api */

    UNUSED (cert_file);

    do {
        /* Save the buffer into enc_file */
        if ((fh = fopen (enc_file, "wb")) == NULL) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Unable to create binary file %s", enc_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        if (fwrite (key, 1, key_bytes, fh) != key_bytes) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Unable to write to binary file %s", enc_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        fclose (fh);
    } while (0);

  return err_value;
}

/*--------------------------
 encrypt_dek_key
 ---------------------------*/
int32_t
encrypt_dek_key (uint8_t * key, size_t key_bytes,
             const char *cert_file, const char *enc_file)
{
    X509 *cert = NULL;       /**< Ptr to X509 certificate read data */
    STACK_OF (X509) * recips = NULL;    /**< Ptr to X509 stack */
    CMS_ContentInfo *cms = NULL;         /**< Ptr to cms structure */
    const EVP_CIPHER *cipher = NULL;     /**< Ptr to EVP_CIPHER */
    int32_t err_value = CAL_SUCCESS;     /**< Return value */
    char err_str[MAX_ERR_STR_BYTES]; /**< Used in preparing error msg */
    BIO *bio_key = NULL;         /**< Bio for the key data to encrypt */
    uint8_t *enc_buf = NULL;      /**< Ptr for encoded key data */
    FILE *fh = NULL;     /**< File handle used with file api */
    size_t cms_info_size = MAX_CMS_DATA; /**< Size of cms content info*/
#ifdef DEBUG
    int32_t i = 0;       /**< Used in for loops */
#endif

    do {
      /* Read the certificate from cert_file */
      cert = read_certificate (cert_file);
        if (!cert) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Cannot open certificate file %s", cert_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Create recipient STACK and add recipient cert to it */
        recips = sk_X509_new_null ();

        if (!recips || !sk_X509_push (recips, cert)) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Cannot instantiate object STACK_OF(%s)", cert_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /*
         * sk_X509_pop_free will free up recipient STACK and its contents
         * so set cert to NULL so it isn't freed up twice.
         */
        cert = NULL;

        /* Instantiate correct cipher */
        if (key_bytes == (AES_KEY_LEN_128 / BYTE_SIZE_BITS))
            cipher = EVP_aes_128_cbc ();
        else if (key_bytes == (AES_KEY_LEN_192 / BYTE_SIZE_BITS))
            cipher = EVP_aes_192_cbc ();
        else if (key_bytes == (AES_KEY_LEN_256 / BYTE_SIZE_BITS))
            cipher = EVP_aes_256_cbc ();
        if (cipher == NULL) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Invalid cipher used for encrypting key %s", enc_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Allocate memory buffer BIO for input key */
        bio_key = BIO_new_mem_buf (key, key_bytes);
        if (!bio_key) {
            fprintf (stderr, "Unable to allocate BIO memory\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Encrypt content of the key with certificate */
        cms = CMS_encrypt (recips, bio_key, cipher,
                           CMS_BINARY | CMS_STREAM);
        if (cms == NULL) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Failed to encrypt key data");
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Finalize the CMS content info structure */
        if (!CMS_final (cms, bio_key, NULL, CMS_BINARY | CMS_STREAM)) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Failed to finalize cms data");
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Alloc mem to convert cms to binary and save it into enc_file */
        enc_buf = malloc (MAX_CMS_DATA);
        if (enc_buf == NULL) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Failed to allocate memory");
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Copy cms info into enc_buf */
        err_value = cms_to_buf (cms, bio_key, enc_buf, &cms_info_size,
                        CMS_BINARY);

        /* Save the buffer into enc_file */
        if ((fh = fopen (enc_file, "wb")) == NULL) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Unable to create binary file %s", enc_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        if (fwrite (enc_buf, 1, cms_info_size, fh) != cms_info_size) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Unable to write to binary file %s", enc_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        fclose (fh);
#ifdef DEBUG
        printf ("Encoded key ;");
        for (i = 0; i < key_bytes; i++) {
            printf ("%02x ", enc_buf[i]);
        }
        printf ("\n");
#endif
    } while (0);

    if (cms)
        CMS_ContentInfo_free (cms);
    if (cert)
        X509_free (cert);
    if (recips)
        sk_X509_pop_free (recips, X509_free);
    if (bio_key)
        BIO_free (bio_key);
    if (enc_buf)
        free(enc_buf);
    return err_value;
}
