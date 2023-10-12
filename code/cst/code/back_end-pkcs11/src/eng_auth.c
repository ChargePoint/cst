// SPDX-License-Identifier: BSD-3-Clause
/*===========================================================================*/
/**
    @file    eng_auth.c

    @brief   Provide functions to encrypt data using CCM.

@verbatim
=============================================================================

    Copyright 2021, 2022 NXP

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
#include "eng_backend.h"

/*--------------------------
 handle_errors
 ---------------------------*/
static void
handle_errors(char *str, int32_t *err_value, char *err_str)
{
    snprintf(err_str, MAX_ERR_STR_BYTES - 1, "%s", str);
    *err_value = CAL_CRYPTO_API_ERROR;
}


/*--------------------------
 encryptccm
 ---------------------------*/
static int32_t
encryptccm(unsigned char *plaintext, int plaintext_len,
			unsigned char *aad, int aad_len, unsigned char *key,
			int key_len, unsigned char *iv, int iv_len,
			const char *out_file, unsigned char *tag, int tag_len,
			int32_t *err_value, char *err_str)
{

#ifdef REMOVE_ENCRYPTION
    UNUSED(plaintext);
    UNUSED(plaintext_len);
    UNUSED(aad);
    UNUSED(aad_len);
    UNUSED(key);
    UNUSED(key_len);
    UNUSED(iv);
    UNUSED(iv_len);
    UNUSED(out_file);
    UNUSED(tag);
    UNUSED(tag_len);
    UNUSED(err_value);
    UNUSED(err_str);

    return CAL_NO_CRYPTO_API_ERROR;
#else
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    unsigned char *ciphertext = NULL;

    FILE *fho = NULL;
    int err = 0;
    do {

        ciphertext = (unsigned char *)malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
        if (NULL == ciphertext) {
            handle_errors("Failed to allocate memory for encrypted data",
                          err_value, err_str);
            return CAL_INSUFFICIENT_MEMORY;
        }

        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new())) {
            handle_errors("Failed to allocate ccm context structure",
                   err_value, err_str);
            break;
        }

        /* Initialise the encryption operation. */
        switch(key_len) {
            case 16:
                err =
                  EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(),
                                      NULL, NULL, NULL);
                break;
            case 24:
                err =
                  EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(),
                                      NULL, NULL, NULL);
                break;
            case 32:
                err =
                  EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(),
                                      NULL, NULL, NULL);
                break;
            default:
                handle_errors("Failed allocating ccm context structure",
                               err_value, err_str);
                EVP_CIPHER_CTX_free(ctx);
                free(ciphertext);
                return *err_value;
        }

        if(err != 1) {
            handle_errors("Failed to initialize ccm context structure",
                   err_value, err_str);
            break;
        }

        /*
         * Setting IV len to 7. Not strictly necessary as this
         * is the default but shown here for the purposes of this example
         */
        if(1 !=
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
                                 iv_len, NULL)) {
            handle_errors("Failed to initialize IV", err_value, err_str);
            break;
        }

        /* Set tag length */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL);

        /* Initialise key and IV */
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
            handle_errors("Failed to initialize key", err_value, err_str);
            break;
        }

        /* Provide the total plaintext length */
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL,
                                   plaintext_len)) {
            handle_errors("Failed to initialize length parameter",
                           err_value, err_str);
            break;
        }

        /*
         * Provide the message to be encrypted, and obtain the encrypted
         * output. EVP_EncryptUpdate can only be called once for this
         */
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
                        plaintext_len)) {
            handle_errors("Failed to encrypt", err_value, err_str);
            break;
        }
        ciphertext_len = len;

        /* Open out_file for writing */
        fho = fopen(out_file, "wb");
        if(fho == NULL) {
            handle_errors("Cannot open file", err_value, err_str);
            break;
        }

        /* Write encrypted data to out file */
        if(fwrite(ciphertext, 1, ciphertext_len, fho)
                   != ciphertext_len) {
            handle_errors("Cannot write file", err_value, err_str);
            break;
        }

        /*
         * Finalise the encryption.
         * Normally ciphertext bytes may be written at this stage,
         * but this does not occur in CCM mode
         */
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
            handle_errors("Failed to finalize", err_value, err_str);
            break;
        }
        ciphertext_len += len;

        /* Get the tag */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG,
                                      16, tag)) {
            handle_errors("Failed to get tag", err_value, err_str);
            break;
        }

      } while(0);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if (NULL != ciphertext) {
        free(ciphertext);
    }

    if(fho) {
        fclose(fho);
    }

    return *err_value;
#endif
}

/*--------------------------
 gen_auth_encrypted_data
 ---------------------------*/
int32_t
gen_auth_encrypted_data(const char *in_file, const char *out_file,
				aead_alg_t aead_alg, uint8_t *aad, size_t aad_bytes,
				uint8_t *nonce, size_t nonce_bytes, uint8_t *mac,
				size_t mac_bytes, size_t key_bytes,
				const char *cert_file, const char *key_file,
				int reuse_dek)
{
    int32_t err_value = CAL_SUCCESS;     /**< status of function calls */
    char err_str[MAX_ERR_STR_BYTES];     /**< Array to hold error string */
    uint8_t key[MAX_AES_KEY_LENGTH];     /**< Buffer for random key */
    FILE *fh = NULL;     /**< Used with files */
    size_t file_size;      /**< Size of in_file */
    unsigned char *plaintext = NULL;     /**< Array to read file data */
    int32_t bytes_read;
#ifdef DEBUG
    int32_t i;       /**< used in for loops */
#endif

    UNUSED(aead_alg);

    do {
        /* Generate Nonce */
        err_value = gen_random_bytes((uint8_t *) nonce, nonce_bytes);
        if(err_value != CAL_SUCCESS) {
            snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                      "Failed to get nonce");
            fprintf(stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
#ifdef DEBUG
        printf("nonce bytes: ");
        for(i = 0; i < nonce_bytes; i++) {
          printf("%02x ", nonce[i]);
        }
        printf("\n");
#endif
      if(reuse_dek) {
            fh = fopen(key_file, "rb");
            if(fh == NULL) {
                snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                  "Unable to open dek file %s", key_file);
                fprintf(stderr, "%s\n", err_str);
                err_value = CAL_FILE_NOT_FOUND;
                break;
            }
          /* Read encrypted data into input_buffer */
            bytes_read = fread(key, 1, key_bytes, fh);
            if(bytes_read == 0) {
                snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                          "Cannot read file %s", key_file);
                fprintf(stderr, "%s\n", err_str);
                err_value = CAL_FILE_NOT_FOUND;
                fclose(fh);
                break;
            }
            fclose(fh);
        }
        else {
            /* Generate random aes key to use it for encrypting data */
            err_value = generate_dek_key(key, key_bytes);
            if(err_value) {
                snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                  "Failed to generate random key");
                fprintf(stderr, "%s\n", err_str);
                err_value = CAL_CRYPTO_API_ERROR;
                break;
              }
        }

#ifdef DEBUG
        printf("random key : ");
        for(i = 0; i < key_bytes; i++) {
            printf("%02x ", key[i]);
        }
        printf("\n");
#endif
        if(cert_file != NULL) {
            /* Encrypt key using cert file and save it in the key_file */
            err_value = encrypt_dek_key(key, key_bytes, cert_file,
                                         key_file);
            if(err_value) {
                snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                  "Failed to encrypt and save key");
                fprintf(stderr, "%s\n", err_str);
                err_value = CAL_CRYPTO_API_ERROR;
                break;
            }
        } else {
            /* Save key in the key_file */
            err_value = write_plaintext_dek_key(key, key_bytes, cert_file,
                                 key_file);
            if(err_value) {
                snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                         "Failed to save key");
                fprintf(stderr, "%s\n", err_str);
                err_value = CAL_CRYPTO_API_ERROR;
                break;
              }
        }
        /* Get the size of in_file */
        fh = fopen(in_file, "rb");
        if(fh == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                  "Unable to open binary file %s", in_file);
            fprintf(stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        fseek(fh, 0, SEEK_END);
        file_size = ftell(fh);
        plaintext =(unsigned char *) malloc(file_size);

        if(plaintext == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                  "Not enough allocated memory");
            fprintf(stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        fclose(fh);

        fh = fopen(in_file, "rb");
        if(fh == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                      "Cannot open file %s", in_file);
            fprintf(stderr, "%s\n", err_str);
            err_value = CAL_FILE_NOT_FOUND;
            break;
        }

        /* Read encrypted data into input_buffer */
        bytes_read = fread(plaintext, 1, file_size, fh);
        /* Reached EOF? */
        if(bytes_read == 0) {
            snprintf(err_str, MAX_ERR_STR_BYTES - 1,
                     "Cannot read file %s", out_file);
            fprintf(stderr, "%s\n", err_str);
            err_value = CAL_FILE_NOT_FOUND;
            break;
        }

        err_value = encryptccm(plaintext, file_size, aad, aad_bytes, key,
                        key_bytes, nonce, nonce_bytes, out_file, mac,
                        mac_bytes, &err_value, err_str);
        if(err_value == CAL_NO_CRYPTO_API_ERROR) {
            printf("Encryption not enabled\n");
            break;
        }
    } while (0);

	free(plaintext);

	/* Clean up */
	return err_value;
}
