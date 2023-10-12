// SPDX-License-Identifier: BSD-3-Clause
/*===========================================================================*/
/**
    @file    backend_engine.c

    @brief   Provide a CST Back-end replacement to use hardware token

@verbatim
=============================================================================

    Copyright 2021-2022 NXP

=============================================================================
@endverbatim */

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#ifndef BACKEND_ENGINE_H
#define BACKEND_ENGINE_H

#include <openssl/cms.h>
#include <adapt_layer.h>
#include "openssl_helper.h"

#define MAX_ERR_STR_BYTES     120    /**< Max. error string bytes */

struct cst_engine_ctx {
/* Engine configuration */
ENGINE *engine;
};

typedef struct cst_engine_ctx ENGINE_CTX;


/*===========================================================================
                                FUNCTIONS
=============================================================================*/

/**  ctx_new
 *
 * Allocates a new functional reference.
 *
 * @returns functional reference if successful NULL otherwise.
 */
ENGINE_CTX *ctx_new(void);

/** ctx_destroy
 *
 * Destroys context and release the functional reference from ctx_new
 *
 * @param[ctx] Pointer to engine context structure
 *
 * @post if successful memory space allocated for functional reference is freed.
 *
 * @pre  #ctx_new has been called previously.
 *
 * @returns 1 if successful 0 otherwise.
 */
int32_t ctx_destroy(ENGINE_CTX *ctx);

/** ctx_init
 *
 * Initialize context
 *
 * @param[ctx] Pointer to engine context structure
 *
 * @post if successful memory space allocated is freed.
 *
 * @pre  #ctx_new has been called previously.
 *
 * @returns 1 if successful 0 otherwise.
 */
int32_t ctx_init(ENGINE_CTX *ctx);

/** ctx_finish
 *
 * Finalize engine operations initialized with ctx_init
 *
 * @param[ctx] Functional reference
 *
 * @pre  #ctx_init has been called previously.
 *
 * @returns 1 if successful 0 otherwise.
 */
int32_t ctx_finish(ENGINE_CTX *ctx);

/**  ENGINE_load_certificate
 *
 * Read certificate with a given reference from engine.
 *
 * @param[in] engine input file
 *
 * @param[in] cert_ref certificate reference
 *
 * @pre @a engine, @a cert_ref must not be NULL.
 *
 * @returns pointer to X.509 certificate if successful, NULL otherwise.
 */
X509 *ENGINE_load_certificate(ENGINE *engine, const char *cert_ref);

/** Copies CMS Content Info with encrypted or signature data to buffer
 *
 * @param[in] cms CMS Content Info
 *
 * @param[in] bio_in input bio
 *
 * @param[out] data_buffer address to data buffer
 *
 * @param[in] data_buffer_size max size, [out] return size
 *
 * @param[in] flags CMS Flags
 *
 * @returns CAL_SUCCESS upon success
 *
 * @returns CAL_CRYPTO_API_ERROR when openssl BIO API fail
 */
int32_t cms_to_buf(CMS_ContentInfo *cms, BIO *bio_in,
				uint8_t *data_buffer, size_t *data_buffer_size,
				int32_t flags);

/** generate_dek_key
 *
 * Uses openssl API to generate a random 128 bit AES key
 *
 * @param[out] key buffer to store the key data
 *
 * @param[in] len length of the key to generate
 *
 * @post if successful the random bytes are placed into output buffer
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @returns if successful function returns location CAL_SUCCESS.
 */
int32_t generate_dek_key(uint8_t *key, int32_t len);

/**  write_plaintext_dek_key
 *
 * Writes the provide DEK to the give path. It will be encrypted
 * under the certificate file if provided.
 *
 * @param[in] key input key data
 *
 * @param[in] key_bytes length of the input key
 *
 * @param[in] cert_file  certificate to encrypt the DEK
 *
 * @param[in] enc_file  destination file
 *
 * @post if successful the dek is written to the file
 *
 * @returns if successful function returns location CAL_SUCCESS.
 */
int32_t write_plaintext_dek_key(uint8_t *key, size_t key_bytes,
				const char *cert_file, const char *enc_file);

/** encrypt_dek_key
 *
 * Uses openssl API to encrypt the key.
 * Saves the encrypted structure to a file
 *
 * @param[in] key input key data
 *
 * @param[in] key_bytes length of the input key
 *
 * @param[in] cert filename of the RSA certificate, dek will
 *            be encrypted with
 *
 * @param[in] file encrypted data saved in the file
 *
 * @post if successful the file is created with the encrypted data
 *
 * @pre  #openssl_initialize has been called previously
 *
 * @returns if successful function returns location CAL_SUCCESS.
 */
int32_t encrypt_dek_key(uint8_t *key, size_t key_bytes,
				const char *cert_file, const char *enc_file);

#endif /* BACKEND_ENGINE_H */
