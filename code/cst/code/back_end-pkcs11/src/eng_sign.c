// SPDX-License-Identifier: BSD-3-Clause
/*===========================================================================*/
/**
    @file    eng_sign.c

    @brief   Implements HAB and AHAB signature generation on hardware token

@verbatim
=============================================================================

    Copyright 2021-2022 NXP

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
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>

#include "pkcs11_backend.h"
#include "eng_backend.h"

#define HASH_BYTES_SHA512     64
#define HASH_BYTES_MAX        HASH_BYTES_SHA512

/*===========================================================================
                          LOCAL FUNCTION PROTOTYPES
=============================================================================*/
/**  engine_calculate_hash
 *
 * Computes the digest of a file.
 *
 * @param[in] in_file input file
 *
 * @param[in] hash_alg digest algorithm
 *
 * @param[out] buf  output digest
 *
 * @param[out] pbuf_bytes  output digest length
 *
 * @pre @a in_file, @a cert_file, @a hash_alg, @a buf and @a pbuf_bytes
 *         must not be NULL.
 *
 * @post On success @a buf is updated to hold the resulting signature and
 *       @a pbuf_bytes is updates to hold the length of the signature in
 *       bytes
 *
 * @returns if successful function returns location CAL_SUCCESS.
 */
//static int32_t
//engine_calculate_hash (const char *in_file, hash_alg_t hash_alg,
//                       uint8_t * buf, int32_t * pbuf_bytes);

/** Converts hash_alg to an equivalent NID value for OpenSSL
 *
 * @param[in] hash_alg Hash digest algorithm from #hash_alg_t
 *
 * @pre hash_alg is a valid value from #hash_alg_t
 *
 * @returns Openssl NID value corresponding to a valid value for
 *           @a hash_alg, NID_undef otherwise.
 */
static int32_t
get_NID (hash_alg_t hash_alg);

/** Generate ECDSA Signature Data
 *
 * Generates a ECDSA signature for the given data file,
 * signer certificate, and hash algorithm. The signature data is returned
 * in a buffer provided by caller.  Note that sign_data cannot be used
 * here since that function requires an input buffer as an argument.
 * For large files it becomes unreasonable to allocate a contigous
 * block of memory.
 *
 * @param[in] in_file string containing path to file with data to sign
 *
 * @param[in] key signing key
 *
 * @param[in] hash_alg hash algorithm from #hash_alg_t
 *
 * @param[out] sig_buf signature data buffer
 *
 * @param[in,out] sig_buf_bytes On input, contains size of @
 *                              a sig_buf in bytes, On output, contains
 *                                size of signature in bytes.
 *
 * @pre @a in_file, @a key, @a sig_buf and
 *        @a sig_buf_bytes must not be NULL.
 *
 * @post On success @a sig_buf is updated to hold the resulting
 *       signature and @a sig_buf_bytes is updates to hold the length
 *       of the signature in bytes
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_INVALID_ARGUMENT One of the input arguments is invalid
 *
 * @retval #CAL_CRYPTO_API_ERROR An Openssl related error has occurred
 */
static int32_t
pkcs11_gen_sig_data_ecdsa (const char *in_file, EVP_PKEY * key,
                           hash_alg_t hash_alg, uint8_t * sig_buf,
                           size_t * sig_buf_bytes);

/** Generate CMS Signature Data
 *
 * Generates a CMS signature for the given data file,
 * signer certificate, and hash algorithm. The signature data is returned
 * in a buffer provided by caller.  Note that sign_data cannot be used
 * here since that function requires an input buffer as an argument.
 * For large files it becomes unreasonable to allocate a contigous
 * block of memory.
 *
 * @param[in] in_file string containing path to file with data to sign
 *
 * @param[in] x509 X509 signer certificate object
 *
 * @param[in] hash_alg hash algorithm from #hash_alg_t
 *
 * @param[out] sig_buf signature data buffer
 *
 * @param[in,out] sig_buf_bytes On input, contains size of @
 *                              a sig_buf in bytes, On output, contains
 *                                size of signature in bytes.
 *
 * @pre @a in_file, @a cert_file, @a key_file, @a sig_buf and
 *        @a sig_buf_bytes must not be NULL.
 *
 * @post On success @a sig_buf is updated to hold the resulting
 *       signature and @a sig_buf_bytes is updates to hold the length
 *       of the signature in bytes
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_INVALID_ARGUMENT One of the input arguments is invalid
 *
 * @retval #CAL_CRYPTO_API_ERROR An Openssl related error has occurred
 */
static int32_t
pkcs11_gen_sig_data_cms (const char *in_file, X509 * x509, EVP_PKEY * pkey,
                         hash_alg_t hash_alg, uint8_t * sig_buf,
                         size_t * sig_buf_bytes);

/** Generate raw PKCS#1 Signature Data
 *
 * Generates a raw PKCS#1 v1.5 signature for the given data file, signer
 * certificate, and hash algorithm. The signature data is returned in
 * a buffer provided by caller.
 *
 * @param[in] in_file string containing path to file with data to sign
 *
 * @param[in] key EVP_PKEY signing key
 *
 * @param[in] hash_alg hash algorithm from #hash_alg_t
 *
 * @param[out] sig_buf signature data buffer
 *
 * @param[in,out] sig_buf_bytes On input, contains size of
 *       @a sig_buf in bytes, On output,
 *         contains size of signature in bytes.
 *
 * @pre @a in_file, @a cert_file, @a key_file, @a sig_buf
 *       and @a sig_buf_bytes must not be NULL.
 *
 * @post On success @a sig_buf is updated to hold the resulting
 *       signature and
 *       @a sig_buf_bytes is updates to hold the length of the
 *       signature in bytes
 *
 * @retval #CAL_SUCCESS API completed its task successfully
 *
 * @retval #CAL_CRYPTO_API_ERROR An Openssl related error has occurred
 */
static int32_t
pkcs11_gen_sig_data_raw (const char *in_file, EVP_PKEY * key,
                         hash_alg_t hash_alg, uint8_t * sig_buf,
                         int32_t * sig_buf_bytes);

/*===========================================================================
                               LOCAL FUNCTIONS
=============================================================================*/
#if 0
/*--------------------------
  engine_calculate_hash
---------------------------*/
static int32_t
engine_calculate_hash (const char *in_file, hash_alg_t hash_alg,
                       uint8_t * buf, int32_t * pbuf_bytes)
{
    const EVP_MD *sign_md;       /**< Ptr to digest name */
    int32_t bio_bytes;       /**< Length of bio data */
    BIO *in = NULL;    /**< Ptr to BIO for reading data from in_file */
    BIO *bmd = NULL;     /**< Ptr to BIO with hash bytes */
    BIO *inp;      /**< Ptr to BIO for appending in with bmd */
    /** Status initialized to API error */
    int32_t err_value = CAL_CRYPTO_API_ERROR;

    sign_md = EVP_get_digestbyname (get_digest_name (hash_alg));
    if (sign_md == NULL) {
        return CAL_INVALID_ARGUMENT;
    }

    /* Read data to generate hash */
    do {

        /* Create necessary bios */
        in = BIO_new (BIO_s_file ());
        bmd = BIO_new (BIO_f_md ());
        if (in == NULL || bmd == NULL) {
            break;
        }

        /* Set BIO to read filename in_file */
        if (BIO_read_filename (in, in_file) <= 0) {
            break;
        }

        /* Set BIO md to given hash */
        if (!BIO_set_md (bmd, sign_md)) {
            break;
        }

        /* Appends BIO in to bmd */
        inp = BIO_push (bmd, in);

        /* Read data from file BIO */
        do {
            bio_bytes = BIO_read (inp, (uint8_t *) buf, *pbuf_bytes);
         } while (bio_bytes > 0);

        /* Check for read error */
        if (bio_bytes < 0) {
            break;
        }

        /* Get the hash */
        bio_bytes = BIO_gets (inp, (char *) buf, *pbuf_bytes);
        if (bio_bytes <= 0) {
            break;
        }

        /* Send the output bytes in pbuf_bytes */
        *pbuf_bytes = bio_bytes;
        err_value = CAL_SUCCESS;
      } while (0);

    if (in != NULL)
        BIO_free (in);
    if (bmd != NULL)
        BIO_free (bmd);

    return err_value;
}
#endif
/*--------------------------
  get_NID
---------------------------*/
static int32_t
get_NID (hash_alg_t hash_alg)
{
    return OBJ_txt2nid (get_digest_name (hash_alg));
}

/*--------------------------
  pkcs11_gen_sig_data_ecdsa
---------------------------*/
static int32_t
pkcs11_gen_sig_data_ecdsa (const char *in_file, EVP_PKEY * key,
                           hash_alg_t hash_alg, uint8_t * sig_buf,
                           size_t * sig_buf_bytes)
{
    BIO *bio_in = NULL;        /**< BIO for in_file data    */
    uint32_t key_size = 0;       /**< n of bytes of key param */
    const EVP_MD *sign_md = NULL;          /**< Digest name             */
    uint8_t *hash = NULL;          /**< Hash data of in_file    */
    int32_t hash_bytes = 0;    /**< Length of hash buffer   */
    uint8_t *sign = NULL;          /**< Signature data in DER   */
    uint32_t sign_bytes = 0;     /**< Length of DER signature */
    uint8_t *r = NULL, *s = NULL;          /**< Raw signature data R&S  */
    size_t bn_bytes = 0;         /**< Length of R,S big num   */
    ECDSA_SIG *sign_dec = NULL;        /**< Raw signature data R|S  */
    int32_t err_value = CAL_SUCCESS;     /**< Return value            */
    char err_str[MAX_ERR_STR_BYTES];     /**< Error string            */
    /**< signature numbers defined as OpenSSL BIGNUM */
    const BIGNUM *sig_r, *sig_s;

    if (!key) {
        fprintf (stderr, "Invalid certificate or key\n");
        return CAL_INVALID_ARGUMENT;
    }

    /* Set signature message digest alg */
    sign_md = EVP_get_digestbyname (get_digest_name (hash_alg));
    if (sign_md == NULL) {
        fprintf (stderr, "Invalid hash digest algorithm\n");
        return CAL_INVALID_ARGUMENT;
    }

    do {
        /* Read Data to be signed */
        if (!(bio_in = BIO_new_file (in_file, "rb"))) {
            snprintf (err_str, MAX_ERR_STR_BYTES,
                     "Cannot open data file %s", in_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Generate hash of data from in_file */
        hash_bytes = HASH_BYTES_MAX;
        hash = OPENSSL_malloc (HASH_BYTES_MAX);

        err_value = calculate_hash (in_file, hash_alg, hash, &hash_bytes);
        if (err_value != CAL_SUCCESS) {
            break;
        }

        /* Generate ECDSA signature with DER encoding */
        sign_bytes = ECDSA_size (EVP_PKEY_get0_EC_KEY (key));
        sign = OPENSSL_malloc (sign_bytes);

        if (0 == ECDSA_sign (0 /* ignored */ , hash, hash_bytes, sign,
                   &sign_bytes, EVP_PKEY_get0_EC_KEY (key))) {
            fprintf (stderr, "Failed to generate ECDSA signature\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        sign_dec = d2i_ECDSA_SIG (NULL, (const uint8_t **) &sign,
                                 sign_bytes);

        if (NULL == sign_dec) {
            fprintf (stderr, "Failed to decode ECDSA signature\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Copy R|S to sig_buf */
        memset (sig_buf, 0, *sig_buf_bytes);

        key_size = EVP_PKEY_bits (key) >> 3;
        if (EVP_PKEY_bits (key) & 0x7)
            key_size += 1;        /* Valid for P-521 */

        if ((key_size * 2) > *sig_buf_bytes) {
            fprintf (stderr, "Signature buffer too small\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        *sig_buf_bytes = key_size * 2;

        ECDSA_SIG_get0 (sign_dec, &sig_r, &sig_s);

        r = get_bn (sig_r, &bn_bytes);
        memcpy (sig_buf + (key_size - bn_bytes), r, bn_bytes);
        free (r);

        s = get_bn (sig_s, &bn_bytes);
        memcpy (sig_buf + key_size + (key_size - bn_bytes), s, bn_bytes);
        free (s);
    } while (0);

    /* Print any Openssl errors */
    if (err_value != CAL_SUCCESS) {
        ERR_print_errors_fp (stderr);
    }

    /* Close everything down */
    if (bio_in)
       BIO_free (bio_in);

  return err_value;
}

/*--------------------------
  pkcs11_gen_sig_data_cms
---------------------------*/
static int32_t
pkcs11_gen_sig_data_cms (const char *in_file, X509 * x509, EVP_PKEY * pkey,
                         hash_alg_t hash_alg, uint8_t * sig_buf,
                         size_t * sig_buf_bytes)
{
    BIO *bio_in = NULL;        /**< BIO for in_file data */
    CMS_ContentInfo *cms = NULL;         /**< Ptr used with openssl API */
    const EVP_MD *sign_md = NULL;          /**< Ptr to digest name */
    int32_t err_value = CAL_SUCCESS;     /**< Used for return value */
    /** Array to hold error string */
    char err_str[MAX_ERR_STR_BYTES];
    /* flags set to match Openssl command line options for generating
     *  signatures
     */
    int32_t flags = CMS_DETACHED | CMS_NOCERTS |
                    CMS_NOSMIMECAP | CMS_BINARY;

    if (!pkey || !x509) {
        fprintf (stderr, "Invalid certificate or key\n");
        return CAL_INVALID_ARGUMENT;
    }
    /* Set signature message digest alg */
    sign_md = EVP_get_digestbyname (get_digest_name (hash_alg));

    if (sign_md == NULL) {
        fprintf (stderr, "Invalid hash digest algorithm\n");
        return CAL_INVALID_ARGUMENT;
    }

    do {
        /* Read Data to be signed */
        if (!(bio_in = BIO_new_file (in_file, "rb"))) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Cannot open data file %s", in_file);
            fprintf (stderr, "%s\n",err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
         }

        /* Generate CMS Signature - can only use CMS_sign if default
         * MD is used which is SHA1 */
        flags |= CMS_PARTIAL;

        cms = CMS_sign (NULL, NULL, NULL, bio_in, flags);
        if (!cms) {
            fprintf (stderr, "Failed to initialize CMS signature\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        if (!CMS_add1_signer (cms, x509, pkey, sign_md, flags)) {
            fprintf (stderr, "Failed to generate CMS signature\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
         }

        /* Finalize the signature */
        if (!CMS_final (cms, bio_in, NULL, flags)) {
            fprintf (stderr, "Failed to finalize CMS signature\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Write CMS signature to output buffer - DER format */
        err_value = cms_to_buf (cms, bio_in, sig_buf, sig_buf_bytes,
                               flags);
    } while (0);

    /* Print any Openssl errors */
    if (err_value != CAL_SUCCESS) {
        ERR_print_errors_fp (stderr);
    }

    /* Close everything down */
    if (cms)
        CMS_ContentInfo_free (cms);
    if (bio_in)
        BIO_free (bio_in);

    return err_value;
}

/*--------------------------
  pkcs11_gen_sig_data_raw
---------------------------*/
static int32_t
pkcs11_gen_sig_data_raw (const char *in_file, EVP_PKEY * key,
                         hash_alg_t hash_alg, uint8_t * sig_buf,
                         int32_t * sig_buf_bytes)
{

    RSA *rsa = NULL;     /**< Ptr to rsa of key data */
    uint8_t *rsa_in = NULL;    /**< Mem ptr for hash data of in_file */
    uint8_t *rsa_out = NULL;     /**< Mem ptr for encrypted data */
    int32_t rsa_inbytes;         /**< Holds the length of rsa_in buf */
    int32_t rsa_outbytes = 0;      /**< Holds the length of rsa_out buf */
    int32_t key_bytes;       /**< Size of key data */
    int32_t hash_nid;      /**< hash id needed for RSA_sign() */
    /**< Holds the return error value */
    int32_t err_value = CAL_CRYPTO_API_ERROR;

    do {
        rsa = EVP_PKEY_get1_RSA (key);
        EVP_PKEY_free (key);

        if (!rsa) {
            fprintf (stderr,
            "Unable to extract RSA key for RAW PKCS#1 signature");
            break;
        }

        rsa_inbytes = HASH_BYTES_MAX;
        rsa_in = (unsigned char *) OPENSSL_malloc (HASH_BYTES_MAX);
        key_bytes = RSA_size (rsa);
        rsa_out = (unsigned char *) OPENSSL_malloc (key_bytes);

        /* Generate hash data of data from in_file */
        err_value =
            calculate_hash (in_file, hash_alg, rsa_in, &rsa_inbytes);
        if (err_value != CAL_SUCCESS) {
            break;
         }

        /* Compute signature.  Note: RSA_sign() adds the appropriate DER
         * encoded prefix internally.
         */
        hash_nid = get_NID (hash_alg);
        if (!RSA_sign (hash_nid, rsa_in, rsa_inbytes, rsa_out,
                   (unsigned int *) &rsa_outbytes, rsa)) {
            err_value = CAL_CRYPTO_API_ERROR;
            fprintf (stderr, "Unable to generate signature");
            break;
        }
        else {
            err_value = CAL_SUCCESS;
        }

        /* Copy signature to sig_buf and update sig_buf_bytes */
        *sig_buf_bytes = rsa_outbytes;
        memcpy (sig_buf, rsa_out, rsa_outbytes);
    } while (0);

    if (err_value != CAL_SUCCESS) {
        ERR_print_errors_fp (stderr);
    }

    if (rsa)
        RSA_free (rsa);
    if (rsa_in)
        OPENSSL_free (rsa_in);
    if (rsa_out)
        OPENSSL_free (rsa_out);
    return err_value;
}

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/
/*--------------------------
 pkcs11_gen_sig_data
 ---------------------------*/
int32_t
pkcs11_gen_sig_data (const char *in_file, const char *cert_ref,
              hash_alg_t hash_alg, sig_fmt_t sig_fmt, uint8_t * sig_buf,
              size_t * sig_buf_bytes, func_mode_t mode)
{
    /* Engine configuration */
    ENGINE_CTX *ctx = NULL;

    /* Certificate and private key */
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;

      /* Operation completed successfully */
    int32_t error = CAL_SUCCESS;

    /* Check for valid arguments */
    if ((!in_file) || (!cert_ref) || (!sig_buf) || (!sig_buf_bytes)) {
       return CAL_INVALID_ARGUMENT;
    }

    /* Allocate new context */
    ctx = ctx_new();

    if(ctx == NULL){
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

    key = ENGINE_load_private_key(ctx->engine, cert_ref, 0, 0);

    if (key == NULL) {
        error = CAL_CRYPTO_API_ERROR;
        goto out;
    }

    /**
    * OpenSSL expects EVP_PKEY to contain the ec_point. PKCS#11 does not
	* return the ec_point as an attribute for private key.
    */
    if(EVP_PKEY_base_id(key) == EVP_PKEY_RSA) {
        error = X509_check_private_key(cert, key);
        if (!error) {
            error = CAL_CRYPTO_API_ERROR;
            goto out;
        }
    }

    if (sig_fmt == SIG_FMT_ECDSA) {
        error = pkcs11_gen_sig_data_ecdsa (in_file, key, hash_alg, sig_buf,
                                           sig_buf_bytes);
    }
    else if (sig_fmt == SIG_FMT_PKCS1) {
        error = pkcs11_gen_sig_data_raw (in_file, key, hash_alg, sig_buf,
                                         (int32_t *) sig_buf_bytes);
    }
    else if (sig_fmt == SIG_FMT_CMS) {
        error = pkcs11_gen_sig_data_cms (in_file, cert, key, hash_alg, sig_buf,
                                         sig_buf_bytes);
    }
    else {
        fprintf (stderr, "Invalid signature format\n");
        return CAL_INVALID_ARGUMENT;
    }

out:
    if(ctx) {
    
   /* Destroy the context: ctx_finish is not called here since
	* ENGINE_finish cleanups the engine instance. Calling ctx_destroy
	* next will lead to null pointer dereference. */
        ctx_destroy(ctx);
    }

    if (error)
        ERR_print_errors_fp(stderr);
    if (cert)
        X509_free (cert);
    if (key)
        EVP_PKEY_free (key);

    return error;
}
