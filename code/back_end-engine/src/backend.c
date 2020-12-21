// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2020 NXP
 *
 * @file    backend.c
 *
 * @brief   An engine backend for Code-Signing Tool.
 *
 * @verbatim
 * ======================================================================
 *
 * Presence of a copyright notice is not an acknowledgment of publication.
 * This software file listing contains information of NXP that is of a
 * confidential and proprietary nature and any viewing or use of this
 * file is prohibited without specific written permission from NXP
 *
 * =======================================================================
 * @endverbatim
 */

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

#define DEBUG

#include "openssl_helper.h"

#define HASH_BYTES_SHA512     64
#define HASH_BYTES_MAX        HASH_BYTES_SHA512
#define MAX_ERR_STR_BYTES     120    /**< Max. error string bytes */
#define MAX_CMS_DATA          4096   /**< Max bytes in CMS_ContentInfo */

#ifdef DEBUG
    #define dbg_fprintf(args...) \
    do { fprintf(stderr, args);  \
    fflush(stderr); } while (0)
#else
    #define dbg_fprintf(args...)
#endif

struct cst_engine_ctx {
    /* Engine configuration */
    ENGINE *engine;
};

typedef struct cst_engine_ctx ENGINE_CTX;

/*=======================================================================+
 LOCAL FUNCTION PROTOTYPES
 =======================================================================*/

/** Converts hash_alg to an equivalent NID value for OpenSSL
 *
 * @param[in] hash_alg Hash digest algorithm from #hash_alg_t
 *
 * @pre hash_alg is a valid value from #hash_alg_t
 *
 * @returns Openssl NID value corresponding to a valid value for
 *           @a hash_alg, NID_undef otherwise.
 */
static int32_t get_NID (hash_alg_t hash_alg);

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
static int32_t gen_sig_data_raw (const char *in_file, EVP_PKEY * key,
                  hash_alg_t hash_alg, uint8_t * sig_buf,
                  int32_t * sig_buf_bytes);

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
static int32_t gen_sig_data_cms (const char *in_file, X509 * x509,
                  EVP_PKEY * pkey, hash_alg_t hash_alg, uint8_t * sig_buf,
                  size_t * sig_buf_bytes);

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
static int32_t cms_to_buf (CMS_ContentInfo * cms, BIO * bio_in,
                uint8_t * data_buffer, size_t * data_buffer_size,
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
static int32_t generate_dek_key (uint8_t * key, int32_t len);

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
static int32_t write_plaintext_dek_key (uint8_t * key, size_t key_bytes,
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
static int32_t encrypt_dek_key (uint8_t * key, size_t key_bytes,
                 const char *cert_file, const char *enc_file);


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
static int32_t engine_calculate_hash(const char *in_file,
            hash_alg_t hash_alg, uint8_t *buf, int32_t *pbuf_bytes);

/**  ctx_new
 *
 * Allocates a new functional reference.
 *
 * @returns functional reference if successful NULL otherwise.
 */
static ENGINE_CTX *ctx_new(void);

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
static int32_t ctx_destroy(ENGINE_CTX *ctx);

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
static int32_t ctx_init(ENGINE_CTX *ctx);

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
static int32_t ctx_finish(ENGINE_CTX *ctx);


/*=======================================================================+
 LOCAL FUNCTION IMPLEMENTATIONS
 =======================================================================*/

/*--------------------------
 ctx_new
 ---------------------------*/
static ENGINE_CTX *ctx_new()
{
    ENGINE_CTX *ctx;
    ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
    return ctx;
}

/*--------------------------
 ctx_destroy
 ---------------------------*/
static int32_t ctx_destroy(ENGINE_CTX *ctx)
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
static int32_t ctx_init(ENGINE_CTX *ctx)
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

    ctx->engine = ENGINE_by_id("cloudhsm");

    if(ctx->engine == NULL)
        return 0;

#ifdef DEBUG
    ENGINE_ctrl_cmd_string(ctx->engine, "VERBOSE", NULL, 0);
#endif

    if (!ENGINE_init(ctx->engine)) {
        ENGINE_free(ctx->engine);
        return 0;
    }

    if (!ENGINE_set_default_RSA(ctx->engine)) {
        fprintf(stderr, "Couldn't set engine as default for RSA\n");
        ENGINE_free(ctx->engine);
        return 0;
    }

    return 1;
}

/*--------------------------
 ctx_finish
 ---------------------------*/
static int32_t ctx_finish(ENGINE_CTX *ctx)
{
    if (ctx) {
        ENGINE_finish(ctx->engine);
    }
    return 1;
}

/**
 * rsa_pem_get_x509() - read a certficate from file
 *
 * @keydir:	Directory containins the key
 * @name	Name of key file
 * @rsap	Returns RSA object, or NULL on failure
 * @return X509 pointer if ok, NULL on error
 */
X509 *read_certificate_pem(const char *cert_path)
{
    X509 *cert;
    FILE *f;
    char path[1024];
    const char *keydir;

    if (cert_path == NULL) {
        fprintf(stderr, "cert_path is null");
        goto out;
    }

    /* Generate Certificate path */
    keydir = getenv("KEY_DIR");
    if (keydir == NULL) {
        fprintf(stderr, "environment variable KEY_DIR not set");
		goto out;
    }
	snprintf(path, sizeof(path), "%s/%s", keydir, cert_path);

    cert = NULL;
    if (path == NULL) {
        fprintf(stderr, "Path is null");
        goto out;
    }
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Couldn't open RSA certificate: '%s': %s\n",
            path, strerror(errno));
        goto out;
    }

    /* Read the certificate */
    if (!PEM_read_X509(f, &cert, NULL, NULL)) {
        fprintf(stderr, "Couldn't read certificate");
        goto out_file;
    }

out_file:
    fclose(f);
out:
    return cert;
}

EVP_PKEY *read_private_key_pem(const char* cert_path)
{
    int r;
    int index;
    EVP_PKEY *pkey;
    EVP_PKEY *pkey_ret;
    RSA *rsa;
    FILE *f;
    char path[1024];
    char keyname[1024];
    const char *tmpstr;
    const char *keydir;

    rsa = NULL;
    pkey = NULL;
    pkey_ret = NULL;

    if (cert_path == NULL) {
        fprintf(stderr, "cert_path is null");
        goto out;
    }

    /* Generate Private key path from cert
     *
     * Expected format of cert path:
     *      crts/SRK1..._crt.pem
     * This will be be converted to:
     *      keys/SRK1..._key.pem
     */
    keydir = getenv("KEY_DIR");
    if (keydir == NULL) {
        fprintf(stderr, "environment variable KEY_DIR not set");
        goto out;
    }
    if (strlen(cert_path) < 13) {
        fprintf(stderr, "invalid path %s. must be in format: crts/<...>_crt.pem",
                cert_path);
        goto out;
    }
    /* Copy cert path, removing first 5 chars (should be "crts/") */
    tmpstr = &cert_path[5];
    strcpy(keyname, tmpstr);
    /* Add null character to remove last 8 characters (should be "_crt.pem") */
    index = strlen(keyname) - 8;
    if (index < 0) {
        fprintf(stderr, "invalid path %s. must be in format: crts/<...>_crt.pem",
                cert_path);
        goto out;
    }
    keyname[index] = '\0';
    snprintf(path, sizeof(path), "%s/keys/%s_key.pem", keydir, keyname);

    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Couldn't open RSA private key: '%s': %s\n",
            path, strerror(errno));
        goto out;
    }

    rsa = PEM_read_RSAPrivateKey(f, 0, NULL, path);
    if (!rsa) {
        fprintf(stderr, "Failure reading private key");
        goto out_file;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        fprintf(stderr, "ENV_PKEY_NEW failed");
        goto out_file;
    }
    r = EVP_PKEY_assign_RSA(pkey, rsa);
    if (r != 1) {
        fprintf(stderr, "EVP_PKEY_assign_RSA failed");
        goto out_file;
    }

    pkey_ret = pkey;

out_file:
    fclose(f);
out:
	return pkey_ret;
}


/*--------------------------
 get_NID
 ---------------------------*/
static int32_t
get_NID (hash_alg_t hash_alg)
{
    return OBJ_txt2nid (get_digest_name (hash_alg));
}

/*--------------------------
 gen_sig_data_ecdsa
 ---------------------------*/
static int32_t
gen_sig_data_ecdsa (const char *in_file, EVP_PKEY * key,
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
 gen_sig_data_cms
 ---------------------------*/
static int32_t
gen_sig_data_cms (const char *in_file, X509 * x509, EVP_PKEY * pkey,
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
 gen_sig_data_raw
 ---------------------------*/
static int32_t
gen_sig_data_raw (const char *in_file, EVP_PKEY * key,
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
            engine_calculate_hash (in_file, hash_alg, rsa_in, &rsa_inbytes);
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

/*--------------------------
 cms_to_buf
 ---------------------------*/
static int32_t
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

/*--------------------------
 engine_calculate_hash
 ---------------------------*/
static int32_t engine_calculate_hash (const char *in_file, hash_alg_t hash_alg,
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

/*--------------------------
 generate_dek_key
 ---------------------------*/
static int32_t
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
static int32_t
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
static int32_t
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
      cert = read_certificate_pem (cert_file);
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
    return err_value;
}

/*--------------------------
 handle_errors
 ---------------------------*/
static void
handle_errors (char *str, int32_t * err_value, char *err_str)
{
    snprintf (err_str, MAX_ERR_STR_BYTES - 1, "%s", str);
    *err_value = CAL_CRYPTO_API_ERROR;
}

/*--------------------------
 encryptccm
 ---------------------------*/
int32_t
encryptccm (unsigned char *plaintext, int plaintext_len,
            unsigned char *aad, int aad_len, unsigned char *key,
            int key_len, unsigned char *iv, int iv_len,
            const char *out_file, unsigned char *tag, int tag_len,
            int32_t * err_value, char *err_str)
{

#ifdef REMOVE_ENCRYPTION
    UNUSED (plaintext);
    UNUSED (plaintext_len);
    UNUSED (aad);
    UNUSED (aad_len);
    UNUSED (key);
    UNUSED (key_len);
    UNUSED (iv);
    UNUSED (iv_len);
    UNUSED (out_file);
    UNUSED (tag);
    UNUSED (tag_len);
    UNUSED (err_value);
    UNUSED (err_str);

    return CAL_NO_CRYPTO_API_ERROR;
#else
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    unsigned char ciphertext[plaintext_len + EVP_MAX_BLOCK_LENGTH];

    FILE *fho = NULL;
    int err = 0;
    do {
        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new ())) {
            handle_errors ("Failed to allocate ccm context structure",
                   err_value, err_str);
            break;
        }

        /* Initialise the encryption operation. */
        switch (key_len) {
            case 16:
                err =
                  EVP_EncryptInit_ex (ctx, EVP_aes_128_ccm (),
                                      NULL, NULL, NULL);
                break;
            case 24:
                err =
                  EVP_EncryptInit_ex (ctx, EVP_aes_192_ccm (),
                                      NULL, NULL, NULL);
                break;
            case 32:
                err =
                  EVP_EncryptInit_ex (ctx, EVP_aes_256_ccm (),
                                      NULL, NULL, NULL);
                break;
            default:
                handle_errors ("Failed allocating ccm context structure",
                               err_value, err_str);
                return *err_value;
        }

        if (err != 1) {
            handle_errors ("Failed to initialize ccm context structure",
                   err_value, err_str);
            break;
        }

        /*
         * Setting IV len to 7. Not strictly necessary as this
         * is the default but shown here for the purposes of this example
         */

        if (1 !=
            EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_CCM_SET_IVLEN,
                                 iv_len, NULL)) {
            handle_errors ("Failed to initialize IV", err_value, err_str);
            break;
        }

        /* Set tag length */
        EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL);

        /* Initialise key and IV */
        if (1 != EVP_EncryptInit_ex (ctx, NULL, NULL, key, iv)) {
            handle_errors ("Failed to initialize key", err_value, err_str);
            break;
        }

        /* Provide the total plaintext length */
        if (1 != EVP_EncryptUpdate (ctx, NULL, &len, NULL,
                                   plaintext_len)) {
            handle_errors ("Failed to initialize length parameter",
                           err_value, err_str);
            break;
        }

        /*
         * Provide the message to be encrypted, and obtain the encrypted
         * output. EVP_EncryptUpdate can only be called once for this
         */
        if (1 != EVP_EncryptUpdate (ctx, ciphertext, &len, plaintext,
                        plaintext_len)) {
            handle_errors ("Failed to encrypt", err_value, err_str);
            break;
        }
        ciphertext_len = len;

        /* Open out_file for writing */
        fho = fopen (out_file, "wb");
        if (fho == NULL) {
            handle_errors ("Cannot open file", err_value, err_str);
            break;
        }

        /* Write encrypted data to out file */
        if (fwrite (ciphertext, 1, ciphertext_len, fho)
                   != ciphertext_len) {
            handle_errors ("Cannot write file", err_value, err_str);
            break;
        }

        /*
         * Finalise the encryption.
         * Normally ciphertext bytes may be written at this stage,
         * but this does not occur in CCM mode
         */
        if (1 != EVP_EncryptFinal_ex (ctx, ciphertext + len, &len)) {
            handle_errors ("Failed to finalize", err_value, err_str);
            break;
        }
        ciphertext_len += len;

        /* Get the tag */
        if (1 != EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_CCM_GET_TAG,
                                      16, tag)) {
            handle_errors ("Failed to get tag", err_value, err_str);
            break;
        }

      } while (0);

    /* Clean up */
    EVP_CIPHER_CTX_free (ctx);

    if (fho) {
        fclose (fho);
    }

    return *err_value;
#endif
}

/*=======================================================================
 GLOBAL FUNCTION IMPLEMENTATIONS
 ======================================================================*/

/*--------------------------------
  get_der_encoded_certificate_data
----------------------------------*/
int32_t get_der_encoded_certificate_data(const char* ref,
                                         uint8_t ** der)
{
    /* Used for returning either size of der data or 0 to indicate an error */
    int32_t ret_val = 0;

    /* Engine configuration */
    ENGINE_CTX *ctx = NULL;

    /* X.509 certificate */
    X509 *cert = NULL;

    /* Allocate new context */
    ctx = ctx_new();

    if(ctx == NULL){
        return 0;
    }

    /* Initialize the context */
    if(!ctx_init(ctx)){
        ctx_destroy(ctx);
        return 0;
    }

    /* Read X509 certificate data */
    cert = read_certificate_pem(ref);
    if (!cert)
    {
       ctx_finish(ctx);
       ctx_destroy(ctx);
       return 0;
    }
#ifdef DEBUG
    X509_print_fp(stdout, cert);
#endif
    /* i2d_X509() allocates memory for der data, converts the X509
     * cert structure to binary der formatted data.  It then
     * returns the address of the memory allocated for the der data
     */
    ret_val = i2d_X509(cert, der);

    /* On error return 0 */
    if (ret_val < 0)
    {
        ret_val = 0;
    }

    /* Finish and destroy the context */
    ctx_finish(ctx);
    ctx_destroy(ctx);

    if(cert)
        X509_free(cert);

    return ret_val;
}

/*--------------------------
 gen_sig_data
 ---------------------------*/
int32_t
gen_sig_data (const char *in_file, const char *cert_ref,
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

    cert = read_certificate_pem (cert_ref);
    if (!cert)
    {
        error = CAL_CRYPTO_API_ERROR;
        goto out;
    }
#ifdef DEBUG
    X509_print_fp(stdout, cert);
#endif
    key = read_private_key_pem(cert_ref);

    if (key == NULL) {
        error = CAL_CRYPTO_API_ERROR;
        goto out;
    }

    error = X509_check_private_key(cert, key);
    if (!error) {
        error = CAL_CRYPTO_API_ERROR;
        goto out;
    }

    if (sig_fmt == SIG_FMT_ECDSA) {
        error = gen_sig_data_ecdsa (in_file, key, hash_alg, sig_buf,
                      sig_buf_bytes);
    }
    else if (sig_fmt == SIG_FMT_PKCS1) {
        error = gen_sig_data_raw (in_file, key, hash_alg, sig_buf,
                        (int32_t *) sig_buf_bytes);
    }
    else if (sig_fmt == SIG_FMT_CMS) {
        error = gen_sig_data_cms (in_file, cert, key, hash_alg, sig_buf,
                        sig_buf_bytes);
    }
    else {
        fprintf (stderr, "Invalid signature format\n");
        return CAL_INVALID_ARGUMENT;
    }

out:
    if(ctx) {
        /* Finish and destroy the context */
        ctx_finish(ctx);
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

/*--------------------------
 gen_auth_encrypted_data
 ---------------------------*/
int32_t
gen_auth_encrypted_data (const char *in_file, const char *out_file,
                 aead_alg_t aead_alg, uint8_t * aad, size_t aad_bytes,
                 uint8_t * nonce, size_t nonce_bytes, uint8_t * mac,
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

    UNUSED (aead_alg);

    do {
        /* Generate Nonce */
        err_value = gen_random_bytes ((uint8_t *) nonce, nonce_bytes);
        if (err_value != CAL_SUCCESS) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                      "Failed to get nonce");
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
#ifdef DEBUG
        printf ("nonce bytes: ");
        for (i = 0; i < nonce_bytes; i++) {
          printf ("%02x ", nonce[i]);
        }
        printf ("\n");
#endif
      if (reuse_dek) {
            fh = fopen (key_file, "rb");
            if (fh == NULL) {
                snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Unable to open dek file %s", key_file);
                fprintf (stderr, "%s\n", err_str);
                err_value = CAL_FILE_NOT_FOUND;
                break;
            }
          /* Read encrypted data into input_buffer */
            bytes_read = fread (key, 1, key_bytes, fh);
            if (bytes_read == 0) {
                snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                          "Cannot read file %s", key_file);
                fprintf (stderr, "%s\n", err_str);
                err_value = CAL_FILE_NOT_FOUND;
                fclose (fh);
                break;
            }
            fclose (fh);
        }
        else {
            /* Generate random aes key to use it for encrypting data */
            err_value = generate_dek_key (key, key_bytes);
            if (err_value) {
                snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Failed to generate random key");
                fprintf (stderr, "%s\n", err_str);
                err_value = CAL_CRYPTO_API_ERROR;
                break;
              }
        }

#ifdef DEBUG
        printf ("random key : ");
        for (i = 0; i < key_bytes; i++) {
            printf ("%02x ", key[i]);
        }
        printf ("\n");
#endif
        if (cert_file != NULL) {
            /* Encrypt key using cert file and save it in the key_file */
            err_value = encrypt_dek_key (key, key_bytes, cert_file,
                                         key_file);
            if (err_value) {
                snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Failed to encrypt and save key");
                fprintf (stderr, "%s\n", err_str);
                err_value = CAL_CRYPTO_API_ERROR;
                break;
            }
        } else {
            /* Save key in the key_file */
            err_value = write_plaintext_dek_key (key, key_bytes, cert_file,
                                 key_file);
            if (err_value) {
                snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                         "Failed to save key");
                fprintf (stderr, "%s\n", err_str);
                err_value = CAL_CRYPTO_API_ERROR;
                break;
              }
        }
        /* Get the size of in_file */
        fh = fopen (in_file, "rb");
        if (fh == NULL) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Unable to open binary file %s", in_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        fseek (fh, 0, SEEK_END);
        file_size = ftell (fh);
        plaintext = (unsigned char *) malloc (file_size);

        if (plaintext == NULL) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                  "Not enough allocated memory");
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        fclose (fh);

        fh = fopen (in_file, "rb");
        if (fh == NULL) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                      "Cannot open file %s", in_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_FILE_NOT_FOUND;
            break;
        }

        /* Read encrypted data into input_buffer */
        bytes_read = fread (plaintext, 1, file_size, fh);
        /* Reached EOF? */
        if (bytes_read == 0) {
            snprintf (err_str, MAX_ERR_STR_BYTES - 1,
                     "Cannot read file %s", out_file);
            fprintf (stderr, "%s\n", err_str);
            err_value = CAL_FILE_NOT_FOUND;
            break;
        }

        err_value = encryptccm (plaintext, file_size, aad, aad_bytes, key,
                        key_bytes, nonce, nonce_bytes, out_file, mac,
                        mac_bytes, &err_value, err_str);
        if (err_value == CAL_NO_CRYPTO_API_ERROR) {
            printf ("Encryption not enabled\n");
            break;
        }
    } while (0);

    free (plaintext);

    /* Clean up */
    return err_value;
}
