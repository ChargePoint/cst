/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2018-2019, 2023 NXP
 */

#ifndef ARCH_TYPES_H
#define ARCH_TYPES_H
/*===========================================================================*/
/**
    @file    arch_types.h

    @brief   Boot architectures interface
 */

/*===========================================================================
                            INCLUDE FILES
=============================================================================*/
#include "hab_types.h"
#include "ahab_types.h"

/*===========================================================================
                                MACROS
=============================================================================*/

/* Maximums supported by the different architectures */
#define MAX_CERTIFICATES_ALLOWED  4    /**< Max number of X.509 certs */
#define MAX_SRK_TABLE_BYTES       3072 /**< Maximum bytes for SRK table */

/* HAB4/AHAB SRK Table definitions */
#define SRK_TABLE_HEADER_BYTES    4    /**< Number of bytes in table header */
#define SRK_KEY_HEADER_BYTES      12   /**< Number of bytes in key header */

/* Missing define in container.h */
#define SRK_RSA3072               0x6

/*===========================================================================
                                TYPEDEFS
=============================================================================*/
typedef enum tgt_e
{
    TGT_UNDEF = 0, /**< Undefined target */
    TGT_HAB,       /**< HAB target       */
    TGT_AHAB       /**< AHAB target      */
} tgt_t;

typedef enum srk_set_e
{
    SRK_SET_UNDEF = 0, /**< Undefined SRK set */
    SRK_SET_NXP,       /**< NXP SRK set       */
    SRK_SET_OEM,       /**< OEM SRK set       */
} srk_set_t;

#endif /* ARCH_TYPES_H */
