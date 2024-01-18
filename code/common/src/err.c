// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2018-2019, 2023 NXP
 */

/*===========================================================================*/
/**
    @file   err.c

    @brief  Implements the error logging interface used by different tools
*/

/*===========================================================================
                                INCLUDE FILES
=============================================================================*/
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "err.h"

/*===========================================================================
                               GLOBAL VARIABLES
=============================================================================*/
extern const char *g_tool_name;

/*===========================================================================
                               GLOBAL FUNCTIONS
=============================================================================*/

/*--------------------------
  error
---------------------------*/
void error(const char *err, ...)
{
    va_list args;

    va_start(args, err);

    printf("\n[ERROR] %s: ", g_tool_name);
    vprintf(err, args);
    printf("\n");

    va_end(args);

    exit(1);
}
