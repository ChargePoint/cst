/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2018-2019, 2023 NXP
 */

#ifndef ERR_H
#define ERR_H
/*===========================================================================*/
/**
    @file    err.h

    @brief   Error logging interface
 */

/*===========================================================================
                         FUNCTION PROTOTYPES
=============================================================================*/
#ifdef __cplusplus
extern "C" {
#endif

/** Display error message
 *
 * Displays error message to STDOUT and exits the program
 *
 * @param[in] err Error string to display to the user
 *
 * @pre  @a err is not NULL
 *
 * @post Program exits with exit code 1.
 */
void
error(const char *err, ...);

#ifdef __cplusplus
}
#endif

#endif /* ERR_H */
