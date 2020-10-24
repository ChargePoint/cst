/*===========================================================================*/
/**
    @file    misc_helper.c

    @brief   Provide miscellaneous helper functions 

@verbatim
=============================================================================

    Copyright 2020 NXP

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
#include <string.h>
#include "misc_helper.h"
#include "err.h"

/*===========================================================================
                               LOCAL CONSTANTS
=============================================================================*/
#define MAX_ERR_MSG_BYTES (1024)

/*===========================================================================
                                 LOCAL MACROS
=============================================================================*/

/*===========================================================================
                  LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
=============================================================================*/

/*===========================================================================
                            LOCAL VARIABLES
=============================================================================*/
char err_msg[MAX_ERR_MSG_BYTES];

/*===========================================================================
                            LOCAL FUNCTION PROTOTYPES
=============================================================================*/
/** Read bytes from a file
 *
 * Reads an amount of bytes from an input file
 *
 * @param[in]  filename Input file name to be read
 *
 * @param[out] byte_str Byte string struct to return the read data
 *
 * @param[in]  offsets  If defined,
 *
 * @pre @a filename and @a offsets must not be NULL
 *
 * @post none
 *
 * @returns the size of memory allocated point to by byte_str
 */

/*===========================================================================
                            LOCAL FUNCTIONS
=============================================================================*/

/*--------------------------
  read_file
---------------------------*/
void
read_file(const char *filename, byte_str_t *byte_str, offsets_t *offsets)
{
    FILE     *file = NULL;
    uint32_t bytes_to_read, read_size;

    /* Open the source file */
    file = fopen(filename, "rb");
    if (NULL == file)
    {
        snprintf(err_msg, MAX_ERR_MSG_BYTES, "Cannot open %s", filename);
        error(err_msg);
    }

    /* Get the file size */
    fseek(file, 0, SEEK_END);
    bytes_to_read = ftell(file);
    rewind(file);

    /* If some offsets are specified, refine the number of bytes to be read */
    if (NULL != offsets)
    {
        if ((bytes_to_read < offsets->first)
            || (bytes_to_read < offsets->second))
        {
            snprintf(err_msg,
                     MAX_ERR_MSG_BYTES,
                     "Offsets defined outside the file %s",
                     filename);
            error(err_msg);
        }

        if (offsets->first > offsets->second)
        {
            error("Incorrect offsets");
        }

        bytes_to_read = offsets->second - offsets->first;

        fseek(file, offsets->first, SEEK_SET);
    }

    /* Save the file data */
    byte_str->entry_bytes = bytes_to_read;
    byte_str->entry       = malloc(bytes_to_read);
    if (NULL == byte_str->entry)
    {
        snprintf(err_msg, MAX_ERR_MSG_BYTES, "Cannot allocate memory for handling %s", filename);
        error(err_msg);
    }

    memset(byte_str->entry, 0, bytes_to_read);
    read_size = fread(byte_str->entry, 1, bytes_to_read, file);

    if (read_size != bytes_to_read)
    {
        snprintf(err_msg, MAX_ERR_MSG_BYTES, "Unexpected read termination of %s", filename);
        error(err_msg);
    }

    fclose(file);
}
