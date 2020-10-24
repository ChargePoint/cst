#ifndef MISC_HELPER_H
#define MISC_HELPER_H
/*===========================================================================*/
/**
    @file    misc_helper.h

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
#include "csf.h"

/*===========================================================================
                    STRUCTURES AND OTHER TYPEDEFS
=============================================================================*/
/** Byte string
 *
 * Defines the byte string struct
 */
typedef struct byte_str_s
{
    uint8_t *entry;
    size_t  entry_bytes;
} byte_str_t;

/*===========================================================================
                         FUNCTION PROTOTYPES
=============================================================================*/
#ifdef __cplusplus
extern "C" {
#endif

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
void
read_file(const char *filename, byte_str_t *byte_str, offsets_t *offsets);

#ifdef __cplusplus
}
#endif

#endif /* MISC_HELPER_H */
