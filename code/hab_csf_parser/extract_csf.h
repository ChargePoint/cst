/*

    Copyright 2017-2019 NXP

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

 */

#ifndef CSF_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define IVT_HDR_VAL         0x402000d1
#define IVT_HDR_MASK        0xf0ffffff

#define assert(x)       if ((x) == 0) { \
                                printf("ASSERT failed at %s:%d\n", __FUNCTION__, __LINE__);    \
                                exit(2); \
                        }

#define HAB_HDR_LEN(h) ((((uint8_t *)&((h)->len))[0] << 8)    \
                        | (((uint8_t *)&((h)->len))[1]))

#define HAB_TAG_CSF      0xD4 /* Command Sequence File HAB_TAG_CSF */

typedef struct __attribute__((packed)) {
        uint32_t header;
        uint32_t start;
        uint32_t res1;
        uint32_t dcd;
        uint32_t boot_data;
        uint32_t self;
        uint32_t csf;
        uint32_t res2;
} ivt_t;

typedef struct __attribute__((packed)) {
        uint8_t tag;
        uint16_t len;
        uint8_t flags;
} hab_hdr_t;

int debug_log;
FILE *fp_debug;

#endif /* CSF_PARSER_H */

const uint8_t *extract_csf(const uint8_t *buf, int buf_size, int *csf_len);
