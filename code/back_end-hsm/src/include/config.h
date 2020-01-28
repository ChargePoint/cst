#ifndef ___CONFIG_H_INC___
#define ___CONFIG_H_INC___
/*===========================================================================*/
/**
 @file    config.h

 @brief   Header file for config.c

 @verbatim
 =============================================================================

    Copyright 2018 NXP

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


#define LIBCONFIG_STATIC

#include <libconfig.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_PATH 260
#define MAX_PIN_LEN 255
#define MAX_AUTH_LEN 32
#define MAX_ID_LEN 128

/* This should definitively be removed in future version */
/* In this version we should have it since we can't modify the frontend to support providing HSM objects ID in CSF file */
typedef struct hsm_object {
	char id[MAX_ID_LEN]; /*HSM Object ID*/
	char file[MAX_PATH]; /*Object path on file system*/
	struct hsm_object *next;
} hsm_object_t;

typedef struct hsm_config {
	unsigned char module_path[MAX_PATH];
	unsigned char pin[MAX_PIN_LEN];
	unsigned long slot;
} hsm_config_t;

int read_hsm_config(const char* config_file, hsm_config_t * config,
		hsm_object_t** hsm_objects);

#endif /* ___CONFIG_H_INC___ */

