/*===========================================================================*/
/**
 @file    config.c

 @brief   Implements an interface to load HSM related configuration and HSM objects
 binding table.

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
 
#include <config.h>

int read_hsm_config(const char* config_file, hsm_config_t * config,
		hsm_object_t** hsm_objects) {
	/* When you are calling config_destroy() library will free all the memory allocated by it. */
	/* So before calling config_destroy() you need to save your result some where else. */

	config_t cfg, *cf;
	const char *hsm_module = NULL;
	const char *hsm_user = NULL;
	const char *hsm_pin = NULL;
	long long hsm_slot = 0;
	config_setting_t *setting = NULL;
	hsm_object_t * chsm_objects = NULL;

	cf = &cfg;
	config_init(cf);

	if (!config_read_file(cf, config_file)) {
		fprintf(stderr, "Error reading configuration file %s:%d - %s\n",
				config_error_file(cf), config_error_line(cf),
				config_error_text(cf));
		config_destroy(cf);
		return 1;
	}

	if (config_lookup_string(cf, "hsm.module", &hsm_module)) {
		strcpy(config->module_path, hsm_module);
	} else {
		printf("=> PKCS#11 MODULE PATH: ");
		scanf("%256s", config->module_path);
	}

	if (config_lookup_string(cf, "hsm.pin", &hsm_pin)) {
		strcpy(config->pin, hsm_pin);
	} else {
		printf("=> PIN: ");
		scanf("%32s", config->pin);
	}
	if (config_lookup_int64(cf, "hsm.slot", &hsm_slot)) {
		config->slot = hsm_slot;
	} else {
		printf("=> SLOT: ");
		scanf("%ld", &config->slot);
	}

	/* Output a list of file-id mapping . */
	setting = config_lookup(&cfg, "hsm.objects");
	if (setting != NULL) {
		unsigned int count = config_setting_length(setting);
		unsigned int i;

		for (i = 0; i < count; ++i) {
			config_setting_t *hsm_object = config_setting_get_elem(setting, i);

			const char *file, *id;

			if (!(config_setting_lookup_string(hsm_object, "id", &id)
					&& config_setting_lookup_string(hsm_object, "file", &file)))
				continue;

			hsm_object_t *hobject;
			hobject = (hsm_object_t *) malloc(sizeof(hsm_object_t));

			strcpy(hobject->id, id);
			strcpy(hobject->file, file);

			hobject->next = chsm_objects;
			chsm_objects = hobject;

		}

		*hsm_objects = chsm_objects;

	}

	config_destroy(&cfg);

	return 0;

}
