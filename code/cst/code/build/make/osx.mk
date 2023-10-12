#==============================================================================
#
#    File Name:  osx.mk
#
#    General Description: Makefile defining platform specific tools for
#                         MacOS/OSX
#
#==============================================================================
#
#    Copyright 2019-2020, 2022 NXP
#
#
#==============================================================================

ifeq ($(ENCRYPTION), no)
	CDEFINES := -DREMOVE_ENCRYPTION
endif

OPENSSL_CONFIG := darwin64-x86_64-cc --prefix="/opt/cst-ssl" --openssldir="/opt/cst-ssl"
