#==============================================================================
#
#    File Name:  osx.mk
#
#    General Description: Makefile defining platform specific tools for
#                         MacOS/OSX
#
#==============================================================================
#
#    Copyright 2019 NXP
#
#
#==============================================================================

ifneq ($(ENCRYPTION), yes)
	CDEFINES := -DREMOVE_ENCRYPTION
endif

OPENSSL_CONFIG := darwin64-x86_64-cc
