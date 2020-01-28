#==============================================================================
#
#    File Name:  linux32.mk
#
#    General Description: Makefile defining platform specific tools for
#                         linux32
#
#==============================================================================
#
#             Freescale Semiconductor
#    (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
#    Copyright 2018-2019 NXP
#
#
#==============================================================================

ifneq ($(ENCRYPTION), yes)
	CDEFINES := -DREMOVE_ENCRYPTION
endif

OPENSSL_CONFIG := linux-generic32
