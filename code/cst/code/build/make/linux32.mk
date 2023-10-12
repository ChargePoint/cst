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
#    Copyright 2018-2020, 2022 NXP
#
#
#==============================================================================

ifeq ($(ENCRYPTION), no)
	CDEFINES := -DREMOVE_ENCRYPTION
endif

OPENSSL_CONFIG := linux-x86  --prefix="/opt/cst-ssl" --openssldir="/opt/cst-ssl"
