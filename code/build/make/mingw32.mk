# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
# Copyright 2018, 2020, 2022 NXP
#
#==============================================================================
#
#    File Name:  mingw32.mk
#
#    General Description: Makefile defining platform specific tools for
#                         mingw32
#
#==============================================================================

# Define -mno-ms-bitfields to get correct bit-field layout of packed structs
EXTRACFLAGS += -mno-ms-bitfields

ifeq ($(ENCRYPTION), no)
	CDEFINES := -DREMOVE_ENCRYPTION -DUSE_APPLINK
endif

EXEEXT = .exe

OPENSSL_CONFIG := mingw --cross-compile-prefix=i686-w64-mingw32- enable-capieng
