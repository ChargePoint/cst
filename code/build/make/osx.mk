# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2019-2020, 2022-2023 NXP
#
#==============================================================================
#
#    File Name:  osx.mk
#
#    General Description: Makefile defining platform specific tools for
#                         MacOS/OSX
#
#==============================================================================

ifeq ($(ENCRYPTION), no)
	CDEFINES := -DREMOVE_ENCRYPTION
endif

OPENSSL_CONFIG := darwin64-x86_64-cc
