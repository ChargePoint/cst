# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
# Copyright 2018-2019, 2022-2023 NXP
#
#==============================================================================
#
#    File Name:  init.mk
#
#    General Description: Makefile defining platform specific tools and
#                         variables used throughout the build machine.
#
#==============================================================================

# Define subsystems and source location
#==============================================================================
CST_CODE_PATH := $(ROOTPATH)/code
SUBSYS        := common back_end-ssl back_end-pkcs11 srktool front_end convlb
VPATH         := $(SUBSYS:%=$(CST_CODE_PATH)/%/src)
ADDONS_PATH   := $(ROOTPATH)/add-ons
VPATH         += $(shell for dir in $(ADDONS_PATH)/*; do \
					if [ -d "$$dir/src" ]; then \
						echo -n "$$dir/src "; \
					fi; \
				done)

# Common commands
#==============================================================================
FIND    := find
CD      := cd
RM      := rm -f
RMDIR   := rm -rf
MKDIR   := mkdir -p
CP_REC  := cp -fr
CP      := cp -f
INSTALL := install

ifeq ($(OSTYPE),osx)
YACC   := yacc
else
YACC   := byacc
endif
LEX    := flex
