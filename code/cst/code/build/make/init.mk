#==============================================================================
#
#    File Name:  init.mk
#
#    General Description: Makefile defining platform specific tools and
#                         variables used throughout the build machine.
#
#==============================================================================
#
#             Freescale Semiconductor
#    (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
#    Copyright 2018-2019 NXP
#
#
#==============================================================================

# Define subsystems and source location
#==============================================================================
CST_CODE_PATH := $(ROOTPATH)/code
SUBSYS        := common back_end srktool front_end convlb
VPATH         := $(SUBSYS:%=$(CST_CODE_PATH)/%/src)

# Common commands
#==============================================================================
FIND   := find
CD     := cd
RM     := rm -f
RMDIR  := rm -rf
MKDIR  := mkdir -p
CP_REC := cp -fr
CP     := cp -f

ifeq ($(OSTYPE),osx)
YACC   := yacc
else
YACC   := byacc
endif
LEX    := flex
