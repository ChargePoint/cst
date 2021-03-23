#==============================================================================
#
#    File Name:  gcc.mk
#
#    General Description: Makefile for native gcc
#
#==============================================================================
#
#             Freescale Semiconductor
#    (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.
#    Copyright 2018 NXP
#
#
#==============================================================================

# Toolchain commands
#==============================================================================
CC      := gcc
AR      := ar
LD      := gcc
OBJCOPY := objcopy

# C compiler flags
#==============================================================================
COPTIONS += -std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Werror -pedantic -fPIC -g

# Linker flags
#==============================================================================
LDOPTIONS += -g

LDLIBS := -lcrypto

# Archiver flags
#==============================================================================
ARFLAGS := -rc
