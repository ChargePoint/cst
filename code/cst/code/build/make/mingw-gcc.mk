#==============================================================================
#
#    File Name:  mingw-gcc.mk
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
CROSSCOMPILER := i686-w64-mingw32-

CC      := $(CROSSCOMPILER)gcc
AR      := $(CROSSCOMPILER)ar
LD      := $(CROSSCOMPILER)gcc
OBJCOPY := $(CROSSCOMPILER)objcopy

# C compiler flags
#==============================================================================
COPTIONS += -std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Werror -g
# -pedantic has been removed due to the OpenSSL #include-d C file
# -fPIC is ignored for this target, the code is already position independent

# Linker flags
#==============================================================================
LDOPTIONS += -g -static

LDLIBS := -lcrypto -lgdi32 -lws2_32

# Archiver flags
#==============================================================================
ARFLAGS := -rc
