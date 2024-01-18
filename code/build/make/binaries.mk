# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011-2015 All rights reserved.
# Copyright 2018-2020, 2022-2023 NXP
#
#===============================================================================
#
#    File Name:  binaries.mk
#
#    General Description: Common makefile for building the CST libraries and
#    tool executables.
#
#===============================================================================

# Default target
#===============================================================================
default: all

# Before including init.mk we need to set relative path to root
# current directory is obj.$(OSTYPE) that is two levels down from root
ROOTPATH := ../..
include ../build/make/$(OSTYPE).mk
include ../build/make/init.mk

# Binaries
#===============================================================================
LIB_BACKEND_SSL    := libbackend-ssl.a
LIB_FRONTEND       := libfrontend.a

EXE_SRKTOOL        := srktool$(EXEEXT)
EXE_CST            := cst$(EXEEXT)
EXE_CONVLB         := convlb$(EXEEXT)
EXE_HAB_LOG_PARSER := hab_log_parser$(EXEEXT)

# Compiler and linker paths
#===============================================================================
CINCLUDES := $(foreach dir,$(VPATH),-I$(dir)/../hdr)

# OpenSSL
COPTIONS  += -I$(_OPENSSL_PATH)/include
LDOPTIONS += -L$(_OPENSSL_PATH) -L$(_OPENSSL_PATH)/lib
ifeq ($(OSTYPE),linux64)
LDOPTIONS += -L$(_OPENSSL_PATH)/lib64
endif

include ../build/make/$(TOOLCHAIN).mk
include ../build/make/objects.mk

# Build header dependency files list
#===============================================================================
DEPLIST := $(subst .o,.d,$(OBJECTS))

# Build Rules
#===============================================================================
all: build

# Executables to be released and where
EXECUTABLES := $(O)/$(OSTYPE)/bin/$(EXE_SRKTOOL)
EXECUTABLES += $(O)/$(OSTYPE)/bin/$(EXE_CST)
EXECUTABLES += $(O)/$(OSTYPE)/bin/$(EXE_HAB_LOG_PARSER)

ifeq ($(OSTYPE),mingw32)
EXECUTABLES += $(O)/keys/$(EXE_CONVLB)
endif

BUILDS := $(EXECUTABLES)

build: $(notdir $(BUILDS))

install: build $(notdir $(EXECUTABLES))
	@echo "Copy executables"
	$(foreach EXE,$(EXECUTABLES), \
	if [ -f "$(notdir $(EXE))" ]; then \
		$(INSTALL) -D -m 755 $(notdir $(EXE)) $(EXE); \
		strip $(EXE); \
	fi;)

$(EXE_SRKTOOL): $(OBJECTS_SRKTOOL)

$(LIB_BACKEND_SSL): $(OBJECTS_BACKEND_SSL)

$(LIB_FRONTEND): $(OBJECTS_FRONTEND)

$(EXE_CST): $(LIB_FRONTEND) $(LIB_BACKEND_SSL)

$(EXE_CONVLB): $(OBJECTS_CONVLB)

ifneq ($(strip $(OBJECTS_HAB_LOG_PARSER)),)
$(EXE_HAB_LOG_PARSER): $(OBJECTS_HAB_LOG_PARSER)
else
$(EXE_HAB_LOG_PARSER):
	@echo "No objects to build $(EXE_HAB_LOG_PARSER), skipping."
endif

clean:
	@echo "Clean obj.$(OSTYPE)"
	@$(FIND) . -type f ! -name "Makefile" -execdir $(RM) {} +

include ../build/make/rules.mk
-include $(DEPLIST)
