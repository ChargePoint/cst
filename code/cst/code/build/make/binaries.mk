#===============================================================================
#
#    File Name:  binaries.mk
#
#    General Description: Common makefile for building the CST libraries and
#    tool executables.
#
#===============================================================================
#
#             Freescale Semiconductor
#    (c) Freescale Semiconductor, Inc. 2011-2015 All rights reserved.
#    Copyright 2018-2020 NXP
#
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
LIB_BACKEND        := libbackend.a
LIB_FRONTEND       := libfrontend.a

EXE_SRKTOOL        := srktool$(EXEEXT)
EXE_CST            := cst$(EXEEXT)
EXE_CONVLB         := convlb$(EXEEXT)

# Compiler and linker paths
#===============================================================================
CINCLUDES := $(SUBSYS:%=-I$(CST_CODE_PATH)/%/hdr)

# OpenSSL
COPTIONS  += -I$(_OPENSSL_PATH)/include
LDOPTIONS += -L$(_OPENSSL_PATH)

include ../build/make/$(TOOLCHAIN).mk
include ../build/make/objects.mk

# Build header dependency files list
#===============================================================================
DEPLIST := $(subst .o,.d,$(OBJECTS))

# Build Rules
#===============================================================================
all: build

# Executables to be released and where
EXECUTABLES := $(DST)/$(OSTYPE)/bin/$(EXE_SRKTOOL)
EXECUTABLES += $(DST)/$(OSTYPE)/bin/$(EXE_CST)

ifeq ($(OSTYPE),mingw32)
EXECUTABLES += $(DST)/keys/$(EXE_CONVLB)
endif

BUILDS := $(EXECUTABLES)

build: $(notdir $(BUILDS))

rel_bin: rel_exe

rel_exe: $(notdir $(EXECUTABLES))
	@echo "Copy executables"
	$(foreach EXE,$(EXECUTABLES),$(CP) $(notdir $(EXE)) $(EXE) ; strip $(EXE) ;)

$(EXE_SRKTOOL): $(OBJECTS_SRKTOOL)

$(LIB_BACKEND): $(OBJECTS_BACKEND)

$(LIB_FRONTEND): $(OBJECTS_FRONTEND)

$(EXE_CST): $(LIB_FRONTEND) $(LIB_BACKEND)

$(EXE_CONVLB): $(OBJECTS_CONVLB)


clean:
	@echo "Clean obj.$(OSTYPE)"
	@$(FIND) . -type f ! -name "Makefile" -execdir $(RM) {} +

include ../build/make/rules.mk
-include $(DEPLIST)
