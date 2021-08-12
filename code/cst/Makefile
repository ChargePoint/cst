#==============================================================================
#
#    File Name:  Makefile
#
#    General Description:  This is the release Makefile for the CST.
#                          Builds the SIS, API library and CST executable
#                          for the selected configurations.
#
#==============================================================================
#
#             Freescale Semiconductor
#    (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
#    Copyright 2017-2019 NXP
#
#==============================================================================

# COMMON MAKEFILE VARIABLES
#==============================================================================
ifndef VERBOSE
.SILENT:
endif

OSTYPES := linux64 linux32 mingw32 osx

OSTYPE ?= $(word 1,$(OSTYPES))

ifeq ($(filter-out $(OSTYPE),$(OSTYPES)),$(OSTYPES))
$(error OSTYPE is not correct (expected values: $(OSTYPES)))
endif

include code/build/make/$(OSTYPE).mk

# Before including init.mk we need to set relative path to root
ROOTPATH := $(PWD)
include code/build/make/init.mk

# RELEASE SPECIFIC VARIABLE DEFINITIONS
#==============================================================================
export DST := $(PWD)/release


# OPENSSL
#===============================================================================
OPENSSL_PATH ?= $(PWD)/../openssl
export _OPENSSL_PATH := $(realpath $(OPENSSL_PATH))

OPENSSL_CONFIG += no-deprecated no-threads no-shared no-dso no-engine no-hw \
                  no-idea

# COMPONENT BUILD RULES
#==============================================================================

# Make destination directories
$(DST)%:
	$(MKDIR) $@

# release binaries for the given configuration
rel_bin: $(DST)/$(OSTYPE)/bin $(DST)/keys
	$(MAKE) -C $(CST_CODE_PATH)/obj.$(OSTYPE) rel_bin

# build binaries for the given configuration
build:
	$(MAKE) -C $(CST_CODE_PATH)/obj.$(OSTYPE) build

# Clean up after build
clean:
	$(MAKE) -C $(CST_CODE_PATH)/obj.$(OSTYPE) clean

# build openssl library
openssl:
	cd $(_OPENSSL_PATH)           && \
	./Configure $(OPENSSL_CONFIG) && \
	make clean                    && \
	make                          && \
	cp ms/applink.c include/openssl/
