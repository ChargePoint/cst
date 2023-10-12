#==============================================================================
#
#    File Name:  Makefile
#
#    General Description:  CST Makefile that builds the CST libraries and
#                          executable.
#
#==============================================================================
#
#             Freescale Semiconductor
#    (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
#    Copyright 2017-2019, 2022 NXP
#
#==============================================================================

# COMMON MAKEFILE VARIABLES
#==============================================================================
ifndef VERBOSE
.SILENT:
endif

OSTYPES := linux64 linux32 mingw32 osx
OSTYPES_BUILD_ALL := $(filter-out osx,$(OSTYPES))

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

OPENSSL_CONFIG += no-deprecated no-threads no-shared no-hw no-idea

# COMPONENT BUILD RULES
#==============================================================================
# build the complete CST package
#all:
#  # Remove osx from 'all' target
#	$(foreach ostype,$(OSTYPES_BUILD_ALL),$(MAKE) OSTYPE=$(ostype) openssl os_bin clean ;)

# Make destination directories
$(DST)%:
	$(MKDIR) $@

# Build CST binary for target OS
os_bin: $(DST)/$(OSTYPE)/bin scripts
	$(MAKE) -C $(CST_CODE_PATH)/obj.$(OSTYPE) rel_bin

# Build binaries for the given configuration
build:
	$(MAKE) -C $(CST_CODE_PATH)/obj.$(OSTYPE) build

# Copy key and certificate generation scripts
scripts: $(DST)/ca $(DST)/keys $(DST)/crts
	@echo "Copy scripts"
	$(CP) ./scripts/*.cnf $(DST)/ca
	$(CP) ./scripts/*.sh  $(DST)/keys
	$(CP) ./scripts/*.bat $(DST)/keys

# Clean up after build
clean:
	$(MAKE) -C $(CST_CODE_PATH)/obj.$(OSTYPE) OSTYPE=$(OSTYPE) clean

# clean up removing all build and release files
clobber:
	@echo "Clean OS objects"
	$(foreach OSTYPE, $(OSTYPES), $(MAKE) OSTYPE=$(OSTYPE) clean ;)
	@echo "Clean release"
	$(RMDIR) $(DST)/

# build openssl library
openssl:
	cd $(_OPENSSL_PATH)           && \
	./Configure $(OPENSSL_CONFIG) && \
	make clean                    && \
	make                          && \
	cp ms/applink.c include/openssl/
