# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
# Copyright 2017-2019, 2022-2023 NXP
#
#==============================================================================
#
#    File Name:  Makefile
#
#    General Description:  CST Makefile that builds the CST libraries and
#                          executable.
#
#==============================================================================

# Define CST version number
export VERSION := 3.4.0

# Common Makefile variables
OSTYPES := linux64 linux32 mingw32 osx
OSTYPES_BUILD_ALL := $(filter-out osx,$(OSTYPES))

# Get operating system name and machine hardware name
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Set SYSTEM_TYPE based on the detected operating system
ifeq ($(UNAME_S),Linux)
    ifeq ($(UNAME_M),x86_64)
        SYSTEM_TYPE := linux64
    else
        SYSTEM_TYPE := linux32
    endif
endif
ifeq ($(UNAME_S),Darwin)
    SYSTEM_TYPE := osx
endif
ifeq ($(UNAME_S),MINGW32_NT-*)
    SYSTEM_TYPE := mingw32
endif

export OSTYPE ?= $(SYSTEM_TYPE)

ifeq ($(filter-out $(OSTYPE),$(OSTYPES)),$(OSTYPES))
$(error OSTYPE is not correct (expected values: $(OSTYPES)))
endif

include code/build/make/$(OSTYPE).mk

# Before including init.mk we need to set relative path to root
ROOTPATH := $(CURDIR)
include code/build/make/init.mk

# Build specific variable definitions
export O ?= $(ROOTPATH)/build

# Define the release package name with the version number
RELEASE_PACKAGE := cst-$(VERSION)

ADDONS     := $(wildcard $(ROOTPATH)/add-ons/*)
ADDONS_OUT := $(ROOTPATH)/add-ons/hab_log_parser
ADDONS_REL := $(filter-out $(ADDONS_OUT),$(ADDONS))

CSTSRC     := $(wildcard $(ROOTPATH)/code/*)
CSTSRC_OBJ := $(addprefix obj.,$(OSTYPES))
CSTSRC_OUT := $(addprefix $(ROOTPATH)/code/,$(CSTSRC_OBJ))
CSTSRC_REL := $(filter-out $(CSTSRC_OUT),$(CSTSRC))

# Build CST binary for target OS
$(O)/$(OSTYPE)/bin: openssl
	$(MAKE) -C $(CST_CODE_PATH)/obj.$(OSTYPE) install

# OpenSSL source and custom build paths
export OPENSSL_VERSION ?= 3.2.0
OPENSSL_TAR := openssl-$(OPENSSL_VERSION).tar.gz
OPENSSL_URL := https://www.openssl.org/source/$(OPENSSL_TAR)
OPENSSL_SRC_DIR := openssl-$(OSTYPE)
OPENSSL_BUILD_DIR := /opt/cst
OPENSSL_CONFIG += no-tests no-threads no-shared no-idea no-hw no-idea

# Check if OPENSSL_PATH is provided and valid
ifdef OPENSSL_PATH
ifeq ($(wildcard $(OPENSSL_PATH)/*),)
$(error OPENSSL_PATH is not valid)
endif
OPENSSL_LIB_DIR := $(OPENSSL_PATH)
openssl:
	@echo "Using provided OpenSSL library."
else
# Default behavior: download and build OpenSSL
OPENSSL_LIB_DIR := $(OPENSSL_SRC_DIR)

# Download and unpack OpenSSL
$(OPENSSL_TAR):
	curl -O $(OPENSSL_URL)

$(OPENSSL_SRC_DIR): $(OPENSSL_TAR)
	tar xzf $(OPENSSL_TAR)
	mv openssl-$(OPENSSL_VERSION) $(OPENSSL_SRC_DIR)

# Build OpenSSL
openssl: $(OPENSSL_SRC_DIR)
	cd $(OPENSSL_SRC_DIR) && ./Configure \
	--prefix=$(OPENSSL_BUILD_DIR) \
	--openssldir=$(OPENSSL_BUILD_DIR) $(OPENSSL_CONFIG)
	$(MAKE) -C $(OPENSSL_SRC_DIR)
	$(CP) $(OPENSSL_SRC_DIR)/ms/applink.c \
	$(OPENSSL_SRC_DIR)/include/openssl/
endif

# OPENSSL_LIB_DIR depends on conditions
$(eval export _OPENSSL_PATH := $(ROOTPATH)/$(OPENSSL_LIB_DIR))

# Make build directories
$(O)%:
	$(MKDIR) $@

# Build binaries
build: $(O)/$(OSTYPE)/bin

# Install binaries, scripts, docs and sources
install: build scripts docs sources

# Helper function to install scripts and configuration files
define install_scripts
	@for dir in scripts $(2); do \
		if [ -d $$dir ]; then \
			find $$dir -name $(1) -type f | while IFS= read -r f; do \
				echo "Installing $$f to $(O)/$(2)"; \
				case $$f in \
				*.sh|*.bat) \
					$(INSTALL) -D -m 0755 "$$f" $(O)/$(2) ;; \
					*) \
					$(CP) "$$f" $(O)/$(2) ;; \
				esac; \
			done; \
		fi; \
	done
endef

# Copy key and certificate generation scripts
scripts: $(O)/ca $(O)/keys $(O)/crts
	@echo "Copy scripts and configuration files"
	$(call install_scripts,*.cnf,ca)
	$(call install_scripts,*.sh,keys)
	$(call install_scripts,*.bat,keys)

# Clean-up after build
clean:
	@echo "Clean-up build objects"
	$(MAKE) -C $(CST_CODE_PATH)/obj.$(OSTYPE) OSTYPE=$(OSTYPE) clean

# Clean-up removing all build output files
clobber:
	@echo "Clean OS objects"
	$(foreach OSTYPE, $(OSTYPES), $(MAKE) OSTYPE=$(OSTYPE) clean ;)
	@echo "Clean build"
	$(RMDIR) $(O)/

# Clean-up the repository by removing untracked files and directories
distclean:
	git clean -dfx

# Copy documentation to output folder
docs: $(O)/docs
	@echo "Copy documentations"
	$(CP_REC) $(shell find docs -name '*.pdf' -o -name '*.md') $(O)/docs
	$(CP_REC) ./Release_Notes.txt  $(O)/
	$(CP_REC) ./BUILD.md           $(O)/
	$(CP_REC) ./LICENSE.openssl    $(O)/
	$(CP_REC) ./LICENSE.bsd3       $(O)/
	@if [ -d "$(ROOTPATH)/add-ons/hab_log_parser" ]; then \
		$(CP_REC) $(ROOTPATH)/add-ons/hab_log_parser/README \
					$(O)/docs/README.hab_log_parser; \
		$(CP_REC) $(ROOTPATH)/add-ons/hab_log_parser/LICENSE.hidapi $(O)/; \
	else \
		echo "Skipping hab_log_parser."; \
	fi
	$(CP_REC) ./Software_Content_Register_CST.txt $(O)/

# Copy source and header directories to output folder
sources: $(addprefix $(O)/code/,$(CSTSRC_OBJ))
	@echo "Copy sources"
	$(CP_REC) Makefile \
	          $(O)/
	$(CP_REC) Dockerfile \
	          $(O)/
	$(CP_REC) Dockerfile.hsm \
	          $(O)/
	$(CP_REC) $(CSTSRC_REL) \
	          $(O)/code/
	$(MKDIR)  $(O)/add-ons/
	$(CP_REC) $(ADDONS_REL) \
	          $(O)/add-ons/
	$(foreach objdir,$(CSTSRC_OBJ), $(MKDIR) $(O)/code/$(objdir); \
		$(CP_REC) $(CST_CODE_PATH)/$(objdir)/Makefile $(O)/code/$(objdir)/ ;)

# Build and the images for all OS targets except OSX. The Docker build
# environment doesn't include cross compile tools for OSX.
build-all:
	$(foreach ostype,$(OSTYPES_BUILD_ALL),$(MAKE) OSTYPE=$(ostype) ;)

install-all:
	$(foreach ostype,$(OSTYPES_BUILD_ALL),$(MAKE) OSTYPE=$(ostype) install ;)

# Sequentially execute build and install for all supported systems,
# then install scripts documentation and source code.
all: build-all install-all scripts docs sources

# Create a package of the build directory
package: all
	@echo "Creating package version $(VERSION)"
	ln -sfn $(O) $(RELEASE_PACKAGE)
	tar -czvf $(RELEASE_PACKAGE).tgz \
	--transform='s,^$(notdir $(O)),$(RELEASE_PACKAGE),' $(notdir $(O))
	@echo "Package file $(RELEASE_PACKAGE).tgz created."

.PHONY: all build-all install-all scripts docs sources package
