# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
# Copyright 2022-2023 NXP
#
#==============================================================================
#
#    File Name:  objects.mk
#
#    General Description: Defines the object files for the api layer
#
#==============================================================================

# List the api object files to be built
OBJECTS += \
	adapt_layer_openssl.o \
	pkey.o \
	cert.o \
	ssl_wrapper.o \
	engine.o

OBJECTS_BACKEND_SSL += \
	adapt_layer_openssl.o \
	pkey.o \
	cert.o \
	ssl_wrapper.o \
	engine.o

OBJECTS_SRKTOOL += \
	cert.o \
	engine.o
