#==============================================================================
#
#    File Name:  objects.mk
#
#    General Description: Defines the object files for the api layer
#
#==============================================================================
#
#
#
#            Freescale Semiconductor
#        (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
#            Copyright 2022 NXP
#
#
#==============================================================================

# List the api object files to be built
OBJECTS += \
	adapt_layer_openssl.o \
	pkey.o \
	cert.o \
	ssl_wrapper.o

OBJECTS_BACKEND_SSL += \
	adapt_layer_openssl.o \
	pkey.o \
	cert.o \
	ssl_wrapper.o

OBJECTS_SRKTOOL += \
	cert.o
