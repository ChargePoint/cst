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
#              Freescale Semiconductor
#        (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
#
#
#
#==============================================================================

# List the api object files to be built
OBJECTS += \
	adapt_layer_openssl.o \
	pkey.o \
	ssl_wrapper.o

OBJECTS_BACKEND += \
	adapt_layer_openssl.o \
	pkey.o \
	ssl_wrapper.o
