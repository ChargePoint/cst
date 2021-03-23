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
#        (c) Freescale Semiconductor, Inc. 2011. All rights reserved.
#        Copyright 2018 NXP
#
#
#==============================================================================

# List the api object files to be built
OBJECTS += \
    openssl_helper.o \
    srk_helper.o \
    err.o

OBJECTS_SRKTOOL += \
    openssl_helper.o \
    srk_helper.o \
    err.o

OBJECTS_FRONTEND += \
    openssl_helper.o \
    srk_helper.o \
    err.o
