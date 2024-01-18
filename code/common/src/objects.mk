# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
# Copyright 2018, 2020, 2023 NXP
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
    misc_helper.o \
    err.o
