# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011. All rights reserved.
# Copyright 2018, 2023 NXP
#
#==============================================================================
#
#    File Name:  objects.mk
#
#    General Description: Defines the object files for the cst front end
#
#==============================================================================

# List the api object files to be built
OBJECTS += \
    csf_cmd_aut_dat.o \
    csf_cmd_ins_key.o \
    csf_cmd_misc.o \
    cst.o \
    acst.o \
    cst_lexer.o \
    cst_parser.o

OBJECTS_FRONTEND += \
    csf_cmd_aut_dat.o \
    csf_cmd_ins_key.o \
    csf_cmd_misc.o \
    cst.o \
    acst.o \
    cst_parser.o \
    cst_lexer.o
