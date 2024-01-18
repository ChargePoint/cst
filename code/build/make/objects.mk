# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011-2015. All rights reserved.
# Copyright 2023 NXP
#
#==============================================================================
#
#    File Name:  objects.mk
#
#    General Description:  This makefile builds a centralized list of all
#                          object files from the objects.mk files
#                          defined for each layer or subcomponent.
#
#==============================================================================

# All library object files to be built are added to $(OBJECTS) by
# Makefile.objects in each subsystem.
OBJECTS :=
OBJECTS_BACKEND :=
OBJECTS_FRONTEND :=
OBJECTS_SRKTOOL :=

# include object files for each subsystem.  Subsystems are defined in init.mk
include $(foreach dir,$(VPATH),$(wildcard $(dir)/objects.mk))
