# SPDX-License-Identifier: BSD-3-Clause
#
# Freescale Semiconductor
# (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.
# Copyright 2019-2020, 2022-2023 NXP
#
#==============================================================================
#
#    File Name:  rules.mk
#
#    General Description: Specific rules for building HAB source files
#
#==============================================================================

# Consolidate all compiler and linker options
CFLAGS  := $(EXTRACFLAGS) \
           $(CINCLUDES)   \
           $(COPTIONS)    \
           $(CDEFINES)    \
           -D$(OSTYPE)=1  \
           -DVERSION=\"$(VERSION)\"

LDFLAGS := $(EXTRALDFLAGS) $(LDOPTIONS) $(LDLIBPATH) $(LDLIBS)
YFLAGS  := -d
LFLAGS  := -t

%: %.o
	@echo "Link $@"
	$(LD) $^ $(LDFLAGS) -o $@
%.a:
	@echo "Create archive $@"
	$(AR) $(ARFLAGS) $@ $^

%.exe:
	@echo "Link $@"
	$(LD) $^ $(LDFLAGS) -o $@

%.o: %.c
	@echo "Compile $@"
	# generate dependency file
	$(CC) -MM $(CFLAGS) -c $< -o $(subst .o,.d,$@)
	# compile
	$(CC) $(CFLAGS) -DFILE_${*F} -c $< -o $@

%.c: %.y
	@echo "Create parser $@"
	$(YACC) $(YFLAGS) -o $@ $<

%.c: %.l
	@echo "Create lexical analyser $@"
	$(LEX) $(LFLAGS) $< > $@
