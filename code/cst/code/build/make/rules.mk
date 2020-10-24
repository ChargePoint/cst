#==============================================================================
#
#    File Name:  rules.mk
#
#    General Description: Specific rules for building HAB source files
#
#==============================================================================
#
#             Freescale Semiconductor
#       (c) Freescale Semiconductor, Inc. 2011, 2012. All rights reserved.
#       Copyright 2018-2019 NXP
#
#
#==============================================================================

# Consolidate all compiler and linker options
CFLAGS  := $(EXTRACFLAGS) $(CINCLUDES) $(COPTIONS) $(CDEFINES)
LDFLAGS := $(EXTRALDFLAGS) $(LDOPTIONS) $(LDLIBPATH) $(LDLIBS)
YFLAGS  := -d
LFLAGS  := -t

%: %.o
	@echo "Link $@"
	$(LD) $^ $(LDFLAGS) -o $@
%.a:
	@echo "Create archive $@"
	$(AR) $(ARFLAGS) $@ $^
ifneq ($(OSTYPE),mingw32)
ifneq ($(OSTYPE),osx)
	$(OBJCOPY) --weaken $@
endif
endif

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
