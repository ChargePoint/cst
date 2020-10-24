#==============================================================================
#
#    File Name:  Makefile
#
#    General Description: Makefile for engine backend of CST
#
#==============================================================================
#
#    Copyright 2020 NXP
#
# Presence of a copyright notice is not an acknowledgement of publication.
# This software file listing contains information of NXP that is of a
# confidential and proprietary nature and any viewing or use of this file is
# prohibited without specific written permission from NXP
#
#==============================================================================

#==============================================================================
# Compiler/Linker/Archiver Commands
#==============================================================================

BIN := cst
LIB := libbackend.a
SRC := backend.c openssl_helper.c
DEP = -lssl -lcrypto -ldl -lpthread

BITNESS := $(shell getconf LONG_BIT)
CFLAGS_32 := -m32
CFLAGS_64 := -m64
LDFLAGS_32 := -m32
LDFLAGS_64 := -m64

CC := gcc
CFLAGS := $(CFLAGS_$(BITNESS)) -g -Wall -Werror -Winline -Wl,--export-all-symbols -Iinclude
LDFLAGS = $(LDFLAGS_$(BITNESS))

ifeq ($(OS),Windows_NT)
DEP += -lpsapi -lgdi32

CFLAGS += -mno-ms-bitfields
endif

OBJ := $(SRC:.c=.o)
ROOT := ../../..
FRONTEND := $(ROOT)/linux$(BITNESS)/lib/libfrontend.a

.PHONY: all
all: $(BIN)

.PHONY: clean
clean:
	-rm -f $(BIN) $(LIB) $(OBJ)

.PHONY: install
install: $(BIN)
	install -d $(PREFIX)/usr/bin
	install -m 0755 cst $(PREFIX)/usr/bin/

$(BIN): $(FRONTEND) $(LIB)
	$(CC) $(LDFLAGS) -o $@ $^ $(DEP)

$(LIB): $(OBJ)
	ar rcs $@ $^

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@
