# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2018-2019, 2023 NXP
#
#==============================================================================
#
#    File Name:  Makefile
#
#    General Description: Makefile for CSF parser
#
#==============================================================================

CC = gcc

COPTS = -g -Wall -Werror
CFLAGS = -I.

DEPS = csf_parser.h extract_csf.h
SRCS = csf_parser.c extract_csf.c

.PHONY: all clean

all: csf_parser

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

csf_parser: csf_parser.c
	$(CC) $(COPTS) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -rvf output csf_parser
