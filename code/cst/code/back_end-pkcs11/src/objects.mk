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
#        Copyright 2021-2022 NXP
#
#
#
#==============================================================================

# List the api object files to be built
OBJECTS += \
	openssl_helper.o \
	eng_backend.o \
	eng_cms.o \
	eng_cert.o \
	eng_dek.o \
	eng_auth.o \
	eng_sign.o 

OBJECTS_BACKEND_PKCS11 += \
	openssl_helper.o \
	eng_backend.o \
	eng_cms.o \
	eng_cert.o \
	eng_dek.o \
	eng_auth.o \
	eng_sign.o

OBJECTS_SRKTOOL += \
	eng_backend.o \
	eng_cert.o
