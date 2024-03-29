
#
# Copyright (C) 2023 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########
SGX_DEBUG ?= 0

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
OUT_OF_PROC ?= 0

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## Enclave Settings ########
Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
        Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
        Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif
Enclave_C_Flags += $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

App_Library := libutils.so

App_C_Flags := $(SGX_COMMON_CFLAGS) $(Enclave_Include_Paths) -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Library_Link_Flags := $(SGX_COMMON_CFLAGS) -lsgx_dcap_ql -lsgx_urts -L${SGXSSL_LIB_PATH} -lsgx_usgxssl -shared

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_Library_Link_Flags := $(SGX_COMMON_CFLAGS) -lsgx_dcap_ql -lsgx_urts -L${SGXSSL_LIB_PATH} -lsgx_usgxssl -shared

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
        -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
        -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
        -Wl,-z,relro,-z,now,-z,noexecstack             \
        -Wl,--version-script=Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)# utils.o
ENCLAVE_LIBRARY_PATH := ./

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave.config.xml

ifeq ($(SGX_DEBUG), 1)
        Build_Mode = HW_DEBUG
else
        Build_Mode = HW_RELEASE
endif

.PHONY: all target run

all: .config_$(Build_Mode)_$(SGX_ARCH)
	$(MAKE) target

target: $(App_Library) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_RELEASE)
	@echo "The project has been built in release hardware mode."
else
	@echo "The project has been built in debug hardware mode."
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## App Objects ########

Enclave_u.o: Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

utils.o: utils.cpp Enclave_u.c
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Library): utils.o Enclave_u.o
	@$(CXX) $(App_Cpp_Flags) $^ -o $@ $(App_Library_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########
Enclave_t.c:
	@$(SGX_EDGER8R) --trusted Enclave.edl
	@echo "GEN  =>  $@"

Enclave_u.c:
	@$(SGX_EDGER8R) --untrusted Enclave.edl
	@echo "GEN  =>  $@"

Enclave_t.o: Enclave_t.c Enclave_u.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Cpp_Objects): Enclave_t.c
%.o: %.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private_sample.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@rm -f $(Enclave_Name)
	@echo "SIGN =>  $@"

.PHONY: clean
clean:
	@rm -f $(App_Library) *.o
	@rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_Cpp_Objects) Enclave_t.* Enclave_u.*
