/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

#include "Enclave_t.h"

#include "sgx_trts.h"
#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "mbusafecrt.h" /* memcpy_s */

/* Global copy of RSA key pair */
static rsa_params_t g_rsa_key;

/* Have we generated RSA key pair already? */
static bool key_pair_created = false;

sgx_status_t enclave_create_pubkey(
    rsa_params_t* key)
{
    sgx_status_t status;
    key->e[0] = 0x10001;
    g_rsa_key.e[0] = 0x10001;

    if (!key_pair_created) {

        status = sgx_create_rsa_key_pair(N_SIZE_IN_BYTES,
                                           E_SIZE_IN_BYTES,
                                           (unsigned char*)g_rsa_key.n,
                                           (unsigned char*)g_rsa_key.d,
                                           (unsigned char*)g_rsa_key.e,
                                           (unsigned char*)g_rsa_key.p,
                                           (unsigned char*)g_rsa_key.q,
                                           (unsigned char*)g_rsa_key.dmp1,
                                           (unsigned char*)g_rsa_key.dmq1,
                                           (unsigned char*)g_rsa_key.iqmp);

        if (SGX_SUCCESS != status) {
            //printf("RSA key pair creation failed.");
            return status;
        }
        key_pair_created = true;
    }

    for(int i = 0; i < N_SIZE_IN_BYTES; i++) {
        key->n[i] = g_rsa_key.n[i];
    }
    for(int i = 0; i < E_SIZE_IN_BYTES; i++) {
        key->e[i] = g_rsa_key.e[i];
    }

    return SGX_SUCCESS;
}

uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target,
                                uint8_t* nonce,
                                uint32_t nonce_size,
                                sgx_report_t* p_report)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_report_data_t report_data = {0};
    uint8_t msg_hash[64] = {0};

    const uint32_t size = nonce_size + E_SIZE_IN_BYTES + N_SIZE_IN_BYTES;

    uint8_t* pdata = (uint8_t *)malloc(size);
    if (!pdata) {
        //printf("ReportData memory allocation failed.");
        return status;
    }

    errno_t err = 0;
    err = memcpy_s(pdata, nonce_size, nonce, nonce_size);
    if (err != 0) {
            //printf("memcpy of nonce failed.");
            goto CLEANUP;
    }

    err = memcpy_s(pdata + nonce_size, E_SIZE_IN_BYTES, ((unsigned char *)g_rsa_key.e), E_SIZE_IN_BYTES);
    if (err != 0) {
        //printf("memcpy of exponent failed.");
        goto CLEANUP;
    }

    err = memcpy_s(pdata + nonce_size + E_SIZE_IN_BYTES, N_SIZE_IN_BYTES, ((unsigned char *)g_rsa_key.n), N_SIZE_IN_BYTES);
    if (err != 0) {
        //printf("memcpy of modulus failed.");
        goto CLEANUP;
    }

    status = sgx_sha256_msg(pdata, size, (sgx_sha256_hash_t *)msg_hash);
    if (SGX_SUCCESS != status) {
        //printf("Hash of userdata failed!");
        goto CLEANUP;
    }

    err = memcpy_s(report_data.d, sizeof(msg_hash), msg_hash, sizeof(msg_hash));
    if (err != 0) {
            //printf("memcpy of reportdata failed.");
            status = SGX_ERROR_UNEXPECTED;
        goto CLEANUP;
    }

    // Generate the report for the app_enclave
    status = sgx_create_report(p_qe3_target, &report_data, p_report);
    if (SGX_SUCCESS != status) {
        //printf("Enclave report creation failed!");
        goto CLEANUP;
    }

CLEANUP:
    free(pdata);
    return status;
}