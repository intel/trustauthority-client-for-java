/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#if defined(__cplusplus)
extern "C" {
#endif

int get_public_key(sgx_enclave_id_t eid, uint8_t **pp_key, uint32_t *p_key_size);
void free_public_key(uint8_t *p_key);
int get_enclave_create_report(sgx_enclave_id_t eid, uint32_t* retval, const sgx_target_info_t* p_qe3_target, uint8_t* nonce, uint32_t nonce_size, sgx_report_t* p_report);

#if defined(__cplusplus)
}
#endif

#endif /*_UTILS_H_*/
