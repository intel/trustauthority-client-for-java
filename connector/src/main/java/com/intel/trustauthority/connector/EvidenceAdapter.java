/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

/**
 * EvidenceAdapter is an interface which exposes methods for collecting Quote from Platform
 * The collectEvidence function is to be implemented by the user.
 */
public interface EvidenceAdapter {
    /**
     * collectEvidence is used to get SGX/TDX quote using DCAP Quote Generation service
     *
     * @param nonce nonce value passed by user
     * @return Evidence object containing the fetched SGX/TDX quote
     */
    Evidence collectEvidence(byte[] nonce) throws Exception;
}