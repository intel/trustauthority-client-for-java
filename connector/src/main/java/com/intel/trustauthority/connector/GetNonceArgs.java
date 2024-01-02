/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

/**
 * GetNonceArgs class for holding the request object to be sent to GetNonce() API
 */
public class GetNonceArgs {

    private String requestId;

    /**
     * Constructs a new GetNonceArgs object with the specified requestId.
     *
     * @param requestId       requestId provided by user.
     */
    public GetNonceArgs(String requestId) {
        this.requestId = requestId;
    }

    /**
     * getter function for requestId
     */
    public String getRequestId() {
        return requestId;
    }
}