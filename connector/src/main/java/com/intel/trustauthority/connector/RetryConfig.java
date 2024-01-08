/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

/**
 * RetryConfig class for holding retry config provided by user for TrustAuthorityConnector
 */
public class RetryConfig {

    private long retryWaitMin; // Minimum time to wait between retries
    private long retryWaitMax; // Maximum time to wait between retries
    private int retryMax;      // Maximum number of retries

    /**
     * Constructs a new Config object with the specified retryWaitMin, retryWaitMax and retryMax.
     *
     * @param retryWaitMin   retryWaitMin in seconds provided by the user.
     * @param retryWaitMax   retryWaitMax in seconds provided by user.
     * @param retryMax       retryMax provided by user.
     */
    public RetryConfig(long retryWaitMin, long retryWaitMax, int retryMax) {
        this.retryWaitMin = 2; // Default: 2 seconds
        this.retryWaitMax = 10; // Default: 10 seconds
        this.retryMax = 2; // Default: 2 retries

        // Set custom values provided by user
        if (retryWaitMin != 0) {
            this.retryWaitMin = retryWaitMin;
        }
        if (retryWaitMax != 0) {
            this.retryWaitMax = retryWaitMax;
        }
        if (retryMax != 0) {
            this.retryMax = retryMax;
        }
    }

    /**
     * getter function for retryWaitMin
     */
    public long getRetryWaitMin() {
        return retryWaitMin;
    }

    /**
     * setter function for retryWaitMin
     */
    public void setRetryWaitMin(long retryWaitMin) {
        this.retryWaitMin = retryWaitMin;
    }

    /**
     * getter function for retryWaitMax
     */
    public long getRetryWaitMax() {
        return retryWaitMax;
    }

    /**
     * setter function for retryWaitMax
     */
    public void setRetryWaitMax(long retryWaitMax) {
        this.retryWaitMax = retryWaitMax;
    }

    /**
     * getter function for retryMax
     */
    public int getRetryMax() {
        return retryMax;
    }

    /**
     * setter function for retryMax
     */
    public void setRetryMax(int retryMax) {
        this.retryMax = retryMax;
    }
}
