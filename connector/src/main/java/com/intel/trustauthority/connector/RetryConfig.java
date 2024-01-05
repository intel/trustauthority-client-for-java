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
     * Constructs a new RetryConfig object with default values
     */
    public RetryConfig() {
        this.retryWaitMin = 2000L; // Default: 2 seconds
        this.retryWaitMax = 10000L; // Default: 10 seconds
        this.retryMax = 2; // Default: 2 retries
    }

    /**
     * Constructs a new Config object with the specified retryWaitMin, retryWaitMax and retryMax.
     *
     * @param retryWaitMin   retryWaitMin in seconds provided by the user.
     * @param retryWaitMax   retryWaitMax in seconds provided by user.
     * @param retryMax       retryMax provided by user.
     */
    public RetryConfig(long retryWaitMin, long retryWaitMax, int retryMax) {
        this.retryWaitMin = retryWaitMin * 1000;
        this.retryWaitMax = retryWaitMax * 1000;
        this.retryMax = retryMax;
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
