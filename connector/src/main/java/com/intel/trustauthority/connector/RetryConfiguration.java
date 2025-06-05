/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.trustauthority.connector;

/**
 * Config class for holding config provided by user for TrustAuthorityConnector
 * This configuration will provide only retry configurations to com.intel.trustauthority.connector.Config 
 * and will skip validation for baseUrl, apiUrl and apiKey.
 */
public class RetryConfiguration extends Config {

    public RetryConfiguration(RetryConfig retryConfig) {
        super(null, null, null, retryConfig);
    }

     /**
     * Override validator function for NULL configuration
     */
    @Override
    public void validate() {}
    
}