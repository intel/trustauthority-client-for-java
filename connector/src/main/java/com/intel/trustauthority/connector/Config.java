/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

// Java Standard Library Imports
import java.net.URL;

/**
 * Config class for holding config provided by user for TrustAuthorityConnector
 */
public class Config {

    private String baseUrl;
    private String apiUrl;
    private String apiKey;
    private URL url;
    private RetryConfig retryConfig;

    /**
     * Constructs a new Config object with the specified baseUrl, apiUrl, apiKey and retryConfig
     *
     * @param baseUrl      baseUrl provided by the user.
     * @param apiUrl       apiUrl provided by user.
     * @param apiKey       apiKey provided by user.
     * @param retryConfig  retryConfig provided by user.
     */
    public Config(String baseUrl, String apiUrl, String apiKey, RetryConfig retryConfig) throws Exception {
        this.baseUrl = baseUrl;
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
        this.url = new URL(apiUrl);
        this.retryConfig = retryConfig;
    }

    /**
     * getter function for baseUrl
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * getter function for apiUrl
     */
    public String getApiUrl() {
        return apiUrl;
    }

    /**
     * getter function for apiKey
     */
    public String getApiKey() {
        return apiKey;
    }

    /**
     * getter function for retryConfig
     */
    public RetryConfig getRetryConfig() {
        return retryConfig;
    }

    /**
     * setter function for baseUrl
     */
    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * setter function for apiUrl
     */
    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    /**
     * setter function for apiKey
     */
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    /**
     * setter function for retryConfig
     */
    public void setRetryConfig(RetryConfig retryConfig) {
        this.retryConfig = retryConfig;
    }
}