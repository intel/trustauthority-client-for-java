/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

/**
 * Config class for holding config provided by user for TrustAuthorityConnector
 */
public class Config {

    private String baseUrl;
    private String apiUrl;
    private String apiKey;
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
        //remote trailing slash or space before assinging
        this.baseUrl = sanitizeUrl(baseUrl);
        this.apiUrl = sanitizeUrl(apiUrl);
        this.apiKey = apiKey;
        this.retryConfig = retryConfig;
    }

    private String sanitizeUrl(String url) {
        if (url == null) {
            return null;
        }
        // Remove trailing slash
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        // Remove leading or trailing space
        url = url.trim();
        return url;
    }
    
     /**
     * validator function for configuration
     */
    public void validate() {
        if (baseUrl == null || baseUrl.isEmpty() || !isSecured(baseUrl)) {
            throw new IllegalArgumentException("Base URL should be valid secure url");
        }
        if (apiUrl == null || apiUrl.isEmpty() || !isSecured(apiUrl)) {
            throw new IllegalArgumentException ("API URL should be valid secure url");
        }
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalArgumentException ("API Key cannot be null or empty");
        }
    }

    private boolean isSecured(String url){
        return url.startsWith("https://");
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
        this.baseUrl = sanitizeUrl(baseUrl);
    }

    /**
     * setter function for apiUrl
     */
    public void setApiUrl(String apiUrl) {
        this.apiUrl = sanitizeUrl(apiUrl);
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