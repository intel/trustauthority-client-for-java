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
    private String retryMax;
    private String retryWaitTime;
    private URL url;

    /**
     * Constructs a new Config object with the specified baseUrl, apiUrl and apiKey.
     *
     * @param baseUrl      baseUrl provided by the user.
     * @param apiUrl       apiUrl provided by user.
     * @param apiKey       apiKey provided by user.
     */
    public Config(String baseUrl, String apiUrl, String apiKey) throws Exception {
        this.baseUrl = baseUrl;
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
        this.url = new URL(apiUrl);
    }

    /**
     * Constructs a new Config object with the specified baseUrl, apiUrl, apiKey, retryMax and retryWaitTime
     *
     * @param baseUrl           baseUrl provided by the user.
     * @param apiUrl            apiUrl provided by user.
     * @param apiKey            apiKey provided by user.
     * @param retryMax          retryMax provided by user.
     * @param retryWaitTime     retryWaitTime provided by user.
     */
    public Config(String baseUrl, String apiUrl, String apiKey, String retryMax, String retryWaitTime) throws Exception {
        this.baseUrl = baseUrl;
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
        this.retryMax = retryMax;
        this.retryWaitTime = retryWaitTime;
        this.url = new URL(apiUrl);
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
     * getter function for retryMax
     */
    public String getRetryMax() {
        return retryMax;
    }

    /**
     * getter function for retryWaitTime
     */
    public String getRetryWaitTime() {
        return retryWaitTime;
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
     * setter function for retryMax
     */
    public void setRetryMax(String retryMax) {
        this.retryMax = retryMax;
    }

    /**
     * setter function for retryWaitTime
     */
    public void setRetryWaitTime(String retryWaitTime) {
        this.retryWaitTime = retryWaitTime;
    }
}