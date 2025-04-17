/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

// Java Standard Library Imports
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Constants class for holding all Constants required by the TrustAuthorityConnector
 */
public class Constants {
    public static final String HEADER_X_API_KEY = "x-api-key";
    public static final String HEADER_ACCEPT = "Accept";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_REQUEST_ID = "request-id";
    public static final String HEADER_TRACE_ID = "trace-id";

    public static final String MIME_APPLICATION_JSON = "application/json";

    public static final long DEFAULT_RETRY_WAIT_TIME_MIN = 2;
    public static final long DEFAULT_RETRY_WAIT_TIME_MAX = 10;
    public static final int DEFAULT_RETRY_MAX = 2;

    public static final String DEFAULT_OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";

    public static final String ENV_TRUSTAUTHORITY_BASE_URL = "TRUSTAUTHORITY_BASE_URL";
    public static final String ENV_TRUSTAUTHORITY_API_URL = "TRUSTAUTHORITY_API_URL";
    public static final String ENV_TRUSTAUTHORITY_API_KEY = "TRUSTAUTHORITY_API_KEY";
    public static final String ENV_TRUSTAUTHORITY_REQUEST_ID = "TRUSTAUTHORITY_REQUEST_ID";
    public static final String ENV_TRUSTAUTHORITY_POLICY_ID = "TRUSTAUTHORITY_POLICY_ID";
    public static final String ENV_TOKEN_SIGNING_ALG = "TOKEN_SIGNING_ALG";
    public static final String ENV_POLICY_MUST_MATCH = "POLICY_MUST_MATCH";
    public static final String ENV_ADAPTER_TYPE = "ADAPTER_TYPE"; 
    public static final String ENV_RETRY_MAX = "RETRY_MAX";
    public static final String ENV_RETRY_WAIT_TIME = "RETRY_WAIT_TIME";
    public static final String ENV_HTTPS_PROXY_HOST = "HTTPS_PROXY_HOST";
    public static final String ENV_HTTPS_PROXY_PORT = "HTTPS_PROXY_PORT";

    public static final String ADAPTER_TYPE_INTEL = "intel";
    public static final String ADAPTER_TYPE_AZURE = "azure";

    // Define a constant retryableStatusCodes Set
    public static final Set<Integer> retryableStatusCodes;

    // Static block to initialize the set
    static {
        Set<Integer> tempSet = new HashSet<>();
        tempSet.add(500); // HttpURLConnection.HTTP_INTERNAL_ERROR
        tempSet.add(503); // HttpURLConnection.HTTP_UNAVAILABLE
        tempSet.add(504); // HttpURLConnection.HTTP_GATEWAY_TIMEOUT

        // Make the set unmodifiable to ensure it remains constant
        retryableStatusCodes = Collections.unmodifiableSet(tempSet);
    }

    //Allowed algorithm
    public static final String ALGO_RS256 = "RS256";        
    public static final String ALGO_PS384 = "PS384";

    //Allowed regular expresion for request-id
    public static final String REQUEST_ID_REGEX = "^[a-zA-Z0-9_ \\/.-]{1,128}$";
}