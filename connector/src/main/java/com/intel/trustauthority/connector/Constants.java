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
    public static final String HEADER_REQUEST_METHOD = "request-method";
    public static final String HEADER_X_API_KEY = "x-api-key";
    public static final String HEADER_ACCEPT = "Accept";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_REQUEST_ID = "request-id";
    public static final String HEADER_TRACE_ID = "trace-id";

    public static final String MIME_APPLICATION_JSON = "application/json";

    public static final String WRITE_OUTPUT = "write-output";

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
}