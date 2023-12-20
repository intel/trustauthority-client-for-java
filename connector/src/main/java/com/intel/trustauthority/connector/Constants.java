package com.intel.trustauthority.connector;

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
    public static final int ATS_CERT_CHAIN_MAX_LEN = 10;
    public static final int MAX_RETRIES = 2;
    public static final int DEFAULT_RETRY_WAIT_MIN_SECONDS = 2;
    public static final int DEFAULT_RETRY_WAIT_MAX_SECONDS = 10;
    public static final String SERVICE_UNAVAILABLE_ERROR = "service unavailable";
}