package com.intel.trustauthority.connector;

// Java Standard Library Imports
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * GetNonceResponse class for holding the response obtained from GetNonce() API
 */
public class GetNonceResponse {

    private VerifierNonce nonce;
    private Map<String, List<String>> headers;

    /**
     * Intializes the GetNonceResponse object.
     */
    public GetNonceResponse() {
        headers = new HashMap<>();
    }

    /**
     * getter function for nonce
     */
    public VerifierNonce getNonce() {
        return nonce;
    }

    /**
     * setter function for nonce
     */
    public void setNonce(VerifierNonce nonce) {
        this.nonce = nonce;
    }

    /**
     * getter function for headers
     */
    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    /**
     * setter function for headers
     */
    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }
}