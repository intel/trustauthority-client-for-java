package com.intel.trustauthority.connector;

// Java Standard Library Imports
import java.util.List;
import java.util.Map;

/**
 * GetTokenResponse class for holding the response obtained from GetToken() API
 */
public class GetTokenResponse {

    private String token;
    private Map<String, List<String>> headers;
    private String error;

    /**
     * Constructs a new GetTokenResponse object with the specified token and headers.
     *
     * @param token             token provided by the user.
     * @param headers           headers provided by user.
     */
    public GetTokenResponse(String token, Map<String, List<String>> headers) {
        this.token = token;
        this.headers = headers;
    }

    /**
     * getter function for token
     */
    public String getToken() {
        return token;
    }

    /**
     * getter function for headers
     */
    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    /**
     * setter function for token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * setter function for headers
     */
    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    /**
     * getter function for error
     */
    public String getError() {
        return this.error;
    }
}