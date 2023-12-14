package trust_authority_client;

// Java Standard Library Imports
import java.util.List;
import java.util.Map;

/**
 * AttestResponse class for holding the response obtained from attest() API
 */
public class AttestResponse {

    private String token;
    private Map<String, List<String>> headers;

    /**
     * Constructs a new AttestResponse object with the specified token and headers.
     *
     * @param token         token provided by the user.
     * @param headers       headers provided by user.
     */
    public AttestResponse(String token, Map<String, List<String>> headers) {
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
     * setter function for headers
     */
    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    /**
     * setter function for token
     */
    public void setToken(String token) {
        this.token = token;
    }
}