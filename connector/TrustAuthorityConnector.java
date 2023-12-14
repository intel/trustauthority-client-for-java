package trust_authority_client;

// Java Standard Library Imports
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.AccessController;
import java.security.Security;
import java.security.SecurityPermission;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CRLSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

// Java Security Imports
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;

// Third-party Library Imports
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;


/**
 * Constants class for holding all Constants required by the TrustAuthorityConnector
 */
class Constants {
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

    public static final int AtsCertChainMaxLen = 5; // Set the maximum length of the certificate chain
}

/**
 * GetNonceResponse class for holding the response obtained from GetNonce() API
 */
class GetNonceResponse {

    private VerifierNonce nonce;
    private Map<String, List<String>> headers;
    private String error;

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

    /**
     * getter function for error
     */
    public String getError() {
        return this.error;
    }

    /**
     * setter function for error
     */
    public void setError(String error) {
        this.error = error;
    }
}

/**
 * GetTokenResponse class for holding the response obtained from GetToken() API
 */
class GetTokenResponse {

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

/**
 * GetNonceArgs class for holding the request object to be sent to GetNonce() API
 */
class GetNonceArgs {

    private String requestId;

    /**
     * Constructs a new GetNonceArgs object with the specified requestId.
     *
     * @param requestId       requestId provided by user.
     */
    public GetNonceArgs(String requestId) {
        this.requestId = requestId;
    }

    /**
     * getter function for requestId
     */
    public String getRequestId() {
        return requestId;
    }
}

/**
 * GetTokenArgs class for holding the request object to be sent to GetToken() API
 */
class GetTokenArgs {

    private VerifierNonce nonce;
    private Evidence evidence;
    private List<UUID> policyIds;
    private String requestId;

    /**
     * Constructs a new GetTokenArgs object with the specified nonce, evidence, policyIds and requestId.
     *
     * @param nonce          VerifierNonce provided by the user.
     * @param evidence       Evidence object provided by user.
     * @param policyIds      policyIds provided by the user.
     * @param requestId      requestId provided by user.
     */
    public GetTokenArgs(VerifierNonce nonce, Evidence evidence, List<UUID> policyIds, String requestId) {
        this.nonce = nonce;
        this.evidence = evidence;
        this.policyIds = policyIds;
        this.requestId = requestId;
    }

    /**
     * getter function for nonce
     */
    public VerifierNonce getNonce() {
        return nonce;
    }

    /**
     * getter function for evidence
     */
    public Evidence getEvidence() {
        return evidence;
    }

    /**
     * getter function for policyIds
     */
    public List<UUID> getPolicyIds() {
        return policyIds;
    }

    /**
     * getter function for requestId
     */
    public String getRequestId() {
        return requestId;
    }
}

/**
 * EvidenceAdapter interface for user to implement SGX/TDX based adapters
 * The collectEvidence function is to be implemented by the user.
 */
interface EvidenceAdapter {
    /**
     * collectEvidence is used to get SGX/TDX quote using DCAP Quote Generation service
     *
     * @param nonce nonce value passed by user
     * @return Evidence object containing the fetched SGX/TDX quote
     */
    Evidence collectEvidence(byte[] nonce) throws Exception;
}

/**
 * VerifierNonce class for holding config provided by user for TrustAuthorityConnector
 */
class VerifierNonce {

    private byte[] val;
    private byte[] iat;
    private byte[] signature;

    /**
     * Default constructor (required for Jackson Object Mapping)
     */
    public VerifierNonce() {
    }

    /**
     * Constructs a new VerifierNonce object with the specified val, iat and signature.
     *
     * @param val           val provided by the user.
     * @param iat           iat provided by user.
     * @param signature     signature provided by user.
     */
    public VerifierNonce(byte[] val, byte[] iat, byte[] signature) {
        this.val = val;
        this.iat = iat;
        this.signature = signature;
    }

    /**
     * getter function for val
     */
    public byte[] getVal() {
        return val;
    }

    /**
     * setter function for val
     */
    public void setVal(byte[] val) {
        this.val = val;
    }

    /**
     * getter function for iat
     */
    public byte[] getIat() {
        return iat;
    }

    /**
     * setter function for iat
     */
    public void setIat(byte[] iat) {
        this.iat = iat;
    }

    /**
     * getter function for signature
     */
    public byte[] getSignature() {
        return signature;
    }

    /**
     * setter function for signature
     */
    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}

/**
 * TokenRequest class for holding Token details to be sent to attest() API
 */
class TokenRequest {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("quote")
    private byte[] quote;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("verifier_nonce")
    private VerifierNonce verifierNonce;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("runtime_data")
    private byte[] runtimeData;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("policy_ids")
    private List<UUID> policyIds;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("event_log")
    private byte[] eventLog;

    /**
     * Constructs a new TokenRequest object with the specified quote, verifierNonce, runtimeData, policyIds and eventLog.
     *
     * @param quote          quote provided by the user.
     * @param verifierNonce  verifierNonce object provided by user.
     * @param runtimeData    runtimeData provided by user.
     * @param policyIds      policyIds provided by user.
     * @param eventLog       eventLog provided by user.
     */
    public TokenRequest(byte[] quote, VerifierNonce verifierNonce, byte[] runtimeData, List<UUID> policyIds, byte[] eventLog) {
        this.quote = quote;
        this.verifierNonce = verifierNonce;
        this.runtimeData = runtimeData;
        this.policyIds = policyIds;
        this.eventLog = eventLog;
    }

    /**
     * getter function for quote
     */
    public byte[] getQuote() {
        return quote;
    }

    /**
     * setter function for quote
     */
    public void setQuote(byte[] quote) {
        this.quote = quote;
    }

    /**
     * getter function for verifierNonce
     */
    public VerifierNonce getVerifierNonce() {
        return verifierNonce;
    }

    /**
     * setter function for verifierNonce
     */
    public void setVerifierNonce(VerifierNonce verifierNonce) {
        this.verifierNonce = verifierNonce;
    }

    /**
     * getter function for runtimeData
     */
    public byte[] getRuntimeData() {
        return runtimeData;
    }

    /**
     * setter function for runtimeData
     */
    public void setRuntimeData(byte[] runtimeData) {
        this.runtimeData = runtimeData;
    }

    /**
     * getter function for policyIds
     */
    public List<UUID> getPolicyIds() {
        return policyIds;
    }

    /**
     * setter function for policyIds
     */
    public void setPolicyIds(List<UUID> policyIds) {
        this.policyIds = policyIds;
    }

    /**
     * getter function for eventLog
     */
    public byte[] getEventLog() {
        return eventLog;
    }

    /**
     * setter function for eventLog
     */
    public void setEventLog(byte[] eventLog) {
        this.eventLog = eventLog;
    }
}

/**
 * ConnectorException class for throwing exceptions
 * This class implements the base Exception interface.
 */
class ConnectorException extends Exception {
    public ConnectorException(String message) {
        super(message);
    }
}

/**
 * TdxAdapter class for TDX Quote collection from TDX enabled platform
 * This class implements the base EvidenceAdapter interface.
 */
public class TrustAuthorityConnector {

    private Config cfg;

    /**
     * Constructs a new TrustAuthorityConnector object with the specified config.
     *
     * @param cfg                       Config object provided by the user.
     */
    public TrustAuthorityConnector(Config cfg) {
        this.cfg = cfg;
    }

    /**
     * getter function for config
     */
    public Config getConfig() {
        return cfg;
    }

    /**
     * setter function for config
     */
    public void setConfig(Config cfg) {
        this.cfg = cfg;
    }

    /**
     * Constructs a new GetNonceResponse object with the specified GetNonceArgs
     * Fetches the nonce from the TrustAuthority server using the specified API URL
     *
     * @param args  GetNonceArgs object provided by the user.
     * @return      GetNonceResponse object
     */
    public GetNonceResponse GetNonce(GetNonceArgs args) throws Exception {
        // Request for nonce from TrustAuthority server
        String url = String.format("%s/appraisal/v1/nonce", cfg.getApiUrl());

        // Create the HttpURLConnection
        HttpURLConnection connection = createConnection(url, "GET");
        // Set the requried Header parameters
        connection.setRequestProperty(Constants.HEADER_X_API_KEY, cfg.getApiKey());
        connection.setRequestProperty(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON);
        connection.setRequestProperty(Constants.HEADER_REQUEST_ID, args.getRequestId());

        // Process the fetched response into the GetNonceResponse object
        GetNonceResponse response = new GetNonceResponse();
        processResponse(connection, response);

        return response;
    }

    /**
     * Constructs a new GetTokenResponse object with the specified GetTokenArgs
     * Fetches the token from the TrustAuthority server using the specified API URL
     *
     * @param args  GetTokenArgs object provided by the user.
     * @return      GetTokenResponse object
     */
    public GetTokenResponse GetToken(GetTokenArgs args) throws IOException {
        // Request for nonce from TrustAuthority server
        String url = String.format("%s/appraisal/v1/attest", cfg.getApiUrl());

        // Create the TokenRequest object
        TokenRequest tr = new TokenRequest(args.getEvidence().getEvidence(), args.getNonce(),
                                           args.getEvidence().getUserData(), args.getPolicyIds(),
                                           args.getEvidence().getEventLog());

        // Convert the TokenRequest to a JSON -> String
        // to send as request to server
        String jsonString = "";
        try {
            // Serialize the TokenRequest object to a JSON string
            ObjectMapper objectMapper = new ObjectMapper();
            jsonString = objectMapper.writeValueAsString(tr);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Create an HTTP Connection and send the request body as a POST request
        HttpURLConnection conn = createConnection(url, "POST", jsonString, args.getRequestId());

        // Fetch the response from the server and process it
        try {
            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP error code: " + responseCode);
            }
            // read the response if connection OK
            String responseBody = readResponseBody(conn);

            // Convert received response string to JSON
            Gson gson = new Gson();
            JsonObject jsonObject = gson.fromJson(responseBody, JsonObject.class);

            // Fetch the String value associated with the key "token"
            String token = jsonObject.get("token").getAsString();

            // Convert the received token and header fields to a GetTokenResponse object
            return new GetTokenResponse(token, conn.getHeaderFields());
        } finally {
            conn.disconnect();
        }
    }

    /**
     * attest is used to initiate remote attestation with Trust Authority
     *
     * @param args  AttestArgs object provided by the user.
     */
    public AttestResponse attest(AttestArgs args) throws Exception {

        // Creating an empty AttestResponse object
        AttestResponse response = new AttestResponse(null, null);

        // Calling the GetNonce() API
        GetNonceResponse nonceResponse = GetNonce(new GetNonceArgs(args.getRequestId()));
        if (nonceResponse.getError() != null) {
            throw new Exception("Failed to collect nonce from Trust Authority: " + nonceResponse.getError());
        }

        System.out.println("Collected nonce from Trust Authority successfully...");

        // Set AttestResponse headers with nonceResponse headers
        response.setHeaders(nonceResponse.getHeaders());

        // Create a combinedNonce using nonceValue and iat from nonceResponse
        byte[] nonceValue = nonceResponse.getNonce().getVal();
        byte[] iat = nonceResponse.getNonce().getIat();
        byte[] combinedNonce = new byte[nonceValue.length + iat.length];
        System.arraycopy(nonceValue, 0, combinedNonce, 0, nonceValue.length);
        System.arraycopy(iat, 0, combinedNonce, nonceValue.length, iat.length);

        // Fetch the SGX/TDX associated quote
        Evidence evidence = args.getAdapter().collectEvidence(combinedNonce);
        if (evidence.getError() != null) {
            throw new Exception("Failed to collect evidence from adapter: " + evidence.getError());
        }

        System.out.println("Collected evidence from adapter successfully...");

        // Calling the GetToken() API
        GetTokenResponse tokenResponse = GetToken(new GetTokenArgs(nonceResponse.getNonce(), evidence, args.getPolicyIds(), args.getRequestId()));
        if (tokenResponse.getError() != null) {
            throw new Exception("Failed to collect token from Trust Authority: " + tokenResponse.getError());
        }

        System.out.println("Collected token from Trust Authority successfully...");

        // Set AttestResponse headers with tokenResponse headers
        response.setToken(tokenResponse.getToken());
        response.setHeaders(tokenResponse.getHeaders());

        return response;
    }

    /**
     * getTokenSigningCertificates is used to get Trust Authority attestation token signing certificates
     *
     * @return The received certs from trust Authority server in bytes format
     */
    public String getTokenSigningCertificates() throws Exception {
        // Format the request endpoint using the URL
        String url = String.format("%s/certs", cfg.getBaseUrl());

        // Create the URL object
        URL urlObj = new URL(url);
        // Initiate the connection
        HttpURLConnection connection = (HttpURLConnection) urlObj.openConnection();
        
        // Set request header properties
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Accept", "application/json");

        // Check for connection status
        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            throw new Exception("Failed to fetch data from " + url + ". Response code: " + responseCode);
        }

        // Fetch the byte stream of jwks response
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        // Close the byte stream once the entire data is received
        reader.close();
        connection.disconnect();

        // return the jwks in string format
        return response.toString();
    }

    // Required for token verification for PS algorithms
    static {
        // Register Bouncy Castle as a JCE provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * verifyToken is used to do signature verification of attestation token recieved from Intel Trust Authority
     *
     * @param token     JWT token in string format
     * 
     * @return          Signed JWS claims object
     */
    public JWTClaimsSet verifyToken(String token) throws Exception {

        try {
            // Create the JWT object by parsing the token
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Retrieve the JWS header
            JWSHeader jwsHeader = signedJWT.getHeader();

            // Fetch kid from parsed token
            String kid = signedJWT.getHeader().getKeyID();
            if (kid == null) {
                throw new IllegalArgumentException("kid field missing in token header");
            }

            // Fetch certs from getTokenSigningCertificates() API
            String jwks = getTokenSigningCertificates();

            // Parse the JWKS
            JWKSet jwkSet = JWKSet.parse(jwks);

            // Check if key is matching with the parsed token
            JWK jwkKey = jwkSet.getKeyByKeyId(kid);
            if (jwkKey == null) {
                throw new IllegalArgumentException("Could not find Key matching the key id");
            }

            // Get the JWK (JSON Web Key) from the set
            RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);

            // Build a RSA public key from the JWK
            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();

            // Get the algorithm dynamically
            JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(rsaKey.getAlgorithm().getName());

            // Create a verifier
            JWSVerifier verifier;
            if (jwsAlgorithm.getName().startsWith("RS")) {
                verifier = new RSASSAVerifier(publicKey);
            } else if (jwsAlgorithm.getName().startsWith("PS")) {
                verifier = new RSASSAVerifier(publicKey);
            } else {
                throw new JOSEException("Unsupported algorithm: " + jwsAlgorithm.getName());
            }

            // Verify the signature
            if (signedJWT.verify(verifier)) {
                // Signature is valid
                System.out.println("JWT signature validated successfully");

                // Extract and print JWT claims
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

                return claims;
            } else {
                // Signature is not valid
                System.out.println("JWT signature is not valid");
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Helper function to create HttpURLConnection based on specified URL and request method
     *
     * @param url       Server URL to create the connectiong with.
     * @param method    Request method type(GET/POST).
     * @return          HttpURLConnection object
     */
    private HttpURLConnection createConnection(String url, String method) throws IOException {
        // Create the URL object
        URL requestUrl = new URL(url);
        // Initiate the connection
        HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();
        connection.setRequestMethod(method);
        connection.setConnectTimeout(0);
        connection.setReadTimeout(0);

        return connection;
    }

    /**
     * Helper function to create HttpURLConnection based on specified URL, request method, request to be sent and request ID
     *
     * @param url           Server URL to create the connectiong with.
     * @param method        Request method type(GET/POST)
     * @param requestBody   Request body to be sent
     * @param requestId     Request ID type(GET/POST).
     * @return              HttpURLConnection object
     */
    private HttpURLConnection createConnection(String url, String method, String requestBody, String requestId) throws IOException {
        // Create the HttpURLConnection from the specified URL
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        // Set the request method and other parameters
        conn.setRequestMethod(method);
        conn.setDoOutput(true);
        conn.setRequestProperty(Constants.HEADER_X_API_KEY, cfg.getApiKey());
        conn.setRequestProperty(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON);
        conn.setRequestProperty(Constants.HEADER_CONTENT_TYPE, Constants.MIME_APPLICATION_JSON);
        conn.setRequestProperty(Constants.HEADER_REQUEST_ID, requestId);

        // Sends request body to server specified by URL
        if (requestBody != null) {
            conn.getOutputStream().write(requestBody.getBytes("UTF-8"));
        }
        return conn;
    }

    /**
     * Helper function to convert HttpURLConnection response to GetNonceResponse object
     *
     * @param connection  HttpURLConnection object provided by the user.
     * @param response    GetNonceResponse object provided by the user.
     */
    private void processResponse(HttpURLConnection connection, GetNonceResponse response) throws IOException {
        // Set response Header fields from the fetched response
        response.setHeaders(connection.getHeaderFields());

        // Check for response code
        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            // Fetch the response from the server
            String responseBody = readResponseBody(connection);

            // Map the fetched response JSON to VerifierNonce object
            ObjectMapper mapper = new ObjectMapper();
            VerifierNonce nonce = mapper.readValue(responseBody, VerifierNonce.class);

            // Set GetNonceResponse object nonce value with VerifierNonce
            response.setNonce(nonce);
        } else {
            // Handle error response
            System.out.println("Processing response failed with response code: " + responseCode);
        }
    }

    /**
     * Helper function to fetch the response from server
     *
     * @param connection  HttpURLConnection object provided by the user.
     * @return            The server response as a string
     */
    private String readResponseBody(HttpURLConnection connection) throws IOException {
        StringBuilder content = new StringBuilder();
        // This initiates the connection with the server and reads the response
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
        }
        return content.toString();
    }
}
