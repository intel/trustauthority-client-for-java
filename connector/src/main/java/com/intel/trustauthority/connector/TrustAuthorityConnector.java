package com.intel.trustauthority.connector;

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
 * TrustAuthorityConnector exposes functions for calling Intel Trust Authority REST APIs
 */
public class TrustAuthorityConnector {

    // Logger object
    private static final Logger logger = LogManager.getLogger(TrustAuthorityConnector.class);

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
            throw new Exception("Processing response failed with response code: " + responseCode);
        }

        return response;
    }

    /**
     * Fetches the token from the TrustAuthority server using the specified API URL
     *
     * @param args  GetTokenArgs object provided by the user.
     * @return      GetTokenResponse object
     */
    public GetTokenResponse GetToken(GetTokenArgs args) throws IOException {
        // Request for token from TrustAuthority server
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

        logger.info("Collected nonce from Trust Authority successfully...");

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

        logger.info("Collected evidence from adapter successfully...");

        // Calling the GetToken() API
        GetTokenResponse tokenResponse = GetToken(new GetTokenArgs(nonceResponse.getNonce(), evidence, args.getPolicyIds(), args.getRequestId()));
        if (tokenResponse.getError() != null) {
            throw new Exception("Failed to collect token from Trust Authority: " + tokenResponse.getError());
        }

        logger.info("Collected token from Trust Authority successfully...");

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
        connection.setRequestProperty(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON);

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
                logger.info("JWT signature validated successfully");

                // Extract and print JWT claims
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

                return claims;
            } else {
                // Signature is not valid
                logger.error("JWT signature is not valid");
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
