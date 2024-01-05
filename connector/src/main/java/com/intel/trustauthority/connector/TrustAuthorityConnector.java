/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
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
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;

// Third-party Library Imports
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
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
     * @param cfg Config object provided by the user.
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
        try{
            // Request for nonce from TrustAuthority server
            String url = String.format("%s/appraisal/v1/nonce", cfg.getApiUrl());

            // Initiate requestUrl based on the url
            URL requestUrl = new URL(url);

            // Set request properties
            Map<String, String> requestProperties = Map.of(
                    Constants.HEADER_REQUEST_METHOD, "GET",
                    Constants.HEADER_X_API_KEY, cfg.getApiKey(),
                    Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON,
                    Constants.HEADER_REQUEST_ID, args.getRequestId()
            );

            // Create the HttpURLConnection
            HttpURLConnection connection = openConnectionWithRetries(requestUrl, requestProperties);

            // Process the fetched response into the GetNonceResponse object
            GetNonceResponse response = new GetNonceResponse();

            // Set response Header fields from the fetched response
            response.setHeaders(connection.getHeaderFields());

            // Fetch the response from the server
            String responseBody = readResponseBody(connection, HttpURLConnection.HTTP_OK);

            // Map the fetched response JSON to VerifierNonce object
            ObjectMapper mapper = new ObjectMapper();
            VerifierNonce nonce = mapper.readValue(responseBody, VerifierNonce.class);

            // Set GetNonceResponse object nonce value with VerifierNonce
            response.setNonce(nonce);

            // Close the connection once the entire data is received
            connection.disconnect();

            return response;
        } catch (Exception e) {
            throw new Exception("GetNonce() failed: " + e);
        }
    }

    /**
     * Fetches the token from the TrustAuthority server using the specified API URL
     *
     * @param args  GetTokenArgs object provided by the user.
     * @return      GetTokenResponse object
     */
    public GetTokenResponse GetToken(GetTokenArgs args) throws Exception {
        try{
            // Request for token from TrustAuthority server
            String url = String.format("%s/appraisal/v1/attest", cfg.getApiUrl());

            // Create the TokenRequest object
            TokenRequest tr = new TokenRequest(args.getEvidence().getQuote(), args.getNonce(),
                                               args.getEvidence().getUserData(), args.getPolicyIds(),
                                               args.getEvidence().getEventLog());

            // Convert the TokenRequest to a JSON -> String
            // to send as request to server
            ObjectMapper objectMapper = new ObjectMapper();
            // Serialize the TokenRequest object to a JSON string
            String jsonString = objectMapper.writeValueAsString(tr);

            // Initiate requestUrl based on the url
            URL requestUrl = new URL(url);

            // Set request properties
            Map<String, String> requestProperties = Map.of(
                    Constants.HEADER_REQUEST_METHOD, "POST",
                    Constants.HEADER_X_API_KEY, cfg.getApiKey(),
                    Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON,
                    Constants.HEADER_CONTENT_TYPE, Constants.MIME_APPLICATION_JSON,
                    Constants.HEADER_REQUEST_ID, args.getRequestId(),
                    Constants.WRITE_OUTPUT, jsonString
            );

            // Create the HttpURLConnection
            HttpURLConnection connection = openConnectionWithRetries(requestUrl, requestProperties);

            // read the response if connection OK
            String responseBody = readResponseBody(connection, HttpURLConnection.HTTP_OK);

            // Convert received response string to JSON
            Gson gson = new Gson();
            JsonObject jsonObject = gson.fromJson(responseBody, JsonObject.class);

            // Fetch the String value associated with the key "token"
            String token = jsonObject.get("token").getAsString();

            // Convert the received token and header fields to a GetTokenResponse object
            GetTokenResponse tokenResponse =  new GetTokenResponse(token, connection.getHeaderFields());

            // Close the connection once the entire data is received
            connection.disconnect();

            return tokenResponse;
        } catch (Exception e) {
            throw new Exception("GetToken() failed: " + e);
        }
    }

    /**
     * attest is used to initiate remote attestation with Trust Authority
     *
     * @param args  AttestArgs object provided by the user.
     *
     * @return AttestResponse object containing the reponse token and headers
     */
    public AttestResponse attest(AttestArgs args) throws Exception {
        try {
            // Creating an empty AttestResponse object
            AttestResponse response = new AttestResponse(null, null);

            // Calling the GetNonce() API
            GetNonceResponse nonceResponse = GetNonce(new GetNonceArgs(args.getRequestId()));
            if (nonceResponse == null) {
                throw new Exception("Failed to collect nonce from Trust Authority");
            }

            logger.debug("Collected nonce from Trust Authority successfully...");

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
            if (evidence == null) {
                throw new Exception("Failed to collect evidence from adapter");
            }

            logger.info("Collected evidence from adapter successfully...");

            // Calling the GetToken() API
            GetTokenResponse tokenResponse = GetToken(new GetTokenArgs(nonceResponse.getNonce(), evidence, args.getPolicyIds(), args.getRequestId()));
            if (tokenResponse == null) {
                throw new Exception("Failed to collect token from Trust Authority");
            }

            logger.info("Collected token from Trust Authority successfully...");

            // Set AttestResponse headers with tokenResponse headers
            response.setToken(tokenResponse.getToken());
            response.setHeaders(tokenResponse.getHeaders());

            return response;
        } catch (Exception e) {
            throw new Exception("attest() failed: " + e);
        }
    }

    /**
     * getTokenSigningCertificates is used to get Trust Authority attestation token signing certificates
     *
     * @return The received certs from trust Authority server in bytes format
     */
    public String getTokenSigningCertificates() throws Exception {
        try {
            // Format the request endpoint using the URL
            String url = String.format("%s/certs", cfg.getBaseUrl());

            // Create the URL object
            URL requestUrl = new URL(url);

            // Set request properties
            Map<String, String> requestProperties = Map.of(
                    Constants.HEADER_REQUEST_METHOD, "GET",
                    Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON
            );

            // Create the HttpURLConnection
            HttpURLConnection connection = openConnectionWithRetries(requestUrl, requestProperties);

            // read the response if connection OK
            String responseBody = readResponseBody(connection, HttpURLConnection.HTTP_OK);

            // Close the connection once the entire data is received
            connection.disconnect();

            // return the jwks in string format
            return responseBody;
        } catch (Exception e) {
            throw new Exception("getTokenSigningCertificates() failed: " + e);
        }
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
                throw new Exception("kid field missing in token header");
            }

            // Fetch certs from getTokenSigningCertificates() API
            String jwks = getTokenSigningCertificates();

            // Parse the JWKS
            JWKSet jwkSet = JWKSet.parse(jwks);

            // Check if keys exist
            if (jwkSet.getKeys().size() == 0) {
                throw new Exception("No keys present in JWKSet");
            }

            // Check if key is matching with the parsed token
            JWK jwkKey = jwkSet.getKeyByKeyId(kid);
            if (jwkKey == null) {
                throw new Exception("Could not find Key matching the key id");
            }

            // Get the JWK (JSON Web Key) from the set
            RSAKey rsaKey = (RSAKey) jwkKey;

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

                return signedJWT.getJWTClaimsSet();
            } else {
                // Signature is not valid
                throw new Exception("JWT signature is not valid");
            }
        } catch (Exception e) {
            throw new Exception("verifyToken() failed: " + e);
        }
    }

    /**
     * Helper function to fetch the response from server
     *
     * @param connection    HttpURLConnection object provided by the user.
     * @param responseCode  Response code of the connection to read input/error message.
     * @return              The server input/error message response as a string
     */
    private String readResponseBody(HttpURLConnection connection, int responseCode) throws IOException {
        StringBuilder content = new StringBuilder();

        // Read the response body
        BufferedReader reader;
        if (responseCode == HttpURLConnection.HTTP_OK) {
            // Read InputStream if connection is successful
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        } else {
            // Read ErrorStream if connection is unsuccessful
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
        }

        // Read the response or error message
        String line;
        StringBuilder response = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        return response.toString();
    }

    /**
     * Helper function to establish HttpURLConnection with retry options
     *
     * @param url                   URL of the server to establish the connection with.
     * @param requestProperties     List of request properties to be set for the connection.
     * @return                      HttpURLConnection object on a successful response.
     */
    private HttpURLConnection openConnectionWithRetries(URL url, Map<String, String> requestProperties) throws Exception {
        // Set maxRetries and retryWaitTimeMillis based on Config
        int maxRetries = cfg.getRetryConfig().getRetryMax();
        long retryWaitTimeMillis = cfg.getRetryConfig().getRetryWaitMin();

        // Initialize connection
        HttpURLConnection connection = null;

        // Retry for establishing connection in a loop if it fails
        for (int retry = 0; retry <= maxRetries; retry++) {
            // Close the connection if already opened
            if (connection != null && connection.getDoOutput()) {
                logger.debug("Closing existing connection");
                connection.disconnect();
            }

            // Open a new connection
            connection = (HttpURLConnection) url.openConnection();

            // Set request properties
            if (requestProperties != null) {
                for (Map.Entry<String, String> entry : requestProperties.entrySet()) {
                    if (entry.getKey() == Constants.HEADER_REQUEST_METHOD) {
                        connection.setRequestMethod(entry.getValue());
                    } else if (entry.getKey() == Constants.WRITE_OUTPUT) {
                        // Ignore setting WRITE_OUTPUT in request
                        // This will be written in OutputStream instead
                    } else {
                        connection.setRequestProperty(entry.getKey(), entry.getValue());
                    }
                }
                // Write output value if provided
                if (requestProperties.containsKey(Constants.WRITE_OUTPUT)) {
                    connection.setDoOutput(true);
                    connection.getOutputStream().write(requestProperties.get(Constants.WRITE_OUTPUT).getBytes("UTF-8"));
                }
            }

            // Establish connection
            int responseCode = connection.getResponseCode();
            // Process the response
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Successful connection
                return connection;
            } else if (Constants.retryableStatusCodes.contains(responseCode)) {
                // Retry for response codes which are in set retryableStatusCodes
                logger.warn("Retrying due to unexpected response code: " + responseCode);
                // If this is not the last retry, wait before the next retry
                if (retry < maxRetries) {

                    // Calculate the wait time with exponential backoff, capped at retryWaitMax
                    long waitTime = Math.min(cfg.getRetryConfig().getRetryWaitMax(),
                                            (1L << retry) * retryWaitTimeMillis);

                    logger.debug("Retrying in " + waitTime + " milliseconds...");
                    try {
                        Thread.sleep(waitTime);
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                    }
                }
            } else {
                // Return for connections where we should not retry for the response code
                throw new Exception("Connection failed with response code: " + responseCode +
                                    " and error: " + readResponseBody(connection, responseCode));
            }
        }

        // If all retries fail, throw an Exception
        throw new Exception("Maximum retries reached. Request failed.");
    }
}
