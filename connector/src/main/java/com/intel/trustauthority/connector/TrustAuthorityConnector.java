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
            String responseBody = readResponseBody(connection);

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
            TokenRequest tr = new TokenRequest(args.getEvidence().getEvidence(), args.getNonce(),
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
            String responseBody = readResponseBody(connection);

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
            String responseBody = readResponseBody(connection);

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

            // Check if key is matching with the parsed token
            JWK jwkKey = jwkSet.getKeyByKeyId(kid);
            if (jwkKey == null) {
                throw new Exception("Could not find Key matching the key id");
            }

            // Check if keys exist
            if (jwkSet.getKeys().size() == 0) {
                throw new Exception("No keys present in JWKSet");
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

    /**
     * Helper function to establish HttpURLConnection with retry options
     *
     * @param url                   URL of the server to establish the connection with.
     * @param requestProperties     List of request properties to be set for the connection.
     * @return                      HttpURLConnection object on a successful response.
     */
    private HttpURLConnection openConnectionWithRetries(URL url, Map<String, String> requestProperties) throws Exception {
        // Set maxRetries and retryWaitTimeMillis based on Config
        int maxRetries = 2; // Default 2
        if (cfg.getRetryMax() != null) {
            maxRetries = Integer.parseInt(cfg.getRetryMax());
        }
        long retryWaitTimeMillis = 2000; // Default 2 seconds
        if (cfg.getRetryWaitTime() != null) {
            retryWaitTimeMillis = Long.parseLong(cfg.getRetryWaitTime()) * 1000;
        }

        HttpURLConnection connection = null;

        // Retry for establishing connection in a loop if it fails
        for (int retry = 0; retry < maxRetries; retry++) {
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
            } else if (responseCode == HttpURLConnection.HTTP_INTERNAL_ERROR ||
                        responseCode == HttpURLConnection.HTTP_UNAVAILABLE ||
                        responseCode == HttpURLConnection.HTTP_GATEWAY_TIMEOUT) {
                // Retry for above response codes 500, 503 and 504
                logger.warn("Retrying due to unexpected response code: " + responseCode);
            } else {
                // Return for connections where we should not retry for the response code
                throw new Exception("Connection failed with response code: " + responseCode);
            }

            // If this is not the last retry, wait before the next retry
            if (retry < maxRetries - 1) {
                try {
                    Thread.sleep(retryWaitTimeMillis);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        // If all retries fail, throw an Exception
        throw new Exception("Maximum retries reached. Request failed.");
    }
}
