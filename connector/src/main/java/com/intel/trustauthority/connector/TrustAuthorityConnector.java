/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.trustauthority.connector.Evidence.EvidenceType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
        //validate configuration
        cfg.validate();
        
        this.cfg = cfg;

        // Register Bouncy Castle as a JCE provider
        // required for token verification for PS algorithms
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * getter function for config
     */
    public Config getConfig() {
        return cfg;
    }

    /**
     * setter function for config
     * @deprecated  Will be remove in next version, Use TrustAuthorityConnector(Config cfg) Constructor
     */

    public void setConfig(Config cfg) {
        //validate configuration
        cfg.validate();
        this.cfg = cfg;
    }

    /**
     * Fetches the nonce from the TrustAuthority server using the specified API URL
     *
     * @param args  GetNonceArgs object provided by the user.
     * @return      GetNonceResponse object
     */
    public GetNonceResponse GetNonce(GetNonceArgs args) throws Exception {
        HttpURLConnection connection = null;

        try {
            // Request for nonce from TrustAuthority server
            String url = String.format("%s/appraisal/v1/nonce", cfg.getApiUrl());

            // Initiate requestUrl based on the url
            URL requestUrl = new URL(url);

            // Set request properties
            Map<String, String> requestProperties = new HashMap<String, String>() {{
                put(Constants.HEADER_X_API_KEY, cfg.getApiKey());
                put(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON);
            }};

            // Add optional requestID
            if (args.getRequestId() != null) {
                requestProperties.putAll(Map.of(
                        Constants.HEADER_REQUEST_ID, args.getRequestId()
                ));
            }

            // Create the HttpURLConnection
            connection = openConnectionWithRetries(requestUrl, "GET", requestProperties, null);

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

            return response;
        } catch (Exception e) {
            throw new Exception("GetNonce() failed: " + e);
        } finally {
            // Close the connection in the finally block to ensure it is always closed
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Fetches the token from the TrustAuthority server using the specified API URL
     *
     * @param args  GetTokenArgs object provided by the user.
     * @return      GetTokenResponse object
     */
    public GetTokenResponse GetToken(GetTokenArgs args) throws Exception {
        HttpURLConnection connection = null;
        String url;
        try {
            args.validate();
            
            if (args.getEvidence().getType().ordinal() == EvidenceType.AZ_TDX.ordinal()) {
                url = String.format("%s/appraisal/v1/attest/azure/tdxvm", cfg.getApiUrl());
            } else if ((args.getEvidence().getType().ordinal() == EvidenceType.TDX.ordinal()) ||
                       (args.getEvidence().getType().ordinal() == EvidenceType.SGX.ordinal())) {
                url = String.format("%s/appraisal/v1/attest", cfg.getApiUrl());
            } else {
                throw new Exception("Invalid evidence type provided");
            }

            // Create the TokenRequest object
            TokenRequest tr = new TokenRequest(args.getEvidence().getQuote(), args.getNonce(), args.getEvidence().getRuntimeData(),
                                               args.getEvidence().getUserData(), args.getPolicyIds(),
                                               args.getEvidence().getEventLog(), args.getTokenSigningAlg(), args.getPolicyMustMatch());

            // Convert the TokenRequest to a JSON -> String
            // to send as request to server
            ObjectMapper objectMapper = new ObjectMapper();
            // Serialize the TokenRequest object to a JSON string
            String jsonString = objectMapper.writeValueAsString(tr);

            // Initiate requestUrl based on the url
            URL requestUrl = new URL(url);

            // Set request properties
            Map<String, String> requestProperties = new HashMap<String, String>() {{
                put(Constants.HEADER_X_API_KEY, cfg.getApiKey());
                put(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON);
                put(Constants.HEADER_CONTENT_TYPE, Constants.MIME_APPLICATION_JSON);
            }};

            // Add optional requestID
            if (args.getRequestId() != null) {
                requestProperties.putAll(Map.of(
                        Constants.HEADER_REQUEST_ID, args.getRequestId()
                ));
            }

            // Create the HttpURLConnection
            connection = openConnectionWithRetries(requestUrl, "POST", requestProperties, jsonString);

            // read the response if connection OK
            String responseBody = readResponseBody(connection, HttpURLConnection.HTTP_OK);

            // Map the fetched response JSON to GetTokenResponse object
            ObjectMapper mapper = new ObjectMapper();
            GetTokenResponse tokenResponse = mapper.readValue(responseBody, GetTokenResponse.class);

            // Set response headers
            tokenResponse.setHeaders(connection.getHeaderFields());

            return tokenResponse;
        } catch (Exception e) {
            throw new Exception("GetToken() failed: " + e);
        } finally {
            // Close the connection in the finally block to ensure it is always closed
            if (connection != null) {
                connection.disconnect();
            }
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
            args.validate();

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

            logger.debug("Collected evidence from adapter successfully...");

            // Calling the GetToken() API
            GetTokenResponse tokenResponse = GetToken(new GetTokenArgs(nonceResponse.getNonce(), evidence, args.getPolicyIds(), args.getRequestId(), args.getTokenSigningAlg(), args.getPolicyMustMatch()));
            if (tokenResponse == null) {
                throw new Exception("Failed to collect token from Trust Authority");
            }

            logger.debug("Collected token from Trust Authority successfully...");

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
        HttpURLConnection connection = null;

        try {
            // Format the request endpoint using the URL
            String url = String.format("%s/certs", cfg.getBaseUrl());

            // Create the URL object
            URL requestUrl = new URL(url);

            // Set request properties
            Map<String, String> requestProperties = Map.of(
                    Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON
            );

            // Create the HttpURLConnection
            connection = openConnectionWithRetries(requestUrl, "GET", requestProperties, null);

            // read the response if connection OK
            String responseBody = readResponseBody(connection, HttpURLConnection.HTTP_OK);

            // return the jwks in string format
            return responseBody;
        } catch (Exception e) {
            throw new Exception("getTokenSigningCertificates() failed: " + e);
        } finally {
            // Close the connection in the finally block to ensure it is always closed
            if (connection != null) {
                connection.disconnect();
            }
        }
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

            // Get the algorithm name from the JWSHeader
            String algorithmName = jwsHeader.getAlgorithm().getName();
            if (!(algorithmName.equals(Constants.ALGO_RS256) || algorithmName.equals(Constants.ALGO_PS384))) {
                throw new JOSEException("Unsupported token signing algorithm: " + algorithmName);
            }

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
            if (jwsAlgorithm.getName().equals(Constants.ALGO_RS256) || jwsAlgorithm.getName().equals(Constants.ALGO_PS384)) {
                verifier = new RSASSAVerifier(publicKey);
            } else {
                throw new JOSEException("Unsupported algorithm: " + jwsAlgorithm.getName());
            }

            // Retrieve the X.509 certificates
            List<X509Certificate> certificates = jwkKey.getParsedX509CertChain();

            if (certificates == null || certificates.isEmpty()) {
                throw new Exception("No X.509 certificates found in the JWK set");
            }
            if (certificates.size() < 3) { // < 3 condition used because we need at least 3 certs: leaf, intermediate, and root CA
                throw new Exception("Insufficient number of certificates in the chain. Expected at least 3.");
            }
            // Identify leaf, CA, and intermediate certificates
            X509Certificate leafCertificate = certificates.get(0);
            X509Certificate caCertificate = certificates.get(certificates.size() - 1);
            List<X509Certificate> intermediateCerts = new ArrayList<>();
            for (int i = 1; i < certificates.size() - 1; i++) {
                intermediateCerts.add(certificates.get(i));
            }
            X509Certificate intermediateCertificate = intermediateCerts.get(0);

            // Get the CRL Distribution Points URI for leafCertificate and intermediateCertificate
            List<String> listcrlDistributionPointsUriLeafCert = getCRLDistributionPoints(leafCertificate);
            List<String> listcrlDistributionPointsUriIntermediateCert = getCRLDistributionPoints(intermediateCertificate);

            // Fetch the ATS CRL object from CRL distribution points of leafCertificate
            X509CRL atsCrl = getCRL(listcrlDistributionPointsUriLeafCert.get(0));

            // verify the ATS Leaf certificate against ATS CRL
            boolean isVerified = verifyCRL(atsCrl, leafCertificate, intermediateCertificate);
            if (!isVerified) {
                throw new Exception("Failed to check ATS Leaf certificate against ATS CRL");
            }

            // Fetch the Root CA CRL object from CRL distribution points of intermediateCertificate
            X509CRL rootCrl = getCRL(listcrlDistributionPointsUriIntermediateCert.get(0));

            // verify the ATS CA Certificate against Root CA CRL
            isVerified = verifyCRL(rootCrl, intermediateCertificate, caCertificate);
            if (!isVerified) {
                throw new Exception("Failed to check ATS CA Certificate against Root CA CRL");
            }

            // Verify the certificate chain
            if (!verifyCertificateChain(certificates)) {
                throw new Exception("Certificate chain verification failed");
            }

            // Verify the signature
            if (signedJWT.verify(verifier)) {
                // Signature is valid
                logger.debug("JWT signature validated successfully");
            } else {
                // Signature is not valid
                throw new Exception("JWT signature is not valid");
            }

            return signedJWT.getJWTClaimsSet();
        } catch (Exception e) {
            throw new Exception("verifyToken() failed: " + e);
        }
    }

    /**
     * Helper function to verify the Certificate against CRL
     *
     * @param crl       certificate revocation list object
     * @param leafCert  leaf cert to be checked for revocation
     * @param caCert    CA certificate for CRL to be verified with
     * @return          True/False based on verification success/failure
     */
    public boolean verifyCRL(X509CRL crl, X509Certificate leafCert, X509Certificate caCert) throws Exception {
        if (leafCert == null || caCert == null || crl == null) {
            throw new Exception("null certificate provided");
        }

        try {
            // Checking CRL signed by CA Certificate
            crl.verify(caCert.getPublicKey());

            // Checking if CRL is outdated
            Date now = new Date();
            if (crl.getNextUpdate().before(now)) {
                throw new Exception("Outdated CRL");
            }

            // Checking if the certificate was revoked
            Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();
            if (revokedCertificates != null) {
                for (X509CRLEntry crlEntry : revokedCertificates) {
                    if (crlEntry.getSerialNumber().equals(leafCert.getSerialNumber())) {
                        throw new Exception("Certificate is revoked");
                    }
                }
            }

            // Return true if the verification passes all checks
            return true;
        } catch (Exception e) {
            throw new Exception("verifyCRL() failed: " + e);
        }
    }

    /**
     * Helper function to retrieve the CRL object from CRLDistributionPoints URL
     *
     * @param crlUrl    URL associated with CRLDistributionPoints
     * @return          X509CRL object retrieved from crlUrl
     */
    public X509CRL getCRL(String crlUrl) throws Exception {
        HttpURLConnection connection = null;
        URL requestUrl = null;
        InputStream inputStream = null;

        try {
            // Create a URL object
            requestUrl = new URL(crlUrl);

            // Create the HttpURLConnection
            connection = openConnectionWithRetries(requestUrl, "GET", null, null);

            // Get the input stream from the connection
            inputStream = connection.getInputStream();

            // Create a CertificateFactory for X.509
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // Convert the InputStream to X509CRL
            X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);

            return crl;
        } catch (Exception e) {
            throw new Exception("getCRL() failed: " + e);
        } finally {
            // Close the input stream
            if (inputStream != null) {
                inputStream.close();
            }

            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Helper function to get CRL Distribution Points for a X509Certificate
     *
     * @param certificate   X509Certificate object
     * @return              List of CRL Distribution points of the X509Certificate
     */
    public List<String> getCRLDistributionPoints(X509Certificate certificate) throws Exception {
        List<String> crlDistributionPoints = new ArrayList<>();

        if (null == certificate) {
            throw new Exception("Null certificate provided");
        }
        
        try {
            // Get the extension value for CRL Distribution Points
            byte[] crlDPExtensionValue = certificate.getExtensionValue(Constants.DEFAULT_OID_CRL_DISTRIBUTION_POINTS);

            if (crlDPExtensionValue != null) {
                // Parse the extension value and extract the URIs
                // Create an ASN1InputStream from the extension value
                ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(crlDPExtensionValue));
                // Extract the octet string
                ASN1OctetString octetString = ASN1OctetString.getInstance(asn1InputStream.readObject());
                // Convert the octet string to an ASN1Primitive
                ASN1Primitive primitive = ASN1Primitive.fromByteArray(octetString.getOctets());
                asn1InputStream.close();

                if (primitive instanceof ASN1Sequence) {
                    // If the primitive is a sequence, proceed with parsing
                    ASN1Sequence seq = (ASN1Sequence) primitive;

                    for (int i = 0; i < seq.size(); i++) {
                        // Extract each DistributionPoint from the sequence
                        DistributionPoint distributionPoint = DistributionPoint.getInstance(seq.getObjectAt(i));
                        DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();

                        if (distributionPointName != null) {
                            // Extract GeneralNames from DistributionPointName
                            GeneralNames generalNames = GeneralNames.getInstance(distributionPointName.getName());
                            for (GeneralName generalName : generalNames.getNames()) {
                                if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                    // Extract URI from GeneralName and add to the list
                                    String uri = generalName.getName().toString();
                                    crlDistributionPoints.add(uri);
                                }
                            }
                        }
                    }
                }
                return crlDistributionPoints;
            } else {
                throw new Exception("CRL Distribution Points extension not found in the certificate.");
            }
        } catch (Exception e) {
            throw new Exception("getCRLDistributionPoints() failed: " + e);
        }
    }

    /**
     * Helper function to verify certificate chain
     *
     * @param certificates    List of certificates to be verified
     * @return                True/False based on verification success/failure
     */
    public boolean verifyCertificateChain(List<X509Certificate> certificateList) throws Exception {
        try {
            for (int i = certificateList.size() - 1; i > 0; i--) {
                X509Certificate issuerCertificate = certificateList.get(i);
                X509Certificate currentCertificate = certificateList.get(i - 1);

                // Check if the current certificate was issued by the previous certificate
                if (!currentCertificate.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
                    logger.debug("Certificate at index " + i + " was not issued by the previous certificate.");
                    return false;
                }

                // Verify the signature of the current certificate using the public key of the issuer
                currentCertificate.verify(issuerCertificate.getPublicKey());
            }

            // If the loop completes without exceptions, the certificate chain is valid
            return true;
        } catch (Exception e) {
            throw new Exception("verifyCertificateChain() failed: " + e);
        }
    }

    /**
     * Helper function to fetch the response from server
     *
     * @param connection    HttpURLConnection object provided by the user.
     * @param responseCode  Response code of the connection to read input/error message.
     * @return              The server input/error message response as a string
     */
    public String readResponseBody(HttpURLConnection connection, int responseCode) throws IOException {

        // Read the response body
        BufferedReader reader;
        if (responseCode == HttpURLConnection.HTTP_OK) {
            // Read InputStream if connection is successful
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), Charset.forName("UTF-8")));
        } else {
            // Read ErrorStream if connection is unsuccessful
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream(), Charset.forName("UTF-8")));
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
     * @param requestMethod         Request method type to be set for the connection.
     * @param requestProperties     List of request properties to be set for the connection.
     * @param requestBody           If provided, writes requestBody to the output stream of connection.
     * @return                      HttpURLConnection object on a successful response.
     */
    public HttpURLConnection openConnectionWithRetries(URL url, String requestMethod, Map<String, String> requestProperties, String requestBody) throws Exception {
        // Set maxRetries and retryWaitTimeMillis based on Config
        int maxRetries = cfg.getRetryConfig().getRetryMax();
        long retryWaitTimeMillis = cfg.getRetryConfig().getRetryWaitMin() * 1000;

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

            // Set request method
            connection.setRequestMethod(requestMethod);

            // Set request properties
            if (requestProperties != null) {
                for (Map.Entry<String, String> entry : requestProperties.entrySet()) {
                    connection.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }

            // Write output value if provided
            if (requestBody != null) {
                connection.setDoOutput(true);
                try(OutputStream out = connection.getOutputStream()){
                    out.write(requestBody.getBytes("UTF-8"));
                    out.flush(); // Ensure all data sent
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
                    long waitTime = Math.min(cfg.getRetryConfig().getRetryWaitMax() * 1000,
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