/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

// JUnit imports for assertions and test annotations
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

// MockServer imports for HTTP server mocking
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

// Base64 utility import
import com.nimbusds.jose.util.Base64;

// Mockito imports for mocking objects and defining behavior
import org.mockito.Mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;
import static org.mockito.ArgumentMatchers.any;

// Utility imports for arrays and UUID
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

// Log4j imports for logging
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// Nimbus JOSE+JWT library import for JWT claims set
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * TrustAuthorityConnectorTest contains unit tests for all APIs exposed by the TrustAuthorityConnector
 */
public class TrustAuthorityConnectorTest {

    // Logger object
    private static final Logger logger = LogManager.getLogger(TrustAuthorityConnectorTest.class);

    // Initialize Mock Server object
    private ClientAndServer mockServer;

    // Initialize Config and TrustAuthorityConnector
    private Config cfg;
    private TrustAuthorityConnector connector;

    // Declare valid jwks
    String valid_jwks;

    @Before
    public void setup() {
        try {
            // Setup Mock Server
            mockServer = new ClientAndServer(); // No-args constructor will start on a free port

            // Default RetryConfig
            RetryConfig retry_config = new RetryConfig();

            // Initialize config required for connector
            cfg = new Config("http://localhost:" + mockServer.getPort(),
                             "http://localhost:" + mockServer.getPort(),
                             "some_key", retry_config);
            assertNotNull(cfg);

            // Initializing connector with the config
            connector = new TrustAuthorityConnector(cfg);
            assertNotNull(connector);

            // Verify connector config
            assertEquals(connector.getConfig(), cfg);

            // Valid valid_jwks for testing
            valid_jwks = "{\"keys\":[{\"alg\":\"PS384\",\"e\":\"AQAB\",\"kid\":\"1a1a2fe5fcf89009e4b96c45e0dceb005ea635d8ba2f6ed9caeef44ae235970decc586154fd9f740fb3b72ca176abb59\",\"kty\":\"RSA\",\"n\":\"vKKV7v7czOHapQ22ZnW677i4BkQIuxVTLk933javfZyLzpM7ZP_Mhvu9QqHrr-iKEqCDBuX1slL_hoB0fTCGGnoFTZ1lTqBdmhFysIgg5uzAqMWL2SJdzYX9RJ_ZXMFnvzTznO-b2jJd864pUI6y72mrzfTqQvgw_60fa3tjc9zjJPiqT1yadKar3G5c0fJqg7AUooTuMkIq291tHqoNhfYzzshZCSFV_d5RruheVMjvgMunx1zISiZ5RNRjcy39G7-08UTCIlSKE_GdsLDNViHqACz60BW3p-kSY5YdoslwKvDUOJnkVZMpJNfdYDoBIiIGgKL2j5H8arHmhSw1A1kl66YdDl7H5Pa46qp4B2FrS5Qpt1D9C-SZXkWN3wzDIQLsHKs0e86R5guLMS9_WcfsPCcHCLjqMZe6S-18SdjwzCK4hbn5vLCZYUzIyVEIcYT8f3mS3s3I1UxJRW53WZOEKkyGVKKGTF8uRxaksFVGrIdW0Q41Wo3mB30N2tqL\",\"x5c\":[\"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\"]}]}";
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @After
    public void tearDown() {
        // Shut down Mock Server after tests are run
        mockServer.stop();
    }

    @Test
    public void testConstants() {
        Constants constants = new Constants();
        assertEquals(Constants.HEADER_REQUEST_METHOD, "request-method");
        assertEquals(Constants.HEADER_X_API_KEY, "x-api-key");
        assertEquals(Constants.HEADER_ACCEPT, "Accept");
        assertEquals(Constants.HEADER_CONTENT_TYPE, "Content-Type");
        assertEquals(Constants.HEADER_REQUEST_ID, "request-id");
        assertEquals(Constants.HEADER_TRACE_ID, "trace-id");
        assertEquals(Constants.MIME_APPLICATION_JSON, "application/json");
        assertEquals(Constants.WRITE_OUTPUT, "write-output");
    }

    @Test
    public void testConfig() {
        try {
            // Default RetryConfig
            RetryConfig retry_config = new RetryConfig();

            // Initialize config
            Config config = new Config("http://localhost:" + mockServer.getPort(),
                                       "http://localhost:" + mockServer.getPort(),
                                       "some_key",
                                       retry_config);
            assertNotNull(config);

            // Test connector config setter
            TrustAuthorityConnector conn = new TrustAuthorityConnector(config);
            conn.setConfig(config);
            assertEquals(conn.getConfig(), config);

            // Testing getters for Config
            assertEquals(config.getBaseUrl(), "http://localhost:" + mockServer.getPort());
            assertEquals(config.getApiUrl(), "http://localhost:" + mockServer.getPort());
            assertEquals(config.getApiKey(), "some_key");

            // Testing setters for Config
            config.setBaseUrl("http://localhost:" + mockServer.getPort());
            config.setApiUrl("http://localhost:" + mockServer.getPort());
            config.setApiKey("some_key");
            assertEquals(config.getBaseUrl(), "http://localhost:" + mockServer.getPort());
            assertEquals(config.getApiUrl(), "http://localhost:" + mockServer.getPort());
            assertEquals(config.getApiKey(), "some_key");

            // Testing getters/setters for RetryConfig
            RetryConfig customRetryConfig = new RetryConfig(2L, 10L, 3);
            config.setRetryConfig(customRetryConfig);
            config.getRetryConfig().setRetryWaitMin(2L);
            config.getRetryConfig().setRetryWaitMax(10L);
            config.getRetryConfig().setRetryMax(3);
            assertEquals(config.getRetryConfig().getRetryWaitMin(), 2);
            assertEquals(config.getRetryConfig().getRetryWaitMax(), 10);
            assertEquals(config.getRetryConfig().getRetryMax(), 3);
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @Test
    public void testTokenRequest() {
        try {
            // Create mock objects for testing
            byte[] expected = {1, 2, 3, 4, 5};
            byte[] actual = {1, 2, 3, 4, 5};
            VerifierNonce mockNonce = new VerifierNonce("mock-val".getBytes(), "mock-iat".getBytes(), "mock-signature".getBytes());
            List<UUID> mockPolicyIDs = Arrays.asList(UUID.randomUUID());

            // Initialize TokenRequest
            TokenRequest token_request = new TokenRequest(expected, mockNonce, expected, mockPolicyIDs, expected);

            // Testing setters for TokenRequest
            token_request.setQuote(expected);
            token_request.setVerifierNonce(mockNonce);
            token_request.setRuntimeData(expected);
            token_request.setPolicyIds(mockPolicyIDs);
            token_request.setEventLog(expected);
            assertArrayEquals(token_request.getQuote(), actual);
            assertEquals(token_request.getVerifierNonce(), mockNonce);
            assertArrayEquals(token_request.getRuntimeData(), actual);
            assertEquals(token_request.getPolicyIds(), mockPolicyIDs);
            assertArrayEquals(token_request.getEventLog(), actual);
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @Test
    public void testEvidence() {
        try {
            // Create mock objects for testing
            byte[] expected = {1, 2, 3, 4, 5};
            byte[] actual = {1, 2, 3, 4, 5};
            long expected_type = 0;

            // Initialize Evidence
            Evidence evidence = new Evidence(expected_type, expected, expected, expected);

            // Testing getters for Evidence
            assertEquals(evidence.getType(), 0);
            assertArrayEquals(evidence.getEvidence(), actual);
            assertArrayEquals(evidence.getUserData(), actual);
            assertArrayEquals(evidence.getEventLog(), actual);
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @Test
    public void testGetNonce() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Initialize nonce_args for GetNonce() API
            GetNonceArgs nonce_args = new GetNonceArgs("mock-request-id");
            assertNotNull(nonce_args);

            // Initialize nonce values for serving from mock server
            String nonce_val = "MjAyMy0xMi0yMCAxNzo0MDowNiArMDAwMCBVVEM=";
            String nonce_iat = "MjAyMi0wOC0yNCAxMjozNjozMi45Mjk3MjIwNzUgKzAwMDAgVVRD";
            String nonce_signature = "g9QC7VxV0n8dID0zSJeVLSULqYCJuv4iMepby91xukrhXgKrKscGXB5lxmT2s3POjxVOG+fSPCYpOKYWRRWAyQ==";

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/nonce"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("{\"val\":\"" + nonce_val + "\",\"iat\":\"" + nonce_iat + "\",\"signature\":\"" + nonce_signature + "\"}"));

            // Calling the GetNonce() API
            GetNonceResponse nonceResponse = connector.GetNonce(nonce_args);

            // Verify response is not empty
            assertNotNull(nonceResponse);
            assertNotNull(nonceResponse.getNonce());

            // Convert nonce values to Base64 decoded bytes
            byte[] decodedBytesVal = Base64.from(nonce_val).decode();
            byte[] decodedBytesIat = Base64.from(nonce_iat).decode();
            byte[] decodedBytesSignature = Base64.from(nonce_signature).decode();

            // Verify the response
            assertArrayEquals(decodedBytesVal, nonceResponse.getNonce().getVal());
            assertArrayEquals(decodedBytesIat, nonceResponse.getNonce().getIat());
            assertArrayEquals(decodedBytesSignature, nonceResponse.getNonce().getSignature());
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @Test
    public void testGetNonceFailure() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Initialize nonce_args for GetNonce() API
            GetNonceArgs nonce_args = new GetNonceArgs("mock-request-id");
            assertNotNull(nonce_args);

            // Stubbing the response with an invalid nonce
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/nonce"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("invalid_nonce"));

            // Calling the GetNonce() API
            GetNonceResponse nonceResponse = connector.GetNonce(nonce_args);
            assertNull(nonceResponse);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testGetToken() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Create a mock GetTokenArgs object
            GetTokenArgs mockArgs = mock(GetTokenArgs.class);
            VerifierNonce mockNonce = new VerifierNonce("mock-val".getBytes(), "mock-iat".getBytes(), "mock-signature".getBytes());
            Evidence mockEvidence = mock(Evidence.class);
            when(mockArgs.getNonce()).thenReturn(mockNonce);
            when(mockArgs.getEvidence()).thenReturn(mockEvidence);
            when(mockArgs.getPolicyIds()).thenReturn(Arrays.asList(UUID.randomUUID()));
            when(mockArgs.getRequestId()).thenReturn("mock-request-id");

            // Sample token to be sent from server
            String token = "mock-token";

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/attest"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("{\"token\":\"" + token + "\"}"));

            // Calling the GetToken() API
            GetTokenResponse tokenResponse = connector.GetToken(mockArgs);
            assertNotNull(tokenResponse);

            // Verify the response
            assertEquals("mock-token", tokenResponse.getToken());
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @Test
    public void testGetTokenFailure() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Create a mock GetTokenArgs object
            GetTokenArgs mockArgs = mock(GetTokenArgs.class);

            // Stubbing the response with an invalid token
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/attest"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("invalid_token"));

            // Calling the GetToken() API
            GetTokenResponse tokenResponse = connector.GetToken(mockArgs);
            assertNull(tokenResponse);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testAttest() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Initialize nonce_args for GetNonce() API
            GetNonceArgs nonce_args = new GetNonceArgs("mock-request-id");
            assertNotNull(nonce_args);

            // Initialize nonce values for serving from mock server
            String nonce_val = "MjAyMy0xMi0yMCAxNzo0MDowNiArMDAwMCBVVEM=";
            String nonce_iat = "MjAyMi0wOC0yNCAxMjozNjozMi45Mjk3MjIwNzUgKzAwMDAgVVRD";
            String nonce_signature = "g9QC7VxV0n8dID0zSJeVLSULqYCJuv4iMepby91xukrhXgKrKscGXB5lxmT2s3POjxVOG+fSPCYpOKYWRRWAyQ==";

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/nonce"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("{\"val\":\"" + nonce_val + "\",\"iat\":\"" + nonce_iat + "\",\"signature\":\"" + nonce_signature + "\"}"));

            // Calling the GetNonce() API
            GetNonceResponse nonceResponse = connector.GetNonce(nonce_args);
            assertNotNull(nonceResponse);

            // Convert nonce values to Base64 decoded bytes
            byte[] decodedBytesVal = Base64.from(nonce_val).decode();
            byte[] decodedBytesIat = Base64.from(nonce_iat).decode();
            byte[] decodedBytesSignature = Base64.from(nonce_signature).decode();

            // Verify response is not empty
            assertNotNull(nonceResponse);
            assertNotNull(nonceResponse.getNonce());

            // Verify the GetNonce() response
            assertArrayEquals(decodedBytesVal, nonceResponse.getNonce().getVal());
            assertArrayEquals(decodedBytesIat, nonceResponse.getNonce().getIat());
            assertArrayEquals(decodedBytesSignature, nonceResponse.getNonce().getSignature());

            // Create a mock GetTokenArgs object
            GetTokenArgs mockArgs = mock(GetTokenArgs.class);
            VerifierNonce mockNonce = new VerifierNonce("mock-val".getBytes(), "mock-iat".getBytes(), "mock-signature".getBytes());
            Evidence mockEvidence = mock(Evidence.class);
            when(mockArgs.getNonce()).thenReturn(mockNonce);
            when(mockArgs.getEvidence()).thenReturn(mockEvidence);
            when(mockArgs.getPolicyIds()).thenReturn(Arrays.asList(UUID.randomUUID()));
            when(mockArgs.getRequestId()).thenReturn("mock-request-id");

            // Sample token to be sent from server
            String token = "mock-token";

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/attest"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("{\"token\":\"" + token + "\"}"));

            // Calling the GetToken() API
            GetTokenResponse tokenResponse = connector.GetToken(mockArgs);
            assertNotNull(tokenResponse);

            // Verify the GetToken() response
            assertEquals("mock-token", tokenResponse.getToken());

            // Create a mock adapter object
            EvidenceAdapter mockAdapter = mock(EvidenceAdapter.class);
            when(mockAdapter.collectEvidence(any())).thenReturn(mockEvidence);

            // Perform the test
            AttestArgs attestArgs = new AttestArgs(mockAdapter, null, "mock-request-id");
            AttestResponse response = connector.attest(attestArgs);

            // Verify the response
            assertNotNull(response);
            assertEquals(tokenResponse.getToken(), response.getToken());
            assertEquals(tokenResponse.getHeaders(), response.getHeaders());

            // Test setters
            tokenResponse.setToken(response.getToken());
            tokenResponse.setHeaders(response.getHeaders());
            assertEquals(tokenResponse.getToken(), response.getToken());
            assertEquals(tokenResponse.getHeaders(), response.getHeaders());
            attestArgs.setRequestId("mock-request-id");
            attestArgs.setPolicyIds(Arrays.asList(UUID.randomUUID()));
            attestArgs.setAdapter(mockAdapter);
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @Test
    public void testAttestNonceFailure() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response with an invalid nonce
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/nonce"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("invalid_nonce"));

            Evidence mockEvidence = mock(Evidence.class);

            // Create a mock adapter object
            EvidenceAdapter mockAdapter = mock(EvidenceAdapter.class);
            when(mockAdapter.collectEvidence(any())).thenReturn(mockEvidence);

            // Perform the test
            AttestArgs attestArgs = new AttestArgs(mockAdapter, null, "mock-request-id");
            AttestResponse response = connector.attest(attestArgs);
            assertNull(response);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testAttestTokenFailure() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Initialize nonce values for serving from mock server
            String nonce_val = "MjAyMy0xMi0yMCAxNzo0MDowNiArMDAwMCBVVEM=";
            String nonce_iat = "MjAyMi0wOC0yNCAxMjozNjozMi45Mjk3MjIwNzUgKzAwMDAgVVRD";
            String nonce_signature = "g9QC7VxV0n8dID0zSJeVLSULqYCJuv4iMepby91xukrhXgKrKscGXB5lxmT2s3POjxVOG+fSPCYpOKYWRRWAyQ==";

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/nonce"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("{\"val\":\"" + nonce_val + "\",\"iat\":\"" + nonce_iat + "\",\"signature\":\"" + nonce_signature + "\"}"));

            // Stubbing the response with an invalid token and 503 response code to exercise retry mechanism
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/appraisal/v1/attest"))
                                .respond(HttpResponse.response().withStatusCode(503)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("invalid_token"));

            Evidence mockEvidence = mock(Evidence.class);

            // Create a mock adapter object
            EvidenceAdapter mockAdapter = mock(EvidenceAdapter.class);
            when(mockAdapter.collectEvidence(any())).thenReturn(mockEvidence);

            // Perform the test
            AttestArgs attestArgs = new AttestArgs(mockAdapter, null, "mock-request-id");
            AttestResponse response = connector.attest(attestArgs);
            assertNull(response);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testGetTokenSigningCertificates() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/certs"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw==\",\"e\":\"AQAB\",\"alg\":\"PS384\",\"x5c\":[\"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\"],\"kid\":\"12345\"}]}"));

            // Calling the getTokenSigningCertificates() API
            String response = connector.getTokenSigningCertificates();
            assertNotNull(response);
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @Test
    public void testGetTokenSigningCertificatesFailure() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response and induce a failure response code 404
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/certs"))
                                .respond(HttpResponse.response().withStatusCode(404)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("Not Found"));

            // Calling the getTokenSigningCertificates() API
            String response = connector.getTokenSigningCertificates();
            assertNull(response);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testVerifyToken() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/certs"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody(valid_jwks));

            // Sample token for testing
            String token = "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vYW1iZXItdGVzdDEtdXNlcjEucHJvamVjdC1hbWJlci1zbWFzLmNvbS9jZXJ0cyIsImtpZCI6IjFhMWEyZmU1ZmNmODkwMDllNGI5NmM0NWUwZGNlYjAwNWVhNjM1ZDhiYTJmNmVkOWNhZWVmNDRhZTIzNTk3MGRlY2M1ODYxNTRmZDlmNzQwZmIzYjcyY2ExNzZhYmI1OSIsInR5cCI6IkpXVCJ9.eyJzZ3hfbXJlbmNsYXZlIjoiMGE3NTZhNjUzYjlhOTJiMTNkYmQ2MjRhNWE1OTY4MTU4OTViMTMwODIwYzU1ZjNiMWI3Y2FmYjMwNDY5NjViYyIsInNneF9tcnNpZ25lciI6ImQ0MTJhNGYwN2VmODM4OTJhNTkxNWZiMmFiNTg0YmUzMWUxODZlNWE0Zjk1YWI1ZjY5NTBmZDRlYjg2OTRkN2IiLCJzZ3hfaXN2cHJvZGlkIjowLCJzZ3hfaXN2c3ZuIjowLCJzZ3hfcmVwb3J0X2RhdGEiOiI0MDE4OWU5YmRiZmRjMzA5OWEwZmE3MzVlYTEyNjkwZDI3MTEyZGUyOWRkYjgxNDFkMGNhYzMzMGNjM2FiYjE5MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneF9pc19kZWJ1Z2dhYmxlIjpmYWxzZSwic2d4X2NvbGxhdGVyYWwiOnsicWVpZGNlcnRoYXNoIjoiYjJjYTcxYjhlODQ5ZDVlNzk5NDUxYjRiZmU0MzE1OWEwZWU1NDgwMzJjZWNiMmMwZTQ3OWJmNmVlM2YzOWZkMSIsInFlaWRjcmxoYXNoIjoiZjQ1NGRjMWI5YmQ0Y2UzNmMwNDI0MWUyYzhjMzdhMmFlMjZiMDc3ZjJjNjZiOTE5ODQzMzY1MzE4YTU5MzMyYyIsInFlaWRoYXNoIjoiOTk1ZDljMmUyYmVhNzYyOWEzMmI2NWUxMmZmZjc1MzJkM2M2YTc2YWFmODEwYjgwZTg5Y2RjNjE4YTJmYTVjOSIsInF1b3RlaGFzaCI6IjViMzJhMWUyZmJjOTdlNTJjZWMxNDgxZTg5ZTNmMmFmYmFjM2QzMDZmMDE5ZTBiYTA3OTAwNGM0ZWM0MzRlNTMiLCJ0Y2JpbmZvY2VydGhhc2giOiJiMmNhNzFiOGU4NDlkNWU3OTk0NTFiNGJmZTQzMTU5YTBlZTU0ODAzMmNlY2IyYzBlNDc5YmY2ZWUzZjM5ZmQxIiwidGNiaW5mb2NybGhhc2giOiJmNDU0ZGMxYjliZDRjZTM2YzA0MjQxZTJjOGMzN2EyYWUyNmIwNzdmMmM2NmI5MTk4NDMzNjUzMThhNTkzMzJjIiwidGNiaW5mb2hhc2giOiI3M2UwYzhkNDU2ODdhMTU2YzUyNzQ1YmRlOWJkMDRkZGU2MTcxY2YzMjFmNDA3NDE5Zjg0MGU5YmJhYzY1ZTAxIn0sImF0dGVzdGVyX2hlbGRfZGF0YSI6IkFRQUJBQjBuQ1RNR3dXOXdtYy93M3dKSGwraDRnODJwMGQ4aWpGU3ZuT2JBdTBEb3pWdHR2d3NweEJRK1ZCdXMvNDhJQVBLQnhmV3owcjYybWNjeHJWMTRndFJaWU9RWHBXUnNPeUF3cHJoNndqWHlHdmtrbDNuVEQ0a0Y0L29WZ1NVaUlwZDZMcjFxUVd6a2N0bnhoWHpkWkxpVWp3TktPNHdIaFdoV1hVNEduSEl4SmQwVUtiQXIyM2lPNGRrSnkxY3dmNUZxd0pROVI2L3UrYW1vLzI0QkZDQUNLamZhbHNpaThXendtSE5UQ3hNeWtGOE0zWEwrTjJCSFdsVlNOa21VLzFSMlp2eFk2V3pQRUpsbGkwVHhySWJwaG1SdHpKM3E2cDdPSktPT2dXKzFCdkxtcUd4K05ZL2xqNjQvRXJOKzBZTVZLNGI3ZU05ZTFIVS9qQ0JRVlpvTnM1LzB1ZUgyOGpjZTJBSituWWUyUFc0R2hXallueklaYnZNTy9QKy9RR3NvRXJlZ2RsQ0c3ZWVvMUZxV1dtdUt0S3N3RStwRmFXbmQwMFJOZ29qMU81anJERmJMM0RpTVYwTGNVOTU5Q3BjV2lkN1VKYmlEUTM1OUgrVVhXZmpNdVJ3aE0yanJhaE9nczd2dFdtWUcrcnZEb0dTS29DQVBQNVhlNlRoU3lBPT0iLCJ2ZXJpZmllcl9ub25jZSI6eyJ2YWwiOiJWV2N3V1hCbmIwdGtiSEJ6YXpaVlZITTBPVGRGWVdoM01Wb3JkVmhHU0VaSlFXVXdTMXBpTXpOVlREa3dlVkl2WTJnemVsRkZkRGx5UVdZM1dYZHhia1ptWWtRMU9WZE5MMnB6VW5GeE1HVnBSRTlZVUVFOVBRPT0iLCJpYXQiOiJNakF5TXkweE1pMHlNU0F3TlRvek1Ub3dPQ0FyTURBd01DQlZWRU09Iiwic2lnbmF0dXJlIjoiVXAyZlluNUhwcTVpbXRmeXZmaWZEQisrbjV2bVVhcXZydU9kQVVtckg4OG5JRWorQU94NXk1ck5sV1BqWkNWcnk1emxpcjVOdUVNa0ZJc2FQV1pJM0t1L2ozQlZNM081dk0yOGJFR3lSYTA2V2phQWtLbktLZ3hrK3NaMG54RVluUGxuTGtweW81YjVKbXBEOFJOWm5iL2d2OXBYaWVxZU1OYThnTStkK2pwMk90M0VqUzR1VmhUYllSYmdxamJ6VlBhNEYrTVgrbnUzR01FSmdKdFlvZnFtZnRHa25mc1VHdW1BVE12Z21NdVV4Vk1lSFhQUUFGd1I4RWJrTE1odzlxOUVyVU1YdTB1Z045cTdsd2QrNUJKZ1pGR0lyeWNWZTRudzJGTVZITzI5SHdlMzM0czdQZ002SEpQR3NpaDN2S3dNVXM4SSt0MWVnUDRzcjJERWJPblZlS254VFdwV1IraUNqZks0NmJicE80VS9GYmN4c0k2SXAxK3ZvOVd5WDBCQVpFSmpuWHpMZGYydHZVRnJjcmJ1dFVYWW1xaWd5dks5SmtpcWltR29JQ3ptYjZuc25wSmJOeFlDK3RNY1FtUFk0ekgva2x2K3p3N0FVZnZvUXFpRG13UmtDYUgvcTRNdmNsKzBwUkwrUFUrbkdidkpHZHJHNk9LVSt2T2UifSwicG9saWN5X2lkc19tYXRjaGVkIjpbeyJpZCI6IjkxNDg4ZTEyLWYzOWUtNGYzZS04NDM1LWQ0OWM4MTNkZWNiNSIsInZlcnNpb24iOiJ2MSJ9XSwicG9saWN5X2lkc191bm1hdGNoZWQiOlt7ImlkIjoiN2YzODE0MzAtNTFmOC00N2IwLWE2ZTAtMzkzZWYxODM3YWYzIiwidmVyc2lvbiI6InYxIn1dLCJwb2xpY3lfZGVmaW5lZF9jbGFpbXMiOnt9LCJhdHRlc3Rlcl90Y2Jfc3RhdHVzIjoiT3V0T2ZEYXRlIiwiYXR0ZXN0ZXJfdGNiX2RhdGUiOiIyMDIxLTExLTEwVDAwOjAwOjAwWiIsImF0dGVzdGVyX2Fkdmlzb3J5X2lkcyI6WyJJTlRFTC1TQS0wMDU4NiIsIklOVEVMLVNBLTAwNjE0IiwiSU5URUwtU0EtMDA2MTUiLCJJTlRFTC1TQS0wMDY1NyIsIklOVEVMLVNBLTAwNzMwIiwiSU5URUwtU0EtMDA3MzgiLCJJTlRFTC1TQS0wMDc2NyIsIklOVEVMLVNBLTAwODI4IiwiSU5URUwtU0EtMDA4MzciXSwiYXR0ZXN0ZXJfdHlwZSI6IlNHWCIsInZlcmlmaWVyX2luc3RhbmNlX2lkcyI6WyI5YTRlMjQ2OS03NGIwLTQ4OWQtOTczYi1jMTU0NzllODNhZDEiLCIxNDc2ZGE3NC0yOTdkLTRiYzEtYjdkMi0xMGUyNTk1MGJhN2MiLCJjMTQyMTcyNi1lYjViLTRmYWEtYmEzOC0zNWZiMGM3ZDk1NDYiLCI4NGNmZGUzYi0wM2Q1LTQ4ZWYtYTIxMC0xZWY5ZTU2MTE2YTMiXSwiZGJnc3RhdCI6ImRpc2FibGVkIiwiZWF0X3Byb2ZpbGUiOiJodHRwczovL2FtYmVyLXRlc3QxLXVzZXIxLnByb2plY3QtYW1iZXItc21hcy5jb20vZWF0X3Byb2ZpbGUuaHRtbCIsImludHVzZSI6ImdlbmVyaWMiLCJ2ZXIiOiIxLjAuMCIsImV4cCI6MTcwMzEzNjk2OCwianRpIjoiOGViNDg2NmMtNTc0Ni00YzdkLWJlNzktM2UwNDlkYzBhNzQ5IiwiaWF0IjoxNzAzMTM2NjY4LCJpc3MiOiJJbnRlbCBUcnVzdCBBdXRob3JpdHkiLCJuYmYiOjE3MDMxMzY2Njh9.tf9oqTHuJKA8LPcqqHndNgLlc7GxCkNx3TerIbHU9OpzoU6pEnbcDo8655p3X1LUQQ1yb-fi5IqRZYO8-KCnsCCAuID8ff4bGwBKCExN0xP656tLbh3w7dyh7miIuJz9JBVvDn41CPKcRotuzoMjMIQzQQiIBaU4bRBDEWHaMEHoGM8qr0KXqz0YP3kKT1f4fL7FAKHjSyxNqqw3_bxFaeFvEBcTCnRBgEUAIxd79Yq0LndDenxAkfEaXOmtCSd_t9-vs7zzBKvbZ_wurVnXQbLaLM8DEMzykZmTB5yIERbrfFzkR-61Uv3cibWGdR8Be0shc3pgvgcXtSKaPsLdNI7pf17S0fCEMwCKtIBStHcDVbyz8fvDHnW8lUsHXHWY4hrXJfTfH0DnoISJCXpXoLLr43D8wAd4PLdUOzaQ0tMYRtCnsWW5lzvpReHzD13GjgCb_2T1KutxR6a9QidIbAAi8i1EUwmvjlloQyPwV0neC5Gczetd79zHHNRrDjpW";

            // Calling the verifyToken() API with valid token
            JWTClaimsSet claims = connector.verifyToken(token);
            assertNotNull(claims);

            // Verify the response
            assertEquals(claims.getIssuer(), "Intel Trust Authority");
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }
    }

    @Test
    public void testVerifyTokenInvalidToken() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/certs"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody(valid_jwks));

            // Sample token for testing
            String invalidToken = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjNmZDc1MWYyZTBkMGY1Mjg0NmMwZWNkNDk3MmM2ZTk5ZGZjNjQyMDUxY2QzMzlkZDliMDQzODFhZjhjMGRkYjgwNDUxNGE3YTFmZWU0NjczYWM4NDRmZDVkYjdmMTVmYiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tJPT6hz2psdkB2yuf17UjqcH1t4ujt9iwRP8iFrG93vMZN2W8umIlYVCE9NVigYoX3EkNuOq_OGlYvfdrUjsYFU-hFLvmORLbaBZ2u0GCfxgrGpYX7ngjZRad_cE9KGcmv6R2fxWI4gF-73DMeaoGWXTVAPlquV_Tyc987zeXj1KXAVO0SDWG68LiWVcl42FUlOI_2mXV4rGsgWLPgbyaa5SuSu-ENreQenvyUMMzdntbJtytQycOxYVrppQJaFNKwn8OfwloGvt7jedylCZgU1MBIrTXUN_lgKAZnFfRxUMfbiV-i73kPqWcOAxbzK8JZPAKv4AyVDWFEBhKKuxiQ";

            // Calling the verifyToken() API with invalid token
            JWTClaimsSet invalidClaims = connector.verifyToken(invalidToken);
            assertNull(invalidClaims);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testVerifyTokenMissingKid() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/certs"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody(valid_jwks));

            // Sample token for testing
            String tokenMissingKid = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.IO_z9EOfF9e2noXDva33D8D2y9CS8Tf9lmB-w7cK5DNawk0r66RrjmY-jk6p8MIha126nniMRI7UZaeSSrfzwwuYVZCD35X7xRqhsRz5mpVkoluooXENIVvE4F8UVpY4yewgB6JXvFFplqaXWCSoQ8GxmwHXnHwEzS_W0df5VqTTBilRtgEEbwqBnANWWVkzm89ZX9d2ebkgow5dG9O-ra0SNhO_-66a4b78wvhiE_dw-99pnYbU-XLUwqVEu1Nk4sMW9jp7Y7d0f_WR9uOcB4SvojVJBTGc9cuCBjDI8g2zYyFs04exifYF7SQiofn1KodR5FDwOUiNwQfC-isnwa9fpKPOuGXEOJm6FBCK7cYrpP0JQrOv3IVeIh1Qix3N6-sF_TfUWgzBZlolvaf98msky8Yv0udyL0rkKMUUStV48R4TTChuAtpxoSu1Fr-sdMhWf76xGHvXjTUL_W4TZA8a3GyxLHawbcXez-Sk357djVol5xDIVAZU3ORpT4RuwPBKaoodEBSSWnFlP0l577Y7J8St0_UdGCyg8TMt2MBjaah1EJRDLOiXw_C0_Efa0rid6HbKlzwhlk6BzXQbnxdRoFBnh2KcsewQMMKfVtv3_nFxvgyiMTgdXY1lbmmVJ9rmEJlVyzCdfLoZavSrBwl5xkGipr657fmZ2Tbe6j0";

            // Calling the verifyToken() API with missing Kid token
            JWTClaimsSet missingKidClaims = connector.verifyToken(tokenMissingKid);
            assertNull(missingKidClaims);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testVerifyTokenInvalidKid() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/certs"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody(valid_jwks));

            // Sample token for testing
            String tokenInvalidKid = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6MTIzNH0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.lsBarFSfZNLtmTJyKfcnxqoU80QTx2PJHU0cl4esXIi64iD0C0h_B2TobIfkcUHIDNnkwcmZmik9dMxQaKU59qW6yUPgN9GcglD6RpgrJ4StHaOpfJvWY6TtsuSdcWlG33wc9RhcZ4PXV4pdYx5210e0PRgGAPelyq0MvdZa1IpZUnssQulMrk6OJNs3L-7ZfI5ZQFmJyWMzWcY7HQ9Nk2vfjaYtChfmKCSVdbyrDjtzsSDY9r5bYMI5pUCxXl30RSiEYv8fOBpYB_TJPxHyC0VaYtYVLIl4ZzUzG5VS4ragjJVXZZkX1tcDSpTakmgMbcvT1aqyJ9iVGJKSzfPovht-HxYlnmPysQPgeYY4LMywlRW8RJned9ZmKZ4F5Y8aTAUWdO4_ruBL0u8Z7J8-BTGkvNUgBUx9c7p_uy1dt7MTQkDW7d6sjP89xoNHnz4z4w7erAEuBEaPrknmYokpIdqf-esynBtW4NfIKyfl-_PGJnngPn7ziBNuTqxzq0sgTdovX8nxwal3LeWVtXx6HzN5CIRcR7BpDNC5jRhsyZ0U-p4D9Iic63KXMQLhkMx3D0vxzpzlT_zhkvw-kqXNsp6sIN3XqwlZjNTX6lptjV_OXnpVgJ8pb5svURGbwWcFIDJlgaYkHn7jLHnnaKz1aaHQezClod6_vbEPyjcfrsI";

            // Calling the verifyToken() API with invalid Kid token
            JWTClaimsSet invalidKidClaims = connector.verifyToken(tokenInvalidKid);
            assertNull(invalidKidClaims);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testVerifyTokenWrongKid() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/certs"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody(valid_jwks));

            // Sample token for testing
            String tokenWrongKid = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.O1YS3tK9moRRMCLkqWloLHIJ_F-NfpfQVFLo4mq3ui4HCgQLAK7bELjHl__igbzF6zTOLd3fwaoCKeVF1DDwBBoPhMXkAjZQMaNBFz8xZghQZfkSJLiMygyrkzSqgzLFMOgdBJaqcKxWT-cbO3JyAmG4sbxxFo8Lh5foVCmzF88aqfX0MPvUuiQG9aNVvJFqj2gW9hTSB3ljhxeRqZhTSQcpEkE67Xpr70rcdXaLbK-Ab4gw9YrW4aMHqR1aeLWg-s1OTosRpJGKLQ90BqWUJSx1QCmzRbAsEOfUeIK2CSwD0miUw6aSR2tVQcj0peZ2T-1xr8j0UFHRGCo5iLyAGBrHuNZ5c3fPL_xygwAkGKSkaO22d0NLRjauNeMKwT16BqZvZdN050AhfkMrwPa6AxQeJC__uBiIScKWK5ZSJJP3ba0_LHCsnnAOVZJMdD0uGdvzwXLhCTT44yeGVRbmw6KvLKjwLLotEsXY6M84rtMYnP16XeenidMH0-5YoaNOkFMR987qV-q2yXRemEHdH4KzmoBnMPtlvTSi1XW4jTM7bgziPEEK44mfZC_bkHKQnEWT51whYOPgcWYwYfjBm0oMoPKeCuIbHU6tMceGqZTsAzaWUSSlti_jVmQFR6Pp22w1d7BY-TGKDDG_wK4adj4n_KoGw5_HFYwoQfb6G_o";

            // Calling the verifyToken() API with wrong Kid token
            JWTClaimsSet wrongKidClaims = connector.verifyToken(tokenWrongKid);
            assertNull(wrongKidClaims);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }

    @Test
    public void testVerifyTokenInvalidJwks() {
        try {
            // Check if config is not null
            assertNotNull(cfg);

            // Check if connector is not null
            assertNotNull(connector);

            // Stubbing the response
            new MockServerClient("localhost", mockServer.getPort())
                                .when(HttpRequest.request().withPath("/certs"))
                                .respond(HttpResponse.response().withStatusCode(200)
                                .withHeader(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON)
                                .withBody("invalid_jwks"));

            // Sample token for testing
            String token = "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vYW1iZXItdGVzdDEtdXNlcjEucHJvamVjdC1hbWJlci1zbWFzLmNvbS9jZXJ0cyIsImtpZCI6IjFhMWEyZmU1ZmNmODkwMDllNGI5NmM0NWUwZGNlYjAwNWVhNjM1ZDhiYTJmNmVkOWNhZWVmNDRhZTIzNTk3MGRlY2M1ODYxNTRmZDlmNzQwZmIzYjcyY2ExNzZhYmI1OSIsInR5cCI6IkpXVCJ9.eyJzZ3hfbXJlbmNsYXZlIjoiMGE3NTZhNjUzYjlhOTJiMTNkYmQ2MjRhNWE1OTY4MTU4OTViMTMwODIwYzU1ZjNiMWI3Y2FmYjMwNDY5NjViYyIsInNneF9tcnNpZ25lciI6ImQ0MTJhNGYwN2VmODM4OTJhNTkxNWZiMmFiNTg0YmUzMWUxODZlNWE0Zjk1YWI1ZjY5NTBmZDRlYjg2OTRkN2IiLCJzZ3hfaXN2cHJvZGlkIjowLCJzZ3hfaXN2c3ZuIjowLCJzZ3hfcmVwb3J0X2RhdGEiOiI0MDE4OWU5YmRiZmRjMzA5OWEwZmE3MzVlYTEyNjkwZDI3MTEyZGUyOWRkYjgxNDFkMGNhYzMzMGNjM2FiYjE5MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneF9pc19kZWJ1Z2dhYmxlIjpmYWxzZSwic2d4X2NvbGxhdGVyYWwiOnsicWVpZGNlcnRoYXNoIjoiYjJjYTcxYjhlODQ5ZDVlNzk5NDUxYjRiZmU0MzE1OWEwZWU1NDgwMzJjZWNiMmMwZTQ3OWJmNmVlM2YzOWZkMSIsInFlaWRjcmxoYXNoIjoiZjQ1NGRjMWI5YmQ0Y2UzNmMwNDI0MWUyYzhjMzdhMmFlMjZiMDc3ZjJjNjZiOTE5ODQzMzY1MzE4YTU5MzMyYyIsInFlaWRoYXNoIjoiOTk1ZDljMmUyYmVhNzYyOWEzMmI2NWUxMmZmZjc1MzJkM2M2YTc2YWFmODEwYjgwZTg5Y2RjNjE4YTJmYTVjOSIsInF1b3RlaGFzaCI6IjViMzJhMWUyZmJjOTdlNTJjZWMxNDgxZTg5ZTNmMmFmYmFjM2QzMDZmMDE5ZTBiYTA3OTAwNGM0ZWM0MzRlNTMiLCJ0Y2JpbmZvY2VydGhhc2giOiJiMmNhNzFiOGU4NDlkNWU3OTk0NTFiNGJmZTQzMTU5YTBlZTU0ODAzMmNlY2IyYzBlNDc5YmY2ZWUzZjM5ZmQxIiwidGNiaW5mb2NybGhhc2giOiJmNDU0ZGMxYjliZDRjZTM2YzA0MjQxZTJjOGMzN2EyYWUyNmIwNzdmMmM2NmI5MTk4NDMzNjUzMThhNTkzMzJjIiwidGNiaW5mb2hhc2giOiI3M2UwYzhkNDU2ODdhMTU2YzUyNzQ1YmRlOWJkMDRkZGU2MTcxY2YzMjFmNDA3NDE5Zjg0MGU5YmJhYzY1ZTAxIn0sImF0dGVzdGVyX2hlbGRfZGF0YSI6IkFRQUJBQjBuQ1RNR3dXOXdtYy93M3dKSGwraDRnODJwMGQ4aWpGU3ZuT2JBdTBEb3pWdHR2d3NweEJRK1ZCdXMvNDhJQVBLQnhmV3owcjYybWNjeHJWMTRndFJaWU9RWHBXUnNPeUF3cHJoNndqWHlHdmtrbDNuVEQ0a0Y0L29WZ1NVaUlwZDZMcjFxUVd6a2N0bnhoWHpkWkxpVWp3TktPNHdIaFdoV1hVNEduSEl4SmQwVUtiQXIyM2lPNGRrSnkxY3dmNUZxd0pROVI2L3UrYW1vLzI0QkZDQUNLamZhbHNpaThXendtSE5UQ3hNeWtGOE0zWEwrTjJCSFdsVlNOa21VLzFSMlp2eFk2V3pQRUpsbGkwVHhySWJwaG1SdHpKM3E2cDdPSktPT2dXKzFCdkxtcUd4K05ZL2xqNjQvRXJOKzBZTVZLNGI3ZU05ZTFIVS9qQ0JRVlpvTnM1LzB1ZUgyOGpjZTJBSituWWUyUFc0R2hXallueklaYnZNTy9QKy9RR3NvRXJlZ2RsQ0c3ZWVvMUZxV1dtdUt0S3N3RStwRmFXbmQwMFJOZ29qMU81anJERmJMM0RpTVYwTGNVOTU5Q3BjV2lkN1VKYmlEUTM1OUgrVVhXZmpNdVJ3aE0yanJhaE9nczd2dFdtWUcrcnZEb0dTS29DQVBQNVhlNlRoU3lBPT0iLCJ2ZXJpZmllcl9ub25jZSI6eyJ2YWwiOiJWV2N3V1hCbmIwdGtiSEJ6YXpaVlZITTBPVGRGWVdoM01Wb3JkVmhHU0VaSlFXVXdTMXBpTXpOVlREa3dlVkl2WTJnemVsRkZkRGx5UVdZM1dYZHhia1ptWWtRMU9WZE5MMnB6VW5GeE1HVnBSRTlZVUVFOVBRPT0iLCJpYXQiOiJNakF5TXkweE1pMHlNU0F3TlRvek1Ub3dPQ0FyTURBd01DQlZWRU09Iiwic2lnbmF0dXJlIjoiVXAyZlluNUhwcTVpbXRmeXZmaWZEQisrbjV2bVVhcXZydU9kQVVtckg4OG5JRWorQU94NXk1ck5sV1BqWkNWcnk1emxpcjVOdUVNa0ZJc2FQV1pJM0t1L2ozQlZNM081dk0yOGJFR3lSYTA2V2phQWtLbktLZ3hrK3NaMG54RVluUGxuTGtweW81YjVKbXBEOFJOWm5iL2d2OXBYaWVxZU1OYThnTStkK2pwMk90M0VqUzR1VmhUYllSYmdxamJ6VlBhNEYrTVgrbnUzR01FSmdKdFlvZnFtZnRHa25mc1VHdW1BVE12Z21NdVV4Vk1lSFhQUUFGd1I4RWJrTE1odzlxOUVyVU1YdTB1Z045cTdsd2QrNUJKZ1pGR0lyeWNWZTRudzJGTVZITzI5SHdlMzM0czdQZ002SEpQR3NpaDN2S3dNVXM4SSt0MWVnUDRzcjJERWJPblZlS254VFdwV1IraUNqZks0NmJicE80VS9GYmN4c0k2SXAxK3ZvOVd5WDBCQVpFSmpuWHpMZGYydHZVRnJjcmJ1dFVYWW1xaWd5dks5SmtpcWltR29JQ3ptYjZuc25wSmJOeFlDK3RNY1FtUFk0ekgva2x2K3p3N0FVZnZvUXFpRG13UmtDYUgvcTRNdmNsKzBwUkwrUFUrbkdidkpHZHJHNk9LVSt2T2UifSwicG9saWN5X2lkc19tYXRjaGVkIjpbeyJpZCI6IjkxNDg4ZTEyLWYzOWUtNGYzZS04NDM1LWQ0OWM4MTNkZWNiNSIsInZlcnNpb24iOiJ2MSJ9XSwicG9saWN5X2lkc191bm1hdGNoZWQiOlt7ImlkIjoiN2YzODE0MzAtNTFmOC00N2IwLWE2ZTAtMzkzZWYxODM3YWYzIiwidmVyc2lvbiI6InYxIn1dLCJwb2xpY3lfZGVmaW5lZF9jbGFpbXMiOnt9LCJhdHRlc3Rlcl90Y2Jfc3RhdHVzIjoiT3V0T2ZEYXRlIiwiYXR0ZXN0ZXJfdGNiX2RhdGUiOiIyMDIxLTExLTEwVDAwOjAwOjAwWiIsImF0dGVzdGVyX2Fkdmlzb3J5X2lkcyI6WyJJTlRFTC1TQS0wMDU4NiIsIklOVEVMLVNBLTAwNjE0IiwiSU5URUwtU0EtMDA2MTUiLCJJTlRFTC1TQS0wMDY1NyIsIklOVEVMLVNBLTAwNzMwIiwiSU5URUwtU0EtMDA3MzgiLCJJTlRFTC1TQS0wMDc2NyIsIklOVEVMLVNBLTAwODI4IiwiSU5URUwtU0EtMDA4MzciXSwiYXR0ZXN0ZXJfdHlwZSI6IlNHWCIsInZlcmlmaWVyX2luc3RhbmNlX2lkcyI6WyI5YTRlMjQ2OS03NGIwLTQ4OWQtOTczYi1jMTU0NzllODNhZDEiLCIxNDc2ZGE3NC0yOTdkLTRiYzEtYjdkMi0xMGUyNTk1MGJhN2MiLCJjMTQyMTcyNi1lYjViLTRmYWEtYmEzOC0zNWZiMGM3ZDk1NDYiLCI4NGNmZGUzYi0wM2Q1LTQ4ZWYtYTIxMC0xZWY5ZTU2MTE2YTMiXSwiZGJnc3RhdCI6ImRpc2FibGVkIiwiZWF0X3Byb2ZpbGUiOiJodHRwczovL2FtYmVyLXRlc3QxLXVzZXIxLnByb2plY3QtYW1iZXItc21hcy5jb20vZWF0X3Byb2ZpbGUuaHRtbCIsImludHVzZSI6ImdlbmVyaWMiLCJ2ZXIiOiIxLjAuMCIsImV4cCI6MTcwMzEzNjk2OCwianRpIjoiOGViNDg2NmMtNTc0Ni00YzdkLWJlNzktM2UwNDlkYzBhNzQ5IiwiaWF0IjoxNzAzMTM2NjY4LCJpc3MiOiJJbnRlbCBUcnVzdCBBdXRob3JpdHkiLCJuYmYiOjE3MDMxMzY2Njh9.tf9oqTHuJKA8LPcqqHndNgLlc7GxCkNx3TerIbHU9OpzoU6pEnbcDo8655p3X1LUQQ1yb-fi5IqRZYO8-KCnsCCAuID8ff4bGwBKCExN0xP656tLbh3w7dyh7miIuJz9JBVvDn41CPKcRotuzoMjMIQzQQiIBaU4bRBDEWHaMEHoGM8qr0KXqz0YP3kKT1f4fL7FAKHjSyxNqqw3_bxFaeFvEBcTCnRBgEUAIxd79Yq0LndDenxAkfEaXOmtCSd_t9-vs7zzBKvbZ_wurVnXQbLaLM8DEMzykZmTB5yIERbrfFzkR-61Uv3cibWGdR8Be0shc3pgvgcXtSKaPsLdNI7pf17S0fCEMwCKtIBStHcDVbyz8fvDHnW8lUsHXHWY4hrXJfTfH0DnoISJCXpXoLLr43D8wAd4PLdUOzaQ0tMYRtCnsWW5lzvpReHzD13GjgCb_2T1KutxR6a9QidIbAAi8i1EUwmvjlloQyPwV0neC5Gczetd79zHHNRrDjpW";

            // Calling the verifyToken() API with valid token
            JWTClaimsSet claims = connector.verifyToken(token);
            assertNull(claims);
        } catch (Exception e) {
            // Ignore exceptions as they are expected in failure conditions
        }
    }
}