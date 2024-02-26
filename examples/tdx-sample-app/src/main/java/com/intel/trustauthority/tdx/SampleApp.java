/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.tdxsampleapp;

// Java Collections Imports
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

// Nimbus JOSE + JWT Library Import
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.util.Base64;

// Third-party Library Imports
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

// trust_authority_client imports
import com.intel.trustauthority.connector.*;
import com.intel.trustauthority.tdx.TdxAdapter;

/**
 * SampleApp class, a sample application demonstrating TDX Quote collection/verification
 * from TDX enabled platform
 */
public class SampleApp {

    // Logger object
    private static final Logger logger = LogManager.getLogger(SampleApp.class);

    public static void main(String[] args) {
        try {
            // Set log level
            setLogLevel();

            // For testing
            byte[] bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

            // Create the TdxAdapter object
            TdxAdapter tdxAdapter = new TdxAdapter(bytes);

            // Fetch the Tdx Quote
            Evidence tdxEvidence = tdxAdapter.collectEvidence(bytes);

            // Convert TDX quote from bytes to Base64
            String base64Quote = Base64.encode(tdxEvidence.getQuote()).toString();

            // Print the TDX quote in Base64 format
            logger.info("TDX quote Base64 Encoded: " + base64Quote);

            // Convert TDX UserData from bytes to Base64
            String base64UserData = Base64.encode(tdxEvidence.getUserData()).toString();

            // Print the TDX UserData in Base64 format
            logger.info("TDX user data Base64 Encoded: " + base64UserData);

            // Initialize Sample App variables
            String[] trustAuthorityVariables = init();
            if (trustAuthorityVariables.length == 0) {
                logger.error("Initialization failed, exiting...");
                System.exit(1);
            }
            String trustAuthorityBaseUrl = trustAuthorityVariables[0];
            String trustAuthorityApiUrl = trustAuthorityVariables[1];
            String trustAuthorityApiKey = trustAuthorityVariables[2];
            String trustAuthorityRequestID = trustAuthorityVariables[3];
            String trustAuthorityPolicyID = trustAuthorityVariables[4];
            String tokenSigningAlg = trustAuthorityVariables[7];

            // Initialize RetryConfig based on system env set
            int retryMax = 2; // Default: 2 retries
            long retryWaitTime = 2; // Default: 2 seconds
            if (trustAuthorityVariables[5] != null) {
                retryMax = Integer.parseInt(trustAuthorityVariables[5]);
            }
            if (trustAuthorityVariables[6] != null) {
                retryWaitTime = Long.parseLong(trustAuthorityVariables[6]);
            }
            // RetryConfig with retryWaitMin and retryMax set
            RetryConfig retryConfig  = new RetryConfig(retryWaitTime, 10, retryMax);

            // Create Policy IDs from trustAuthorityPolicyID string
            List<UUID> policyIDs = parseUUIDString(trustAuthorityPolicyID);

            // Initialize config required for connector using trustAuthorityBaseUrl, trustAuthorityApiUrl, trustAuthorityApiKey and retryConfig
            Config cfg = new Config(trustAuthorityBaseUrl, trustAuthorityApiUrl, trustAuthorityApiKey, retryConfig);
    
            // Initializing connector with the config
            TrustAuthorityConnector connector = new TrustAuthorityConnector(cfg);

            // Verifying attestation for TDX platform
            AttestArgs attestArgs = new AttestArgs(tdxAdapter, policyIDs, trustAuthorityRequestID, tokenSigningAlg);
            AttestResponse response = connector.attest(attestArgs);

            // Print the Request ID of token fetched from Trust Authority
            if (response.getHeaders().containsKey("request-id")) {
                logger.info("Request ID: " + response.getHeaders().get("request-id"));
            }

            // Print the Trace ID of token fetched from Trust Authority
            logger.info("Trace ID: " + response.getHeaders().get("trace-id"));

            // Print the Token fetched from Trust Authority
            logger.info("Token fetched from Trust Authority: " + response.getToken());

            // Verify the received token
            JWTClaimsSet claims = connector.verifyToken(response.getToken());

            logger.info("Successfully verified token.");
        } catch (Exception e) {
            logger.error("Exception: " + e);
            System.exit(1);
        }
    }

    /**
     * Helper function to set log level for all loggers
     *
     */
    private static void setLogLevel() {
        // Fetch the log level from an environment variable
        String logLevel = System.getenv("LOG_LEVEL");
        if (logLevel == null) {
            logger.debug("LOG_LEVEL environment variable not set. Using default log level: INFO");
            logLevel = "info";
        }

        // Set of strings to compare against
        String[] logLevels = {"info", "trace", "debug", "warn", "error", "fatal"};

        // Check if the targetString is not equal to any of the logLevels
        boolean notEqual = Arrays.stream(logLevels).noneMatch(logLevel.toLowerCase()::equals);
        if (notEqual) {
            logger.debug("Invalid LOG_LEVEL set. Using default log level: INFO");
            logLevel = "info";
        }

        // Set log level based on environment variable
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configurator.setRootLevel(org.apache.logging.log4j.Level.valueOf(logLevel));
        ctx.updateLoggers();
    }

    /**
     * Helper function to initialize the Sample App
     * 
     * @return String[] object containing the trust authority variables
     */
    private static String[] init() {
        String[] initializer = new String[8];

        // Fetch proxy settings from environment
        String httpsHost = System.getenv(Constants.ENV_HTTPS_PROXY_HOST);
        if (httpsHost != null) {
            // Setting proxy settings host
            System.setProperty("https.proxyHost", httpsHost);
        }
        String httpsPort = System.getenv(Constants.ENV_HTTPS_PROXY_PORT);
        if (httpsPort != null) {
            // Setting proxy settings port
            System.setProperty("https.proxyPort", httpsPort);
        }
        logger.debug("HTTPS_PROXY_HOST: " + httpsHost + ", HTTPS_PROXY_PORT: " + httpsPort);

        // Fetch TRUSTAUTHORITY_BASE_URL, TRUSTAUTHORITY_API_URL and TRUSTAUTHORITY_API_KEY from environment
        String trustAuthorityBaseUrl = System.getenv(Constants.ENV_TRUSTAUTHORITY_BASE_URL);
        if (trustAuthorityBaseUrl == null) {
            logger.error("TRUSTAUTHORITY_BASE_URL is not set.");
            // Exit if env variable not set
            System.exit(1);
        }
        String trustAuthorityApiUrl = System.getenv(Constants.ENV_TRUSTAUTHORITY_API_URL);
        if (trustAuthorityApiUrl == null) {
            logger.error("TRUSTAUTHORITY_API_URL is not set.");
            // Exit if env variable not set
            System.exit(1);
        }
        String trustAuthorityApiKey = System.getenv(Constants.ENV_TRUSTAUTHORITY_API_KEY);
        if (trustAuthorityApiKey == null) {
            logger.error("TRUSTAUTHORITY_API_KEY is not set.");
            // Exit if env variable not set
            System.exit(1);
        }
        String trustAuthorityRequestID = System.getenv(Constants.ENV_TRUSTAUTHORITY_REQUEST_ID);
        if (trustAuthorityRequestID != null) {
            initializer[3] = trustAuthorityRequestID;
        }
        String trustAuthorityPolicyID = System.getenv(Constants.ENV_TRUSTAUTHORITY_POLICY_ID);
        if (trustAuthorityPolicyID != null) {
            initializer[4] = trustAuthorityPolicyID;
        }
        String tokenSigningAlg = System.getenv(Constants.ENV_TOKEN_SIGNING_ALG);
        if (tokenSigningAlg != null) {
            initializer[7] = tokenSigningAlg;
        }
        logger.debug("TRUSTAUTHORITY_BASE_URL: " + trustAuthorityBaseUrl + ", TRUSTAUTHORITY_API_URL: " + trustAuthorityApiUrl);
        
        String retry_max = System.getenv(Constants.ENV_RETRY_MAX);
        if (retry_max != null) {
            initializer[5] = retry_max;
        }
        String retry_wait_time = System.getenv(Constants.ENV_RETRY_WAIT_TIME);
        if (retry_wait_time != null) {
            initializer[6] = retry_wait_time;
        }

        // Initialize trust authority variables
        initializer[0] = trustAuthorityBaseUrl;
        initializer[1] = trustAuthorityApiUrl;
        initializer[2] = trustAuthorityApiKey;

        return initializer;
    }

    /**
     * Helper function to parse the UUID String
     *
     * @param uuidString Comma separated list of UUIDs
     *
     * @return List<UUID> object containing Policy IDs
     */
    private static List<UUID> parseUUIDString(String uuidString) throws Exception {
        // Return null when policyID is not passed
        if (uuidString == null) {
            return null;
        }
        List<UUID> uuidList = new ArrayList<>();

        // Split the comma-separated string into an array of strings
        String[] uuidArray = uuidString.split(",");

        // Iterate through the array and parse each string into a UUID
        for (String uuidStr : uuidArray) {
            try {
                UUID uuid = UUID.fromString(uuidStr.trim());
                uuidList.add(uuid);
            } catch (IllegalArgumentException e) {
                // Handle the case where the string is not a valid UUID
                throw new Exception("Invalid UUID format: " + uuidStr);
            }
        }

        return uuidList;
    }
}