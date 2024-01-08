/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

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
 * TdxSampleApp class, a sample application demonstrating TDX Quote collection/verification
 * from TDX enabled platform
 */
public class TdxSampleApp {

    // Logger object
    private static final Logger logger = LogManager.getLogger(TdxSampleApp.class);

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
            logger.debug("TDX quote Base64 Encoded: " + base64Quote);

            // Convert TDX UserData from bytes to Base64
            String base64UserData = Base64.encode(tdxEvidence.getUserData()).toString();

            // Print the TDX UserData in Base64 format
            logger.debug("TDX user data Base64 Encoded: " + base64UserData);

            // Initialize Sample App variables
            String[] trust_authority_variables = init();
            String trustauthority_base_url = trust_authority_variables[0];
            String trustauthority_api_url = trust_authority_variables[1];
            String trustauthority_api_key = trust_authority_variables[2];
            String trustauthority_request_id = trust_authority_variables[3];
            String trustauthority_policy_id = trust_authority_variables[4];

            // Initialize RetryConfig based on system env set
            int retryMax = 2; // Default: 2 retries
            long retryWaitTime = 2; // Default: 2 seconds
            if (trust_authority_variables[5] != null) {
                retryMax = Integer.parseInt(trust_authority_variables[5]);
            }
            if (trust_authority_variables[6] != null) {
                retryWaitTime = Long.parseLong(trust_authority_variables[6]);
            }
            // RetryConfig with retryWaitMin and retryMax set
            RetryConfig retry_config  = new RetryConfig(retryWaitTime, 10, retryMax);

            // Create Policy IDs from trustauthority_policy_id string
            List<UUID> policyIDs = parseUUIDString(trustauthority_policy_id);

            // Initialize config required for connector using trustauthority_base_url, trustauthority_api_url, trustauthority_api_key and retry_config
            Config cfg = new Config(trustauthority_base_url, trustauthority_api_url, trustauthority_api_key, retry_config);
    
            // Initializing connector with the config
            TrustAuthorityConnector connector = new TrustAuthorityConnector(cfg);

            // Verifying attestation for TDX platform
            AttestArgs attestArgs = new AttestArgs(tdxAdapter, policyIDs, trustauthority_request_id);
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
            logger.info("LOG_LEVEL environment variable not set. Using default log level: INFO");
            logLevel = "info";
        }

        // Set of strings to compare against
        String[] logLevels = {"info", "trace", "debug", "warn", "error", "fatal"};

        // Check if the targetString is not equal to any of the logLevels
        boolean notEqual = Arrays.stream(logLevels).noneMatch(logLevel.toLowerCase()::equals);
        if (notEqual) {
            logger.info("Invalid LOG_LEVEL set. Using default log level: INFO");
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
        String[] initializer = new String[7];

        // Fetch proxy settings from environment
        String httpsHost = System.getenv("HTTPS_PROXY_HOST");
        if (httpsHost != null) {
            // Setting proxy settings host
            System.setProperty("https.proxyHost", httpsHost);
        }
        String httpsPort = System.getenv("HTTPS_PROXY_PORT");
        if (httpsPort != null) {
            // Setting proxy settings port
            System.setProperty("https.proxyPort", httpsPort);
        }
        logger.debug("HTTPS_PROXY_HOST: " + httpsHost + ", HTTPS_PROXY_PORT: " + httpsPort);

        // Fetch TRUSTAUTHORITY_BASE_URL, TRUSTAUTHORITY_API_URL and TRUSTAUTHORITY_API_KEY from environment
        String trustauthority_base_url = System.getenv("TRUSTAUTHORITY_BASE_URL");
        if (trustauthority_base_url == null) {
            logger.error("TRUSTAUTHORITY_BASE_URL is not set.");
            // Exit if env variable not set
            System.exit(1);
        }
        String trustauthority_api_url = System.getenv("TRUSTAUTHORITY_API_URL");
        if (trustauthority_api_url == null) {
            logger.error("TRUSTAUTHORITY_API_URL is not set.");
            // Exit if env variable not set
            System.exit(1);
        }
        String trustauthority_api_key = System.getenv("TRUSTAUTHORITY_API_KEY");
        if (trustauthority_api_key == null) {
            logger.error("TRUSTAUTHORITY_API_KEY is not set.");
            // Exit if env variable not set
            System.exit(1);
        }
        String trustauthority_request_id = System.getenv("TRUSTAUTHORITY_REQUEST_ID");
        if (trustauthority_request_id != null) {
            initializer[3] = trustauthority_request_id;
        }
        String trustauthority_policy_id = System.getenv("TRUSTAUTHORITY_POLICY_ID");
        if (trustauthority_policy_id != null) {
            initializer[4] = trustauthority_policy_id;
        }
        logger.debug("TRUSTAUTHORITY_BASE_URL: " + trustauthority_base_url + ", TRUSTAUTHORITY_API_URL: " + trustauthority_api_url);
        
        String retry_max = System.getenv("RETRY_MAX");
        if (retry_max != null) {
            initializer[5] = retry_max;
        }
        String retry_wait_time = System.getenv("RETRY_WAIT_TIME");
        if (retry_wait_time != null) {
            initializer[6] = retry_wait_time;
        }

        // Initialize trust authority variables
        initializer[0] = trustauthority_base_url;
        initializer[1] = trustauthority_api_url;
        initializer[2] = trustauthority_api_key;

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