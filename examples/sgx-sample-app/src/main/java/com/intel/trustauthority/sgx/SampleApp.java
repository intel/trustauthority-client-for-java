/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.sgxsampleapp;

// Java Collections Imports
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.security.SecureRandom;

// JNA (Java Native Access) Library Imports
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Memory;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.TypeMapper;
import com.sun.jna.Structure.FieldOrder;
import com.sun.jna.Function;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.ByteByReference;

// Nimbus JOSE + JWT Library Import
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;

// Third-party Library Imports
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

// trust_authority_client imports
import com.intel.trustauthority.connector.*;
import com.intel.trustauthority.sgx.SgxAdapter;

/**
 * EnclaveLibrary interface for creating enclave report
 * This interface extends the base Library class.
 */
interface EnclaveLibrary extends Library {

    // private variable to hold an instance of the native library interface
    EnclaveLibrary INSTANCE = (EnclaveLibrary) Native.loadLibrary("./enclave/libutils.so", EnclaveLibrary.class);

    // get_public_key() function to fetch the public key to be passed to SGXAdapter
    int get_public_key(long eid, PointerByReference pp_key, IntByReference p_key_size);

    // free_public_key() function to free the public key
    void free_public_key(Pointer key);

    // Initialize the function pointer for enclave_create_report() function from enclave .so file
    Function myFunctionPointer = Function.getFunction("./enclave/libutils.so", "enclave_create_report");
}

/**
 * SgxUrtsLibrary interface for creating the sgx enclave
 * This interface extends the base Library class.
 */
interface SgxUrtsLibrary extends Library {

    // private variable to hold an instance of the native library sgx_urts interface
    SgxUrtsLibrary INSTANCE = (SgxUrtsLibrary) Native.loadLibrary("sgx_urts", SgxUrtsLibrary.class);

    // Initialize the C native function sgx_create_enclave()
    int sgx_create_enclave(String enclaveFilePath, int debug, byte[] launchToken, IntByReference updated, long[] id, int[] misc_attr);

    // Initialize the C native function sgx_destroy_enclave()
    int sgx_destroy_enclave(long eid);
}

/**
 * SampleApp class, a sample application demonstrating SGX Quote collection/verification
 * from SGX enabled platform
 */
public class SampleApp {

    // Logger object
    private static final Logger logger = LogManager.getLogger(SampleApp.class);

    public static void main(String[] args) {
        try {
            // Set log level
            setLogLevel();

            // Path of enclave .so file
            String enclavePath = "./enclave/enclave.signed.so";

            // Initialize SGX enclave related variables
            long[] enclaveId = new long[1];
            IntByReference updated = new IntByReference(0);
            byte[] launchToken = new byte[1024];
            int[] miscAttr = new int[1];

            // Create SGX enclave
            int result = SgxUrtsLibrary.INSTANCE.sgx_create_enclave(enclavePath, 0, launchToken, updated, enclaveId, miscAttr);
            if (result != 0) {
                logger.error("Failed to create enclave: " + Integer.toHexString(result));
                System.exit(1);
            }
            logger.info("Enclave created successfully. Enclave ID: " + enclaveId[0]);

            // Initialize get_public_key() API variables
            PointerByReference pp_key = new PointerByReference();
            IntByReference p_key_size = new IntByReference();

            // Call get_public_key() and fetch the public key to be passed to SgxAdapter
            int ret = EnclaveLibrary.INSTANCE.get_public_key(enclaveId[0], pp_key, p_key_size);
            if (ret != 0) {
                logger.error("Error: Failed to retrieve key from sgx enclave");
                System.exit(1);
            }

            // Fetch the output values of get_public_key() call to convert it to Java variables
            Pointer keyPointer = pp_key.getValue();
            int keySize = p_key_size.getValue();

            // Convert the C bytes to Java bytes
            byte[] keyBytes = keyPointer.getByteArray(0, keySize);
            // Free the C bytes
            EnclaveLibrary.INSTANCE.free_public_key(keyPointer);

            // Create the SgxAdapter object
            SgxAdapter sgxAdapter = new SgxAdapter(enclaveId[0], keyBytes, EnclaveLibrary.myFunctionPointer);

            // Fetch the Sgx Quote
            Evidence sgxEvidence = sgxAdapter.collectEvidence(keyBytes);

            // Convert SGX quote from bytes to Base64
            String base64Quote = Base64.encode(sgxEvidence.getQuote()).toString();

            // Print the SGX quote in Base64 format
            logger.info("SGX quote Base64 Encoded: " + base64Quote);

            // Convert SGX UserData from bytes to Base64
            String base64UserData = Base64.encode(sgxEvidence.getUserData()).toString();

            // Print the SGX UserData in Base64 format
            logger.info("SGX user data Base64 Encoded: " + base64UserData);

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
            boolean policyMustMatch = false;
            if (trustAuthorityVariables[8] != null) {
                policyMustMatch = trustAuthorityVariables[8].equalsIgnoreCase("true");
            }
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

            // Verifying attestation for SGX platform
            AttestArgs attestArgs = new AttestArgs(sgxAdapter, policyIDs, trustAuthorityRequestID, tokenSigningAlg, policyMustMatch);
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
            logger.error("Token verification failed with exception: " + e);
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
        String[] initializer = new String[9];

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
        if (trustAuthorityBaseUrl == null || trustAuthorityBaseUrl.trim().length() == 0) {
            logger.error("TRUSTAUTHORITY_BASE_URL is not set.");
            // Exit if env variable not set
            System.exit(1);
        }
        String trustAuthorityApiUrl = System.getenv(Constants.ENV_TRUSTAUTHORITY_API_URL);
        if (trustAuthorityApiUrl == null || trustAuthorityApiUrl.trim().length() == 0) {
            logger.error("TRUSTAUTHORITY_API_URL is not set.");
            // Exit if env variable not set
            System.exit(1);
        }
        String trustAuthorityApiKey = System.getenv(Constants.ENV_TRUSTAUTHORITY_API_KEY);
        if (trustAuthorityApiKey == null || trustAuthorityApiKey.trim().length() == 0) {
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

        logger.debug("TRUSTAUTHORITY_BASE_URL: " + trustAuthorityBaseUrl + ", TRUSTAUTHORITY_API_URL: " + trustAuthorityApiUrl);
        
        String retry_max = System.getenv(Constants.ENV_RETRY_MAX);
        if (retry_max != null) {
            initializer[5] = retry_max;
        }
        String retry_wait_time = System.getenv(Constants.ENV_RETRY_WAIT_TIME);
        if (retry_wait_time != null) {
            initializer[6] = retry_wait_time;
        }
        String tokenSigningAlg = System.getenv(Constants.ENV_TOKEN_SIGNING_ALG);
        if (tokenSigningAlg != null) {
            initializer[7] = tokenSigningAlg;
        }
        String policyMustMatch = System.getenv(Constants.ENV_POLICY_MUST_MATCH);
        if (policyMustMatch != null) {
            initializer[8] = policyMustMatch;
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