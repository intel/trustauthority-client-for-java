/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.trustauthority.tdx;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.Arrays;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.trustauthority.connector.*;
import com.intel.trustauthority.connector.Evidence.EvidenceType;

public class AzureTdxAdapter implements EvidenceAdapter {

    private byte[] userData;
    /**
     * Constructs a new TdxAdapter object with the specified user data.
     *
     * @param userData user data provided by the user.
     */
    public AzureTdxAdapter(byte[] userData) {
        this.userData = userData;
    }

    public static BufferedWriter stdout;

     /**
     * collectEvidence is used to get TDX quote using Azure Quote Generation service
     *
     * @param nonce nonce value passed by user
     * @return Evidence object containing the fetched TDX quote
     */
    public Evidence collectEvidence(byte[] nonce) throws Exception {

        // Initialize reportData with a default size of 64 bytes
        byte[] reportData = new byte[64];

        // If nonce or userData is not null, compute SHA-512 digest
        if (nonce != null || this.userData != null) {
            MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
            sha512Digest.update(nonce); // Update digest with nonce
            sha512Digest.update(this.userData); // Update digest with userData
            reportData = sha512Digest.digest(); // Compute the final digest
        }

        // Get the updated report from TPM using the computed reportData
        byte[] tpmReport = getTdReport(reportData);

        // Extract the first 1024 bytes of the TPM report to TD Report
        byte[] tdReport = new byte[1024];
        System.arraycopy(tpmReport, 32, tdReport, 0, 1024);

        // Extract the runtime data size from the TPM report
        ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOfRange(tpmReport, 1232, 1232+4));
        bb.order(ByteOrder.LITTLE_ENDIAN);
        int runtimeDataSize = bb.getInt();
        
        // Extract the runtime data from the TPM report
        byte[] runtimeData = new byte[runtimeDataSize];
        System.arraycopy(tpmReport, 1236, runtimeData, 0, runtimeDataSize);
        System.out.write(runtimeData);

        // Get the TD quote using the extracted TD Report
        byte[] quote = getTdQuote(tdReport);

        // Return the Evidence object containing the quote, userData, and runtimeData
        return new Evidence(EvidenceType.AZ_TDX, quote, this.userData, null, runtimeData);
    }

    private byte[] getTdReport(byte[] reportData) throws IOException {
        // Initialize a byte array to store the TPM report
        byte[] tpmReport = new byte[2600];
        try {
            // Use ProcessBuilder to execute the command to read the TPM NV public area 0x1400002
            ProcessBuilder pb = new ProcessBuilder("tpm2_nvreadpublic", "0x01400002");
            Process pr = pb.start();
            int exitCode = pr.waitFor();
            if (exitCode != 0) {
                // If the read command fails, define a new NV index 0x1400002
                pb = new ProcessBuilder("tpm2_nvdefine", "-C", "o", "0x01400002", "-s", "64");
                pr = pb.start();
                exitCode = pr.waitFor();
                if (exitCode != 0) {
                    // Throw an exception if the define command fails
                    throw new IOException("TPM nvdefine command failed with exit code " + exitCode);
                }
            }
    
            // Prepare to write the report data to the TPM NV index 0x1400002
            pb = new ProcessBuilder("tpm2_nvwrite", "-C", "o", "0x1400002", "-i", "-");
            pr = pb.start();
            try (OutputStream os = pr.getOutputStream()) {
                // Write the report data to the TPM NV index
                os.write(reportData);
            }
            exitCode = pr.waitFor();
            if (exitCode != 0) {
                // Throw an exception if the write command fails
                throw new IOException("TPM nvwrite command failed with exit code " + exitCode);
            }
            // Sleep for 3 seconds to ensure the write operation is completed
            Thread.sleep(3000);
    
            // Execute the command to read the updated TPM report from TPM NV index 0x01400001
            pb = new ProcessBuilder("tpm2_nvread", "-C", "o", "0x01400001");
            pr = pb.start();
            exitCode = pr.waitFor();
            if (exitCode != 0) {
                // Throw an exception if the read command fails
                throw new IOException("TPM nvread command failed with exit code " + exitCode);
            }
            // Read the TPM report into the byte array
            int bytesRead = pr.getInputStream().read(tpmReport);
            if (bytesRead == -1 ){
                throw new IOException("Failed to read TPM report");                
            }
        } catch (IOException | InterruptedException exc) {
            // Catch and rethrow any IO or interruption exceptions
            throw new IOException("Error occurred", exc);
        }
        // Return the TPM report
        return tpmReport;
    }

    private byte[] getTdQuote(byte[] reportData) throws Exception {
        HttpURLConnection connection = null;
        try {
            // Request for quote from Azure server
            String url = "http://169.254.169.254/acc/tdquote";
            // Create the QuoteRequest object
            QuoteRequest quoteRequest = new QuoteRequest(new String(Base64.encodeBase64(reportData)));
             // Convert the QuoteRequest to a JSON -> String to send as request to server
            ObjectMapper objectMapper = new ObjectMapper();
            // Serialize the QuoteRequest object to a JSON string
            String quoteRequestJson = objectMapper.writeValueAsString(quoteRequest);

            // Create a URL object based on the url string
            URL requestUrl = new URL(url);

            // Create a new TrustAuthorityConnector object
            // Config in this instance has been set to null except for retry config since there is no need for others in this context
            Config config = new Config(null, null, null, new RetryConfig(0, 0, 1));
            TrustAuthorityConnector trustAuthorityConnector = new TrustAuthorityConnector(config);

            // Create a map of request properties to set the headers for the request
            Map<String, String> requestProperties = new HashMap<String, String>() {{
                put(Constants.HEADER_ACCEPT, Constants.MIME_APPLICATION_JSON);
                put(Constants.HEADER_CONTENT_TYPE, Constants.MIME_APPLICATION_JSON);
            }};
            
            // Open a connection to the server with the request URL, request method, request properties, and request body
            connection = trustAuthorityConnector.openConnectionWithRetries(requestUrl, "POST", requestProperties, quoteRequestJson);
            
            // read the response if connection OK
            String response = trustAuthorityConnector.readResponseBody(connection, HttpURLConnection.HTTP_OK);

            // Map the fetched response JSON to GetTokenResponse object
            ObjectMapper mapper = new ObjectMapper();
            QuoteResponse quoteResponse = mapper.readValue(response.toString(), QuoteResponse.class);
            
            return Base64.decodeBase64(quoteResponse.getQuote());

        } catch (Exception e) {
            throw new Exception("getTdQuote() failed: " + e);
        } finally {
            // Close the connection in the finally block to ensure it is always closed
            if (connection != null) {
                connection.disconnect();
            }
        }    
    }
}