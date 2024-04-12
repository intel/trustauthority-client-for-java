/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

// Java Standard Library Imports
import java.util.List;
import java.util.UUID;

// Third-party Library Imports
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * TokenRequest class for holding Token details to be sent to attest() API
 */
public class TokenRequest {

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

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("policy_must_match")
    private boolean policyMustMatch;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("token_signing_alg")
    private String tokenSigningAlg;

    /**
     * Constructs a new TokenRequest object with the specified quote, verifierNonce, runtimeData, policyIds and eventLog.
     *
     * @param quote             quote provided by the user.
     * @param verifierNonce     verifierNonce object provided by user.
     * @param runtimeData       runtimeData provided by user.
     * @param policyIds         policyIds provided by user.
     * @param eventLog          eventLog provided by user.
     * @param tokenSigningAlg   tokenSigningAlg provided by user.
     * @param policyMustMatch   policyMustMatch provided by user.
     */
    public TokenRequest(byte[] quote, VerifierNonce verifierNonce, byte[] runtimeData, List<UUID> policyIds, byte[] eventLog, String tokenSigningAlg, boolean policyMustMatch) {
        this.quote = quote;
        this.verifierNonce = verifierNonce;
        this.runtimeData = runtimeData;
        this.policyIds = policyIds;
        this.eventLog = eventLog;
        this.tokenSigningAlg = tokenSigningAlg;
        this.policyMustMatch = policyMustMatch;
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

    /**
     * getter function for tokenSigningAlg
     */
    public String getTokenSigningAlg() {
        return tokenSigningAlg;
    }

    /**
     * setter function for tokenSigningAlg
     */
    public void setTokenSigningAlg(String tokenSigningAlg) {
        this.tokenSigningAlg = tokenSigningAlg;
    }
 
    /**
     * getter function for policyMustMatch
     */
    public boolean getPolicyMustMatch() {
        return policyMustMatch;
    }

    /**
     * setter function for policyMustMatch
     */
    public void setPolicyMustMatch(boolean policyMustMatch) {
        this.policyMustMatch = policyMustMatch;
    }
}