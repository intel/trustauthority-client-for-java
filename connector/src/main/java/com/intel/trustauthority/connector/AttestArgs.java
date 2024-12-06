/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;

/**
 * AttestArgs class for holding the request object to be sent to attest() API
 */
public class AttestArgs {

    private EvidenceAdapter adapter;
    private List<UUID> policyIds;
    private String requestId;
    private String tokenSigningAlg;
    private boolean policyMustMatch;

    /**
     * Constructs a new AttestArgs object with the specified adapter, policyIds and requestId.
     *
     * @param adapter           adapter provided by the user.
     * @param policyIds         policyIds provided by user.
     * @param requestId         requestId provided by user.
     * @param tokenSigningAlg   tokenSigningAlg provided by user.
     * @param policyMustMatch   policyMustMatch provided by user.
     */
    public AttestArgs(EvidenceAdapter adapter, List<UUID> policyIds, String requestId, String tokenSigningAlg, boolean policyMustMatch) {
        this.adapter = adapter;
        this.policyIds = policyIds;
        this.requestId = requestId;
        this.tokenSigningAlg = tokenSigningAlg;
        this.policyMustMatch = policyMustMatch;
    }

    /**
     * getter function for adapter
     */
    public EvidenceAdapter getAdapter() {
        return adapter;
    }

    /**
     * getter function for policyIds
     */
    public List<UUID> getPolicyIds() {
        return policyIds;
    }

    /**
     * getter function for requestId
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * setter function for adapter
     */
    public void setAdapter(EvidenceAdapter adapter) {
        this.adapter = adapter;
    }

    /**
     * setter function for policyIds
     */
    public void setPolicyIds(List<UUID> policyIds) {
        this.policyIds = policyIds;
    }

    /**
     * setter function for requestId
     */
    public void setRequestId(String requestId) {
        this.requestId = requestId;
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

    /**
     * validator function for arguments
     */
    public void validate() throws JOSEException{
        if (!("".equals(this.tokenSigningAlg) || null == this.tokenSigningAlg)){
            //Skip validation of alogrithms if tokenSigningAlg is empty or null
            if (!(this.tokenSigningAlg.equals(Constants.ALGO_RS256) || this.tokenSigningAlg.equals(Constants.ALGO_PS384))) {
                throw new JOSEException("Unsupported token signing algorithm: " + this.tokenSigningAlg);
            }                
        }                
    }
}