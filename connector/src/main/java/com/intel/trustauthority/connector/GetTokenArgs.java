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
 * GetTokenArgs class for holding the request object to be sent to GetToken() API
 */
public class GetTokenArgs {

    private VerifierNonce nonce;
    private Evidence evidence;
    private List<UUID> policyIds;
    private String requestId;
    private String tokenSigningAlg;
    private boolean policyMustMatch;

    /**
     * Constructs a new GetTokenArgs object with the specified nonce, evidence, policyIds and requestId.
     *
     * @param nonce             VerifierNonce provided by the user.
     * @param evidence          Evidence object provided by user.
     * @param policyIds         policyIds provided by the user.
     * @param requestId         requestId provided by user.
     * @param tokenSigningAlg   tokenSigningAlg provided by user.
     * @param policyMustMatch   policyMustMatch provided by user.
     */
    public GetTokenArgs(VerifierNonce nonce, Evidence evidence, List<UUID> policyIds, String requestId, String tokenSigningAlg, boolean policyMustMatch) {
        this.nonce = nonce;
        this.evidence = evidence;
        this.policyIds = policyIds;
        this.requestId = requestId;
        this.tokenSigningAlg = tokenSigningAlg;
        this.policyMustMatch = policyMustMatch;
    }

    /**
     * getter function for nonce
     */
    public VerifierNonce getNonce() {
        return nonce;
    }

    /**
     * getter function for evidence
     */
    public Evidence getEvidence() {
        return evidence;
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
     * getter function for tokenSigningAlg
     */
    public String getTokenSigningAlg() {
        return tokenSigningAlg;
    }
    
    /**
     * getter function for policyMustMatch
     */
    public boolean getPolicyMustMatch() {
        return policyMustMatch;
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