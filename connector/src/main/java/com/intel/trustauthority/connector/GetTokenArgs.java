package com.intel.trustauthority.connector;

// Java Standard Library Imports
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * GetTokenArgs class for holding the request object to be sent to GetToken() API
 */
public class GetTokenArgs {

    private VerifierNonce nonce;
    private Evidence evidence;
    private List<UUID> policyIds;
    private String requestId;

    /**
     * Constructs a new GetTokenArgs object with the specified nonce, evidence, policyIds and requestId.
     *
     * @param nonce          VerifierNonce provided by the user.
     * @param evidence       Evidence object provided by user.
     * @param policyIds      policyIds provided by the user.
     * @param requestId      requestId provided by user.
     */
    public GetTokenArgs(VerifierNonce nonce, Evidence evidence, List<UUID> policyIds, String requestId) {
        this.nonce = nonce;
        this.evidence = evidence;
        this.policyIds = policyIds;
        this.requestId = requestId;
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
}