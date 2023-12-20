package com.intel.trustauthority.connector;

/**
 * VerifierNonce class for holding processed nonce from GetNonce() API
 */
public class VerifierNonce {

    private byte[] val;
    private byte[] iat;
    private byte[] signature;

    /**
     * Default constructor (required for Jackson Object Mapping)
     */
    public VerifierNonce() {
    }

    /**
     * Constructs a new VerifierNonce object with the specified val, iat and signature.
     *
     * @param val           val provided by the user.
     * @param iat           iat provided by user.
     * @param signature     signature provided by user.
     */
    public VerifierNonce(byte[] val, byte[] iat, byte[] signature) {
        this.val = val;
        this.iat = iat;
        this.signature = signature;
    }

    /**
     * getter function for val
     */
    public byte[] getVal() {
        return val;
    }

    /**
     * setter function for val
     */
    public void setVal(byte[] val) {
        this.val = val;
    }

    /**
     * getter function for iat
     */
    public byte[] getIat() {
        return iat;
    }

    /**
     * setter function for iat
     */
    public void setIat(byte[] iat) {
        this.iat = iat;
    }

    /**
     * getter function for signature
     */
    public byte[] getSignature() {
        return signature;
    }

    /**
     * setter function for signature
     */
    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}