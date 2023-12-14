package trust_authority_client;

/**
 * Evidence class for holding the SGX/TDX Quote fetched from SGX/TDX enabled platform
 */
public class Evidence {

    private long type;
    private byte[] evidence;
    private byte[] userData;
    private byte[] eventLog;
    private String error;

    /**
     * Constructs a new Evidence object with the specified type, evidence, userData and eventLog.
     *
     * @param type           type provided by the user.
     * @param evidence       evidence provided by user.
     * @param userData       userData by the user.
     * @param eventLog       eventLog provided by user.
     */
    public Evidence(long type, byte[] evidence, byte[] userData, byte[] eventLog) {
        this.type = type;
        this.evidence = evidence;
        this.userData = userData;
        this.eventLog = eventLog;
    }

    /**
     * getter function for type
     */
    public long getType() {
        return type;
    }

    /**
     * getter function for evidence
     */
    public byte[] getEvidence() {
        return evidence;
    }

    /**
     * getter function for userData
     */
    public byte[] getUserData() {
        return userData;
    }

    /**
     * getter function for eventLog
     */
    public byte[] getEventLog() {
        return eventLog;
    }

    /**
     * getter function for error
     */
    public String getError() {
        return this.error;
    }

    /**
     * setter function for error
     */
    public void setError(String error) {
        this.error = error;
    }
}