package trust_authority_client;

// public class SgxAdapter implements EvidenceAdapter {}
public class SgxAdapter {

    private long EID;
    private byte[] uData;
    private Object reportFunction;

    public SgxAdapter(long eid, byte[] udata, Object reportFunction) {
        this.EID = eid;
        this.uData = udata;
        this.reportFunction = reportFunction;
    }

    public static SgxAdapter newEvidenceAdapter(long eid, byte[] udata, Object reportFunction) {
        return new SgxAdapter(eid, udata, reportFunction);
    }

    public Evidence collectEvidence(byte[] nonce) {
        long retVal = 0;
        // sgx_target_info_t qe3_target = new sgx_target_info_t();
        // sgx_report_t p_report = new sgx_report_t();

        // long qe3_ret = sgx_qe_get_target_info(qe3_target);
        // if (qe3_ret != 0) {
        //     return null; // Handle the error case
        // }

        // long status = get_report((report_fx) reportFunction, EID, retVal, qe3_target, nonce, nonce.length, p_report);

        // if (status != 0) {
        //     return null; // Handle the error case
        // }

        // if (retVal != 0) {
        //     return null; // Handle the error case
        // }

        // long quote_size = 0;
        // qe3_ret = sgx_qe_get_quote_size(quote_size);
        // if (qe3_ret != 0) {
        //     return null; // Handle the error case
        // }

        // byte[] quote_buffer = new byte[(int) quote_size];

        // qe3_ret = sgx_qe_get_quote(p_report, (int) quote_size, quote_buffer);
        // if (qe3_ret != 0) {
        //     return null; // Handle the error case
        // }

        // return new Evidence(0, quote_buffer, uData);

        return new Evidence(0, null, null, null);
    }
}