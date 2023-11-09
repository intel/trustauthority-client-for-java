package trust_authority_client;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Memory;
import com.sun.jna.ptr.IntByReference;

public class SgxAdapter implements EvidenceAdapter {

    private long EID;
    private byte[] uData;
    private Object reportFunction;

    public SgxAdapter(long eid, byte[] udata, Object reportFunction) {
        this.EID = eid;
        this.uData = udata;
        this.reportFunction = reportFunction;
    }

    public SgxAdapter newEvidenceAdapter(long eid, byte[] udata, Object reportFunction) {
        return new SgxAdapter(eid, udata, reportFunction);
    }

    // Define JNA interface for the SGX library
    public interface SgxLibrary extends Library {
        int sgx_qe_get_target_info(sgx_target_info_t targetInfo);
        int get_report(report_fx fx, long eid, IntByReference retVal, sgx_target_info_t p_qe3_target, Pointer nonce, int nonce_size, sgx_report_t p_report);
        int sgx_qe_get_quote_size(IntByReference quote_size);
        int sgx_qe_get_quote(sgx_report_t p_report, int quote_size, Pointer quote_buffer);
    }

    // Define JNA data structures to match the C structs
    public static class sgx_target_info_t extends Structure {
        // Define structure fields to match the C struct
    }

    public static class sgx_report_t extends Structure {
        // Define structure fields to match the C struct
    }

    // Define the callback function type
    public interface report_fx extends SgxLibrary {
        int callback(long eid, IntByReference retVal, sgx_target_info_t p_qe3_target, Pointer nonce, int nonce_size, sgx_report_t p_report);
    }

    private SgxLibrary sgxLibrary = (SgxLibrary) Native.load("sgx_dcap_ql", SgxLibrary.class);

    public Evidence collectEvidence(byte[] nonce) {
        IntByReference retVal = new IntByReference(0);
        sgx_target_info_t qe3_target = new sgx_target_info_t();
        sgx_report_t p_report = new sgx_report_t();

        int qe3_ret = sgxLibrary.sgx_qe_get_target_info(qe3_target);
        if (qe3_ret != 0) {
            throw new RuntimeException("sgx_qe_get_target_info return error code " + Integer.toHexString(qe3_ret));
        }

        Pointer noncePtr = new Memory(nonce.length);
        noncePtr.write(0, nonce, 0, nonce.length);

        int status = sgxLibrary.get_report(new report_fx() {
            @Override
            public int callback(long eid, IntByReference retVal, sgx_target_info_t p_qe3_target, Pointer nonce, int nonce_size, sgx_report_t p_report) {
                // Define the callback logic here
                // This method should set the retVal, p_qe3_target, and p_report parameters accordingly.
                // You can implement your logic based on the provided parameters.
                // Make sure to handle any exceptions or errors properly.
                return 0; // Replace with actual return value
            }
        }, this.EID, retVal, qe3_target, noncePtr, nonce.length, p_report);

        if (status != 0) {
            throw new RuntimeException("Report callback returned error code " + Integer.toHexString(status));
        }

        if (retVal.getValue() != 0) {
            throw new RuntimeException("Report retval returned " + Integer.toHexString(retVal.getValue()));
        }

        IntByReference quoteSize = new IntByReference();
        qe3_ret = sgxLibrary.sgx_qe_get_quote_size(quoteSize);
        if (qe3_ret != 0) {
            throw new RuntimeException("sgx_qe_get_quote_size return error code " + Integer.toHexString(qe3_ret));
        }

        byte[] quoteBuffer = new byte[quoteSize.getValue()];
        qe3_ret = sgxLibrary.sgx_qe_get_quote(p_report, quoteSize.getValue(), new Memory(quoteBuffer));
        if (qe3_ret != 0) {
            throw new RuntimeException("sgx_qe_get_quote return error code " + Integer.toHexString(qe3_ret));
        }

        return new Evidence(0, quoteBuffer, this.uData, null);
    }

    public static void main(String[] args) {
        // For testing with random junk value
        byte[] bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        SgxAdapter sgx_adapter = new SgxAdapter(1, bytes, null);
    }
}