package trust_authority_client;

// Java Collections Imports
import java.util.List;
import java.util.Arrays;

// JNA (Java Native Access) Library Imports
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Memory;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.TypeMapper;
import com.sun.jna.Structure.FieldOrder;
import com.sun.jna.Function;

/**
 * SgxAdapter class for SGX Quote collection from SGX enabled platform
 * This class implements the base EvidenceAdapter interface.
 */
public class SgxAdapter implements EvidenceAdapter {

    private long EID;
    private byte[] uData;
    private Function reportFunction;

    /**
     * Constructs a new SgxAdapter object with the specified eid, udata and reportFunction.
     *
     * @param eid               eid specified by user.
     * @param udata             udata provided by the user.
     * @param reportFunction    Function pointer to enclave function provided by user.
     */
    public SgxAdapter(long eid, byte[] udata, Function reportFunction) {
        this.EID = eid;
        this.uData = udata;
        this.reportFunction = reportFunction;
    }

    /**
     * Constructs a new SgxAdapter object with the specified eid, udata and reportFunction.
     *
     * @param eid               eid specified by user.
     * @param udata             udata provided by the user.
     * @param reportFunction    Function pointer to enclave function provided by user.
     * @return SgxAdapter object
     */
    public SgxAdapter newEvidenceAdapter(long eid, byte[] udata, Function reportFunction) {
        return new SgxAdapter(eid, udata, reportFunction);
    }

    /**
     * SgxLibrary is an interface that extends JNA's Library interface.
     * It defines the methods that will be mapped to the native library functions.
     */
    public interface SgxLibrary extends Library {
        int sgx_qe_get_target_info(sgx_target_info_t targetInfo);
        int sgx_qe_get_quote_size(IntByReference quote_size);
        int sgx_qe_get_quote(sgx_report_t p_report, int quote_size, Pointer quote_buffer);
    }

    // private variable to hold an instance of the native library sgx_dcap_ql interface
    private SgxLibrary sgxLibrary = (SgxLibrary) Native.load("sgx_dcap_ql", SgxLibrary.class);

    /**
     * Java object representing a C struct sgx_config_svn_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_config_svn_t extends Structure {
        public short value;

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("value");
        }
    }

    /**
     * Java object representing a C struct sgx_misc_select_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_misc_select_t extends Structure {
        public int value;

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("value");
        }
    }

    /**
     * Java object representing a C struct sgx_config_id_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_config_id_t extends Structure {
        public byte[] id = new byte[64];

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("id");
        }
    }

    /**
     * Java object representing a C struct sgx_target_info_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public class sgx_target_info_t extends Structure {

        // Variables are mapped to their respective C struct variables
        public sgx_measurement_t mr_enclave;
        public sgx_attributes_t attributes;
        public byte[] reserved1 = new byte[2];
        public sgx_config_svn_t config_svn;
        public sgx_misc_select_t misc_select;
        public byte[] reserved2 = new byte[8];
        public sgx_config_id_t config_id;
        public byte[] reserved3 = new byte[384];
    
        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("mr_enclave", "attributes", "reserved1", "config_svn", "misc_select", "reserved2", "config_id", "reserved3");
        }
    }

    /**
     * Java object representing a C struct sgx_cpu_svn_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_cpu_svn_t extends Structure {
        public byte[] svn = new byte[16];

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("svn");
        }
    }

    /**
     * Java object representing a C struct sgx_attributes_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_attributes_t extends Structure {
        public long flags;
        public long xfrm;

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("flags", "xfrm");
        }
    }

    /**
     * Java object representing a C struct sgx_measurement_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_measurement_t extends Structure {
        public byte[] m = new byte[32];

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("m");
        }
    }

    /**
     * Java object representing a C struct sgx_report_data_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_report_data_t extends Structure {
        public byte[] d = new byte[64];

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("d");
        }
    }

    /**
     * Java object representing a C struct sgx_isvext_prod_id_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_isvext_prod_id_t extends Structure {
        public byte[] id = new byte[16];

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("id");
        }
    }

    /**
     * Java object representing a C struct sgx_report_body_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_report_body_t extends Structure {

        // Variables are mapped to their respective C struct variables
        public sgx_cpu_svn_t cpu_svn;
        public int misc_select;
        public byte[] reserved1 = new byte[12];
        public sgx_isvext_prod_id_t isv_ext_prod_id;
        public sgx_attributes_t attributes;
        public sgx_measurement_t mr_enclave;
        public byte[] reserved2 = new byte[32];
        public sgx_measurement_t mr_signer;
        public byte[] reserved3 = new byte[32];
        public byte[] config_id = new byte[64];
        public short isv_prod_id;
        public short isv_svn;
        public short config_svn;
        public byte[] reserved4 = new byte[42];
        public byte[] isv_family_id = new byte[16];
        public sgx_report_data_t report_data;

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("cpu_svn", "misc_select", "reserved1", "isv_ext_prod_id", "attributes", "mr_enclave", "reserved2", "mr_signer", "reserved3", "config_id",
                                 "isv_prod_id", "isv_svn", "config_svn", "reserved4", "isv_family_id", "report_data");
        }
    }

    /**
     * Java object representing a C struct sgx_key_id_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_key_id_t extends Structure {
        public byte[] id = new byte[32];

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("id");
        }
    }

    /**
     * Java object representing a C struct sgx_mac_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_mac_t extends Structure {
        public byte[] mac = new byte[16];

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("mac");
        }
    }

    /**
     * Java object representing a C struct sgx_report_t.
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class sgx_report_t extends Structure {
        public sgx_report_body_t body;
        public sgx_key_id_t key_id;
        public sgx_mac_t mac;

        /**
         * Specifies the order of fields in the native structure.
         *
         * @return A list of field names in the order they appear in the native structure.
         */
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("body", "key_id", "mac");
        }
    }

    /**
     * collectEvidence is used to get SGX quote using DCAP Quote Generation library
     *
     * @param nonce nonce value passed by user
     * @return Evidence object containing the fetched SGX quote
     */
    public Evidence collectEvidence(byte[] nonce) {

        // Report return value
        IntByReference retVal = new IntByReference(0);

        // Define structs required to be passed to fetch the report
        sgx_target_info_t qe3_target = new sgx_target_info_t();
        sgx_report_t p_report = new sgx_report_t();

        // Fetch target info by calling the respective sgx sdk function
        int qe3_ret = sgxLibrary.sgx_qe_get_target_info(qe3_target);
        if (qe3_ret != 0) {
            throw new RuntimeException("sgx_qe_get_target_info return error code " + Integer.toHexString(qe3_ret));
        }

        // Create Nonce object based on nonce input provided by user
        Pointer noncePtr = new Memory(nonce.length);
        noncePtr.write(0, nonce, 0, nonce.length);

        // To fetch size of the nonce input
        int nonce_size = nonce.length;

        // Call the passed function pointer with the required parameters
        int status = reportFunction.invokeInt(new Object[]{this.EID, retVal, qe3_target, noncePtr, nonce_size, p_report});
        if (status != 0) {
            throw new RuntimeException("Report callback returned error code " + Integer.toHexString(status));
        }
        if (retVal.getValue() != 0) {
            throw new RuntimeException("Report retval returned " + Integer.toHexString(retVal.getValue()));
        }

        // Quote size C native object
        IntByReference quoteSize = new IntByReference();

        // Fetch the quote size by calling the respective sgx sdk function
        qe3_ret = sgxLibrary.sgx_qe_get_quote_size(quoteSize);
        if (qe3_ret != 0) {
            throw new RuntimeException("sgx_qe_get_quote_size return error code " + Integer.toHexString(qe3_ret));
        }

        // Create a quote buffer object with the required quote size
        Pointer quoteBuffer = new Memory(quoteSize.getValue());

        // Fetch the sgx quote by calling the respective sgx sdk function
        qe3_ret = sgxLibrary.sgx_qe_get_quote(p_report, quoteSize.getValue(), quoteBuffer);
        if (qe3_ret != 0) {
            throw new RuntimeException("sgx_qe_get_quote return error code " + Integer.toHexString(qe3_ret));
        }

        // Convert C native quote buffer to bytes
        byte[] result = quoteBuffer.getByteArray(0, quoteSize.getValue());

        // Construct and return Evidence object attached with the fetched SGX Quote
        return new Evidence(0, result, this.uData, null);
    }
}