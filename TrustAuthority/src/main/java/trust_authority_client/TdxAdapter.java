import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

public class TdxAdapter implements EvidenceAdapter  {

    private byte[] uData;
    private EventLogParser evLogParser;

    private TdxAdapter(byte[] uData, EventLogParser evLogParser) {
        this.uData = uData;
        this.evLogParser = evLogParser;
    }

    public static TdxAdapter newEvidenceAdapter(byte[] uData, EventLogParser evLogParser) {
        return new TdxAdapter(uData, evLogParser);
    }

    public Evidence collectEvidence(byte[] nonce) {

        // Convert the byte array to tdx_report_data_t structure
        TdxAttestLibrary.tdx_report_data_t tdxReportData = new TdxAttestLibrary.tdx_report_data_t();
        System.arraycopy(reportData, 0, tdxReportData.d, 0, reportData.length);

        // Create tdx_uuid_t structure (assuming it has some fields)
        TdxAttestLibrary.tdx_uuid_t selectedAttKeyId = new TdxAttestLibrary.tdx_uuid_t();

        // Call tdx_att_get_quote
        IntByReference quoteSize = new IntByReference();
        PointerByReference quoteBuf = new PointerByReference();
        int ret = TdxAttestLibrary.INSTANCE.tdx_att_get_quote(tdxReportData, null, 0, selectedAttKeyId, quoteBuf, quoteSize, 0);
        if (ret != 0) {
            throw new RuntimeException("tdx_att_get_quote returned error code " + ret);
        }

        // Extract the quote
        Pointer quotePointer = quoteBuf.getValue();
        byte[] quote = quotePointer.getByteArray(0, quoteSize.getValue());

        // Free the quote buffer
        TdxAttestLibrary.INSTANCE.tdx_att_free_quote(quotePointer);

        return new Evidence(1, quote, userData, eventLog);
    }
}