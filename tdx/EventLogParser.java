package trust_authority_client;

// Java NIO Imports
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

// Java Collections Imports
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

/**
 * Please ignore the contents of this file
 * 
 * The classes and functions defined in this file are for future optimizations
 * for TDX if required and are not being used in TdxAdapter at the moment.
 */


class EventLogParserConstants {

    private static final String uefiEventLogFile = "";

    private static final int CcelFileLength = 56;
    private static final String CcelSignature = "CCEL";
    private static final String AcpiTablePath = "/sys/firmware/acpi/tables/";
    private static final String AcpiTableDataPath = "/sys/firmware/acpi/tables/data/";
    private static final String CcelPath = AcpiTablePath + CcelSignature;
    private static final String CcelDataPath = AcpiTableDataPath + CcelSignature;

    private static final int Uint8Size = 1;
    private static final int Uint16Size = 2;
    private static final int Uint32Size = 4;
    private static final int Uint64Size = 8;
    private static final int ExtDataElementOffset = 92;

    private static final int UefiBaseOffset = 48;
    private static final int UefiSizeOffset = 40;

    private static final int Event80000001 = 0x80000001;
    private static final int Event80000002 = 0x80000002;
    private static final int Event80000007 = 0x80000007;
    private static final int Event8000000A = 0x8000000A;
    private static final int Event8000000B = 0x8000000B;
    private static final int Event8000000C = 0x8000000C;
    private static final int Event80000010 = 0x80000010;
    private static final int Event800000E0 = 0x800000E0;
    private static final int Event00000007 = 0x00000007;
    private static final int Event00000001 = 0x00000001;
    private static final int Event00000003 = 0x00000003;
    private static final int Event00000005 = 0x00000005;
    private static final int Event0000000A = 0x0000000A;
    private static final int Event0000000C = 0x0000000C;
    private static final int Event00000012 = 0x00000012;
    private static final int Event00000010 = 0x00000010;
    private static final int Event00000011 = 0x00000011;
    private static final int EV_IPL = 0x0000000D;

    private static final String SHA256 = "SHA256";
    private static final String SHA384 = "SHA384";
    private static final String SHA512 = "SHA512";
    private static final String SM3_256 = "SM3_256";

    private static final int AlgSHA256 = 0xb;
    private static final int AlgSHA384 = 0xc;
    private static final int AlgSHA512 = 0xd;
    private static final int AlgSM3_256 = 0x12;
    private static final String NullUnicodePoint = "\u0000";

    private static final Map<Integer, String> eventNameList = new HashMap<>();
    static {
        eventNameList.put(0x00000000, "EV_PREBOOT_CERT");
        eventNameList.put(0x00000001, "EV_POST_CODE");
        eventNameList.put(0x00000002, "EV_UNUSED");
        eventNameList.put(0x00000003, "EV_NO_ACTION");
        eventNameList.put(0x00000004, "EV_SEPARATOR");
        eventNameList.put(0x00000005, "EV_ACTION");
        eventNameList.put(0x00000006, "EV_EVENT_TAG");
        eventNameList.put(0x00000007, "EV_S_CRTM_CONTENTS");
        eventNameList.put(0x00000008, "EV_S_CRTM_VERSION");
        eventNameList.put(0x00000009, "EV_CPU_MICROCODE");
        eventNameList.put(0x0000000A, "EV_PLATFORM_CONFIG_FLAGS");
        eventNameList.put(0x0000000B, "EV_TABLE_OF_DEVICES");
        eventNameList.put(0x0000000C, "EV_COMPACT_HASH");
        eventNameList.put(0x0000000D, "EV_IPL");
        eventNameList.put(0x0000000E, "EV_IPL_PARTITION_DATA");
        eventNameList.put(0x0000000F, "EV_NONHOST_CODE");
        eventNameList.put(0x00000010, "EV_NONHOST_CONFIG");
        eventNameList.put(0x00000011, "EV_NONHOST_INFO");
        eventNameList.put(0x00000012, "EV_OMIT_BOOT_DEVICE_EVENTS");
        eventNameList.put(0x80000000, "EV_EFI_EVENT_BASE");
        eventNameList.put(0x80000001, "EV_EFI_VARIABLE_DRIVER_CONFIG");
        eventNameList.put(0x80000002, "EV_EFI_VARIABLE_BOOT");
        eventNameList.put(0x80000003, "EV_EFI_BOOT_SERVICES_APPLICATION");
        eventNameList.put(0x80000004, "EV_EFI_BOOT_SERVICES_DRIVER");
        eventNameList.put(0x80000005, "EV_EFI_RUNTIME_SERVICES_DRIVER");
        eventNameList.put(0x80000006, "EV_EFI_GPT_EVENT");
        eventNameList.put(0x80000007, "EV_EFI_ACTION");
        eventNameList.put(0x80000008, "EV_EFI_PLATFORM_FIRMWARE_BLOB");
        eventNameList.put(0x80000009, "EV_EFI_HANDOFF_TABLES");
        eventNameList.put(0x8000000A, "EV_EFI_PLATFORM_FIRMWARE_BLOB2");
        eventNameList.put(0x8000000B, "EV_EFI_HANDOFF_TABLES2");
        eventNameList.put(0x8000000C, "EV_EFI_VARIABLE_BOOT2");
        eventNameList.put(0x80000010, "EV_EFI_HCRTM_EVENT");
        eventNameList.put(0x800000E0, "EV_EFI_VARIABLE_AUTHORITY");
        eventNameList.put(0x800000E1, "EV_EFI_SPDM_FIRMWARE_BLOB");
        eventNameList.put(0x800000E2, "EV_EFI_SPDM_FIRMWARE_CONFIG");
    }
}

class RtmrEventLog {
    private RtmrData rtmr;
    private List<RtmrEvent> rtmrEvents;

    public RtmrData getRtmr() {
        return rtmr;
    }

    public void setRtmr(RtmrData rtmr) {
        this.rtmr = rtmr;
    }

    public List<RtmrEvent> getRtmrEvents() {
        return rtmrEvents;
    }

    public void setRtmrEvents(List<RtmrEvent> rtmrEvents) {
        this.rtmrEvents = rtmrEvents;
    }
}

class RtmrData {
    private long index;
    private String bank;

    public long getIndex() {
        return index;
    }

    public void setIndex(long index) {
        this.index = index;
    }

    public String getBank() {
        return bank;
    }

    public void setBank(String bank) {
        this.bank = bank;
    }
}

class RtmrEvent {
    private String typeID;
    private String typeName;
    private List<String> tags;
    private String measurement;

    public String getTypeID() {
        return typeID;
    }

    public void setTypeID(String typeID) {
        this.typeID = typeID;
    }

    public String getTypeName() {
        return typeName;
    }

    public void setTypeName(String typeName) {
        this.typeName = typeName;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    public String getMeasurement() {
        return measurement;
    }

    public void setMeasurement(String measurement) {
        this.measurement = measurement;
    }
}

class tcgPcrEventV2 {
    private long pcrIndex;
    private long eventType;
    private tpmlDigestValue digest;
    private long eventSize;
    private byte[] event;

    public long getPcrIndex() {
        return pcrIndex;
    }

    public void setPcrIndex(long pcrIndex) {
        this.pcrIndex = pcrIndex;
    }

    public long getEventType() {
        return eventType;
    }

    public void setEventType(long eventType) {
        this.eventType = eventType;
    }

    public tpmlDigestValue getDigest() {
        return digest;
    }

    public void setDigest(tpmlDigestValue digest) {
        this.digest = digest;
    }

    public long getEventSize() {
        return eventSize;
    }

    public void setEventSize(long eventSize) {
        this.eventSize = eventSize;
    }

    public byte[] getEvent() {
        return event;
    }

    public void setEvent(byte[] event) {
        this.event = event;
    }
}

class tpmlDigestValue {
    private long count;
    private List<tpmtHA> digests;

    public long getCount() {
        return count;
    }

    public void setCount(long count) {
        this.count = count;
    }

    public List<tpmtHA> getDigests() {
        return digests;
    }

    public void setDigests(List<tpmtHA> digests) {
        this.digests = digests;
    }
}

class tpmtHA {
    private int hashAlg;
    private byte[] digestData;

    public int getHashAlg() {
        return hashAlg;
    }

    public void setHashAlg(int hashAlg) {
        this.hashAlg = hashAlg;
    }

    public byte[] getDigestData() {
        return digestData;
    }

    public void setDigestData(byte[] digestData) {
        this.digestData = digestData;
    }
}

class tcgPcrEventV1 {
    private long pcrIndex;
    private long eventType;
    private byte[] digest;
    private long eventSize;
    private byte[] event;

    public long getPcrIndex() {
        return pcrIndex;
    }

    public void setPcrIndex(long pcrIndex) {
        this.pcrIndex = pcrIndex;
    }

    public long getEventType() {
        return eventType;
    }

    public void setEventType(long eventType) {
        this.eventType = eventType;
    }

    public byte[] getDigest() {
        return digest;
    }

    public void setDigest(byte[] digest) {
        this.digest = digest;
    }

    public long getEventSize() {
        return eventSize;
    }

    public void setEventSize(long eventSize) {
        this.eventSize = eventSize;
    }

    public byte[] getEvent() {
        return event;
    }

    public void setEvent(byte[] event) {
        this.event = event;
    }
}

class uefiGUID {
    private long data1;
    private int data2;
    private int data3;
    private byte[] data4;

    public long getData1() {
        return data1;
    }

    public void setData1(long data1) {
        this.data1 = data1;
    }

    public int getData2() {
        return data2;
    }

    public void setData2(int data2) {
        this.data2 = data2;
    }

    public int getData3() {
        return data3;
    }

    public void setData3(int data3) {
        this.data3 = data3;
    }

    public byte[] getData4() {
        return data4;
    }

    public void setData4(byte[] data4) {
        this.data4 = data4;
    }
}

class uefiVariableData {
    private uefiGUID variableName;
    private long unicodeNameLength;
    private long variableDataLength;
    private char[] unicodeName;
    private byte[] variableData;

    public uefiGUID getVariableName() {
        return variableName;
    }

    public void setVariableName(uefiGUID variableName) {
        this.variableName = variableName;
    }

    public long getUnicodeNameLength() {
        return unicodeNameLength;
    }

    public void setUnicodeNameLength(long unicodeNameLength) {
        this.unicodeNameLength = unicodeNameLength;
    }

    public long getVariableDataLength() {
        return variableDataLength;
    }

    public void setVariableDataLength(long variableDataLength) {
        this.variableDataLength = variableDataLength;
    }

    public char[] getUnicodeName() {
        return unicodeName;
    }

    public void setUnicodeName(char[] unicodeName) {
        this.unicodeName = unicodeName;
    }

    public byte[] getVariableData() {
        return variableData;
    }

    public void setVariableData(byte[] variableData) {
        this.variableData = variableData;
    }
}

// This interface has to be implemented by File or UEFI EventLogParser
public interface EventLogParser {
    List<RtmrEventLog> getEventLogs() throws Exception;
}

// Class to hold all functions independent functions cannot be defined without a class
class EventLogParserClass {

    public ByteBuffer parseTcgSpecEvent(ByteBuffer buf, int size) throws Exception {
        TcgPcrEventV1 tcgPcrEvent = new TcgPcrEventV1();
        tcgPcrEvent.pcrIndex = buf.getInt();
        tcgPcrEvent.eventType = buf.getInt();
        tcgPcrEvent.digest = new byte[32];
        buf.get(tcgPcrEvent.digest);
        tcgPcrEvent.eventSize = buf.getInt();

        tcgPcrEvent.event = new byte[tcgPcrEvent.eventSize];
        buf.get(tcgPcrEvent.event);

        return buf.slice().position(tcgPcrEvent.eventSize + 32);
    }

    public List<RtmrEventLog> createEventLog(ByteBuffer buf, int size, List<RtmrEventLog> rtmrEventLogs) throws Exception {
        TcgPcrEventV2 tcgPcrEvent2 = new TcgPcrEventV2();
        TpmlDigestValue tpmlDigestValues = new TpmlDigestValue();

        // Implement the logic for creating event logs here

        return rtmrEventLogs;
    }

    public String removeUnicode(String input) {
        StringBuilder cleanInput = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isBmpCodePoint(c)) {
                cleanInput.append(c);
            }
        }
        return cleanInput.toString();
    }

    public HashData getHashData(int offset, int digestSize, ByteBuffer buf) {
        byte[] digest = new byte[digestSize];
        buf.get(digest);
        String digestStr = bytesToHex(digest);
        return new HashData(digestStr, offset + digestSize, buf);
    }

    public List<String> getEventTag(int eventType, byte[] eventData, int eventSize, int pcrIndex) throws Exception {
        // Implement the logic for getting event tags here
        return new ArrayList<>();
    }

    public String bytesToHex(byte[] bytes) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte aByte : bytes) {
            hexStringBuilder.append(String.format("%02x", aByte));
        }
        return hexStringBuilder.toString();
    }

    private static class TcgPcrEventV1 {
        int pcrIndex;
        int eventType;
        byte[] digest;
        int eventSize;
        byte[] event;
    }

    private static class TcgPcrEventV2 {
        int pcrIndex;
        int eventType;
        TpmlDigestValue tpmlDigestValues;
        int offset;
    }

    private static class TpmlDigestValue {
        int count;
    }

    private static class HashData {
        String digestStr;
        int offset;
        ByteBuffer buf;

        HashData(String digestStr, int offset, ByteBuffer buf) {
            this.digestStr = digestStr;
            this.offset = offset;
            this.buf = buf;
        }
    }
}