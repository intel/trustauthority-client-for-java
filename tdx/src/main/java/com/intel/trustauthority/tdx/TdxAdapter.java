/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.tdx;

// Java Standard Library Imports
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

// JNA (Java Native Access) Library Imports
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Library;
import com.sun.jna.Structure;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

// Jackson JSON Library Import
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

// Trust Authority Connector import
import com.intel.trustauthority.connector.*;

/**
 * TdxAdapter class for TDX Quote collection from TDX enabled platform
 * This class implements the base EvidenceAdapter interface.
 */
public class TdxAdapter implements EvidenceAdapter {

    private byte[] uData;

    /**
     * Constructs a new TdxAdapter object with the specified user data.
     *
     * @param uData user data provided by the user.
     */
    public TdxAdapter(byte[] uData) {
        this.uData = uData;
    }

    /**
     * TdxAttestLibrary is an interface that extends JNA's Library interface.
     * It defines the methods that will be mapped to the native library functions.
     */
    public interface TdxAttestLibrary extends Library {
        // private variable to hold an instance of the native library tdx_attest interface
        TdxAttestLibrary INSTANCE = (TdxAttestLibrary) Native.load("tdx_attest", TdxAttestLibrary.class);
    
        int tdx_att_get_quote(Pointer tdxReportData, Pointer attReport, int attReportSize,
                              TdxUuid selectedAttKeyId, PointerByReference quoteBuf, IntByReference quoteSize, int flags);
    
        int tdx_att_free_quote(Pointer quoteBuf);
    }

    /**
     * Java object representing C struct TdxUuid : tdx_attest.h
     * Extends JNA's Structure class for seamless mapping to native memory.
     */
    public static class TdxUuid extends Structure {
        public byte[] d = new byte[16];

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
     * collectEvidence is used to get TDX quote using DCAP Quote Generation service
     *
     * @param nonce nonce value passed by user
     * @return Evidence object containing the fetched TDX quote
     */
    public Evidence collectEvidence(byte[] nonce) throws NoSuchAlgorithmException {

        MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
        sha512Digest.update(nonce);
        sha512Digest.update(this.uData);
        byte[] reportData = sha512Digest.digest();

        // cReportData holds the reportdata provided as input from attested app
        Memory cReportData = new Memory(reportData.length);
        cReportData.write(0, reportData, 0, reportData.length);

        // Passing this as null as it's not required
        TdxUuid selectedAttKeyId = new TdxUuid();

        // Initialize TDX Quote objects
        IntByReference quoteSize = new IntByReference();
        PointerByReference quoteBuf = new PointerByReference();

        // Fetch TDX Quote by calling the respective tdx sdk function
        int ret = TdxAttestLibrary.INSTANCE.tdx_att_get_quote(cReportData, null, 0,
                                                              selectedAttKeyId, quoteBuf,
                                                              quoteSize, 0);
        if (ret != 0) {
            throw new RuntimeException("tdx_att_get_quote returned error code " + ret);
        }

        // Convert fetched Tdx Quote to bytes
        byte[] quote = quoteBuf.getValue().getByteArray(0, quoteSize.getValue());

        // Free TDX Quote by calling the respective tdx sdk function to avoid memory leaks
        ret = TdxAttestLibrary.INSTANCE.tdx_att_free_quote(quoteBuf.getValue());
        if (ret != 0) {
            throw new RuntimeException("tdx_att_free_quote returned error code " + ret);
        }

        // Construct and return Evidence object attached with the fetched TDX Quote
        return new Evidence(1, quote, uData, null);
    }
}