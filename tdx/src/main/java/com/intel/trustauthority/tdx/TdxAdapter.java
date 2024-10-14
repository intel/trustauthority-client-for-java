/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.tdx;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Library;
import com.sun.jna.Structure;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

// Trust Authority Connector import
import com.intel.trustauthority.connector.*;
import com.intel.trustauthority.connector.Evidence.EvidenceType;
import com.intel.trustauthority.exception.ConfigfsException;
import com.intel.trustauthority.exception.GenerationMismatchedException;
import com.intel.trustauthority.exception.PathException;
import com.intel.trustauthority.linuxtsm.LinuxTsmClient;
import com.intel.trustauthority.linuxtsm.TsmClient;
import com.intel.trustauthority.report.Request;
import com.intel.trustauthority.report.Response;

/**
 * TdxAdapter class for TDX Quote collection from TDX enabled platform This class implements the base EvidenceAdapter interface.
 */
public class TdxAdapter implements EvidenceAdapter {
	private static final Logger logger = LogManager.getLogger(TdxAdapter.class);

	private byte[] userData;

	/**
	 * Constructs a new TdxAdapter object with the specified user data.
	 *
	 * @param userData user data provided by the user.
	 */
	public TdxAdapter(byte[] userData) {
		this.userData = userData;
	}

	/**
	 * collectEvidence is used to get TDX quote using configfs-tsm
	 *
	 * @param nonce nonce value passed by user
	 * @return Evidence object containing the fetched TDX quote
	 * @throws ConfigfsExeception
	 */
	public Evidence collectEvidence(byte[] nonce) throws NoSuchAlgorithmException, ConfigfsException {

		MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
		sha512Digest.update(nonce);
		sha512Digest.update(this.userData);
		byte[] reportData = sha512Digest.digest();

		Response resp;

		try {
			resp = TsmClient.getReport(new Request(reportData, false));
			if (resp == null) {
				throw new RuntimeException("Received null response from report");
			}
		} catch (PathException | GenerationMismatchedException | IOException e) {
			e.printStackTrace();
			throw new RuntimeException("Caught Exception while getReport ", e.getCause());
		}
		// Construct and return Evidence object attached with the fetched TDX Quote
		return new Evidence(EvidenceType.TDX, resp.getOutBlob(), null, null, this.userData);
	}
}