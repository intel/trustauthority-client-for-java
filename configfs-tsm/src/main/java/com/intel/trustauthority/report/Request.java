/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.report;

/**
 * Request for attestation report
 */
public class Request {
	// Bytes to write in inBlob file
	byte[] inBlob;

	/*
	 * If TSM implementation provider supports the concept of attestation reports
	 * for TVMs running at different privilege levels, like SEV-SNP "VMPL", specify
	 * the privilege level via this attribute. The minimum acceptable value is
	 * conveyed via @privlevel_floor and the maximum acceptable value is
	 * TSM_PRIVLEVEL_MAX (3).
	 */
	Privilege privilege;

	// Set to true to get AuxBlob in response, applicable if auxBlob is supported
	boolean getAuxBlob;

	public Request(byte[] inBlob, boolean getAuxBlob) {
		this.inBlob = inBlob;
		this.getAuxBlob = getAuxBlob;
	}

	public Request(byte[] inBlob, boolean getAuxBlob, Privilege privilege) {
		this.inBlob = inBlob;
		this.getAuxBlob = getAuxBlob;
		this.privilege = privilege;
	}
}
