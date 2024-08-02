/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.report;

/**
 * Attestation report response
 */
public class Response {
	/*
 	(RO) A name for the format-specification of @outblob like "sev_guest" [1] or "tdx_guest" [2] in the near term, or a common standard format in the future.

	[1]: SEV Secure Nested Paging Firmware ABI Specification 
	Revision 1.55 Table 22
	https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf

	[2]: Intel® Trust Domain Extensions Data Center Attestation
	Primitives : Quote Generation Library and Quote Verification
	Library Revision 0.8 Appendix 4,5
	https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
 	*/
	protected String provider;
	
	
	/*
	 (RO) Binary attestation report generated from @inblob and other options The format of the report is implementation specific
		where the implementation is conveyed via the @provider attribute.
	 */
	protected byte[] outBlob;
	
	
	/*
	(RO) Optional supplemental data that a TSM may emit, visibility of this attribute depends on TSM, and may be empty if no auxiliary data is available.
	 */
	protected byte[] auxBlob;
	
	public String getProvider() {
		return provider;
	}
	public byte[] getOutBlob() {
		return outBlob;
	}
	public byte[] getAuxBlob() {
		return auxBlob;
	}
	
	
}
