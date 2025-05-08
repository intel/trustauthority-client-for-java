/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.report;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.intel.trustauthority.exception.ConfigfsException;
import com.intel.trustauthority.exception.GenerationMismatchedException;
import com.intel.trustauthority.configfsi.Constants;
import com.intel.trustauthority.configfsi.Client;
import com.intel.trustauthority.configfsi.TsmPath;
import com.intel.trustauthority.configfsi.Utils;

public class OpenReport {
	//(WO) Up to 64 bytes of user specified binary data
	protected byte[] inBlob;
	
	/*
 	(WO) Attribute is visible if a TSM implementation provider supports the concept of attestation reports for TVMs running at
 	different privilege levels, like SEV-SNP "VMPL", specify the privilege level via this attribute.  The minimum acceptable
 	value is conveyed via @privlevel_floor and the maximum acceptable value is TSM_PRIVLEVEL_MAX (3).
	*/
	protected Privilege privilege;
	
	/*
  	@default false
  	Setting this true will set auxBlob data in the report if exists
	*/
	boolean getAuxBlob;
		
	//This is entry path to create directory under config tsm path 
	TsmPath entry;
	
	//Expected generation from tsmpath/entry/generation file
	int expectedGeneration;
	
	//client for file operations
	Client client;
	
	private static final Logger logger = LogManager.getLogger(OpenReport.class);

	public OpenReport(Client client, TsmPath entry) {
		this.client = client;
		this.entry = entry;
	}

	protected String attribute(String subtree) {
		//For every attribute create a clone as not to set attribute to object
		TsmPath iEntry = new TsmPath(this.entry);
		iEntry.attribute = subtree;
		return iEntry.toString();
	}
	
	//Destroy entry directory from tsm path
	public void destroy() throws IOException, ConfigfsException {
		if (this.entry != null) {
			//Setting attribute null to get path upto entry
			this.entry.attribute = null;
			String entryPath = this.entry.toString();
			logger.debug("Destroying path {}", entryPath);
			this.client.RemoveAll(entryPath);
			this.entry = null;
		}
	}
	
	//Read privilegeLevelFloor from /sys/kernel/config/tsm/report/$name/privlevel_floor
	//(RO) Indicates the minimum permissible value that can be written to @privlevel.
	public int privilegeLevelFloor() throws IOException, ConfigfsException {
		byte[] data = this.readOption(Constants.PRIV_FLR);
		return Utils.bytesToInt(data, 10);
	}
	
	
	public void writeOption(String subtree, byte[] data) throws IOException, ConfigfsException {
		logger.trace("Writting file {}", this.attribute(subtree));
		//Writing to file should increment expected generation
		this.client.writeFile(this.attribute(subtree), data);
		this.expectedGeneration++;
	}

	public byte[] readOption(String subtree) throws IOException, ConfigfsException {
		byte[] data = this.client.readFile(this.attribute(subtree));
		int genearation = Report.readUint64File(client, this.attribute(Constants.GENERATION));
		// While reading attribute expected generation should match
		if(genearation != this.expectedGeneration) {
			logger.error("Unexpected generation received {}, expected {}".subSequence(genearation, this.expectedGeneration));
			throw new GenerationMismatchedException(genearation, this.expectedGeneration, subtree);
		}
		return data;
	}

	
	/** Method to get Binary attestation report generated from @inblob and other options
	 * @return com.intel.trustauthority.report.Response
	 * @throws IOException
	 * @throws ConfigfsException
	 */
	public Response get() throws IOException, ConfigfsException {
		//Write tsmpath/inblob 
		this.writeOption(Constants.IN_BLOB, this.inBlob);
		if (this.privilege != null) {
			this.writeOption("privlevel", String.format("%d", this.privilege.level).getBytes());
		}

		Response response = new Response();
		if (this.getAuxBlob) {
			//auxblob can be empty if auxiliary data is not available
			response.auxBlob = this.readOption(Constants.AUX_BLOB);
		}
		
		response.outBlob = this.readOption(Constants.OUT_BLOB);
		byte[] providerDataByt = this.readOption(Constants.PROVIDER);
		response.provider = new String(providerDataByt, StandardCharsets.UTF_8);
		return response;
	}

	public void setInBlob(byte[] inBlob) {
		this.inBlob = inBlob;
	}

	public void setPrivilege(Privilege privilege) {
		this.privilege = privilege;
	}
	
	
}
