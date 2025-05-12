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
import com.intel.trustauthority.linuxtsm.TsmClient;
import com.intel.trustauthority.configfsi.Constants;
import com.intel.trustauthority.configfsi.Client;
import com.intel.trustauthority.configfsi.TsmPath;
import com.intel.trustauthority.configfsi.Utils;

public class Report {
	private static final Logger logger = LogManager.getLogger(Report.class);
	private static String SUB_SYSTEM = "report";
	private static String SUB_SYSTEM_PATH = Constants.TSM_PREFIX + "/" + SUB_SYSTEM;
	
	public static int readUint64File(Client client ,String p) throws IOException, ConfigfsException{
		byte[] data = client.readFile(p);
		return Utils.bytesToInt(data, 10);
	}
	
	public static OpenReport createOpenReport(Client client) throws IOException, ConfigfsException {
		String tempFile = client.mkdirTemp(SUB_SYSTEM_PATH, Constants.ENTRY);
		return Report.unsafeWrap(client, tempFile);		
	}
	
	public static OpenReport unsafeWrap(Client client, String entryPath) throws IOException, ConfigfsException{
		TsmPath p = TsmPath.ParseTsmPath(entryPath);
		OpenReport r = new OpenReport(client, new TsmPath(SUB_SYSTEM, p.getEntry()));
		r.expectedGeneration = readUint64File(client, r.attribute(Constants.GENERATION));
		logger.debug("Received expected geneartion {}", r.expectedGeneration);
		return r;
	}
	
	public static OpenReport create(Client client, Request req) throws IOException, ConfigfsException{
		OpenReport r = createOpenReport(client);
		r.inBlob = req.inBlob;
		r.privilege = req.privilege;
		r.getAuxBlob = req.getAuxBlob;
		return r;		
	}
		
	public static Response get(Client client, Request request) throws IOException, ConfigfsException {
		OpenReport r = create(client, request);
		Response response = r.get();
		r.destroy();
		return response;
	}	
}
