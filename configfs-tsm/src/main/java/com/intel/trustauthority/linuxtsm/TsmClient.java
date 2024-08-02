/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.linuxtsm;

import java.io.File;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.intel.trustauthority.configfsi.Constants;
import com.intel.trustauthority.configfsi.Client;
import com.intel.trustauthority.configfsi.TsmPath;
import com.intel.trustauthority.exception.ConfigfsException;
import com.intel.trustauthority.exception.PathException;
import com.intel.trustauthority.report.OpenReport;
import com.intel.trustauthority.report.Report;
import com.intel.trustauthority.report.Request;
import com.intel.trustauthority.report.Response;

public class TsmClient {
	private static final Logger logger = LogManager.getLogger(TsmClient.class);

	// makeClient returns a client for using configfs for TSM use.
	public static Client makeClient() throws PathException {
		// Linux client expects just the "report" subsystem for now.
		String checkPath = String.format("%s%s%s", Constants.TSM_PREFIX, TsmPath.SEPERATOR, Constants.REPORT);
		File checkFile = new File(checkPath);
		if (!checkFile.exists()) {
			logger.error("{} not exists", checkPath);
			throw new PathException(String.format("directory {} does not exists", checkPath));
		} else {
			logger.debug("{} exists", checkPath);
		}

		if (!checkFile.isDirectory()) {
			logger.error(" {} not a directory", checkPath);
			throw new PathException(String.format("file {} should be directory", checkPath));
		}
		return new LinuxTsmClient();
	}

	/*
	 * Method return Response containing attestation binary report for given request
	 * @param request Request to get report data. 
	 * @return Response Contains Attestation report and provider 
	 * @throws IOException
	 * @throws ConfigfsException 
	 */
	public static Response getReport(Request request) throws IOException, ConfigfsException {
		Client client = makeClient();
		OpenReport r = Report.create(client, request);
		Response response = r.get();
		r.destroy();
		return response;
	}

}
