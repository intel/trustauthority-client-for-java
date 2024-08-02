/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.configfsi;

import java.io.IOException;

import com.intel.trustauthority.exception.ConfigfsException;


/**
 * Client for File operation.
 * Consumer of this library should implement Client or can use com.intel.trustauthority.linuxtsm.LinuxTsmClient
 */
public interface Client {
	

	/** Create folder for report under dir.
	 * @param dir: 		Will contain path for report /sys/kernel/config/tsm/report 
	 * @param pattern:	Pattern for entry in the report directory dir. Directory dir and pattern can be use together to create report entry folder
	 * @return Created entry path which should contain generation, outblob, inblob
	 * @throws IOException
	 * @throws ConfigfsException
	 */
	public String mkdirTemp(String dir, String pattern) throws IOException,ConfigfsException;
	
	
	/** Write file 
	 * @param name: Directory path returned by mkdirTemp function
	 * @param contents: nonce + seed byte to store in inblob file
	 * @throws IOException
	 * @throws ConfigfsException
	 */
	public void writeFile(String name, byte[] contents) throws IOException, ConfigfsException;
	
	/** Read binary file created on adding nonce content to inblob file
	 * @param name: Directory path returned by mkdirTemp function
	 * @return byte from outblob, auxblob file
	 * @throws IOException
	 * @throws ConfigfsException
	 */
	public byte[] readFile(String name)  throws IOException, ConfigfsException;
	
	
	/**Removes directory path returned by mkdirTemp function
	 * @param path: Directory path returned by mkdirTemp function
	 * @throws IOException
	 * @throws ConfigfsException
	 */
	public void RemoveAll(String path) throws IOException, ConfigfsException;
}
