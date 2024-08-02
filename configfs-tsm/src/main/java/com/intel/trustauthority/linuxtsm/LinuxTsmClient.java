/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.linuxtsm;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Random;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.intel.trustauthority.configfsi.Constants;
import com.intel.trustauthority.exception.PathException;
import com.intel.trustauthority.configfsi.Client;

/**
 * LinuxTsmClient provides implementation of com.intel.trustauthority.configfsi.Client for
 * subsystem operations in Linux.
 */
public class LinuxTsmClient implements Client {
	private static final Logger logger = LogManager.getLogger(TsmClient.class);

	@Override
	public String mkdirTemp(String dir, String pattern) throws IOException, PathException {
		File file = new File(String.format("%s%s%s%d", dir, File.separator, pattern, getRandomNumber(Constants.RAND_MIN_NUM, Constants.RAND_MAX_NUM)));
		logger.debug("Creating dir {}", file.getAbsolutePath());
		if(!file.mkdirs()) {
			logger.error("Unable to create dir {}", file.getAbsolutePath());
			throw new PathException(String.format("Unable to create directory %s", file.getAbsolutePath()));
		}else {
			logger.debug("Created dir {}", file.getAbsolutePath());
		}
		return file.getPath();
	}

	@Override
	public byte[] readFile(String name) throws IOException {
		File file = new File(name);
		return Files.readAllBytes(file.toPath());
	}

	@Override
	public void writeFile(String name, byte[] contents) throws IOException {
		File file = new File(name);
		Files.write(file.toPath(), contents);
	}

	@Override
	public void RemoveAll(String path) throws IOException {
		logger.debug("Removing file  {}", path);
		File entry = new File(path);
		if (!entry.delete()) {
			logger.error("Unable to delete");
		}
	}
	
	public int getRandomNumber(int min, int max) {
		Random random = new Random() ;
		int randomNumber = random.nextInt(max + 1 - min) + min;        
		return randomNumber;
	}

}
