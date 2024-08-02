/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.exception;

public class PrivLevelFormatException extends ConfigfsException{
	/**
	 * This exception is for Privileged reports errors
	 */
	private static final long serialVersionUID = 404546668079029357L;

	public PrivLevelFormatException() {
		super();
	}
	
	public PrivLevelFormatException(String msg) {
		super(msg);
	}
}
