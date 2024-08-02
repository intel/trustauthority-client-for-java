/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.exception;

public class PathException extends ConfigfsException{
	/**
	 * This exception would be thrown for path/directory related errors 
	 */
	private static final long serialVersionUID = 1157403473530689084L;

	public PathException() {
		super();
	}
	
	public PathException(String str) {
		super(str);
	}
}