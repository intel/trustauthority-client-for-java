/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.exception;

public class ConfigfsException extends Exception{
	/**
	 * Generic ConfigfsException, All Exception under this package will extends this.
	 */
	private static final long serialVersionUID = 5306801227267018660L;

	public ConfigfsException() {
		super();
	}
	
	public ConfigfsException(String str) {
		super(str);
	}
	
}
