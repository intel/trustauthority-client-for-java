/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.configfsi;

public class Constants {
	public static final String GENERATION = "generation";
	public static final String ENTRY = "entry";
	public static final String AUX_BLOB = "auxblob";
	public static final String OUT_BLOB = "outblob";
	public static final String IN_BLOB = "inblob";
	public static final String PROVIDER = "provider";
	public static final String PRIV_FLR = "privlevel_floor";
	public static final String TSM_PREFIX = "/sys/kernel/config/tsm";
	public static final String REPORT = "report";
	
	public static final int RAND_MAX_NUM = 100000000;
	public static final int RAND_MIN_NUM = 9999999;
}
