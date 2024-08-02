/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.configfsi;

import java.nio.charset.StandardCharsets;

public class Utils {
	public static int bytesToInt(byte[] data, int base) {
		String uintData = new String(data, StandardCharsets.UTF_8);
		return Integer.parseInt(uintData.trim(), base);			
	}
}
