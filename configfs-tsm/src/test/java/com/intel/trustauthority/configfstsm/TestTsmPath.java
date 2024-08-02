/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.configfstsm;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

import com.intel.trustauthority.exception.PathException;
import com.intel.trustauthority.configfsi.Constants;
import com.intel.trustauthority.configfsi.TsmPath;

public class TestTsmPath {
	
	public TestTsmPath() {
		// TODO Auto-generated constructor stub
	}
	
	private static class TestParamsClass {
		String input;
		TsmPath output;
		PathException pexc;
		
		private TestParamsClass(String input, TsmPath output) {
			this.input = input;
			this.output = output;
		}
		
		private TestParamsClass(String input, PathException pexc) {
			this.input = input;
			this.pexc = pexc;
		}
	}
	
	@Test
	public void testPath() {		
		List<TestParamsClass> testParamClass = new ArrayList<TestParamsClass>();
		testParamClass.add(new TestParamsClass("not/to/configfs", new PathException(String.format("%s does not begin with %s", "not/to/configfs", Constants.TSM_PREFIX))));
		testParamClass.add(new TestParamsClass("///sys/kernel/config/tsm", new PathException(String.format("%s does not begin with %s", "///sys/kernel/config/tsm", Constants.TSM_PREFIX))));
		testParamClass.add(new TestParamsClass("/sys/kernel/config/tsm/report/is/way/too/long", 
				new PathException(String.format("%s suffix expected to be of form subsystem[/entry[/attribute]] (debug %s)", "/sys/kernel/config/tsm/report/is/way/too/long", "report/is/way/too/long"))));
		testParamClass.add(new TestParamsClass("/sys/kernel/config/tsm/a", new TsmPath("a")));
		testParamClass.add(new TestParamsClass("/sys/kernel/config/tsm/a/b", new TsmPath("a", "b")));
		testParamClass.add(new TestParamsClass("/sys/kernel/config/tsm/a/b/c", new TsmPath("a", "b", "c")));
		
		int tpcLen = testParamClass.size();
		for (int i=0; i<tpcLen; i++) {
			try {
				TsmPath tsmPth = TsmPath.ParseTsmPath(testParamClass.get(i).input);
				//Function output cannot be null
				if(tsmPth == null) {
					fail(String.format("Test failed for %s, output should not be empty", testParamClass.get(i).input));
					continue;
				}
				if (!testParamClass.get(i).output.equals(tsmPth)){
					fail(String.format("Test failed for %s, output did not match", testParamClass.get(i).input));
				}
			}catch(PathException pe) {
				if (testParamClass.get(i).pexc == null) {
					fail(String.format("Test failed for %s, Should not caught exception", testParamClass.get(i).input));
				}
				if(!pe.getMessage().equals(testParamClass.get(i).pexc.getMessage())) {
					fail(String.format("Test failed for %s, caught wrong exception", testParamClass.get(i).input));
				}
			}catch(Exception e) {
				fail(String.format("Test failed for %s, caught generic exception", testParamClass.get(i).input));
			}
			
		}	            		
	}
}
