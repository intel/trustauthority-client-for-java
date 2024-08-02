/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.exception;

public class GenerationMismatchedException extends ConfigfsException {
	/**
	 * If retrieved generation is not matching with expected generation this exception would be thrown
	 * Getter function will give expected and received generation
	 */
	private static final long serialVersionUID = 1815003888069194103L;
	int gotGeneation;
	int expectedGeneration;
	String attribute;

	private GenerationMismatchedException() {
		super();
	}

	public GenerationMismatchedException(int gotGeneation, int expectedGeneartion, String attribute) {
		super(String.format("expected geneartion [%d], Got generation [%d], Attribute [%s]", expectedGeneartion,
				gotGeneation, attribute));
		this.gotGeneation = gotGeneation;
		this.expectedGeneration = expectedGeneartion;
		this.attribute = attribute;
	}

	public int getGotGeneration() {
		return gotGeneation;
	}

	public void setGotGeneration(int gotGeneation) {
		this.gotGeneation = gotGeneation;
	}

	public int getExpectedGeneration() {
		return expectedGeneration;
	}

	public void setExpectedGeneration(int expectedGeneration) {
		this.expectedGeneration = expectedGeneration;
	}

}
