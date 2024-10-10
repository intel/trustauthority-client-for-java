/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.tdx;

// Third-party Library Imports
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * QuoteRequest class for holding TD report details
 */
public class QuoteRequest {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("report")
    private String report;

    /**
     * Constructs a new QuoteRequest object with the specified report.
     *
     * @param report          report retrieved from TPM.
     */
    public QuoteRequest(String report) {
        this.report = report;
    }

    /**
     * getter function for report
     */
    public String getReport() {
        return report;
    }

    /**
     * setter function for report
     */
    public void setReport(String report) {
        this.report = report;
    }
}