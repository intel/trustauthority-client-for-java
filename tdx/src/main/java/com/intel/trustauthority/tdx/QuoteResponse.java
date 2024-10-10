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
 * QuoteResponse class for holding generated quote
 */
public class QuoteResponse {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("quote")
    private String quote;

    /**
     * Constructs a new QuoteResponse object with the specified quote.
     *
     * @param quote quote returned from Azure.
     */
    public QuoteResponse(String quote) {
        this.quote = quote;
    }

    /**
     * Default constructor (required for Jackson Object Mapping)
     */
    public QuoteResponse() {
    }

    /**
     * getter function for quote
     */
    public String getQuote() {
        return quote;
    }

    /**
     * setter function for quote
     */
    public void setQuote(String quote) {
        this.quote = quote;
    }
}