/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

/**
 * Evidence class for holding the SGX/TDX Quote fetched from SGX/TDX enabled platform
 */
public class Evidence {

    private long type;
    private byte[] quote;
    private byte[] userData;
    private byte[] eventLog;

    /**
     * Constructs a new Evidence object with the specified type, quote, userData and eventLog.
     *
     * @param type           type provided by the user.
     * @param quote          quote provided by user.
     * @param userData       userData by the user.
     * @param eventLog       eventLog provided by user.
     */
    public Evidence(long type, byte[] quote, byte[] userData, byte[] eventLog) {
        this.type = type;
        this.quote = quote;
        this.userData = userData;
        this.eventLog = eventLog;
    }

    /**
     * getter function for type
     */
    public long getType() {
        return type;
    }

    /**
     * getter function for quote
     */
    public byte[] getQuote() {
        return quote;
    }

    /**
     * getter function for userData
     */
    public byte[] getUserData() {
        return userData;
    }

    /**
     * getter function for eventLog
     */
    public byte[] getEventLog() {
        return eventLog;
    }
}