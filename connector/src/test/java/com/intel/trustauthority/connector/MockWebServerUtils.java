/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.connector;

import javax.net.ssl.SSLSocketFactory;

import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;

public class MockWebServerUtils {
    public static SSLSocketFactory createInsecureSslSocketFactory() {
        HeldCertificate heldCertificate = new HeldCertificate.Builder()
        .commonName("localhost")
        .addSubjectAlternativeName("localhost")
        .build();
        
        HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
            .heldCertificate(heldCertificate)
            .build();
        return serverCertificates.sslSocketFactory();
    }
}
