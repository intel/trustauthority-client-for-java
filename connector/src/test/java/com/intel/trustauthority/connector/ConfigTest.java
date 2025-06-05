/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */


package com.intel.trustauthority.connector;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Test;

public class ConfigTest {
    //Should not throw exception
    @Test
    public void testNullConfigUrl(){
        
        Config cfg;
        try {
            cfg = new RetryConfiguration(new RetryConfig(0,0,1));
            
            //Adding assert as per coverity scan report
            assertNotNull(cfg);

            // Act
            TrustAuthorityConnector conn = new TrustAuthorityConnector(cfg);

            //Assert            
            assertNotNull(conn);
        } catch (Exception ex) {
            assertNull(ex);
        }  
    }
}
