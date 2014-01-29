/*
 * This code was written by Bear Giles <bgiles@otterca.com>and he
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Any contributions made by others are licensed to this project under
 * one or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * 
 * Copyright (c) 2012 Bear Giles <bgiles@otterca.com>
 */
package com.otterca.persistence.dao;

import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.support.AnnotationConfigContextLoader;
import org.testng.annotations.Test;

import com.otterca.common.crypto.CryptoConfiguration;

/**
 * 
 * @author bgiles@otterca.com
 */
@ContextConfiguration(loader = AnnotationConfigContextLoader.class, classes = {
        KeyStoreConfiguration.class, DatastoreConfiguration.class, CryptoConfiguration.class })
@ActiveProfiles("dev")
public class X509CertificateDaoDatastoreTest extends X509CertificateDaoTest {

    /**
     * Test CRUD methods.
     */
    @Test(enabled = false)
    public void testCRUD() throws Exception {
        // super.doCRUD();
    }

    /**
     * Test RFC-specified search mechanisms.
     */
    @Test(enabled = false)
    public void testFindByX() throws Exception {
        // super.doFindByX();
    }
}
