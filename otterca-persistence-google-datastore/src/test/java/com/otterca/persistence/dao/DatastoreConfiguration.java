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

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.google.appengine.api.datastore.DatastoreService;

/**
 * Configuration used in DAO tests.
 * 
 * @author bgiles@otterca.com
 */
@Configuration
@Profile("dev")
@ParametersAreNonnullByDefault
public class DatastoreConfiguration {
    private TestDatastoreServiceFactory factory;
    private DatastoreService datastoreService;

    /**
     * Initialize datastore service factory.
     * 
     * @throws Exception
     */
    @PostConstruct
    public void initialize() throws Exception {
        factory = new TestDatastoreServiceFactory();
        factory.initialize();
        datastoreService = factory.getObject();
    }

    /**
     * Tear down datastore service factory
     */
    @PreDestroy
    public void destroy() {
        factory.destroy();
    }

    /**
     * Get test datastoreService.
     * 
     * @return
     */
    @Bean
    public synchronized DatastoreService getDatastoreService() throws Exception {
        return datastoreService;
    }

    /**
     * Get Certificate DAO
     * 
     * @return
     */
    @Bean
    public X509CertificateDao getX509CertificateDao() throws Exception {
        return new X509CertificateDaoDatastore();
    }
}