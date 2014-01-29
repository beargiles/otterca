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

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.springframework.beans.factory.FactoryBean;

import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.tools.development.testing.LocalDatastoreServiceTestConfig;
import com.google.appengine.tools.development.testing.LocalServiceTestHelper;
import com.google.appengine.tools.development.testing.LocalTaskQueueTestConfig;

/**
 * Spring bean that creates Google datastores suitable for testing.
 * 
 * @author bgiles@otterca.com
 */
public class TestDatastoreServiceFactory implements FactoryBean<DatastoreService> {
    private LocalServiceTestHelper helper;

    /**
     * Default constructor. Sets up Google Datastore environment.
     */
    public TestDatastoreServiceFactory() {
        helper = new LocalServiceTestHelper(new LocalTaskQueueTestConfig(),
                new LocalDatastoreServiceTestConfig());
    }

    /**
     * Initialize local datastore
     */
    @PostConstruct
    public void initialize() {
        helper.setUp();
    }

    /**
     * Tear down local datastore
     */
    @PreDestroy
    public void destroy() {
        helper.tearDown();
    }

    /**
     * @see org.springframework.beans.factory.FactoryBean#getObject()
     */
    @Override
    public DatastoreService getObject() throws Exception {
        return DatastoreServiceFactory.getDatastoreService();
    }

    /**
     * @see org.springframework.beans.factory.FactoryBean#getObjectType()
     */
    @Override
    public Class<?> getObjectType() {
        return DatastoreService.class;
    }

    /**
     * @see org.springframework.beans.factory.FactoryBean#isSingleton()
     */
    @Override
    public boolean isSingleton() {
        return false;
    }
}