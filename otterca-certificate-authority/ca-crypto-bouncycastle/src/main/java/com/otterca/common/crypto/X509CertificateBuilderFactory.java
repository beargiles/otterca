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
package com.otterca.common.crypto;

import java.security.GeneralSecurityException;

import org.springframework.beans.factory.FactoryBean;

/**
 * Spring bean that creates X509CertificateBuilders.
 * 
 * @author bgiles@otterca.com
 */
public class X509CertificateBuilderFactory implements
        FactoryBean<X509CertificateBuilder> {

    /**
     * @see org.springframework.beans.factory.FactoryBean#getObject()
     */
    @Override
    public X509CertificateBuilder getObject() throws GeneralSecurityException {
        return new X509CertificateBuilderImpl();
    }

    /**
     * @see org.springframework.beans.factory.FactoryBean#getObjectType()
     */
    @Override
    public Class<?> getObjectType() {
        return X509CertificateBuilder.class;
    }

    /**
     * @see org.springframework.beans.factory.FactoryBean#isSingleton()
     */
    @Override
    public boolean isSingleton() {
        return false;
    }
}
