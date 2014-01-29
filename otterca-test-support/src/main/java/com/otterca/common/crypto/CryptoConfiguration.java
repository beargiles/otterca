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

import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ResourceBundle;

import javax.annotation.ParametersAreNonnullByDefault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Configuration containing cryptographic methods. These classes assume the
 * Bouncycastle implementation for convenience.
 * 
 * @author bgiles@otterca.com
 */
@Configuration
@Profile("dev")
@ParametersAreNonnullByDefault
public class CryptoConfiguration {
    private static final Logger log = LoggerFactory.getLogger(CryptoConfiguration.class);
    private static final ResourceBundle bundle = ResourceBundle.getBundle(CryptoConfiguration.class
            .getName());
    private static final CertificateFactory factory;
    private X509CertificateUtil x509CertUtil;

    static {
        // Get standard certificate factory.
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            log.error("unable to create X.509 CertificateFactory: " + e.getMessage());
            throw new ExceptionInInitializerError("unable to create X.509 CertificateFactory: "
                    + e.getMessage());
        }
    }

    /**
     * Get certificate factory. This is standard Java class.
     */
    @Bean
    public CertificateFactory getCertificateFactory() throws CertificateException {
        return factory;
    }

    /**
     * Get utility class.
     * 
     * @return
     */
    @Bean
    public synchronized X509CertificateUtil getX509CertificateUtil() {
        if (x509CertUtil == null) {
            String classname = bundle.getString("X509CertificateUtil.classname");
            try {
                log.debug("using {} for X509CertificiateUtil class", classname);
                Class<?> c = this.getClass().getClassLoader().loadClass(classname);
                x509CertUtil = (X509CertificateUtil) c.getConstructor(Void.class).newInstance();
            } catch (ClassNotFoundException e) {
                log.warn("unable to load class {}", classname);
            } catch (NoSuchMethodException e) {
                log.warn("unable to load class {}", classname);
            } catch (InvocationTargetException e) {
                log.warn("unable to load class {}", classname);
            } catch (IllegalAccessException e) {
                log.warn("unable to load class {}", classname);
            } catch (InstantiationException e) {
                log.warn("unable to load class {}", classname);
            }
        }
        return x509CertUtil;
    }
}