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

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ResourceBundle;

import javax.annotation.ParametersAreNonnullByDefault;

import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

/**
 * Configuration used in DAO tests. All singleton beans use lazy initialization.
 * 
 * @author bgiles@otterca.com
 */
@Configuration
@Profile("dev")
@ParametersAreNonnullByDefault
public class KeyStoreConfiguration {
    private static final ResourceBundle masterkey = ResourceBundle.getBundle("masterkey");
    private static final ResourceBundle bundle = ResourceBundle
            .getBundle(KeyStoreConfiguration.class.getName());
    private KeyStore keyStore;

    /**
     * Get keystore containing certificates used in DAO unit tests.
     * 
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    @Bean
    public synchronized KeyStore getKeyStore() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {

        if (keyStore == null) {
            keyStore = KeyStore.getInstance(bundle.getString("keystore.type"));
            InputStream is = null;
            try {
                Resource resource = new ClassPathResource(bundle.getString("keystore.location"));
                is = resource.getInputStream();
                if (masterkey.containsKey("master.password")) {
                    BasicTextEncryptor encryptor = new BasicTextEncryptor();
                    encryptor.setPassword(masterkey.getString("master.password"));
                    keyStore.load(is, encryptor.decrypt(bundle.getString("keystore.password"))
                            .toCharArray());
                } else {
                    keyStore.load(is, null);
                }
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        }
        return keyStore;
    }
}