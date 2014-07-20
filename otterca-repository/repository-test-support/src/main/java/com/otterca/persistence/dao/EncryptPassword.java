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

import java.util.ResourceBundle;

import javax.annotation.ParametersAreNonnullByDefault;

import org.jasypt.util.text.BasicTextEncryptor;

/**
 * Simple standalone application that encrypts the contents of the command line.
 * It is used to encrypt passwords used elsewhere.
 * 
 * @author bgiles@coyotesong.com
 */
@ParametersAreNonnullByDefault
public final class EncryptPassword {
    private static final ResourceBundle masterkey = ResourceBundle.getBundle("masterkey");

    /**
     * Hide constructor since this is a utility class.
     */
    private EncryptPassword() {

    }

    /*
     * Standalone app simply encrypts the contents of the command line.
     * 
     * @param args
     * 
     * @throws Exception
     */
    public static void main(String[] args) {
        if (!masterkey.containsKey("master.password")) {
            System.err.println("no password specified in bundle");
        } else {
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(masterkey.getString("master.password"));
            for (String arg : args) {
                System.out.printf("'%s' -> '%s'%n", arg, encryptor.encrypt(arg));
            }
        }
    }
}
