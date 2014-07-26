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
package com.otterca.common.crypto.util;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * List services and their respective providers. Many of the services requirean
 * AlgorithmParameter value.
 * 
 * The most commonly used services include
 * <ul>
 * <li>AlgorithmParameterGenerator - generates values passed to other services</li>
 * <li>AlgorithmParameters - values passed to other services</li>
 * <li>Cipher - performs encryption</li>
 * <li>KeyFactory - converts between public keypairs and raw bytes</li>
 * <li>KeyGenerator - creates symmetric keys</li>
 * <li>KeyPairGenerator - creates public/private key pairs</li>
 * <li>KeyStore - stores certificates and private keys</li>
 * <li>MessageDigest - computes MD5, SHA1, etc.</li>
 * <li>SecretKeyFactory - converts betwee symmetric keys and raw bytes</li>
 * <li>SecureRandom - creates cryptographically strong pseudorandom values</li>
 * </ul>
 * 
 * Less commonly used services include
 * <ul>
 * <li>CertStore - like KeyStore but only stores certificates</li>
 * <li>CertificateFactory - converts between certificates and raw bytes</li>
 * <li>Mac - computes cryptographically strong message digests</li>
 * </ul>
 * 
 * @author Bear Giles <bgiles@coyotesong.com>
 */
public class ListServices {
	public static void main(String[] args) {
		// Security.addProvider(new
		// org.bouncycastle.jce.provider.BouncyCastleProvider());

		final Map<String, List<Provider>> services = new TreeMap<>();
		for (Provider provider : Security.getProviders()) {
			for (Provider.Service service : provider.getServices()) {
				if (services.containsKey(service.getType())) {
					final List<Provider> providers = services.get(service
							.getType());
					if (!providers.contains(provider)) {
						providers.add(provider);
					}
				} else {
					final List<Provider> providers = new ArrayList<>();
					providers.add(provider);
					services.put(service.getType(), providers);
				}
			}
		}

		for (String type : services.keySet()) {
			System.out.printf("%-20s: %s\n", type,
					Arrays.toString(services.get(type).toArray()));
		}
	}
}
