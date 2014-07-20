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

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Class that creates and initialized a Keystore for testing purposes.
 * 
 * @author bgiles@otterca.com
 */
public class TestKeyStoreInitialization {

    private static final char[] password = "password".toCharArray();

    private final Provider provider;
    private final KeyStore ks;
    private final KeyPairGenerator keyPairGen;
    private BigInteger serial = BigInteger.ONE;

    public TestKeyStoreInitialization() throws Exception {
        provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        ks = KeyStore.getInstance("PKCS12"); // or JKS...
        ks.load(null);

        keyPairGen = KeyPairGenerator.getInstance("RSA", provider);
        keyPairGen.initialize(512);

        // policyGenerator = new SimplePolicyGeneratorImpl(
        // "http://otterca.com/cps/userdefined.txt",
        // "otterca project at google-code",
        // "This certificate is created for testing purposes only. There are no warranties of usability.",
        // Integer.valueOf(1));
    }

    /**
     * 
     * @param alias
     * @param dirName
     * @param notBefore
     * @param notAfter
     * @return
     * @throws Exception
     */
    public BigInteger createSelfSignedCertificate(String alias, String dirName,
            Date notBefore, Date notAfter) throws Exception {
        X509CertificateBuilder builder = new X509CertificateBuilderImpl();
        // Arrays.asList(policyGenerator));
        KeyPair keyPair = keyPairGen.generateKeyPair();

        builder.setSerialNumber(serial);
        builder.setIssuer(dirName);
        builder.setSubject(dirName);
        builder.setNotBefore(notBefore);
        builder.setNotAfter(notAfter);
        builder.setPublicKey(keyPair.getPublic());

        builder.setEmailAddresses(alias + "@example.com");
        builder.setBasicConstraints(true, 0);
        // builder.setKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);

        X509Certificate cert = builder.build(keyPair.getPrivate());

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;

        // add entry to keystore.
        ks.setKeyEntry(alias, keyPair.getPrivate(), password, chain);

        serial = serial.add(BigInteger.ONE);

        return chain[0].getSerialNumber();
    }

    /**
     * 
     * @param alias
     * @param dirName
     * @param signer
     * @param notBefore
     * @param notAfter
     * @return
     * @throws Exception
     */
    public BigInteger createCACertificate(String alias, String dirName,
            String signer, Date notBefore, Date notAfter) throws Exception {
        X509CertificateBuilder builder = new X509CertificateBuilderImpl();
        // Arrays.asList(policyGenerator));
        KeyPair keyPair = keyPairGen.generateKeyPair();

        builder.setSerialNumber(serial);
        builder.setIssuer((X509Certificate) ks.getCertificate(signer));
        builder.setSubject(dirName);
        builder.setNotBefore(notBefore);
        builder.setNotAfter(notAfter);
        builder.setPublicKey(keyPair.getPublic());

        builder.setEmailAddresses(alias + "@example.com");
        builder.setBasicConstraints(true, 0);
        // builder.setKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);

        X509Certificate cert = builder.build(keyPair.getPrivate());

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;

        // add entry to keystore.
        ks.setKeyEntry(alias, keyPair.getPrivate(), password, chain);

        serial = serial.add(BigInteger.ONE);

        return chain[0].getSerialNumber();
    }

    /**
     * @param args
     */
    public void createKeystore(OutputStream os) throws Exception {
        // TODO Auto-generated method stub

        // create keys
        // add keys
        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 1);
        createSelfSignedCertificate("root1", "CN=root1", notBefore.getTime(),
                notAfter.getTime());
        createSelfSignedCertificate("root2", "CN=root2", notBefore.getTime(),
                notAfter.getTime());

        createCACertificate("ca1.1", "CN=ca1.1", "root1", notBefore.getTime(),
                notAfter.getTime());
        createCACertificate("ca1.2", "CN=ca1.2", "root1", notBefore.getTime(),
                notAfter.getTime());
        createCACertificate("ca2.1", "CN=ca2.1", "root2", notBefore.getTime(),
                notAfter.getTime());
        createCACertificate("ca2.2", "CN=ca2.2", "root2", notBefore.getTime(),
                notAfter.getTime());

        // save keystore
        ks.store(os, password);
        os.close();
    }

    /**
     * Create keystore containing test material.
     * 
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        TestKeyStoreInitialization tksi = new TestKeyStoreInitialization();

        OutputStream os = null;
        try {
            os = new FileOutputStream("test-keystore.p12");
            tksi.createKeystore(os);
        } finally {
            if (os != null) {
                os.close();
            }
        }
    }
}
