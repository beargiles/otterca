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

//
//import static org.testng.Assert.assertEquals;
//import static org.testng.Assert.assertNull;
//import static org.testng.Assert.assertTrue;
//
//import java.security.KeyStore;
//import java.security.cert.X509Certificate;
//import java.util.List;
//
//import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
//
//import com.otterca.common.crypto.X509CertificateUtil;

/**
 * Unit test for X509CertificateDao implementations.
 * 
 * @author bgiles@otterca.com
 */
public abstract class X509CertificateDaoTest extends AbstractTestNGSpringContextTests {
    // @Autowired
    // protected KeyStore ks;
    //
    // @Autowired
    // protected X509CertificateUtil x509CertUtil;
    //
    // @Autowired
    // protected X509CertificateDao dao;
    //
    // /**
    // * Test basic lifecycle of a certificate.
    // */
    // protected void doCRUD() throws Exception {
    // assertTrue(ks.containsAlias("root1"));
    // X509Certificate expected = (X509Certificate) ks.getCertificate("root1");
    // dao.put(expected);
    //
    // X509Certificate actual =
    // dao.getCertificate(expected.getIssuerDN().getName(),
    // expected.getSerialNumber());
    //
    // assertEquals(actual.getSerialNumber(), expected.getSerialNumber(),
    // "mismatched serial number");
    // assertEquals(actual.getIssuerDN(), expected.getIssuerDN(),
    // "mismatched issuer");
    // assertEquals(actual.getSubjectDN(), expected.getSubjectDN(),
    // "mismatched subject");
    //
    // dao.deleteCertificate(expected.getIssuerDN().getName(),
    // expected.getSerialNumber());
    //
    // actual = dao.getCertificate(expected.getIssuerDN().getName(),
    // expected.getSerialNumber());
    // assertNull(actual);
    // }
    //
    // /**
    // * Test RFC-specified search mechanisms.
    // */
    // protected void doFindByX() throws Exception {
    // X509Certificate expected = (X509Certificate) ks.getCertificate("root1");
    // dao.put(expected);
    //
    // X509Certificate expected2 = (X509Certificate) ks.getCertificate("root2");
    // dao.put(expected2);
    //
    // List<X509Certificate> certs =
    // dao.findByCommonName(x509CertUtil.getName(expected));
    // assertEquals(1, certs.size());
    // assertEquals(x509CertUtil.getName(certs.get(0)),
    // x509CertUtil.getName(expected));
    //
    // certs = dao.findByFingerprint(x509CertUtil.getFingerprint(expected));
    // assertEquals(1, certs.size());
    // assertEquals(x509CertUtil.getFingerprint(certs.get(0)),
    // x509CertUtil.getFingerprint(expected));
    //
    // certs =
    // dao.findByCertificateHash(x509CertUtil.getCertificateHash(expected));
    // assertEquals(1, certs.size());
    // assertEquals(x509CertUtil.getCertificateHash(certs.get(0)),
    // x509CertUtil.getCertificateHash(expected));
    //
    // certs = dao.findByIHash(x509CertUtil.getIHash(expected));
    // assertEquals(1, certs.size());
    // assertEquals(x509CertUtil.getIHash(certs.get(0)),
    // x509CertUtil.getIHash(expected));
    //
    // certs = dao.findBySHash(x509CertUtil.getSHash(expected));
    // assertEquals(1, certs.size());
    // assertEquals(x509CertUtil.getSHash(certs.get(0)),
    // x509CertUtil.getSHash(expected));
    //
    // // certs = dao.findByAkidHash(x509CertUtil.getAkidHash(expected));
    // // assertEquals(1, certs.size());
    // // assertEquals(x509CertUtil.getAkidHash(certs.get(0)),
    // // x509CertUtil.getAkidHash(expected));
    //
    // certs = dao.findBySkidHash(x509CertUtil.getSkidHash(expected));
    // assertEquals(1, certs.size());
    // assertEquals(x509CertUtil.getSkidHash(certs.get(0)),
    // x509CertUtil.getSkidHash(expected));
    //
    // dao.deleteCertificate(expected.getIssuerDN().getName(),
    // expected.getSerialNumber());
    // dao.deleteCertificate(expected2.getIssuerDN().getName(),
    // expected2.getSerialNumber());
    // }
}
