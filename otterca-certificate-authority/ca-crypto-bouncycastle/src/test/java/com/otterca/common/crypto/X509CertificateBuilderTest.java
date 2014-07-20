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
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Legacy unit tests for X509CertificateBuilder. The remaining methods should be
 * moved to the X509CertificateBuilderAcceptanceTest class.
 * 
 * @author bgiles@otterca.com
 */
public class X509CertificateBuilderTest {
    protected final Provider provider;

    /**
     * Default constructor.
     * 
     * @throws Exception
     */
    public X509CertificateBuilderTest() throws GeneralSecurityException {
        provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    /**
     * Test builder with self-signed certificate. All properties are set.
     * 
     * @throws Exception
     */
    // @Test
    public void testBuilderSelfSignedCert() {
        // String email = "email";
        // String dnsName = "otterca.com";
        // String ipAddress = "127.0.0.1";
        // String dirName = "CN=subject";
        // String issuerEmail = "issuer email";
        // String issuerDnsName = "issuer.otterca.com";
        // String issuerIpAddress = "127.0.0.2";
        // String issuerDirName = "CN=issuer";

        /*
         * X509CertificateBuilder builder = new X509CertificateBuilderImpl();
         * 
         * // create certificate builder.setSerialNumber(serial);
         * builder.setSubject(subjectName); builder.setIssuer(subjectName);
         * builder.setNotBefore(notBefore.getTime());
         * builder.setNotAfter(notAfter.getTime());
         * builder.setPublicKey(keyPair.getPublic());
         * builder.setEmailAddresses(email); builder.setDnsNames(dnsName);
         * builder.setIpAddresses(ipAddress);
         * builder.setDirectoryNames(dirName);
         * builder.setIssuerEmailAddresses(issuerEmail);
         * builder.setIssuerDnsNames(issuerDnsName);
         * builder.setIssuerIpAddresses(issuerIpAddress);
         * builder.setIssuerDirectoryNames(issuerDirName);
         * 
         * X509Certificate cert = builder.build(keyPair.getPrivate());
         * 
         * // perform basic validation. cert.verify(keyPair.getPublic());
         * 
         * // verify the basics assertEquals(cert.getSerialNumber(), serial);
         * assertEquals(cert.getSubjectDN().getName(), subjectName);
         * assertEquals(cert.getIssuerDN().getName(), subjectName);
         * assertEquals(cert.getNotBefore(), notBefore.getTime());
         * assertEquals(cert.getNotAfter(), notAfter.getTime());
         * assertEquals(cert.getPublicKey(), keyPair.getPublic());
         * 
         * assertEquals(-1, cert.getBasicConstraints());
         * 
         * JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
         * 
         * // verify that we have a SKID. SubjectKeyIdentifier kid =
         * utils.createSubjectKeyIdentifier(keyPair.getPublic());
         * SubjectKeyIdentifier skid = new SubjectKeyIdentifierStructure(
         * cert.getExtensionValue
         * (X509Extension.subjectKeyIdentifier.toString()));
         * assertEquals(skid.getKeyIdentifier(), kid.getKeyIdentifier());
         * 
         * // verify that we have an AKID. byte[] akidExt =
         * cert.getExtensionValue
         * (X509Extension.authorityKeyIdentifier.toString());
         * AuthorityKeyIdentifier akid = new
         * AuthorityKeyIdentifierStructure(akidExt);
         * assertEquals(akid.getKeyIdentifier(), kid.getKeyIdentifier());
         * assertEquals(akid.getAuthorityCertSerialNumber(), serial);
         * GeneralName[] akidNames = akid.getAuthorityCertIssuer().getNames();
         * assertEquals(akidNames.length, 1);
         * assertEquals(akidNames[0].getName().toString(), subjectName);
         * 
         * // verify the subject alternative names. for (List<?> obj :
         * cert.getSubjectAlternativeNames()) { switch (((Number)
         * obj.get(0)).intValue()) { case GeneralName.rfc822Name:
         * assertEquals(obj.get(1), email); break; case GeneralName.dNSName:
         * assertEquals(obj.get(1), dnsName); break; case GeneralName.iPAddress:
         * assertEquals(obj.get(1), ipAddress); break; case
         * GeneralName.directoryName: assertEquals(obj.get(1), dirName); break;
         * default: fail("unexpected subject alternative name"); } }
         * 
         * // verify the issuer alternative names. for (List<?> obj :
         * cert.getIssuerAlternativeNames()) { switch (((Number)
         * obj.get(0)).intValue()) { case GeneralName.rfc822Name:
         * assertEquals(obj.get(1), issuerEmail); break; case
         * GeneralName.dNSName: assertEquals(obj.get(1), issuerDnsName); break;
         * case GeneralName.iPAddress: assertEquals(obj.get(1),
         * issuerIpAddress); break; case GeneralName.directoryName:
         * assertEquals(obj.get(1), issuerDirName); break; default:
         * fail("unexpected issuer alternative name"); } }
         * 
         * serial = serial.add(BigInteger.ONE);
         */
    }

    /**
     * Test builder with CertificatePolicy.
     * 
     * @throws Exception
     */
    // @Test(enabled = false)
    public void testBuilderCertWithCertificatePolicy()
            throws GeneralSecurityException {
        // String cps = "http://example.com";
        // String organization = "Acme Industries";
        // String notice = "do not use if chasing road runners";
        // X509ExtensionGenerator policyGenerator = new
        // SimplePolicyGeneratorImpl(cps, organization,
        // notice, 1);
        // X509CertificateBuilder builder = new X509CertificateBuilderImpl();
        // Arrays.asList(policyGenerator));

        /*
         * // create self-signed cert with policy.
         * builder.setSerialNumber(serial); builder.setSubject(issuerName);
         * builder.setIssuer(issuerName);
         * builder.setNotBefore(notBefore.getTime());
         * builder.setNotAfter(notAfter.getTime());
         * builder.setPublicKey(issuerKeyPair.getPublic()); X509Certificate cert
         * = builder.build(issuerKeyPair.getPrivate());
         * 
         * // verify policy is present. byte[] policyBytes =
         * cert.getExtensionValue
         * (X509Extensions.CertificatePolicies.toString()); ASN1Primitive asn1 =
         * X509ExtensionUtil.fromExtensionValue(policyBytes);
         * CertificatePolicies policies = CertificatePolicies.getInstance(asn1);
         * 
         * for (PolicyInformation info : policies.getPolicyInformation()) { if
         * (id_qt_cps.equals(info.getPolicyIdentifier())) { DLSequence dls =
         * (DLSequence) info.getPolicyQualifiers(); for (int i = 0; i <
         * dls.size(); i++) { DLSequence dls1 = (DLSequence) dls.getObjectAt(i);
         * PolicyQualifierInfo pqInfo = new PolicyQualifierInfo(
         * (ASN1ObjectIdentifier) dls1.getObjectAt(0), dls1.getObjectAt(1)); //
         * DLSequence dls1 = (DLSequence) dls.getObjectAt(i); if
         * (id_qt_cps.equals(pqInfo.getPolicyQualifierId())) {
         * assertEquals(pqInfo.getQualifier().toString(), cps); } else {
         * fail("unknown policy qualifier id: " +
         * pqInfo.getPolicyQualifierId()); } } } else if
         * (id_qt_unotice.equals(info.getPolicyIdentifier())) { DLSequence dls =
         * (DLSequence) info.getPolicyQualifiers(); for (int i = 0; i <
         * dls.size(); i++) { UserNotice userNotice =
         * UserNotice.getInstance((DLSequence) dls.getObjectAt(i));
         * assertEquals(userNotice.getNoticeRef().getOrganization().getString(),
         * organization);
         * assertEquals(userNotice.getNoticeRef().getNoticeNumbers
         * ()[0].getValue(), BigInteger.ONE);
         * assertEquals(userNotice.getExplicitText().getString(), notice); } }
         * else { fail("unknown policy identifier: " +
         * info.getPolicyIdentifier()); } }
         * 
         * serial = serial.add(BigInteger.ONE);
         */
    }
}
