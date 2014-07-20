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
package com.otterca.common.crypto.acceptance;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import javax.naming.InvalidNameException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.otterca.common.crypto.GeneralSubtree;
import com.otterca.common.crypto.X509CertificateBuilder;
import com.otterca.common.crypto.X509CertificateBuilderException;
import com.otterca.common.crypto.X509CertificateBuilderImpl;
import com.otterca.common.crypto.X509CertificateUtil;
import com.otterca.common.crypto.X509CertificateUtilImpl;

/**
 * Acceptance test for X509CertificateBuilder. This class should have no
 * dependency on this implementation other than the constructor. Technically it
 * should be in a separate module since it can be reused by other crypto API
 * implementations but in practice it's not worth the effort while there's only
 * a single implementation.
 * 
 * @author bgiles@otterca.com
 */
public class X509CertificateBuilderAcceptanceTest {
    // standard values
    private static final String PRIVATE_KEY_USAGE_PERIOD_OID = "2.5.29.16";
    private static final String NAME_CONSTRAINTS_OID = "2.5.29.30";
    private static final String INHIBIT_ANY_POLICY_OID = "2.5.29.54";
    private static final String AUTHORITY_INFO_ACCESS_OID = "1.3.6.1.5.5.7.1.1";
    private static final String SUBJECT_INFO_ACCESS_OID = "1.3.6.1.5.5.7.1.11";

    // test values
    private static final String SUBJECT_NAME = "CN=subject";
    private static final String ISSUER_NAME = "CN=issuer";
    private static final String GRANDFATHER_NAME = "CN=grandfather";
    // private static final char[] KEY_PASSWORD = "password".toCharArray();

    private final com.otterca.common.crypto.GeneralName.URI expectedGeneralNameUri1;
    private final com.otterca.common.crypto.GeneralName.URI expectedGeneralNameUri2;
    private final com.otterca.common.crypto.GeneralName.Directory expectedGeneralNameDir;
    private final com.otterca.common.crypto.GeneralName.Email expectedGeneralNameEmail;
    private final com.otterca.common.crypto.GeneralName.DNS expectedGeneralNameDns;
    private final com.otterca.common.crypto.GeneralName.IpAddress expectedGeneralNameIpAddress;

    private final X509CertificateUtil certUtil;
    private final Calendar notBefore;
    private final Calendar notAfter;
    private final KeyPair keyPair;
    private final KeyPair issuerKeyPair;
    private final KeyPair grandfatherKeyPair;
    private BigInteger serial = BigInteger.ONE;
    private X509CertificateBuilder builder;

    /**
     * Default constructor.
     * 
     * @throws Exception
     */
    protected X509CertificateBuilderAcceptanceTest()
            throws GeneralSecurityException, InvalidNameException,
            URISyntaxException, UnknownHostException, IOException {
        certUtil = new X509CertificateUtilImpl();

        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));

        // create key pairs. this is for testing so we use 512-bit keys for
        // speed.
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(512);
        keyPair = keyPairGen.generateKeyPair();
        issuerKeyPair = keyPairGen.generateKeyPair();
        grandfatherKeyPair = keyPairGen.generateKeyPair();

        notBefore = Calendar.getInstance();
        notBefore.set(Calendar.MINUTE, 0);
        notBefore.set(Calendar.SECOND, 0);
        notBefore.set(Calendar.MILLISECOND, 0);
        notAfter = Calendar.getInstance();
        notAfter.setTime(notBefore.getTime());
        notAfter.add(Calendar.YEAR, 1);

        expectedGeneralNameUri1 = new com.otterca.common.crypto.GeneralName.URI(
                "http://example.com");
        expectedGeneralNameUri2 = new com.otterca.common.crypto.GeneralName.URI(
                "ldap://example.net");
        expectedGeneralNameDir = new com.otterca.common.crypto.GeneralName.Directory(
                "C=US,ST=AK,C=Anchorage");
        expectedGeneralNameEmail = new com.otterca.common.crypto.GeneralName.Email(
                "bob@example.com");
        expectedGeneralNameDns = new com.otterca.common.crypto.GeneralName.DNS(
                "example.com");
        expectedGeneralNameIpAddress = new com.otterca.common.crypto.GeneralName.IpAddress(
                "127.0.0.1");
    }

    /**
     * Per-method initialization - get fresh certificate builder.
     */
    @BeforeMethod
    public void init() throws GeneralSecurityException {
        builder = new X509CertificateBuilderImpl();
    }

    /**
     * Populate a builder with standard values used in testing.
     * 
     * @param builder
     */
    public void populate(X509CertificateBuilder builder) {
        serial = serial.add(BigInteger.ONE);
        builder.setSerialNumber(serial);
        builder.setSubject(SUBJECT_NAME);
        builder.setIssuer(SUBJECT_NAME);
        builder.setNotBefore(notBefore.getTime());
        builder.setNotAfter(notAfter.getTime());
        builder.setPublicKey(keyPair.getPublic());
    }

    /**
     * Test builder with issuer certificate.
     * 
     * @throws Exception
     */
    @Test
    public void testBuilderCertWithValidIssuer()
            throws GeneralSecurityException {
        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(ISSUER_NAME);
        builder.setPublicKey(issuerKeyPair.getPublic());
        builder.setBasicConstraints(true);

        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        // perform basic validation.
        issuer.verify(issuerKeyPair.getPublic());

        // verify the basics
        assertEquals(issuer.getSerialNumber(), serial);
        assertEquals(issuer.getSubjectDN().getName(), ISSUER_NAME);
        assertEquals(issuer.getIssuerDN().getName(), ISSUER_NAME);
        assertEquals(issuer.getNotBefore(), notBefore.getTime());
        assertEquals(issuer.getNotAfter(), notAfter.getTime());
        // assertEquals(issuer.getPublicKey(), issuerKeyPair.getPublic());
        // FIXME: returns null

        builder.reset();

        // create subject certificate
        populate(builder);
        builder.setIssuer(issuer);

        X509Certificate cert = builder.build(keyPair.getPrivate());

        // perform basic validation.
        cert.verify(keyPair.getPublic());

        // verify the basics
        assertEquals(cert.getSerialNumber(), serial);
        assertEquals(cert.getSubjectDN().getName(), SUBJECT_NAME);
        assertEquals(cert.getIssuerDN().getName(), ISSUER_NAME);
        assertEquals(cert.getNotBefore(), notBefore.getTime());
        assertEquals(cert.getNotAfter(), notAfter.getTime());
        // assertEquals(cert.getPublicKey(), keyPair.getPublic()); FIXME:
        // returns null
    }

    /**
     * Test builder with nonsigning issuer certificate.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderCertWithNonSigningIssuer()
            throws GeneralSecurityException {
        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(ISSUER_NAME);
        builder.setPublicKey(issuerKeyPair.getPublic());

        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        builder.reset();

        // create subject certificate
        populate(builder);
        builder.setIssuer(issuer);

        builder.build(keyPair.getPrivate());

        // FIXME
        // assertTrue(
        // cert.getNonCriticalExtensionOIDs().contains(X509Extensions.NameConstraints.getId()),
        // "certificate does not contain expected Name Constraints extension");
    }

    /**
     * Test builder with expired issuer certificate.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderCertWithExpiredIssuer()
            throws GeneralSecurityException {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.set(Calendar.YEAR, 2000);

        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(ISSUER_NAME);
        builder.setNotBefore(cal.getTime());
        cal.add(Calendar.YEAR, 1);
        builder.setNotAfter(cal.getTime());
        builder.setPublicKey(issuerKeyPair.getPublic());

        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        builder.reset();

        // create subject certificate
        populate(builder);
        builder.setIssuer(issuer);

        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder with not-yet-valid issuer certificate.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderCertIssuerNotYetValid()
            throws GeneralSecurityException {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.add(Calendar.YEAR, 10);

        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(ISSUER_NAME);
        builder.setNotBefore(cal.getTime());
        cal.add(Calendar.YEAR, 1);
        builder.setNotAfter(cal.getTime());
        builder.setPublicKey(issuerKeyPair.getPublic());

        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        builder.reset();

        // create subject certificate
        populate(builder);
        builder.setIssuer(issuer);

        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder with bad notBefore/notAfter values.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderCertWithBadDates() throws GeneralSecurityException {
        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(ISSUER_NAME);
        builder.setPublicKey(issuerKeyPair.getPublic());

        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        builder.reset();

        // create subject certificate
        populate(builder);
        builder.setSubject(SUBJECT_NAME);
        builder.setIssuer(issuer);

        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder with unlimited pathlength value.
     * 
     * @throws Exception
     */
    @Test
    public void testBuilderCertWithUnlimitedPathLength()
            throws GeneralSecurityException {
        // create grandparent certificate
        populate(builder);
        builder.setSubject(GRANDFATHER_NAME);
        builder.setIssuer(GRANDFATHER_NAME);
        builder.setPublicKey(grandfatherKeyPair.getPublic());
        builder.setBasicConstraints(true);

        X509Certificate grandfather = builder.build(grandfatherKeyPair
                .getPrivate());

        assertEquals(grandfather.getBasicConstraints(), Integer.MAX_VALUE);

        builder.reset();

        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(grandfather);
        builder.setBasicConstraints(true, 0);
        builder.setPublicKey(issuerKeyPair.getPublic());

        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        assertEquals(issuer.getBasicConstraints(), 0);
    }

    /**
     * Test builder with sufficent pathlength value.
     * 
     * @throws Exception
     */
    @Test
    public void testBuilderCertWithSufficientPathLength()
            throws GeneralSecurityException {
        // create grandparent certificate
        populate(builder);
        builder.setSubject(GRANDFATHER_NAME);
        builder.setIssuer(GRANDFATHER_NAME);
        builder.setPublicKey(grandfatherKeyPair.getPublic());
        builder.setBasicConstraints(true, 1);

        X509Certificate grandfather = builder.build(grandfatherKeyPair
                .getPrivate());

        assertEquals(grandfather.getBasicConstraints(), 1);

        builder.reset();

        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(grandfather);
        builder.setBasicConstraints(true, 0);
        builder.setPublicKey(issuerKeyPair.getPublic());

        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        assertEquals(issuer.getBasicConstraints(), 0);

        builder.reset();

        // create subject certificate
        populate(builder);
        builder.setSubject(SUBJECT_NAME);
        builder.setIssuer(issuer);

        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertEquals(cert.getBasicConstraints(), -1);
    }

    /**
     * Test builder with insufficent pathlength value.
     * 
     * @throws Exception
     *             // assertTrue( //
     *             cert.getNonCriticalExtensionOIDs().contains(
     *             X509Extensions.NameConstraints.getId()), //
     *             "certificate does not contain expected Name Constraints extension"
     *             );
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderCertWithBadPathLength()
            throws GeneralSecurityException {
        // create grandparent certificate
        populate(builder);
        builder.setSubject(GRANDFATHER_NAME);
        builder.setIssuer(GRANDFATHER_NAME);
        builder.setPublicKey(grandfatherKeyPair.getPublic());
        builder.setBasicConstraints(true, 0);

        X509Certificate grandfather = builder.build(grandfatherKeyPair
                .getPrivate());

        assertEquals(grandfather.getBasicConstraints(), 0);

        builder.reset();

        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(grandfather);
        builder.setBasicConstraints(true, 0);
        builder.setPublicKey(issuerKeyPair.getPublic());

        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        assertEquals(issuer.getBasicConstraints(), -1);

        builder.reset();

        // create subject certificate
        populate(builder);
        builder.setIssuer(issuer);

        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder when missing serial number.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderMissingSerialNumber()
            throws GeneralSecurityException {
        serial = serial.add(BigInteger.ONE);
        builder.setSubject(SUBJECT_NAME);
        builder.setIssuer(SUBJECT_NAME);
        builder.setNotBefore(notBefore.getTime());
        builder.setNotAfter(notAfter.getTime());
        builder.setPublicKey(keyPair.getPublic());
        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder when missing subject.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderMissingSubject() throws GeneralSecurityException {
        serial = serial.add(BigInteger.ONE);
        builder.setSerialNumber(serial);
        builder.setIssuer(ISSUER_NAME);
        builder.setNotBefore(notBefore.getTime());
        builder.setNotAfter(notAfter.getTime());
        builder.setPublicKey(keyPair.getPublic());
        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder when missing issuer.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderMissingIssuer() throws GeneralSecurityException {
        serial = serial.add(BigInteger.ONE);
        builder.setSerialNumber(serial);
        builder.setSubject(SUBJECT_NAME);
        builder.setNotBefore(notBefore.getTime());
        builder.setNotAfter(notAfter.getTime());
        builder.setPublicKey(keyPair.getPublic());
        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder when missing 'not before' date.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderMissingNotBefore() throws GeneralSecurityException {
        serial = serial.add(BigInteger.ONE);
        builder.setSerialNumber(serial);
        builder.setSubject(SUBJECT_NAME);
        builder.setIssuer(SUBJECT_NAME);
        builder.setNotAfter(notAfter.getTime());
        builder.setPublicKey(keyPair.getPublic());
        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder when missing 'not after' date.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderMissingNotAfter() throws GeneralSecurityException {
        serial = serial.add(BigInteger.ONE);
        builder.setSerialNumber(serial);
        builder.setSubject(SUBJECT_NAME);
        builder.setIssuer(SUBJECT_NAME);
        builder.setNotBefore(notBefore.getTime());
        builder.setPublicKey(keyPair.getPublic());
        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder when missing public key.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderMissingPublicKey() throws GeneralSecurityException {
        serial = serial.add(BigInteger.ONE);
        builder.setSerialNumber(serial);
        builder.setSubject(SUBJECT_NAME);
        builder.setIssuer(SUBJECT_NAME);
        builder.setNotBefore(notBefore.getTime());
        builder.setNotAfter(notAfter.getTime());
        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder when 'notBefore' date is after 'notAfter' date.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = X509CertificateBuilderException.class)
    public void testBuilderBadDates() throws GeneralSecurityException {
        serial = serial.add(BigInteger.ONE);
        builder.setSerialNumber(serial);
        builder.setSubject(SUBJECT_NAME);
        builder.setIssuer(SUBJECT_NAME);
        builder.setNotBefore(notAfter.getTime());
        builder.setNotAfter(notBefore.getTime());
        builder.setPublicKey(keyPair.getPublic());
        builder.build(keyPair.getPrivate());
    }

    /**
     * Test builder with 'inhibitAnyPolicy'.
     * 
     * @throws Exception
     */
    @Test
    public void testInhibitAnyPolicy() throws GeneralSecurityException {
        // make sure there's no extension by default
        populate(builder);
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getCriticalExtensionOIDs()
                        .contains(INHIBIT_ANY_POLICY_OID),
                "certificate contains unexpected InhibitAnyPolicy extension");
        assertNull(certUtil.getInhibitAnyPolicy(cert));

        // test with final cert - should be removed
        builder.reset();
        populate(builder);
        builder.setInhibitAnyPolicy(6);
        cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getCriticalExtensionOIDs()
                        .contains(INHIBIT_ANY_POLICY_OID),
                "certificate contains unexpected InhibitAnyPolicy extension");
        assertNull(certUtil.getInhibitAnyPolicy(cert));

        // now try it with CA cert - should work.
        builder.reset();
        populate(builder);
        builder.setBasicConstraints(true);
        builder.setInhibitAnyPolicy(6);
        cert = builder.build(keyPair.getPrivate());
        assertTrue(
                cert.getCriticalExtensionOIDs()
                        .contains(INHIBIT_ANY_POLICY_OID),
                "certificate does not contain expected InhibitAnyPolicy extension");
        assertEquals(certUtil.getInhibitAnyPolicy(cert), Integer.valueOf(6));

        // TODO also check behavior when issuer has inhibit any policy set.
    }

    /**
     * Test builder with no 'Names'
     */
    @Test
    public void testBuilderNoNames() throws GeneralSecurityException {
        populate(builder);
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getNonCriticalExtensionOIDs().contains(
                        NAME_CONSTRAINTS_OID),
                "certificate contains unexpected Name Constraints extension");

        assertTrue(certUtil.getPermittedNames(cert).isEmpty());
        assertTrue(certUtil.getExcludedNames(cert).isEmpty());

        builder.reset();
    }

    /**
     * Test builder with 'permittedNames'.
     * 
     * FIXME: add min/max. Add URI?
     * 
     * @throws Exception
     */
    @Test
    public void testBuilderPermittedNames() throws GeneralSecurityException {
        populate(builder);
        builder.setPermittedNames("CN=Alice", "CN=Bob");
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        NAME_CONSTRAINTS_OID),
                "certificate does not contain expected Name Constraints extension");

        List<GeneralSubtree> names = certUtil.getPermittedNames(cert);
        assertEquals(names.size(), 2);
        assertEquals(names.get(0).getName().getName(), "CN=Alice");
        assertEquals(names.get(1).getName().getName(), "CN=Bob");
    }

    /**
     * Test builder with 'excludedNames'
     * 
     * FIXME: add min/max. Add URI?
     * 
     * @throws Exception
     */
    @Test
    public void testBuilderExcludedNames() throws GeneralSecurityException {
        populate(builder);
        builder.setExcludedNames("CN=Alice", "CN=Bob");
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        NAME_CONSTRAINTS_OID),
                "certificate does not contain expected Name Constraints extension");

        List<GeneralSubtree> names = certUtil.getExcludedNames(cert);
        assertEquals(names.size(), 2);
        assertEquals(names.get(0).getName().getName(), "CN=Alice");
        assertEquals(names.get(1).getName().getName(), "CN=Bob");
    }

    /**
     * Test builder with 'OCSP Locations'
     * 
     * @throws Exception
     */
    @Test
    public void testOcspLocations() throws GeneralSecurityException,
            URISyntaxException, InvalidNameException {
        // make sure there's no extension by default
        populate(builder);
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getNonCriticalExtensionOIDs().contains(
                        AUTHORITY_INFO_ACCESS_OID),
                "certificate does not contain expected AIA extension");
        assertTrue(certUtil.getOcspLocations(cert).isEmpty());

        // test it with some general names.
        builder.reset();
        populate(builder);
        builder.setOcspLocations(expectedGeneralNameUri1,
                expectedGeneralNameUri2, expectedGeneralNameDir);
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        AUTHORITY_INFO_ACCESS_OID),
                "certificate does not contain expected AIA extension");

        List<com.otterca.common.crypto.GeneralName<?>> actual = certUtil
                .getOcspLocations(cert);
        assertEquals(actual.get(0), expectedGeneralNameUri1);
        assertEquals(actual.get(1), expectedGeneralNameUri2);
        assertEquals(actual.get(2), expectedGeneralNameDir);

        // test it again with the URI convenience method.
        builder.reset();
        populate(builder);
        builder.setOcspLocations(expectedGeneralNameUri1.get(),
                expectedGeneralNameUri2.get());
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        AUTHORITY_INFO_ACCESS_OID),
                "certificate does not contain expected AIA extension");

        actual = certUtil.getOcspLocations(cert);
        assertEquals(actual.get(0), expectedGeneralNameUri1);
        assertEquals(actual.get(1), expectedGeneralNameUri2);
    }

    /**
     * Test builder with 'CA Issuer Locations'
     * 
     * @throws Exception
     */
    @Test
    public void testCaIssuerLocations() throws GeneralSecurityException,
            URISyntaxException, InvalidNameException {
        // make sure there are no extensions by default.
        populate(builder);
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getNonCriticalExtensionOIDs().contains(
                        AUTHORITY_INFO_ACCESS_OID),
                "certificate contains unexpected AIA extension");
        assertTrue(certUtil.getCaIssuersLocations(cert).isEmpty());

        // test it with some general names.
        builder.reset();
        populate(builder);
        builder.setCaIssuersLocations(expectedGeneralNameUri1,
                expectedGeneralNameUri2, expectedGeneralNameDir);
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        AUTHORITY_INFO_ACCESS_OID),
                "certificate does not contain expected AIA extension");

        List<com.otterca.common.crypto.GeneralName<?>> actual = certUtil
                .getCaIssuersLocations(cert);
        assertEquals(actual.get(0), expectedGeneralNameUri1);
        assertEquals(actual.get(1), expectedGeneralNameUri2);
        assertEquals(actual.get(2), expectedGeneralNameDir);

        // test it again with the URI convenience method.
        builder.reset();
        populate(builder);
        builder.setCaIssuersLocations(expectedGeneralNameUri1.get(),
                expectedGeneralNameUri2.get());
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        AUTHORITY_INFO_ACCESS_OID),
                "certificate does not contain expected AIA extension");

        actual = certUtil.getCaIssuersLocations(cert);
        assertEquals(actual.get(0), expectedGeneralNameUri1);
        assertEquals(actual.get(1), expectedGeneralNameUri2);
    }

    /**
     * Test builder with 'CA Repositories'
     * 
     * @throws Exception
     */
    @Test
    public void testCaRepositories() throws GeneralSecurityException,
            URISyntaxException, InvalidNameException {
        // make sure there are no extensions by default.
        populate(builder);
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getNonCriticalExtensionOIDs().contains(
                        SUBJECT_INFO_ACCESS_OID),
                "certificate contains unexpected SIA extension");
        assertTrue(certUtil.getCaRepositories(cert).isEmpty());

        // test it with some general names.
        builder.reset();
        populate(builder);
        builder.setCaRepositories(expectedGeneralNameUri1,
                expectedGeneralNameUri2, expectedGeneralNameDir);
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        SUBJECT_INFO_ACCESS_OID),
                "certificate does not contain expected SIA extension");

        List<com.otterca.common.crypto.GeneralName<?>> actual = certUtil
                .getCaRepositories(cert);
        assertEquals(actual.get(0), expectedGeneralNameUri1);
        assertEquals(actual.get(1), expectedGeneralNameUri2);
        assertEquals(actual.get(2), expectedGeneralNameDir);

        // test it again with the URI convenience method.
        builder.reset();
        populate(builder);
        builder.setCaRepositories(expectedGeneralNameUri1.get(),
                expectedGeneralNameUri2.get());
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        SUBJECT_INFO_ACCESS_OID),
                "certificate does not contain expected AIA extension");

        actual = certUtil.getCaRepositories(cert);
        assertEquals(actual.get(0), expectedGeneralNameUri1);
        assertEquals(actual.get(1), expectedGeneralNameUri2);
    }

    /**
     * Test builder with 'timestamping''
     * 
     * @throws Exception
     */
    @Test
    public void testTimestamping() throws GeneralSecurityException,
            URISyntaxException, InvalidNameException {
        // make sure there are no extensions by default.
        populate(builder);
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getNonCriticalExtensionOIDs().contains(
                        SUBJECT_INFO_ACCESS_OID),
                "certificate contains unexpected SIA extension");
        assertTrue(certUtil.getTimestamping(cert).isEmpty());

        // test it with some general names.
        builder.reset();
        populate(builder);
        builder.setTimestampingLocations(expectedGeneralNameUri1,
                expectedGeneralNameUri2, expectedGeneralNameEmail,
                expectedGeneralNameDns, expectedGeneralNameIpAddress);
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        SUBJECT_INFO_ACCESS_OID),
                "certificate does not contain expected SIA extension");

        List<com.otterca.common.crypto.GeneralName<?>> actual = certUtil
                .getTimestamping(cert);
        assertEquals(actual.get(0), expectedGeneralNameUri1);
        assertEquals(actual.get(1), expectedGeneralNameUri2);
        assertEquals(actual.get(2), expectedGeneralNameEmail);
        assertEquals(actual.get(3), expectedGeneralNameDns);
        assertEquals(actual.get(4), expectedGeneralNameIpAddress);

        // test it again with the URI convenience method.
        builder.reset();
        populate(builder);
        builder.setTimestampingLocations(expectedGeneralNameUri1.get(),
                expectedGeneralNameUri2.get());
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        SUBJECT_INFO_ACCESS_OID),
                "certificate does not contain expected AIA extension");

        actual = certUtil.getTimestamping(cert);
        assertEquals(actual.get(0), expectedGeneralNameUri1);
        assertEquals(actual.get(1), expectedGeneralNameUri2);
    }

    /**
     * Test builder with 'private key usage period'
     * 
     * @throws Exception
     */
    @Test
    public void testPrivateKeyUsagePeriod() throws GeneralSecurityException {
        // make sure there are no extensions by default.
        populate(builder);
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getNonCriticalExtensionOIDs().contains(
                        PRIVATE_KEY_USAGE_PERIOD_OID),
                "certificate contains unexpected Private Key Usage Period extension");
        assertEquals(certUtil.getPrivateKeyUsagePeriod(cert).length, 0);

        // test it with two dates.
        builder.reset();
        populate(builder);
        builder.setPrivateKeyUsagePeriod(notBefore.getTime(),
                notAfter.getTime());
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        PRIVATE_KEY_USAGE_PERIOD_OID),
                "certificate does not contain expected Private Key Usage Period extension");

        Date[] dates = certUtil.getPrivateKeyUsagePeriod(cert);

        assertEquals(dates[0], notBefore.getTime());
        assertEquals(dates[1], notAfter.getTime());

        // test it with just 'not before' date.
        builder.reset();
        populate(builder);
        builder.setPrivateKeyUsagePeriod(notBefore.getTime(), null);
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        PRIVATE_KEY_USAGE_PERIOD_OID),
                "certificate does not contain expected Private Key Usage Period extension");

        dates = certUtil.getPrivateKeyUsagePeriod(cert);

        assertEquals(dates[0], notBefore.getTime());
        assertEquals(dates[1], null);

        // test it with just 'not after' date.
        builder.reset();
        populate(builder);
        builder.setPrivateKeyUsagePeriod(null, notAfter.getTime());
        cert = builder.build(keyPair.getPrivate());

        assertTrue(
                cert.getNonCriticalExtensionOIDs().contains(
                        PRIVATE_KEY_USAGE_PERIOD_OID),
                "certificate does not contain expected Private Key Usage Period extension");

        dates = certUtil.getPrivateKeyUsagePeriod(cert);

        assertEquals(dates[0], null);
        assertEquals(dates[1], notAfter.getTime());

        // test it with no dates. The extension should not be added.
        builder.reset();
        populate(builder);
        builder.setPrivateKeyUsagePeriod(null, null);
        cert = builder.build(keyPair.getPrivate());

        assertFalse(
                cert.getNonCriticalExtensionOIDs().contains(
                        PRIVATE_KEY_USAGE_PERIOD_OID),
                "certificate contains unexpected Private Key Usage Period extension");
    }

    /**
     * Test conversion to byte array and back.
     */
    @Test
    public void testTestRoundtrip() throws GeneralSecurityException {
        populate(builder);
        X509Certificate expected = builder.build(keyPair.getPrivate());

        X509Certificate actual = certUtil.getCertificate(expected.getEncoded());
        assertEquals(actual.getSerialNumber(), expected.getSerialNumber());
        assertEquals(actual.getIssuerDN().toString(), expected.getIssuerDN()
                .toString());
        assertEquals(actual.getSubjectDN().toString(), expected.getSubjectDN()
                .toString());
        assertEquals(actual.getNotBefore(), expected.getNotBefore());
        assertEquals(actual.getNotAfter(), expected.getNotAfter());
    }

    /**
     * Test search criteria. There's no easy way to check the subject key id and
     * authority key id - we can get the extension's bytes but still need to
     * parse them.
     */
    @Test
    public void testTestSearchCriteria() throws GeneralSecurityException {

        // create issuer certificate
        populate(builder);
        builder.setSubject(ISSUER_NAME);
        builder.setIssuer(ISSUER_NAME);
        builder.setBasicConstraints(true);
        X509Certificate issuer = builder.build(issuerKeyPair.getPrivate());

        builder.reset();

        // create subject certificate
        populate(builder);
        builder.setIssuer(issuer);
        X509Certificate cert = builder.build(keyPair.getPrivate());

        assertEquals(certUtil.getFingerprint(cert),
                toHex(DigestUtils.sha(cert.getEncoded())));
        assertEquals(certUtil.getCertificateHash(cert),
                rfc4387(cert.getEncoded()));
        assertEquals(certUtil.getIHash(cert), rfc4387(cert
                .getIssuerX500Principal().getEncoded()));
        assertEquals(certUtil.getSHash(cert), rfc4387(cert
                .getSubjectX500Principal().getEncoded()));
    }

    /**
     * Compute SHA1 hash of DER-encoded value, encode it using Base64, and drop
     * the trailing '='. (from X509CertificateUtil)
     * 
     * @param asn1
     * @return
     */
    public final String rfc4387(byte[] asn1) {
        byte[] digest = DigestUtils.sha(asn1);
        return Base64.encodeBase64String(digest).substring(0, 28);
    }

    /**
     * Return colon-separated hex string, e.g., 01:23:45:67.
     * 
     * Implementation note: this algorithm could be made a little more
     * efficient. :-) (from X509CertificateUtil)
     * 
     * @param data
     * @return
     */
    public final String toHex(byte[] data) {
        String hex = Hex.encodeHexString(data);
        StringBuilder sb = new StringBuilder();
        sb.append(hex.substring(0, 2));
        for (int i = 2; i < hex.length(); i += 2) {
            sb.append(':');
            sb.append(hex.charAt(i));
            sb.append(hex.charAt(i + 1));
        }
        return sb.toString();
    }
}
