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

import static org.bouncycastle.asn1.x509.PolicyQualifierId.id_qt_cps;
import static org.bouncycastle.asn1.x509.PolicyQualifierId.id_qt_unotice;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.testng.annotations.Test;

/**
 * Unit tests for SimplePolicyGeneratorImpl.
 * 
 * @author bgiles@otterca.com
 */
@SuppressWarnings("deprecation")
public class SimplePolicyGeneratorTest {
    private static final X500Principal SUBJECT = new X500Principal("CN=subject");
    private static final X509Certificate ISSUER = null;
    private static final String CPS_URI = "http://otterca.com";
    private static final String ORGANIZATION = "Otter CA";
    private static final String USER_NOTICE = "Notice";

    /**
     * Test behavior when no policies are set.
     * 
     * @throws IOException
     */
    @Test
    @edu.umd.cs.findbugs.annotations.SuppressWarnings("NP_NONNULL_PARAM_VIOLATION")
    public void testNoPolicy() throws IOException {
        SimplePolicyGeneratorImpl generator = new SimplePolicyGeneratorImpl();
        byte[] policyBytes = generator.getExtension(SUBJECT, ISSUER);
        assertNull(policyBytes);
    }

    /**
     * Test behavior when CPS is set.
     * 
     * @throws IOException
     */
    @Test
    @edu.umd.cs.findbugs.annotations.SuppressWarnings("NP_NONNULL_PARAM_VIOLATION")
    public void testCpsPolicy() throws IOException {
        SimplePolicyGeneratorImpl generator = new SimplePolicyGeneratorImpl(
                CPS_URI, null, null, null);

        // get policy extensions
        byte[] policyBytes = generator.getExtension(SUBJECT, ISSUER);
        assertNotNull(policyBytes);

        X509Extensions exts = X509Extensions.getInstance(DLSequence
                .fromByteArray(policyBytes));
        ASN1Encodable asn1 = exts.getExtension(
                X509Extensions.CertificatePolicies).getParsedValue();
        CertificatePolicies policies = CertificatePolicies.getInstance(asn1);
        assertNotNull(policies, "unable to find CertificatePolicies extension");

        for (PolicyInformation info : policies.getPolicyInformation()) {
            if (id_qt_cps.equals(info.getPolicyIdentifier())) {
                DLSequence dls = (DLSequence) info.getPolicyQualifiers();
                for (int i = 0; i < dls.size(); i++) {
                    DLSequence dls1 = (DLSequence) dls.getObjectAt(i);
                    PolicyQualifierInfo pqInfo = new PolicyQualifierInfo(
                            (ASN1ObjectIdentifier) dls1.getObjectAt(0),
                            dls1.getObjectAt(1));
                    // DLSequence dls1 = (DLSequence) dls.getObjectAt(i);
                    if (id_qt_cps.equals(pqInfo.getPolicyQualifierId())) {
                        assertEquals(pqInfo.getQualifier().toString(), CPS_URI);
                    } else {
                        fail("unknown policy qualifier id: "
                                + pqInfo.getPolicyQualifierId());
                    }
                }
            } else {
                fail("unknown policy identifier: " + info.getPolicyIdentifier());
            }
        }
    }

    /**
     * Test behavior when user notice is set.
     * 
     * @throws IOException
     */
    @Test
    @edu.umd.cs.findbugs.annotations.SuppressWarnings("NP_NONNULL_PARAM_VIOLATION")
    public void testUserNoticePolicy() throws IOException {
        SimplePolicyGeneratorImpl generator = new SimplePolicyGeneratorImpl(
                null, ORGANIZATION, USER_NOTICE, Integer.valueOf(1));

        // get policy extensions
        byte[] policyBytes = generator.getExtension(SUBJECT, ISSUER);
        assertNotNull(policyBytes);

        X509Extensions exts = X509Extensions.getInstance(DLSequence
                .fromByteArray(policyBytes));
        ASN1Encodable asn1 = exts.getExtension(
                X509Extensions.CertificatePolicies).getParsedValue();
        CertificatePolicies policies = CertificatePolicies.getInstance(asn1);
        assertNotNull(policies, "unable to find CertificatePolicies extension");

        for (PolicyInformation info : policies.getPolicyInformation()) {
            if (id_qt_unotice.equals(info.getPolicyIdentifier())) {
                DLSequence dls = (DLSequence) info.getPolicyQualifiers();
                for (int i = 0; i < dls.size(); i++) {
                    UserNotice userNotice = UserNotice
                            .getInstance((DLSequence) dls.getObjectAt(i));
                    assertEquals(userNotice.getNoticeRef().getOrganization()
                            .getString(), ORGANIZATION);
                    assertEquals(
                            userNotice.getNoticeRef().getNoticeNumbers()[0]
                                    .getValue(),
                            BigInteger.ONE);
                    assertEquals(userNotice.getExplicitText().getString(),
                            USER_NOTICE);
                }
            } else {
                fail("unknown policy identifier: " + info.getPolicyIdentifier());
            }
        }
    }
}
