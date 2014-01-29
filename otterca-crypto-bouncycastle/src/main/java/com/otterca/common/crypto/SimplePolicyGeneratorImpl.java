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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.NoticeReference;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Simple PolicyGenerator that returns a static CPS url, organization and user
 * notice.
 * 
 * @author bgiles@otterca.com
 */
@SuppressWarnings("deprecation")
public class SimplePolicyGeneratorImpl implements X509ExtensionGenerator {

    private static final PolicyInformation[] emptyPolicyInformationArray = new PolicyInformation[0];

    @Autowired
    private String cpsUri;

    @Autowired
    private String organization;

    @Autowired
    private String userNotice;

    @Autowired
    private Integer noticeNumber;

    /**
     * Default constructor
     */
    public SimplePolicyGeneratorImpl() {

    }

    /**
     * Constructor taking arguments.
     * 
     * @param cpsUri
     * @param organization
     * @param userNotice
     * @param noticeNumber
     */
    public SimplePolicyGeneratorImpl(String cpsUri, String organization,
            String userNotice, Integer noticeNumber) {
        this.cpsUri = cpsUri;
        this.organization = organization;
        this.userNotice = userNotice;
        this.noticeNumber = noticeNumber;
    }

    /**
     * @see com.otterca.common.crypto.X509ExtensionGenerator#getObjectIdentifier()
     */
    public String getObjectIdentifier() {
        return X509Extensions.CertificatePolicies.toString();
    }

    /**
     * @see com.otterca.common.crypto.X509ExtensionGenerator#isCritical()
     */
    public boolean isCritical() {
        return false;
    }

    /**
     * @see com.otterca.common.crypto.X509ExtensionGenerator#getExtension(X500Principal,
     *      X509Certificate)
     */
    @Override
    public byte[] getExtension(X500Principal subject, X509Certificate issuer)
            throws IOException {
        X509ExtensionsGenerator generator = new X509ExtensionsGenerator();

        List<PolicyInformation> policies = new ArrayList<PolicyInformation>();

        PolicyInformation info = getCpsPolicyInformation();
        if (info != null) {
            policies.add(info);
        }

        info = getUserNoticePolicyInformation();
        if (info != null) {
            policies.add(info);
        }

        byte[] bytes = null;
        if (!policies.isEmpty()) {
            CertificatePolicies certificatePolicies = new CertificatePolicies(
                    policies.toArray(emptyPolicyInformationArray));
            generator.addExtension(X509Extensions.CertificatePolicies, false,
                    certificatePolicies);
            bytes = generator.generate().getEncoded();
        }

        return bytes;
    }

    /**
     * Get CPS policy information.
     * 
     * @return
     */
    public PolicyInformation getCpsPolicyInformation() {
        PolicyInformation cps = null;
        if (cpsUri != null) {
            cps = new PolicyInformation(id_qt_cps, new DERSequence(
                    new PolicyQualifierInfo(cpsUri)));
        }
        return cps;
    }

    /**
     * Get user notification policy information.
     * 
     * @return
     */
    public PolicyInformation getUserNoticePolicyInformation() {
        PolicyInformation unotice = null;
        if ((organization != null) && (userNotice != null)) {
            ASN1EncodableVector noticeNumbers = new ASN1EncodableVector();
            if (noticeNumber != null) {
                noticeNumbers.add(new DERInteger(noticeNumber.intValue()));
            }
            NoticeReference noticeReference = new NoticeReference(organization,
                    noticeNumbers);
            unotice = new PolicyInformation(id_qt_unotice,
                    new DERSequence(new UserNotice(noticeReference,
                            new DisplayText(userNotice))));
        }
        return unotice;
    }
}
