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

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Vector;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.naming.InvalidNameException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.otterca.common.crypto.X509CertificateBuilderException.ErrorType;

/**
 * Convenience class that builds X509 certificates.
 * 
 * Implementation note: we use subclasses instead of external classes in an
 * effort to reduce the risk of race conditions by an attacker. This isn't 100%
 * effective since a sophisticated attacker can use reflection to make fields
 * visible anyway.
 * 
 * Implementation note: should we use dependency injection to make it easy to
 * support alternative Providers?
 * 
 * @author bgiles@otterca.com
 */
@ParametersAreNonnullByDefault
@SuppressWarnings("deprecation")
public class X509CertificateBuilderImpl implements X509CertificateBuilder {
    private static final ResourceBundle bundle = ResourceBundle
            .getBundle(X509CertificateBuilder.class.getName());
    private static final Logger log = LoggerFactory
            .getLogger(X509CertificateBuilderImpl.class);
    public static final String SIGNATURE_ALGORITHM = bundle
            .getString("signatureAlgorithm");
    private static final ASN1ObjectIdentifier id_ad_caRepositories = new ASN1ObjectIdentifier(
            "1.3.6.1.5.5.7.48.5");
    private static final ASN1ObjectIdentifier id_ad_timeStamping = new ASN1ObjectIdentifier(
            "1.3.6.1.5.5.7.48.3");
    private X509CertificateBuilderValidator validator;
    private X509CertificateUtil util = new X509CertificateUtilImpl();
    private X509Certificate issuer;
    private BigInteger serialNumber;
    private X509Principal subjectDN;
    private X509Principal issuerDN;
    private Date notBefore;
    private Date notAfter;
    private PublicKey pubkey;
    private final List<GeneralName> subjectNames = new ArrayList<GeneralName>();
    private final List<GeneralName> issuerNames = new ArrayList<GeneralName>();
    private final List<GeneralSubtree> permittedNames = new ArrayList<GeneralSubtree>();
    private final List<GeneralSubtree> excludedNames = new ArrayList<GeneralSubtree>();
    private final Map<String, List<String>> subjectDirectoryAttributes = new HashMap<String, List<String>>();
    private KeyUsage keyUsage;
    private ExtendedKeyUsage extendedKeyUsage;
    private Integer inhibitAnyPolicyDepth;
    private final List<GeneralName> ocspLocations = new ArrayList<GeneralName>();
    private final List<GeneralName> caIssuersLocations = new ArrayList<GeneralName>();
    private final List<GeneralName> caRepositories = new ArrayList<GeneralName>();
    private final List<GeneralName> timestamping = new ArrayList<GeneralName>();
    private final List<DistributionPoint> crlDistributionPoints = Collections
            .emptyList();
    private List<PolicyInformation> policyInformation = new ArrayList<PolicyInformation>();
    private PrivateKeyUsagePeriod privateKeyUsagePeriod;
    private X509V3CertificateGenerator generator;
    // AttributeCertificateInfo
    // IssuingDistribution Point
    private Date now = new Date();

    private boolean basicConstraint;
    private Integer pathLengthConstraint = null;

    @Autowired
    private List<X509ExtensionGenerator> extensionGenerators = Collections
            .emptyList();

    private static final PolicyInformation[] emptyPolicyInformationArray = new PolicyInformation[0];
    private static final GeneralName[] emptyGeneralNameArray = new GeneralName[0];
    private static final DistributionPoint[] emptyDistributionPointArray = new DistributionPoint[0];

    /**
     * Default constructor.
     */
    public X509CertificateBuilderImpl() throws GeneralSecurityException {
        util = new X509CertificateUtilImpl();
        validator = new StandardValidator();
    }

    /**
     * Constructor taking explicit policyGenerator.
     * 
     * @param policyGenerator
     */
    public X509CertificateBuilderImpl(
            List<X509ExtensionGenerator> extensionGenerators)
            throws GeneralSecurityException {
        this();
        // make defensive copy
        this.extensionGenerators = new ArrayList<X509ExtensionGenerator>(
                extensionGenerators);
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#reset()
     */
    @Override
    public void reset() {
        issuer = null;
        serialNumber = null;
        subjectDN = null;
        issuerDN = null;
        notBefore = null;
        notAfter = null;
        pubkey = null;
        subjectNames.clear();
        issuerNames.clear();
        keyUsage = null;
        basicConstraint = false;
        pathLengthConstraint = null;

        permittedNames.clear();
        excludedNames.clear();
        subjectDirectoryAttributes.clear();
        keyUsage = null;
        extendedKeyUsage = null;
        inhibitAnyPolicyDepth = null;
        ocspLocations.clear();
        caIssuersLocations.clear();
        caRepositories.clear();
        timestamping.clear();

        crlDistributionPoints.clear();

        policyInformation.clear();
        privateKeyUsagePeriod = null;

        now = new Date();
        validator = new StandardValidator();
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setSerialNumber(java
     *      .math.BigInteger)
     */
    @Override
    public X509CertificateBuilder setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setSubject(java.lang
     *      .String)
     */
    @Override
    public X509CertificateBuilder setSubject(String dirName) {
        this.subjectDN = new X509Principal(dirName);
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setIssuer(java.lang
     *      .String)
     */
    @Override
    public X509CertificateBuilder setIssuer(String dirName) {
        this.issuerDN = new X509Principal(dirName);
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setNotBefore(java.
     *      util.Date)
     */
    @Override
    public X509CertificateBuilder setNotBefore(Date notBefore) {
        // make defensive copy
        this.notBefore = new Date(notBefore.getTime());
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setNotAfter(java.util
     *      .Date)
     */
    @Override
    public X509CertificateBuilder setNotAfter(Date notAfter) {
        // make defensive copy
        this.notAfter = new Date(notAfter.getTime());
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setPublicKey(java.
     *      security.PublicKey)
     */
    @Override
    public X509CertificateBuilder setPublicKey(PublicKey pubkey) {
        this.pubkey = pubkey;
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setIssuer(java.security
     *      .cert.X509Certificate)
     */
    @Override
    public X509CertificateBuilder setIssuer(X509Certificate issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setEmailAddresses(java.lang.String)
     */
    @Override
    public X509CertificateBuilder setEmailAddresses(String... emailAddresses) {
        for (String address : emailAddresses) {
            subjectNames.add(new GeneralName(GeneralName.rfc822Name, address));
        }
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setDnsNames(java.lang
     *      .String)
     */
    @Override
    public X509CertificateBuilder setDnsNames(String... dnsNames) {
        for (String name : dnsNames) {
            subjectNames.add(new GeneralName(GeneralName.dNSName, name));
        }
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setIpAddresses(java
     *      .lang.String)
     */
    @Override
    public X509CertificateBuilder setIpAddresses(String... ipAddresses) {
        for (String address : ipAddresses) {
            subjectNames.add(new GeneralName(GeneralName.iPAddress, address));
        }
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setDirectoryNames(java.lang.String)
     */
    @Override
    public X509CertificateBuilder setDirectoryNames(String... dirNames) {
        for (String name : dirNames) {
            subjectNames.add(new GeneralName(GeneralName.directoryName, name));
        }
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setIssuerEmailAddresses
     *      (java.lang.String)
     */
    @Override
    public X509CertificateBuilder setIssuerEmailAddresses(
            String... emailAddresses) {
        for (String address : emailAddresses) {
            issuerNames.add(new GeneralName(GeneralName.rfc822Name, address));
        }
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setIssuerDnsNames(java.lang.String)
     */
    @Override
    public X509CertificateBuilder setIssuerDnsNames(String... dnsNames) {
        for (String name : dnsNames) {
            issuerNames.add(new GeneralName(GeneralName.dNSName, name));
        }
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setIssuerIpAddresses
     *      (java.lang.String)
     */
    @Override
    public X509CertificateBuilder setIssuerIpAddresses(String... ipAddresses) {
        for (String address : ipAddresses) {
            issuerNames.add(new GeneralName(GeneralName.iPAddress, address));
        }
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setIssuerDirectoryNames
     *      (java.lang.String)
     */
    @Override
    public X509CertificateBuilder setIssuerDirectoryNames(String... dirNames) {
        for (String name : dirNames) {
            issuerNames.add(new GeneralName(GeneralName.directoryName, name));
        }
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setBasicConstraints
     *      (boolean)
     */
    @Override
    public X509CertificateBuilder setBasicConstraints(boolean basicConstraint) {
        this.basicConstraint = basicConstraint;
        return this;
    }

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#setBasicConstraints
     *      (boolean, int)
     */
    @Override
    public X509CertificateBuilder setBasicConstraints(boolean basicConstraint,
            int pathLengthConstraint) {
        this.basicConstraint = basicConstraint;
        this.pathLengthConstraint = pathLengthConstraint;
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#
     *      setCRLDistributionPoints(List<Object>)
     */
    @Override
    public X509CertificateBuilder setCrlDistributionPoints(List<Object> values)
            throws URISyntaxException, InvalidNameException {
        throw new RuntimeException("Unimplemented method");
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setInhibitAnyPolicy(int)
     */
    @Override
    public X509CertificateBuilder setInhibitAnyPolicy(int depth) {
        this.inhibitAnyPolicyDepth = Integer.valueOf(depth);
        return this;
    }

    /**
     * @see 
     *      com.otterca.common.crypto.X509CertificateBuilder#setFreshestCRL(List<
     *      Object>)
     */
    @Override
    public X509CertificateBuilder setFreshestCrl(List<Object> values)
            throws URISyntaxException, InvalidNameException {
        throw new RuntimeException("Unimplemented method");
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setPrivateKeyUsagePeriod(Date,
     *      Date)
     */
    @Override
    public X509CertificateBuilder setPrivateKeyUsagePeriod(
            @Nullable Date notBefore, @Nullable Date notAfter) {

        if ((notBefore == null) && (notAfter == null)) {
            return this;
        }

        DERGeneralizedTime gtNotBefore = (notBefore != null) ? new DERGeneralizedTime(
                notBefore) : null;
        DERGeneralizedTime gtNotAfter = (notAfter != null) ? new DERGeneralizedTime(
                notAfter) : null;

        DERSequence seq = null;
        if ((gtNotBefore != null) && (gtNotAfter != null)) {
            seq = new DERSequence(new DERTaggedObject[] {
                    new DERTaggedObject(0, gtNotBefore),
                    new DERTaggedObject(1, gtNotAfter) });
        } else if (gtNotBefore != null) {
            seq = new DERSequence(new DERTaggedObject[] { new DERTaggedObject(
                    0, gtNotBefore) });
        } else {
            seq = new DERSequence(new DERTaggedObject[] { new DERTaggedObject(
                    1, gtNotAfter) });
        }

        this.privateKeyUsagePeriod = PrivateKeyUsagePeriod.getInstance(seq);
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setPermittedNames(java.lang.String[])
     */
    @Override
    public X509CertificateBuilder setPermittedNames(String... names) {
        for (String name : names) {
            permittedNames.add(new GeneralSubtree(new X500Principal(name)));
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setExcludedNames(java.lang.String[])
     */
    @Override
    public X509CertificateBuilder setExcludedNames(String... names) {
        for (String name : names) {
            excludedNames.add(new GeneralSubtree(new X500Principal(name)));
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setOcspLocations(URI...)
     */
    // @Override
    public X509CertificateBuilder setOcspLocations(URI... locations) {
        ocspLocations.clear();
        for (URI location : locations) {
            ocspLocations
                    .add(new GeneralName(GeneralName.uniformResourceIdentifier,
                            location.toString()));
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setOcspLocation(com.otterca.common.crypto.GeneralName...)
     */
    @Override
    public X509CertificateBuilder setOcspLocations(
            com.otterca.common.crypto.GeneralName<?>... names) {
        ocspLocations.clear();
        for (com.otterca.common.crypto.GeneralName<?> name : names) {
            switch (name.getType()) {
            case DIRECTORY:
                ocspLocations.add(new GeneralName(GeneralName.directoryName,
                        name.get().toString()));
                break;
            case URI:
                ocspLocations.add(new GeneralName(
                        GeneralName.uniformResourceIdentifier, name.get()
                                .toString()));
                break;
            default:
                throw new IllegalArgumentException(
                        "unexpected type for OCSP location: " + name.getType());
            }
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setCaIssuersLocations(URI...)
     */
    // @Override
    public X509CertificateBuilder setCaIssuersLocations(URI... locations) {
        caIssuersLocations.clear();
        for (URI location : locations) {
            caIssuersLocations
                    .add(new GeneralName(GeneralName.uniformResourceIdentifier,
                            location.toString()));
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setCaIssuersLocations(com.otterca.common.crypto.GeneralName...)
     */
    @Override
    public X509CertificateBuilder setCaIssuersLocations(
            com.otterca.common.crypto.GeneralName<?>... names) {
        caIssuersLocations.clear();
        for (com.otterca.common.crypto.GeneralName<?> name : names) {
            switch (name.getType()) {
            case DIRECTORY:
                caIssuersLocations.add(new GeneralName(
                        GeneralName.directoryName, name.get().toString()));
                break;
            case URI:
                caIssuersLocations.add(new GeneralName(
                        GeneralName.uniformResourceIdentifier, name.get()
                                .toString()));
                break;
            default:
                throw new IllegalArgumentException(
                        "unexpected type for CA Issuer location: "
                                + name.getType());
            }
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setCaRepositories(URI...)
     */
    // @Override
    public X509CertificateBuilder setCaRepositories(URI... locations) {
        caRepositories.clear();
        for (URI location : locations) {
            caRepositories
                    .add(new GeneralName(GeneralName.uniformResourceIdentifier,
                            location.toString()));
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setCaRepositories(com.otterca.common.crypto.GeneralName...)
     */
    @Override
    public X509CertificateBuilder setCaRepositories(
            com.otterca.common.crypto.GeneralName<?>... names) {
        caRepositories.clear();
        for (com.otterca.common.crypto.GeneralName<?> name : names) {
            switch (name.getType()) {
            case DIRECTORY:
                caRepositories.add(new GeneralName(GeneralName.directoryName,
                        name.get().toString()));
                break;
            case URI:
                caRepositories.add(new GeneralName(
                        GeneralName.uniformResourceIdentifier, name.get()
                                .toString()));
                break;
            default:
                throw new IllegalArgumentException(
                        "unexpected type for CA repository: " + name.getType());
            }
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setTimestampingLocations(URI...)
     */
    // @Override
    public X509CertificateBuilder setTimestampingLocations(URI... locations) {
        timestamping.clear();
        for (URI location : locations) {
            timestamping
                    .add(new GeneralName(GeneralName.uniformResourceIdentifier,
                            location.toString()));
        }
        return this;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateBuilder#setTimestampingLocations(com.otterca.common.crypto.GeneralName...)
     */
    @Override
    public X509CertificateBuilder setTimestampingLocations(
            com.otterca.common.crypto.GeneralName<?>... names) {
        timestamping.clear();
        for (com.otterca.common.crypto.GeneralName<?> name : names) {
            switch (name.getType()) {
            case URI:
                timestamping.add(new GeneralName(
                        GeneralName.uniformResourceIdentifier, name.get()
                                .toString()));
                break;
            case EMAIL:
                timestamping.add(new GeneralName(GeneralName.rfc822Name, name
                        .get().toString()));
                break;
            case DNS:
                timestamping.add(new GeneralName(GeneralName.dNSName, name
                        .get().toString()));
                break;
            case IP_ADDRESS:
                timestamping.add(new GeneralName(GeneralName.iPAddress,
                        ((InetAddress) name.get()).getHostAddress()));
                break;
            default:
                throw new IllegalArgumentException(
                        "unexpected type for Timestamping location: "
                                + name.getType());
            }
        }
        return this;
    }

    /**
     * Set Authority Key Identifier (RFC3280 4.2.1.1)
     * 
     * @throws InvalidKeyException
     * @throws CertificateParsingException
     */
    protected final void setAKID() throws InvalidKeyException,
            CertificateParsingException {
        if (issuer != null) {
            // signed certificates
            AuthorityKeyIdentifierStructure akis = new AuthorityKeyIdentifierStructure(
                    issuer);
            generator.addExtension(X509Extensions.AuthorityKeyIdentifier,
                    false, akis);
        } else {
            // self-signed certificates since we already require subjectDN =
            // issuerDN
            GeneralNames issuerName = new GeneralNames(new GeneralName(
                    GeneralName.directoryName, issuerDN));
            AuthorityKeyIdentifier akis = new AuthorityKeyIdentifierStructure(
                    pubkey);
            akis = new AuthorityKeyIdentifier(akis.getKeyIdentifier(),
                    issuerName, serialNumber);
            generator.addExtension(X509Extensions.AuthorityKeyIdentifier,
                    false, akis);
        }
    }

    /**
     * Set Subject Key Identifier (RFC3280 4.2.1.2). The RFC says that final
     * certs should not include SKIDs but it doesn't prohibit them and they make
     * it a lot easier to locate those certificates in a database.
     * 
     * @throws InvalidKeyException
     */
    protected final void setSKID() throws InvalidKeyException {
        SubjectKeyIdentifierStructure skis = new SubjectKeyIdentifierStructure(
                pubkey);
        generator
                .addExtension(X509Extensions.SubjectKeyIdentifier, false, skis);
    }

    /**
     * Set Key Usage (RFC3280 4.2.1.3)
     */
    protected void setKeyUsage() {
    }

    /**
     * Set Private Key Usage Period (RFC3280 4.2.1.4)
     */
    protected void setPrivateKeyUsagePeriod() {
        if (privateKeyUsagePeriod != null) {
            generator.addExtension(X509Extensions.PrivateKeyUsagePeriod, false,
                    privateKeyUsagePeriod);
        }
    }

    /**
     * Set Certificate Policies (RFC3280 4.2.1.5)
     */
    protected void setCertificatePolicies() {
        if (!policyInformation.isEmpty()) {
            if (policyInformation.size() == 1) {
                generator.addExtension(X509Extensions.CertificatePolicies,
                        false,
                        new CertificatePolicies(policyInformation.get(0)));
            } else {
                generator.addExtension(
                        X509Extensions.CertificatePolicies,
                        false,
                        new CertificatePolicies(policyInformation
                                .toArray(emptyPolicyInformationArray)));
            }
        }
    }

    /**
     * Set Policy Mappings (RFC3280 4.2.1.6)
     */
    protected void setPolicyMappings() {
    }

    /**
     * Set Subject Alternative Name (RFC3280 4.2.1.7)
     */
    protected void setSubjectAlternativeName() {
        if (!subjectNames.isEmpty()) {
            generator.addExtension(
                    X509Extensions.SubjectAlternativeName,
                    false,
                    new GeneralNames(subjectNames
                            .toArray(emptyGeneralNameArray)));
        }
    }

    /**
     * Set Issuer Alternative Name (RFC3280 4.2.1.8)
     */
    protected void setIssuerAlternativeName() {
        if (!issuerNames.isEmpty()) {
            generator
                    .addExtension(
                            X509Extensions.IssuerAlternativeName,
                            false,
                            new GeneralNames(issuerNames
                                    .toArray(emptyGeneralNameArray)));
        }
    }

    /**
     * Set Subject Directory Attributes (RFC3280 4.2.1.9)
     */
    protected void setSubjectDirectoryAttributes() {
        if (!subjectDirectoryAttributes.isEmpty()) {
            // TODO: create actual attributes
            Vector<Attribute> attributes = new Vector<Attribute>();
            generator.addExtension(X509Extensions.SubjectDirectoryAttributes,
                    false, new SubjectDirectoryAttributes(attributes));
        }
    }

    /**
     * Set Basic Constraint (RFC3280 4.2.1.10). Field validation is handled by
     * validator - we do not attempt to clean up values here.
     */
    protected final void setBasicConstraint() {
        if (basicConstraint) {
            if (pathLengthConstraint == null) {
                generator.addExtension(X509Extensions.BasicConstraints, true,
                        new BasicConstraints(basicConstraint));
            } else {
                generator.addExtension(X509Extensions.BasicConstraints, true,
                        new BasicConstraints(pathLengthConstraint));
            }
        }
    }

    /**
     * Set Name Constraints (RFC3280 4.2.1.11)
     */
    protected void setNameConstraints() {
        // FIXME: add constraints inherited from parent?
        if (!permittedNames.isEmpty() || !excludedNames.isEmpty()) {

            // convert permitted names.
            Vector<org.bouncycastle.asn1.x509.GeneralSubtree> permitted = new Vector<org.bouncycastle.asn1.x509.GeneralSubtree>();
            for (int i = 0; i < permittedNames.size(); i++) {
                GeneralSubtree g = permittedNames.get(i);
                GeneralName name = new GeneralName(new X500Name(g.getName()
                        .getName()));
                permitted.add(new org.bouncycastle.asn1.x509.GeneralSubtree(
                        name, g.getMin(), g.getMax()));
            }

            // convert excluded names.
            Vector<org.bouncycastle.asn1.x509.GeneralSubtree> excluded = new Vector<org.bouncycastle.asn1.x509.GeneralSubtree>();
            for (int i = 0; i < excludedNames.size(); i++) {
                GeneralSubtree g = excludedNames.get(i);
                GeneralName name = new GeneralName(new X500Name(g.getName()
                        .getName()));
                excluded.add(new org.bouncycastle.asn1.x509.GeneralSubtree(
                        name, g.getMin(), g.getMax()));
            }
            generator.addExtension(X509Extensions.NameConstraints, false,
                    new NameConstraints(permitted, excluded));
        }
    }

    /**
     * Set Policy Constraints (RFC3280 4.2.1.12)
     */
    protected void setPolicyConstraints() {
        // generator.addExtension(X509Extensions.PolicyConstraints, false, )
    }

    /**
     * Set Extended Key Usage (RFC3280 4.2.1.13)
     */
    protected void setExtendedKeyUsage() throws InvalidKeyException {
        if (extendedKeyUsage != null) {
            generator.addExtension(X509Extensions.ExtendedKeyUsage, false,
                    extendedKeyUsage);
        }
    }

    /**
     * Set CRL Distribution Points (RFC3280 4.2.1.14)
     */
    protected void setCRLDistributionPoints() {
        if (!crlDistributionPoints.isEmpty()) {
            generator.addExtension(
                    X509Extensions.CRLDistributionPoints,
                    false,
                    new CRLDistPoint(crlDistributionPoints
                            .toArray(emptyDistributionPointArray)));
        }
    }

    /**
     * Set Inhibit Any-Policy (RFC3280 4.2.1.15).
     */
    protected void setInhibitAnyPolicy() {
        if (inhibitAnyPolicyDepth != null) {
            generator.addExtension(X509Extensions.InhibitAnyPolicy, true,
                    new DERInteger(inhibitAnyPolicyDepth));
        }
    }

    /**
     * Set Freshest CRL (aka Delta CRL Distribution Point) (RFC3280 4.2.1.16)
     */
    protected void setFreshestCRL() {
        // generator.addExtension(X509Extensions.FreshestCRL, false, )
    }

    // ---------------------------------------------

    /**
     * Set Authority Information Access (RFC5280 4.2.2)
     */
    protected void setAuthorityInfoAccess() {
        if (!ocspLocations.isEmpty() || !caIssuersLocations.isEmpty()) {
            ASN1Encodable[] values = new ASN1Encodable[ocspLocations.size()
                    + caIssuersLocations.size()];

            // add OCSP locations
            for (int i = 0; i < ocspLocations.size(); i++) {
                values[i] = new AccessDescription(AccessDescription.id_ad_ocsp,
                        ocspLocations.get(i));
            }

            // add CA Issuers locations
            int offset = ocspLocations.size();
            for (int i = 0; i < caIssuersLocations.size(); i++) {
                values[i + offset] = new AccessDescription(
                        AccessDescription.id_ad_caIssuers,
                        caIssuersLocations.get(i));
            }
            DERSequence seq = new DERSequence(values);
            generator.addExtension(X509Extensions.AuthorityInfoAccess, false,
                    seq);
        }
    }

    /**
     * Set Subject Information Access (RFC5280 4.2.3)
     */
    protected void setSubjectInfoAccess() {
        if (!caRepositories.isEmpty() || !timestamping.isEmpty()) {
            ASN1Encodable[] values = new ASN1Encodable[caRepositories.size()
                    + timestamping.size()];

            // add CA Repositories
            for (int i = 0; i < caRepositories.size(); i++) {
                values[i] = new AccessDescription(id_ad_caRepositories,
                        caRepositories.get(i));
            }

            // add TimeStamping locations.
            int offset = caRepositories.size();
            for (int i = 0; i < timestamping.size(); i++) {
                values[i + offset] = new AccessDescription(id_ad_timeStamping,
                        timestamping.get(i));
            }
            DERSequence seq = new DERSequence(values);
            generator
                    .addExtension(X509Extensions.SubjectInfoAccess, false, seq);
        }
    }

    /**
     * ?????
     */
    protected void setIssuingDistributionPoint() {
        // IssuingDistributionPoint issuingDistributionPoint = new
        // IssuingDistributionPoint(....)
        // generator.addExtension(X509Extensions.IssuingDistributionPoint,
        // false, issuingDistributionPoint);
    }

    // ipAddress?

    /**
     * @see com.otterca.repository.util.X509CertificateBuilder#build(java.security
     *      .PrivateKey)
     */
    @Override
    public X509Certificate build(PrivateKey pkey) throws InvalidKeyException,
            NoSuchAlgorithmException, SignatureException,
            CertificateEncodingException, CertificateParsingException,
            KeyStoreException {

        // validate everything going into the certificate. Standard validations
        // are quick, issuer validations may require significant resources.
        validator.validate();

        generator = new X509V3CertificateGenerator();

        // set the mandatory properties
        generator.setSerialNumber(serialNumber);
        generator.setIssuerDN((issuer == null) ? issuerDN : new X509Principal(
                issuer.getIssuerDN().getName()));
        generator.setSubjectDN(subjectDN);
        generator.setNotBefore(notBefore);
        generator.setNotAfter(notAfter);
        generator.setPublicKey(pubkey);
        generator.setSignatureAlgorithm(SIGNATURE_ALGORITHM);

        // can this certificate be used to sign more certificates?
        // make sure pathLengthConstraint is always lower than issuer's.
        setBasicConstraint();
        setSKID();
        setAKID();

        setSubjectAlternativeName();
        setIssuerAlternativeName();
        setExtendedKeyUsage();
        setInhibitAnyPolicy();
        setPrivateKeyUsagePeriod();
        setNameConstraints();
        setAuthorityInfoAccess();
        setSubjectInfoAccess();

        // set/clear key usage flag.
        if (keyUsage != null) {
            if (basicConstraint) {
                keyUsage = new KeyUsage(keyUsage.intValue()
                        | KeyUsage.keyCertSign);

            } else {
                keyUsage = new KeyUsage(keyUsage.intValue()
                        & (Integer.MAX_VALUE ^ KeyUsage.keyCertSign));
            }
        } else if (basicConstraint) {
            keyUsage = new KeyUsage(KeyUsage.keyCertSign);
        }

        // add mandatory key usage constraints.
        if (keyUsage != null) {
            generator.addExtension(X509Extensions.KeyUsage, true, keyUsage);
        }

        // establish any extensions.
        for (X509ExtensionGenerator extGenerator : extensionGenerators) {
            try {
                byte[] extensionBytes = extGenerator.getExtension(
                        new X500Principal(subjectDN.getEncoded()), issuer);
                if (extensionBytes != null) {
                    X509Extensions exts = X509Extensions.getInstance(DLSequence
                            .fromByteArray(extensionBytes));
                    ASN1Encodable asn1 = exts.getExtension(
                            X509Extensions.CertificatePolicies)
                            .getParsedValue();
                    DERObjectIdentifier objectIdentifier = new DERObjectIdentifier(
                            extGenerator.getObjectIdentifier());
                    generator.addExtension(objectIdentifier,
                            extGenerator.isCritical(), asn1);
                }
            } catch (IOException e) {
                log.info("X509Extension extraction threw IOException! "
                        + e.getMessage());
                // throw an exception if this is an error in a critical
                // extension. Otherwise
                // will continue to build the certificate and count on the
                // caller's verification
                // process.
                if (extGenerator.isCritical()) {
                    X509CertificateBuilderException ex = new X509CertificateBuilderException();
                    ex.addError(ErrorType.OTHER_ERROR, e.getMessage());
                    throw ex;
                }
            }
        }

        X509Certificate cert = generator.generate(pkey);

        return cert;
    }

    /**
     * Builder that allows us to use non-standard validator. This method should
     * only be used when creating test objects.
     */
    X509Certificate build(PrivateKey pkey, boolean strict)
            throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, CertificateEncodingException,
            CertificateParsingException, KeyStoreException {
        if (strict) {
            validator = new StandardValidator();
        } else {
            validator = new NullValidator();
        }
        return build(pkey);
    }

    /**
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        ToStringBuilder builder = new ToStringBuilder(this,
                ToStringStyle.SHORT_PREFIX_STYLE);
        DateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss");

        builder.append("serialNumber", serialNumber);
        builder.append("subject", quote(subjectDN));
        builder.append("issuer", (issuer == null) ? quote(issuerDN)
                : quote(issuer.getSubjectDN()));
        builder.append("notBefore",
                (notBefore == null) ? notBefore : df.format(notBefore));
        builder.append("notAfter",
                (notAfter == null) ? notAfter : df.format(notAfter));

        if (!subjectNames.isEmpty()) {
            builder.append("altSubjectNames", quote(Arrays
                    .toString(subjectNames.toArray(emptyGeneralNameArray))));
        }

        if (!issuerNames.isEmpty()) {
            builder.append("altIssuerNames", quote(Arrays.toString(issuerNames
                    .toArray(emptyGeneralNameArray))));
        }

        return builder.toString();
    }

    /**
     * Convenience method to quote string. This is necessary since some values
     * may contain internal commas and that would mess up parsing later.
     * 
     * @param o
     * @return
     */
    String quote(@Nullable Object o) {
        if (o != null) {
            return "\"" + o.toString() + "\"";
        }
        return null;
    }

    /**
     * A 'null' validator only verifies that the mandatory fields are present.
     * It should only be used when creating test objects.
     * 
     * @author bgiles@otterca.com
     */
    class NullValidator implements X509CertificateBuilderValidator {
        public void validate() throws X509CertificateBuilderException {
            List<ErrorType> errors = new ArrayList<ErrorType>();

            if (serialNumber == null) {
                errors.add(ErrorType.MISSING_SERIAL_NUMBER);
            }
            if (subjectDN == null) {
                errors.add(ErrorType.MISSING_SUBJECT_DN);
            }
            if ((issuerDN == null) && (issuer == null)) {
                errors.add(ErrorType.MISSING_ISSUER_DN);
            }
            if (notBefore == null) {
                errors.add(ErrorType.MISSING_NOT_BEFORE_DATE);
            }
            if (notAfter == null) {
                errors.add(ErrorType.MISSING_NOT_AFTER_DATE);
            }
            if (pubkey == null) {
                errors.add(ErrorType.MISSING_PUBLIC_KEY);
            }

            if (!errors.isEmpty()) {
                X509CertificateBuilderException ex = new X509CertificateBuilderException(
                        errors);
                log.debug("{}; values: {}", ex.getMessage(), this.toString());
                throw ex;
            }
        }
    }

    /**
     * A 'standard' validator performs extensive checks to ensure that fields
     * are consistent with X509 Certificate RFC. This implementation will
     * 
     * @author bgiles@otterca.com
     */
    class StandardValidator implements X509CertificateBuilderValidator {

        /**
         * Perform standard validations
         */
        public void validate() throws X509CertificateBuilderException {
            List<ErrorType> errors = new ArrayList<ErrorType>();

            if (serialNumber == null) {
                errors.add(ErrorType.MISSING_SERIAL_NUMBER);
            }
            if (subjectDN == null) {
                errors.add(ErrorType.MISSING_SUBJECT_DN);
            }
            if ((issuerDN == null) && (issuer == null)) {
                errors.add(ErrorType.MISSING_ISSUER_DN);
            }
            if (notBefore == null) {
                errors.add(ErrorType.MISSING_NOT_BEFORE_DATE);
            }
            if (notAfter == null) {
                errors.add(ErrorType.MISSING_NOT_AFTER_DATE);
            }
            if (pubkey == null) {
                errors.add(ErrorType.MISSING_PUBLIC_KEY);
            }

            if (issuer == null) {
                // require issuer cert for everything other than self-signed
                // certs.
                if (issuerDN == null) {
                    errors.add(ErrorType.MISSING_ISSUER_DN);
                } else if (!issuerDN.equals(subjectDN)) {
                    errors.add(ErrorType.MISSING_ISSUER_CERTIFICATE);
                }
            } else {
                // verify issuer's cert is active.
                if (!(issuer.getNotBefore().before(now) && now.before(issuer
                        .getNotAfter()))) {
                    errors.add(ErrorType.INVALID_ISSUER);
                }

                // verify our 'notBefore' is within range of issuer's
                // certificate.
                if ((notBefore != null)
                        && notBefore.before(issuer.getNotBefore())) {
                    setNotBefore(issuer.getNotBefore());
                }
                if ((notBefore != null)
                        && notBefore.after(issuer.getNotAfter())) {
                    errors.add(ErrorType.UNACCEPTABLE_DATE_RANGE);
                }

                // verify our 'notAfter' is within range of issuer's
                // certificate.
                if ((notAfter != null) && notAfter.after(issuer.getNotAfter())) {
                    setNotAfter(issuer.getNotAfter());
                }
                if ((notAfter != null)
                        && notAfter.before(issuer.getNotBefore())) {
                    errors.add(ErrorType.UNACCEPTABLE_DATE_RANGE);
                }

                // verify issuer can sign certificates
                int pathLenConstraint = issuer.getBasicConstraints();
                if (pathLenConstraint < 0) {
                    errors.add(ErrorType.ISSUER_CANNOT_SIGN_CERTIFICATES);
                } else if ((pathLengthConstraint == null)
                        || (pathLenConstraint <= pathLengthConstraint)) {
                    log.debug("path length constraint must be strictly decreasing");
                    pathLengthConstraint = pathLenConstraint - 1;
                }

                // verify issuer has necessary KeyUsage flag. This is an
                // optional extension but we can reasonably demand it of
                // ourselves.
                // TODO: re-enable.
                // if ((issuer.getKeyUsage() == null) ||
                // !issuer.getKeyUsage()[5]) {
                // errors.add(ErrorType.ISSUER_CANNOT_SIGN_CERTIFICATES);
                // }

                // make sure we adhere to any name constraints (to be added)

                // verify inhibitAnyPolicy depth is decreasing. Strictly
                // speaking
                // we should follow the entire issue cert chain to find any
                // inhibitAnyPolicy extensions but we just
                Integer issuerInhibitAnyPolicy = util
                        .getInhibitAnyPolicy(issuer);
                if (issuerInhibitAnyPolicy != null) {
                    if ((inhibitAnyPolicyDepth != null)
                            && (issuerInhibitAnyPolicy < inhibitAnyPolicyDepth)) {
                        errors.add(ErrorType.INHIBIT_ANY_POLICY_DEPTH_MUST_DECREASE);
                    } else {
                        log.debug("inhibitAnyPolicy was not set even though parent had one. Setting one.");
                        inhibitAnyPolicyDepth = issuerInhibitAnyPolicy - 1;
                    }

                    // verify that specific policy is set if issuer's depth is
                    // zero.
                }
            }

            // make sure dates aren't flipped.
            if ((notBefore != null) && (notAfter != null)
                    && !notAfter.after(notBefore)) {
                errors.add(ErrorType.UNACCEPTABLE_DATE_RANGE);
            }

            // check Authority Key Identifier (RFC3280 4.2.1.1) (handled by
            // generator)

            // check Subject Key Identifier (RFC3280 4.2.1.2) (handled by
            // generator)

            // check Key Usage (RFC3280 4.2.1.3) (to be added)
            // (make sure they make sense)

            // check Private Key Usage Period (RFC3280 4.2.1.4)
            if (privateKeyUsagePeriod != null) {
                if (privateKeyUsagePeriod.getNotBefore() != null) {
                    try {
                        Date notBefore = privateKeyUsagePeriod.getNotBefore()
                                .getDate();
                        if ((notBefore != null) && !notBefore.before(now)) {
                            errors.add(ErrorType.PRIVATE_KEY_USAGE_PERIOD_VIOLATES_NOT_BEFORE);
                        }
                    } catch (ParseException e) {
                        errors.add(ErrorType.PRIVATE_KEY_USAGE_PERIOD_VIOLATES_NOT_BEFORE);
                    }
                }

                if (privateKeyUsagePeriod.getNotAfter() != null) {
                    try {
                        Date notAfter = privateKeyUsagePeriod.getNotAfter()
                                .getDate();
                        if ((notAfter != null) && !notAfter.after(now)) {
                            errors.add(ErrorType.PRIVATE_KEY_USAGE_PERIOD_VIOLATES_NOT_AFTER);
                        }
                    } catch (ParseException e) {
                        errors.add(ErrorType.PRIVATE_KEY_USAGE_PERIOD_VIOLATES_NOT_AFTER);
                    }
                }
            }

            // check Certificate Policies (RFC3280 4.2.1.5) (to be added)

            // check Policy Mappings (RFC3280 4.2.1.6) (to be added)

            // check Subject Alternative Name (RFC3280 4.2.1.7) (nothing to do)

            // check Issuer Alternative Name (RFC3280 4.2.1.8) (nothing to do)

            // check Subject Directory Attributes (RFC3280 4.2.1.9) (to be
            // added)
            // (to be implemented)

            // check Basic Constraint (RFC3280 4.2.1.10)
            // verify pathLengthConstraint is not set if basicConstraint is not
            // set.
            if (!basicConstraint && (pathLengthConstraint != null)) {
                log.debug("pathLengthConstraint must not be set if basicConstraint is not set");
                pathLengthConstraint = null;
            }

            // verify basicConstraint is not set if pathLengthConstraint is less
            // than 0.
            if ((pathLengthConstraint != null) && (pathLengthConstraint < -1)
                    && basicConstraint) {
                errors.add(ErrorType.BAD_PATH_LENGTH_CONSTRAINT_WITH_BASIC_CONSTRAINT);
            }

            // check Name Constraint (RFC3280 4.2.1.11) (to be added)

            // check Policy Constraints (RFC3280 4.2.1.12) (to be added)

            // check Extended Key Usage (RFC3280 4.2.1.13) (to be added)
            // (make sure they make sense)

            // check CRL Distribution Points (RFC3280 4.2.1.14) (to be added)

            // check Inhibit Any-Policy (RFC3280 4.2.1.15).
            // verify inhibitAnyPolicy depth is non-negative
            if (inhibitAnyPolicyDepth != null) {
                if (basicConstraint && (inhibitAnyPolicyDepth < 0)) {
                    errors.add(ErrorType.NEGATIVE_INHIBIT_ANY_POLICY_DEPTH);
                } else if (!basicConstraint) {
                    log.debug("inhibitAnyPolicy cannot be set for final certificate. Clearing it.");
                    inhibitAnyPolicyDepth = null;
                }
            }

            // check Freshest CRL (aka Delta CRL Distribution Point) (RFC3280
            // 4.2.1.16) (to be added)

            // check Set Authority Information Access (RFC5280 4.2.2) (to be
            // added)
            // (make sure general names are allowed types)

            // check Subject Information Access (RFC5280 4.2.3) (to be added)
            // (make sure general names are allowed types)

            if (!errors.isEmpty()) {
                X509CertificateBuilderException ex = new X509CertificateBuilderException(
                        errors);
                log.debug("{}; values: {}", ex.getMessage(), this.toString());
                throw ex;
            }
        }
    }
}
