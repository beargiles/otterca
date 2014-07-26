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

import static org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers;
import static org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import org.bouncycastle.asn1.x509.CRLDistPoint;
//import org.bouncycastle.asn1.x509.DistributionPoint;

/**
 * Implementation of X509CertificateUtil.
 * 
 * @author bgiles@otterca.com
 */
@SuppressWarnings("deprecation")
public class X509CertificateUtilImpl implements X509CertificateUtil {
    private static final Logger LOG = LoggerFactory
            .getLogger(X509CertificateUtilImpl.class);
    private static final ASN1ObjectIdentifier id_ad_caRepositories = new ASN1ObjectIdentifier(
            "1.3.6.1.5.5.7.48.5");
    private static final ASN1ObjectIdentifier id_ad_timeStamping = new ASN1ObjectIdentifier(
            "1.3.6.1.5.5.7.48.3");

    private CertificateFactory certificateFactory;

    /**
     * Default constructor.
     */
    public X509CertificateUtilImpl() throws GeneralSecurityException {
        certificateFactory = CertificateFactory.getInstance("X.509");
    }

    /**
     * Constructor taking CertificateFactory.
     * 
     * @param certificateFactory
     */
    public X509CertificateUtilImpl(CertificateFactory certificateFactory)
            throws GeneralSecurityException {
        this();
        this.certificateFactory = certificateFactory;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getPermittedNames(X509Certificate)
     */
    @Override
    public List<GeneralSubtree> getPermittedNames(X509Certificate cert) {
        List<GeneralSubtree> results = Collections.emptyList();
        byte[] bytes = cert.getExtensionValue(X509Extensions.NameConstraints
                .toString());
        if (bytes != null) {
            try {
                DLSequence seq = (DLSequence) X509ExtensionUtil
                        .fromExtensionValue(bytes);
                for (int i = 0; i < seq.size(); i++) {
                    ASN1TaggedObject asn1 = (ASN1TaggedObject) seq
                            .getObjectAt(i);
                    if (asn1.getTagNo() == 0) {
                        results = new ArrayList<GeneralSubtree>(seq.size());
                        ASN1Sequence s = (ASN1Sequence) asn1.getObject();
                        for (int j = 0; j < s.size(); j++) {
                            org.bouncycastle.asn1.x509.GeneralSubtree subtree = org.bouncycastle.asn1.x509.GeneralSubtree
                                    .getInstance(s.getObjectAt(j));
                            // convert from bouncycastle to standard Java
                            // classes
                            X500Principal name = new X500Principal(subtree
                                    .getBase().getName().toASN1Primitive()
                                    .getEncoded());
                            results.add(new GeneralSubtree(name, subtree
                                    .getMinimum(), subtree.getMaximum()));
                        }
                    }
                }
            } catch (IOException e) {
                LOG.info("impossible IOException in X509ExtensionUtil.fromExtensionValue(): "
                        + e.getMessage(), e);
            }
        }
        return results;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getExcludedNames(X509Certificate)
     */
    @Override
    public List<GeneralSubtree> getExcludedNames(X509Certificate cert) {
        List<GeneralSubtree> results = Collections.emptyList();
        byte[] bytes = cert.getExtensionValue(X509Extensions.NameConstraints
                .toString());
        if (bytes != null) {
            try {
                DLSequence seq = (DLSequence) X509ExtensionUtil
                        .fromExtensionValue(bytes);
                for (int i = 0; i < seq.size(); i++) {
                    ASN1TaggedObject asn1 = (ASN1TaggedObject) seq
                            .getObjectAt(i);
                    if (asn1.getTagNo() == 1) {
                        results = new ArrayList<GeneralSubtree>(seq.size());
                        ASN1Sequence s = (ASN1Sequence) asn1.getObject();
                        for (int j = 0; j < s.size(); j++) {
                            org.bouncycastle.asn1.x509.GeneralSubtree subtree = org.bouncycastle.asn1.x509.GeneralSubtree
                                    .getInstance(s.getObjectAt(j));
                            // convert from bouncycastle to standard Java
                            // classes
                            X500Principal name = new X500Principal(subtree
                                    .getBase().getName().toASN1Primitive()
                                    .getEncoded());
                            results.add(new GeneralSubtree(name, subtree
                                    .getMinimum(), subtree.getMaximum()));
                        }
                    }
                }
            } catch (IOException e) {
                LOG.info("impossible IOException in X509ExtensionUtil.fromExtensionValue(): "
                        + e.getMessage(), e);
            }
        }
        return results;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getPrivateKeyUsagePeriod
     *      (java.security.cert.X509Certificate)
     */
    @Override
    public Date[] getPrivateKeyUsagePeriod(X509Certificate cert) {
        Date[] dates = new Date[0];
        byte[] bytes = cert
                .getExtensionValue(X509Extensions.PrivateKeyUsagePeriod
                        .toString());
        if (bytes != null) {
            try {
                DLSequence seq = (DLSequence) X509ExtensionUtil
                        .fromExtensionValue(bytes);
                PrivateKeyUsagePeriod period = PrivateKeyUsagePeriod
                        .getInstance(seq);
                dates = new Date[2];
                dates[0] = (period.getNotBefore() != null) ? period
                        .getNotBefore().getDate() : null;
                dates[1] = (period.getNotAfter() != null) ? period
                        .getNotAfter().getDate() : null;
            } catch (IOException e) {
                LOG.info("impossible IOException in X509ExtensionUtil.fromExtensionValue(): "
                        + e.getMessage(), e);
            } catch (ParseException e) {
                LOG.info("impossible ParseException: " + e.getMessage(), e);
            }
        }
        return dates;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.common.crypto.X509CertificateUtil#getCertificatePolicies(
     * java.security.cert.X509Certificate)
     */
    @Override
    public Object getCertificatePolicies(X509Certificate cert) {
        // TODO implement getCertificatePolicies()
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.common.crypto.X509CertificateUtil#getPolicyMappings(java.
     * security.cert.X509Certificate)
     */
    @Override
    public Object getPolicyMappings(X509Certificate cert) {
        // TODO implement getPolicyMappings()
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.common.crypto.X509CertificateUtil#getSubjectDirectoryAttributes
     * (java.security.cert.X509Certificate)
     */
    @Override
    public Object getSubjectDirectoryAttributes(X509Certificate cert) {
        // TODO implement getSubjectDirectoryAttributes()
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.common.crypto.X509CertificateUtil#getPolicyConstraints(java
     * .security.cert.X509Certificate)
     */
    @Override
    public Object getPolicyConstraints(X509Certificate cert) {
        // TODO implement getPolicyConstraints()
        return null;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getCRLDistributionPoints
     *      (java.security.cert.X509Certificate)
     */
    @Override
    public List<Object> getCrlDistributionPoints(X509Certificate cert)
            throws URISyntaxException, InvalidNameException {
        List<Object> results = Collections.emptyList();
        byte[] bytes = cert
                .getExtensionValue(X509Extensions.CRLDistributionPoints
                        .toString());
        if (bytes != null) {
            // TODO implement getCrlDistributionPoints()
            // CRLDistPoint points = CRLDistPoint.getInstance(bytes);
            // for (DistributionPoint point : points.getDistributionPoints()) {
            // }
        }
        return results;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getInhibitAnyPolicy(java
     *      .security.cert.X509Certificate)
     */
    @Override
    public Integer getInhibitAnyPolicy(X509Certificate cert) {
        Integer depth = null;
        byte[] bytes = cert.getExtensionValue(X509Extensions.InhibitAnyPolicy
                .toString());
        if (bytes != null) {
            try {
                DEROctetString asn1 = (DEROctetString) DEROctetString
                        .fromByteArray(bytes);
                // FIXME: what's actually encoded here? What's the first two
                // bytes?
                byte[] buffer = new byte[asn1.getOctets().length - 2];
                System.arraycopy(asn1.getOctets(), 2, buffer, 0, buffer.length);
                depth = (new DERInteger(buffer)).getValue().intValue();
            } catch (IOException e) {
                LOG.info("impossible IOException in X509ExtensionUtil.fromExtensionValue(): "
                        + e.getMessage(), e);
            }
        }
        return depth;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getFreshestCrl(java.security
     *      .cert.X509Certificate)
     */
    @Override
    public List<Object> getFreshestCrl(X509Certificate cert)
            throws URISyntaxException, InvalidNameException {
        List<Object> results = Collections.emptyList();
        byte[] bytes = cert.getExtensionValue(X509Extensions.SubjectInfoAccess
                .toString());
        if (bytes != null) {
            // TODO: implement getFreshestCrl()
            // CRLDistPoint points = CRLDistPoint.getInstance(bytes);
            // for (DistributionPoint point : points.getDistributionPoints()) {
            // }
        }
        return results;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getOcspLocations(X509Certificate)
     */
    @Override
    public List<com.otterca.common.crypto.GeneralName<?>> getOcspLocations(
            X509Certificate cert) throws URISyntaxException,
            InvalidNameException {
        List<com.otterca.common.crypto.GeneralName<?>> locations = Collections
                .emptyList();
        byte[] bytes = cert
                .getExtensionValue(X509Extensions.AuthorityInfoAccess
                        .toString());
        if (bytes != null) {
            try {
                DLSequence seq = (DLSequence) X509ExtensionUtil
                        .fromExtensionValue(bytes);
                locations = new ArrayList<com.otterca.common.crypto.GeneralName<?>>(
                        seq.size());
                for (int i = 0; i < seq.size(); i++) {
                    AccessDescription desc = AccessDescription.getInstance(seq
                            .getObjectAt(i));
                    if (id_ad_ocsp.equals(desc.getAccessMethod())) {
                        switch (desc.getAccessLocation().getTagNo()) {
                        case GeneralName.directoryName:
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.Directory(
                                            new LdapName(desc
                                                    .getAccessLocation()
                                                    .getName().toString())));
                            break;
                        case GeneralName.uniformResourceIdentifier:
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.URI(
                                            ((DERIA5String) desc
                                                    .getAccessLocation()
                                                    .getName()).getString()));
                            break;
                        default:
                            LOG.info("unexpected GeneralName type "
                                    + desc.getAccessLocation().getTagNo()
                                    + " in certificate OCSPLocations extension");
                            break;
                        }
                    }
                }
            } catch (IOException e) {
                LOG.info("impossible IOException in X509ExtensionUtil.fromExtensionValue(): "
                        + e.getMessage(), e);
            }
        }
        return locations;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getCaIssuersLocations(X509Certificate)
     */
    @Override
    public List<com.otterca.common.crypto.GeneralName<?>> getCaIssuersLocations(
            X509Certificate cert) throws URISyntaxException,
            InvalidNameException {
        List<com.otterca.common.crypto.GeneralName<?>> locations = Collections
                .emptyList();
        byte[] bytes = cert
                .getExtensionValue(X509Extensions.AuthorityInfoAccess
                        .toString());
        if (bytes != null) {
            try {
                DLSequence seq = (DLSequence) X509ExtensionUtil
                        .fromExtensionValue(bytes);
                locations = new ArrayList<com.otterca.common.crypto.GeneralName<?>>(
                        seq.size());
                for (int i = 0; i < seq.size(); i++) {
                    AccessDescription desc = AccessDescription.getInstance(seq
                            .getObjectAt(i));
                    if (id_ad_caIssuers.equals(desc.getAccessMethod())) {
                        switch (desc.getAccessLocation().getTagNo()) {
                        case GeneralName.directoryName:
                            LdapName name = new LdapName(((X500Name) desc
                                    .getAccessLocation().getName()).toString());
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.Directory(
                                            name));
                            break;
                        case GeneralName.uniformResourceIdentifier:
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.URI(
                                            ((DERIA5String) desc
                                                    .getAccessLocation()
                                                    .getName()).getString()));
                            break;
                        default:
                            LOG.info("unexpected GeneralName type "
                                    + desc.getAccessLocation().getTagNo()
                                    + " in certificate CaIssuersLocations extension");
                        }
                    }
                }
            } catch (IOException e) {
                LOG.info("impossible IOException in X509ExtensionUtil.fromExtensionValue(): "
                        + e.getMessage(), e);
            }
        }
        return locations;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getCaRepositories(java.
     *      security.cert.X509Certificate)
     */
    @Override
    public List<com.otterca.common.crypto.GeneralName<?>> getCaRepositories(
            X509Certificate cert) throws InvalidNameException,
            URISyntaxException {
        List<com.otterca.common.crypto.GeneralName<?>> locations = Collections
                .emptyList();
        byte[] bytes = cert.getExtensionValue(X509Extensions.SubjectInfoAccess
                .toString());
        if (bytes != null) {
            try {
                DLSequence seq = (DLSequence) X509ExtensionUtil
                        .fromExtensionValue(bytes);
                locations = new ArrayList<com.otterca.common.crypto.GeneralName<?>>(
                        seq.size());
                for (int i = 0; i < seq.size(); i++) {
                    AccessDescription desc = AccessDescription.getInstance(seq
                            .getObjectAt(i));
                    if (id_ad_caRepositories.equals(desc.getAccessMethod())) {
                        switch (desc.getAccessLocation().getTagNo()) {
                        case GeneralName.directoryName:
                            LdapName name = new LdapName(((X500Name) desc
                                    .getAccessLocation().getName()).toString());
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.Directory(
                                            name));
                            break;
                        case GeneralName.uniformResourceIdentifier:
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.URI(
                                            ((DERIA5String) desc
                                                    .getAccessLocation()
                                                    .getName()).getString()));
                            break;
                        default:
                            LOG.info("unexpected GeneralName type "
                                    + desc.getAccessLocation().getTagNo()
                                    + " in certificate CaRepositories extension");
                        }
                    }
                }
            } catch (IOException e) {
                LOG.info("impossible IOException in X509ExtensionUtil.fromExtensionValue(): "
                        + e.getMessage(), e);
            }
        }
        return locations;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getTimestamping(java.security
     *      .cert.X509Certificate)
     */
    @Override
    public List<com.otterca.common.crypto.GeneralName<?>> getTimestamping(
            X509Certificate cert) throws InvalidNameException,
            URISyntaxException {
        List<com.otterca.common.crypto.GeneralName<?>> locations = Collections
                .emptyList();
        byte[] bytes = cert.getExtensionValue(X509Extensions.SubjectInfoAccess
                .toString());
        if (bytes != null) {
            try {
                DLSequence seq = (DLSequence) X509ExtensionUtil
                        .fromExtensionValue(bytes);
                locations = new ArrayList<com.otterca.common.crypto.GeneralName<?>>(
                        seq.size());
                for (int i = 0; i < seq.size(); i++) {
                    AccessDescription desc = AccessDescription.getInstance(seq
                            .getObjectAt(i));
                    if (id_ad_timeStamping.equals(desc.getAccessMethod())) {
                        switch (desc.getAccessLocation().getTagNo()) {
                        case GeneralName.dNSName:
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.DNS(
                                            desc.getAccessLocation().getName()
                                                    .toString()));
                            break;
                        case GeneralName.uniformResourceIdentifier:
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.URI(
                                            ((DERIA5String) desc
                                                    .getAccessLocation()
                                                    .getName()).getString()));
                            break;
                        case GeneralName.rfc822Name:
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.Email(
                                            ((DERIA5String) desc
                                                    .getAccessLocation()
                                                    .getName()).getString()));
                            break;
                        case GeneralName.iPAddress:
                            locations
                                    .add(new com.otterca.common.crypto.GeneralName.IpAddress(
                                            InetAddress
                                                    .getByAddress(((DEROctetString) desc
                                                            .getAccessLocation()
                                                            .getName())
                                                            .getOctets())));
                            break;
                        default:
                            LOG.info("unexpected GeneralName type "
                                    + desc.getAccessLocation().getTagNo()
                                    + " in certificate TimeStamping extension");
                        }
                    }
                }
            } catch (IOException e) {
                LOG.info("impossible IOException in X509ExtensionUtil.fromExtensionValue(): "
                        + e.getMessage(), e);
            }
        }
        return locations;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.common.crypto.X509CertificateUtil#getIssuingDistributionPoint
     * (java.security.cert.X509Certificate)
     */
    @Override
    public List<Object> getIssuingDistributionPoint(X509Certificate cert) {
        // TODO implement getIssuingDistributionPoint()
        return null;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getCertificate(byte[])
     */
    @Override
    public X509Certificate getCertificate(byte[] bytes)
            throws CertificateException {
        InputStream is = null;
        X509Certificate cert = null;
        try {
            is = new ByteArrayInputStream(bytes);
            cert = (X509Certificate) certificateFactory.generateCertificate(is);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    LOG.info(
                            "impossible exception closing ByteArrayInputStream: {}",
                            e.getMessage(), e);
                }
            }
        }
        return cert;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getName(java.security.cert.X509Certificate)
     */
    @Override
    public String getName(X509Certificate cert)
            throws CertificateEncodingException {
        X500Principal subject = cert.getSubjectX500Principal();
        return subject.getName("RFC2253",
                Collections.singletonMap("CN oid", (String) null)); // FIXME
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getFingerprint(java.security.cert.X509Certificate)
     */
    @Override
    public String getFingerprint(X509Certificate cert)
            throws CertificateEncodingException {
        return toHex(DigestUtils.sha(cert.getEncoded()));
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getCertificateHash(java.security.cert.X509Certificate)
     */
    @Override
    public String getCertificateHash(X509Certificate cert)
            throws CertificateEncodingException {
        return rfc4387(cert.getEncoded());
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getIHash(java.security.cert.X509Certificate)
     */
    @Override
    public String getIHash(X509Certificate cert)
            throws CertificateEncodingException {
        return rfc4387(cert.getIssuerX500Principal().getEncoded());
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getSHash(java.security.cert.X509Certificate)
     */
    @Override
    public String getSHash(X509Certificate cert)
            throws CertificateEncodingException {
        return rfc4387(cert.getSubjectX500Principal().getEncoded());
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getAkidHash(java.security.cert.X509Certificate)
     */
    @Override
    public String getAkidHash(X509Certificate cert)
            throws CertificateEncodingException {
        String results = null;
        byte[] bytes = cert
                .getExtensionValue(X509Extensions.AuthorityKeyIdentifier
                        .toString());
        if (bytes != null) {
            AuthorityKeyIdentifier sis = AuthorityKeyIdentifierStructure
                    .getInstance(bytes);
            results = rfc4387(sis.getKeyIdentifier());
        }
        return results;
    }

    /**
     * @see com.otterca.common.crypto.X509CertificateUtil#getSkidHash(java.security.cert.X509Certificate)
     */
    @Override
    public String getSkidHash(X509Certificate cert)
            throws CertificateEncodingException {
        String results = null;
        byte[] bytes = cert
                .getExtensionValue(X509Extensions.SubjectKeyIdentifier
                        .toString());
        if (bytes != null) {
            SubjectKeyIdentifier sis = SubjectKeyIdentifierStructure
                    .getInstance(bytes);
            results = rfc4387(sis.getKeyIdentifier());
        }
        return results;
    }

    /**
     * Compute SHA1 hash of DER-encoded value, encode it using Base64, and drop
     * the trailing '='.
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
     * efficient. :-)
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
