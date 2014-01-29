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
package com.otterca.persistence.entity;

import static javax.persistence.GenerationType.AUTO;
import static javax.persistence.TemporalType.TIMESTAMP;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.Transient;

import org.springframework.beans.factory.annotation.Autowired;

import com.otterca.common.crypto.X509CertificateUtil;

/**
 * Persisted information about an X509 Certificate.
 * 
 * - the certificate itself (in DER format) - certificate status (ACTIVE,
 * EXPIRED, REVOKED, etc.) - revocation date - revocation reason
 * 
 * - the subjectDN (cached for searches) - the issuerDN (cached for searches) -
 * the 'notBefore' date (cached for searches) - the 'notAfter' date (cached for
 * searches)
 * 
 * - the fingerprint or 'certHash' (base64, for lookup per RFC4387) - the sHash
 * (base 64, for lookup per RFC4387) - the iHash (base 64, for lookup per
 * RFC4387) - the sKIDHash (base64, for lookup per RFC4387)
 * 
 * - the subject key identifier (hex, for lookup) - the aKIDHash (for recursive
 * lookups) - the issuer key identifier (hex, for recursive lookup)
 * 
 * (not yet implemented - RFC2585-specified values for name, iAndSHash and uri
 * searches)
 * 
 * Note: 'fingerprint' is consistent with OpenSSL but subject hash is not. The
 * RFC specification is followed.
 * 
 * @author bgiles@otterca.com
 */
@Entity
@Table(name = "certificate")
@ParametersAreNonnullByDefault
public class X509CertificateEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final CertificateFactory certificateFactory;

    @Autowired
    private transient X509CertificateUtil x509CertUtil;

    @Id
    @GeneratedValue(strategy = AUTO)
    @Column(name = "cert_id")
    private Long id;

    @Column(name = "serial_no", nullable = false, length = 40)
    private BigInteger serialNumber;

    @Column(name = "cert", nullable = false, length = 1000)
    private byte[] certificate;

    @Column(name = "subject", nullable = false, length = 200)
    private String subject;

    @Column(name = "issuer", nullable = false, length = 200)
    private String issuer;

    @Temporal(TIMESTAMP)
    @Column(name = "not_before", nullable = false)
    private Date notBefore;

    @Temporal(TIMESTAMP)
    @Column(name = "not_after", nullable = false)
    private Date notAfter;

    @Column(name = "name", nullable = false, length = 80)
    private String name;

    @Column(name = "fingerprint", nullable = false, length = 80)
    private String fingerprint;

    @Column(name = "cert_hash", nullable = false, length = 40)
    private String certHash;

    @Column(name = "subject_hash", nullable = false, length = 28)
    private String sHash;

    @Column(name = "issuer_hash", nullable = false, length = 28)
    private String iHash;

    // @Column(name = "subject_key_id", nullable = false, length = 80)
    // private String skid;

    @Column(name = "skid_hash", nullable = true, length = 28)
    private String skidHash;

    // @Column(name = "authority_key_id", nullable = false, length = 80)
    // private String akid;

    @Column(name = "akid_hash", nullable = true, length = 28)
    private String akidHash;

    // @Column(name = "iands_hash", nullable = true, length = 28)
    // private String iAndSHash;

    @Enumerated
    @Column(name = "cert_status", nullable = false, length = 15)
    private Status status = Status.UNKNOWN;

    public enum Status {
        UNKNOWN, ACTIVE, EXPIRED, REVOKED, NOT_YET_VALID
    };

    @Transient
    private Date revocationDate;

    @Transient
    private int reasonCode;

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /**
     * Default constructor.
     */
    public X509CertificateEntity() {

    }

    /**
     * Copy constructor
     */
    public X509CertificateEntity(X509Certificate cert) throws CertificateEncodingException,
            NoSuchAlgorithmException, IOException {

        if (cert == null) {
            throw new IllegalArgumentException("cert must not be null");
        }

        cacheAttributes(cert);
    }

    /**
     * Cache values within certificate. They should never be set directly and
     * the actual values in the database should be created via triggers.
     * 
     * @param cert
     */
    protected final void cacheAttributes(X509Certificate cert) throws CertificateEncodingException,
            IOException {
        serialNumber = cert.getSerialNumber();
        certificate = cert.getEncoded();
        subject = cert.getSubjectDN().getName();
        issuer = cert.getIssuerDN().getName();
        notBefore = cert.getNotBefore();
        notAfter = cert.getNotAfter();

        name = x509CertUtil.getName(cert);
        fingerprint = x509CertUtil.getFingerprint(cert);
        certHash = x509CertUtil.getCertificateHash(cert);
        iHash = x509CertUtil.getIHash(cert);
        sHash = x509CertUtil.getSHash(cert);
        akidHash = x509CertUtil.getAkidHash(cert);
        skidHash = x509CertUtil.getSkidHash(cert);
    }

    /**
     * @return the id
     */
    public Long getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * @return the serialNumber
     */
    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    /**
     * @return the subject
     */
    public String getSubject() {
        return subject;
    }

    /**
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * @return the notBefore
     */
    public Date getNotBefore() {
        return new Date(notBefore.getTime());
    }

    /**
     * @return the notAfter
     */
    public Date getNotAfter() {
        return new Date(notAfter.getTime());
    }

    /**
     * @return the subject's comon name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the certificate hash (RFC4387 certHash)
     */
    public String getCertificateHash() {
        return certHash;
    }

    /**
     * @return the issuer hash (RFC4387 iHash)
     */
    public String getIssuerHash() {
        return iHash;
    }

    /**
     * @return the subject hash (RFC4387 sHash)
     */
    public String getSubjectHash() {
        return sHash;
    }

    /**
     * @return the authority keyid hash (RFC4387 aKIDHash)
     */
    public String getAkidHash() {
        return akidHash;
    }

    /**
     * @return the subject keyid hash (RFC4387 sKIDHash)
     */
    public String getSkidHash() {
        return skidHash;
    }

    /**
     * @return the certificate (DER-encoded)
     */
    public byte[] getCertificate() {
        byte[] value = new byte[certificate.length];
        System.arraycopy(certificate, 0, value, 0, certificate.length);
        return value;
    }

    /**
     * @return the certificate's fingerprint (compatible with openssl)
     */
    public String getFingerprint() {
        return fingerprint;
    }

    /**
     * @param certificate
     *            the certificate to set
     */
    public void setCertificate(byte[] certificate) {
        // create defensive copy
        this.certificate = new byte[certificate.length];
        System.arraycopy(certificate, 0, this.certificate, 0, certificate.length);
    }

    /**
     * @return the status
     */
    public Status getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(Status status) {
        this.status = status;
    }

    /**
     * @return the revocationDate
     */
    public Date getRevocationDate() {
        return new Date(revocationDate.getTime());
    }

    /**
     * @param revocationDate
     *            the revocationDate to set
     */
    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = new Date(revocationDate.getTime());
    }

    /**
     * The 'reason code' is a bit-mapped reason why a certificate has been
     * revoked. RFC3280 specifies the bits as
     * 
     * <ul>
     * <li>0: unusued</li>
     * <li>1: key compromised</li>
     * <li>2: CA compromised</li>
     * <li>3: affiliation changed</li>
     * <li>4: superceded</li>
     * <li>5: cesssation of operation</li>
     * <li>6: certificate hold</li>
     * <li>7: privilege withdrawn</li>
     * <li>8: AA compromise</li>
     * </ul>
     * 
     * @return the reasonCode
     */
    public int getRevocationReason() {
        return reasonCode;
    }

    /**
     * @param reasonCode
     *            the reasonCode to set
     */
    public void setReasonCode(int reasonCode) {
        this.reasonCode = reasonCode;
    }

    /**
     * 
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    public X509Certificate getX509Certificate() throws IOException, CertificateException {
        if (certificate == null) {
            return null;
        }

        InputStream is = null;
        X509Certificate cert = null;
        try {
            is = new ByteArrayInputStream(certificate);
            cert = (X509Certificate) certificateFactory.generateCertificate(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }
        return cert;
    }
}
