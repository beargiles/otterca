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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;

/**
 * Methods required to store and retrieve certificates from the repository.
 * 
 * FIXME: add optional 'revoked' parameter to findByX - only returns
 * certificates that are not revoked, that are revoked, or either.
 * 
 * @author bgiles@otterca.com
 */
@ParametersAreNonnullByDefault
public interface X509CertificateDao {

    /**
     * Save or update a certificate.
     * 
     * @param certificate
     * @throws CertificateEncodingException
     * @throws IOException
     */
    void put(X509Certificate certificate) throws IOException, CertificateEncodingException;

    /**
     * Retrieve a certificate by issuer DN and serial number. This is guaranteed
     * to be unique.
     * 
     * @param issuerDN
     * @param serialNumber
     * @return
     */
    X509Certificate getCertificate(String issuerDN, BigInteger serialNumber)
            throws CertificateException;

    /**
     * Search by RFC criteria 'name'
     * 
     * @param commonName
     * @return possibly empty list of matching certificates
     */
    List<X509Certificate> findByCommonName(String commonName) throws CertificateException;

    /**
     * Search by RFC criteria 'fingerprint'
     * 
     * @param fingerprint
     * @return possibly empty list of matching certificates
     */
    List<X509Certificate> findByFingerprint(String fingerprint) throws CertificateException;

    /**
     * Search by RFC criteria 'certificate hash'
     * 
     * @param hash
     * @return possibly empty list of matching certificates
     */
    List<X509Certificate> findByCertificateHash(String hash) throws CertificateException;

    /**
     * Search by RFC criteria 'issuer hash'
     * 
     * @param hash
     * @return possibly empty list of matching certificates
     */
    List<X509Certificate> findByIHash(String hash) throws CertificateException;

    /**
     * Search by RFC criteria 'subject hash'
     * 
     * @param hash
     * @return possibly empty list of matching certificates
     */
    List<X509Certificate> findBySHash(String hash) throws CertificateException;

    /**
     * Search by RFC criteria 'authority keyid hash'
     * 
     * @param hash
     * @return possibly empty list of matching certificates
     */
    List<X509Certificate> findByAkidHash(String hash) throws CertificateException;

    /**
     * Search by RFC criteria 'subject keyid hash'
     * 
     * @param hash
     * @return possibly empty list of matching certificates
     */
    List<X509Certificate> findBySkidHash(String hash) throws CertificateException;

    /**
     * Search by RFC criteria 'subject keyid hash'
     * 
     * @param email
     * @return possibly empty list of matching certificates
     */
    // List<X509Certificate> findByEmail(String email);

    /**
     * Delete a certificate by issuer DN and serial number. This method should
     * only be used in unit tests.
     * 
     * @param issuerDN
     * @param serialNumber
     * @return
     */
    void deleteCertificate(String issuerDN, BigInteger serialNumber) throws CertificateException;

    /**
     * Mark certificate as trusted.
     * 
     * @param issuerDN
     * @param serialNumber
     */
    void trust(String issuerDN, BigInteger serialNumber);

    /**
     * Mark certificate as untrusted.
     * 
     * @param issuerDN
     * @param serialNumber
     */
    void distrust(String issuerDN, BigInteger serialNumber);

    /**
     * Determine whether certificate is trusted.
     * 
     * @param issuerDN
     * @param serialNumber
     * @return
     */
    Boolean isTrusted(String issuerDN, BigInteger serialNumber);

    /**
     * Mark certificate as revoked. This will recursively mark all child
     * certificates as revoked as well.
     * 
     * @param issuerDN
     * @param serialNumber
     */
    void revoked(String issuerDN, BigInteger serialNumber, String reason);

    /**
     * Determine whether certificate is revoked.
     * 
     * @param issuerDN
     * @param serialNumber
     * @return
     */
    Boolean isRevoked(String issuerDN, BigInteger serialNumber);
}
