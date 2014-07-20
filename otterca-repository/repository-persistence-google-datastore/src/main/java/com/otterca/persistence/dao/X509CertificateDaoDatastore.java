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
import java.util.ArrayList;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;

import org.springframework.beans.factory.annotation.Autowired;

import com.google.appengine.api.datastore.Blob;
import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.Query;
import com.google.appengine.api.datastore.Query.FilterOperator;
import com.otterca.common.crypto.X509CertificateUtil;

/**
 * Implementation of X509CertificateDao.
 * 
 * Implementation note: delete certificates? don't want to do it in production
 * database but do want to do it in test databases.
 * 
 * @author bgiles@otterca.com
 */
@ParametersAreNonnullByDefault
public class X509CertificateDaoDatastore implements X509CertificateDao {
    private static final String KIND = "application/x509"; // ???
    private static final String CERTIFICATE = "certificate";
    private static final String SERIAL_NUMBER = "serialNumber";
    private static final String SUBJECT_DN = "subjectDN";
    private static final String ISSUER_DN = "issuerDN";
    private static final String NOT_BEFORE = "notBefore";
    private static final String NOT_AFTER = "notAfter";

    private static final String COMMON_NAME = "commonName";
    private static final String FINGERPRINT = "fingerprint";
    private static final String CERT_HASH = "certHash";
    private static final String SKID_HASH = "skidHash";
    private static final String AKID_HASH = "akidHash";
    private static final String SUBJECT_HASH = "sHash";
    private static final String ISSUER_HASH = "iHash";

    private static final String STATUS = "status";
    private static final String TRUSTED = "trusted";

    // TODO: pull this from enum.
    private static final String UNKNOWN = "unknown";
    // private static final String ACTIVE = "active";
    // private static final String EXPIRED = "expired";
    // private static final String REVOKED = "revoked";
    // private static final String NOT_YET_READY = "not_yet_ready";

    @Autowired
    private X509CertificateUtil x509CertUtil;

    @Autowired
    private DatastoreService datastore;

    /**
     * Default constructor.
     */
    public X509CertificateDaoDatastore() {
    }

    /**
     * Constructor used during testing.
     */
    X509CertificateDaoDatastore(DatastoreService datastore, X509CertificateUtil x509CertUtil) {
        this.datastore = datastore;
        this.x509CertUtil = x509CertUtil;
    }

    /**
     * Generate standard key.
     * 
     * @param cert
     * @return
     */
    public Key generateKey(X509Certificate cert) {
        return KeyFactory.createKey(KIND, cert.getIssuerDN() + ":"
                + cert.getSerialNumber().toString(16));
    }

    /**
     * Generate standard key.
     * 
     * @param issuerDN
     * @param serialNumber
     * @return
     */
    public Key generateKey(String issuerDN, BigInteger serialNumber) {
        return KeyFactory.createKey(KIND, issuerDN + ":" + serialNumber.toString(16));
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#put(java.security.cert
     *      .X509Certificate)
     */
    public void put(X509Certificate cert) throws IOException, CertificateEncodingException {

        // TODO: we want cert's issuer to be its parent. For now certs don't
        // have parents.
        Key key = generateKey(cert);
        Entity e = new Entity(key);

        // also set parent...

        e.setProperty(CERTIFICATE, new Blob(cert.getEncoded()));
        // up to 20 octets - 40 characters
        e.setProperty(SERIAL_NUMBER, cert.getSerialNumber().toString(16));
        // up to 500 unicode characters
        e.setProperty(SUBJECT_DN, cert.getSubjectDN().getName());
        // up to 500 unicode characters
        e.setProperty(ISSUER_DN, cert.getIssuerDN().getName());
        e.setProperty(NOT_BEFORE, cert.getNotBefore());
        e.setProperty(NOT_AFTER, cert.getNotAfter());

        // RFC search criteria
        e.setProperty(COMMON_NAME, x509CertUtil.getName(cert));
        e.setProperty(FINGERPRINT, x509CertUtil.getFingerprint(cert));
        e.setProperty(CERT_HASH, x509CertUtil.getCertificateHash(cert));
        e.setProperty(ISSUER_HASH, x509CertUtil.getIHash(cert));
        e.setProperty(SUBJECT_HASH, x509CertUtil.getSHash(cert));
        // e.setProperty(AKID_HASH, x509CertUtil.getAkidHash(cert));
        e.setProperty(SKID_HASH, x509CertUtil.getSkidHash(cert));
        // e.setProperty(IANDS_HASH, x509CertUtil.getIandSHash(cert));

        // e.setProperty(EMAIL) ?...

        e.setUnindexedProperty(TRUSTED, false);
        e.setUnindexedProperty(STATUS, UNKNOWN);

        datastore.put(e);
    }

    /**
     * Verify that cached results are consistent. It's a strong indication that
     * someone has been screwing with the database if the values are
     * inconsistent. This is computationally expensive but the cost of a
     * corrupted database is far worse.
     * 
     * @param entity
     * @param cert
     */
    public void validate(Entity entity, X509Certificate cert) throws CertificateException {
        if (!cert.getSerialNumber().equals(entity.getProperty(SERIAL_NUMBER))) {
            throw new CertificateException("serial number did not match");
        }
        if (!cert.getIssuerDN().equals(entity.getProperty(ISSUER_DN))) {
            throw new CertificateException("issuer dn did not match");
        }
        if (!cert.getSubjectDN().equals(entity.getProperty(SUBJECT_DN))) {
            throw new CertificateException("subject dn did not match");
        }
        if (!cert.getNotBefore().equals(entity.getProperty(NOT_BEFORE))) {
            throw new CertificateException("notBefore did not match");
        }
        if (!cert.getNotAfter().equals(entity.getProperty(NOT_AFTER))) {
            throw new CertificateException("notAfter did not match");
        }
        if (!x509CertUtil.getName(cert).equals(entity.getProperty(COMMON_NAME))) {
            throw new CertificateException("common name did not match");
        }
        if (!x509CertUtil.getFingerprint(cert).equals(entity.getProperty(FINGERPRINT))) {
            throw new CertificateException("cached fingerprints did not match");
        }
        if (!x509CertUtil.getCertificateHash(cert).equals(entity.getProperty(CERT_HASH))) {
            throw new CertificateException("cached certificate hash did not match");
        }
        if (!x509CertUtil.getIHash(cert).equals(entity.getProperty(ISSUER_HASH))) {
            throw new CertificateException("cached issuer hash did not match");
        }
        if (!x509CertUtil.getSHash(cert).equals(entity.getProperty(SUBJECT_HASH))) {
            throw new CertificateException("cached subject hash did not match");
        }
        if (!x509CertUtil.getAkidHash(cert).equals(entity.getProperty(AKID_HASH))) {
            throw new CertificateException("cached AKID hash did not match");
        }
        if (!x509CertUtil.getSkidHash(cert).equals(entity.getProperty(SKID_HASH))) {
            throw new CertificateException("cached SKID hash did not match");
        }
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#getCertificate(java.lang.String,
     *      java.lang.Integer)
     */
    public X509Certificate getCertificate(String issuerDN, BigInteger serialNumber)
            throws CertificateException {
        return getCertificate(generateKey(issuerDN, serialNumber));
    }

    /**
     * 
     * @param key
     * @return
     * @throws CertificateException
     */
    public X509Certificate getCertificate(Key key) throws CertificateException {
        X509Certificate cert = null;
        try {
            Entity entity = datastore.get(key);
            Blob blob = (Blob) entity.getProperty(CERTIFICATE);
            cert = x509CertUtil.getCertificate(blob.getBytes());

            validate(entity, cert);
        } catch (EntityNotFoundException e) {
            // log miss
        }
        return cert;
    }

    /**
     * Find matching certificates.
     */
    public List<X509Certificate> findByQuery(Query query) throws CertificateException {
        List<X509Certificate> results = new ArrayList<X509Certificate>();
        for (Entity entity : datastore.prepare(query).asIterable()) {
            Blob blob = (Blob) entity.getProperty(CERTIFICATE);
            X509Certificate cert = x509CertUtil.getCertificate(blob.getBytes());
            validate(entity, cert);
            results.add(cert);
        }
        return results;
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#findByCommonName(java.lang.String)
     */
    @Override
    public List<X509Certificate> findByCommonName(String commonName) throws CertificateException {
        Query query = new Query(KIND);
        query.addFilter(COMMON_NAME, FilterOperator.EQUAL, commonName);
        List<X509Certificate> certificates = findByQuery(query);

        // verify results
        for (X509Certificate cert : certificates) {
            if (!x509CertUtil.getName(cert).equals(commonName)) {
                throw new IllegalStateException(
                        "results of database were not consistent for common name '" + commonName
                                + "'");
            }
        }

        return certificates;
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#findByFingerprint(java.lang.String)
     */
    @Override
    public List<X509Certificate> findByFingerprint(String fingerprint) throws CertificateException {
        Query query = new Query(KIND);
        query.addFilter(FINGERPRINT, FilterOperator.EQUAL, fingerprint);
        List<X509Certificate> certificates = findByQuery(query);

        // verify results
        for (X509Certificate cert : certificates) {
            if (!x509CertUtil.getFingerprint(cert).equals(fingerprint)) {
                throw new IllegalStateException(
                        "results of database were not consistent for fingerprint '" + fingerprint
                                + "'");
            }
        }

        return certificates;
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#findByCertificateHash(java.lang.String)
     */
    @Override
    public List<X509Certificate> findByCertificateHash(String hash) throws CertificateException {
        Query query = new Query(KIND);
        query.addFilter(CERT_HASH, FilterOperator.EQUAL, hash);
        List<X509Certificate> certificates = findByQuery(query);

        // verify results
        for (X509Certificate cert : certificates) {
            if (!x509CertUtil.getCertificateHash(cert).equals(hash)) {
                throw new IllegalStateException(
                        "results of database were not consistent for certificate hash '" + hash
                                + "'");
            }
        }

        return certificates;
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#findByIHash(java.lang.String)
     */
    @Override
    public List<X509Certificate> findByIHash(String hash) throws CertificateException {
        Query query = new Query(KIND);
        query.addFilter(ISSUER_HASH, FilterOperator.EQUAL, hash);
        List<X509Certificate> certificates = findByQuery(query);

        // verify results
        for (X509Certificate cert : certificates) {
            if (!x509CertUtil.getIHash(cert).equals(hash)) {
                throw new IllegalStateException(
                        "results of database were not consistent for issuer hash '" + hash + "'");
            }
        }

        return certificates;
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#findBySHash(java.lang.String)
     */
    @Override
    public List<X509Certificate> findBySHash(String hash) throws CertificateException {
        Query query = new Query(KIND);
        query.addFilter(SUBJECT_HASH, FilterOperator.EQUAL, hash);
        List<X509Certificate> certificates = findByQuery(query);

        // verify results
        for (X509Certificate cert : certificates) {
            if (!x509CertUtil.getSHash(cert).equals(hash)) {
                throw new IllegalStateException(
                        "results of database were not consistent for subject hash '" + hash + "'");
            }
        }

        return certificates;
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#findByAkidHash(java.lang.String)
     */
    @Override
    public List<X509Certificate> findByAkidHash(String hash) throws CertificateException {
        Query query = new Query(KIND);
        query.addFilter(AKID_HASH, FilterOperator.EQUAL, hash);
        List<X509Certificate> certificates = findByQuery(query);

        // verify results
        for (X509Certificate cert : certificates) {
            if (!x509CertUtil.getAkidHash(cert).equals(hash)) {
                throw new IllegalStateException(
                        "results of database were not consistent for AKID hash '" + hash + "'");
            }
        }

        return certificates;
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#findBySkidHash(java.lang.String)
     */
    @Override
    public List<X509Certificate> findBySkidHash(String hash) throws CertificateException {
        Query query = new Query(KIND);
        query.addFilter(SKID_HASH, FilterOperator.EQUAL, hash);
        List<X509Certificate> certificates = findByQuery(query);

        // verify results
        for (X509Certificate cert : certificates) {
            if (!x509CertUtil.getSkidHash(cert).equals(hash)) {
                throw new IllegalStateException(
                        "results of database were not consistent for SKID hash '" + hash + "'");
            }
        }

        return certificates;
    }

    /**
     * @see com.otterca.persistence.dao.X509CertificateDao#deleteCertificate(java.lang.String,
     *      java.lang.Integer)
     */
    public void deleteCertificate(String issuerDN, BigInteger serialNumber)
            throws CertificateException {
        deleteCertificate(generateKey(issuerDN, serialNumber));
    }

    /**
     * 
     * @param key
     * @return
     * @throws CertificateException
     */
    public void deleteCertificate(Key key) throws CertificateException {
        datastore.delete(key);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#trust(java.lang.String,
     * java.math.BigInteger)
     */
    @Override
    public void trust(String issuerDN, BigInteger serialNumber) {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#distrust(java.lang.String,
     * java.math.BigInteger)
     */
    @Override
    public void distrust(String issuerDN, BigInteger serialNumber) {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#isTrusted(java.lang.String
     * , java.math.BigInteger)
     */
    @Override
    public Boolean isTrusted(String issuerDN, BigInteger serialNumber) {
        // TODO Auto-generated method stub
        return false;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#revoked(java.lang.String,
     * java.math.BigInteger, java.lang.String)
     */
    @Override
    public void revoked(String issuerDN, BigInteger serialNumber, String reason) {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#isRevoked(java.lang.String
     * , java.math.BigInteger)
     */
    @Override
    public Boolean isRevoked(String issuerDN, BigInteger serialNumber) {
        // TODO Auto-generated method stub
        return false;
    }
}
