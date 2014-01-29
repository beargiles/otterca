/**
 * 
 */
package com.otterca.persistence.dao;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.persistence.EntityManager;

/**
 * @author bgiles
 * 
 */
@ParametersAreNonnullByDefault
public class X509CertificateDaoJpa implements X509CertificateDao {
    // private EntityManager entityManager;

    /**
     * Injection setter.
     * 
     * @param entityManager
     */
    public void setEntityManager(EntityManager entityManager) {
        // this.entityManager = entityManager;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#put(java.security.cert
     * .X509Certificate)
     */
    @Override
    public void put(X509Certificate certificate) throws IOException {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#getCertificate(java.lang
     * .String, java.math.BigInteger)
     */
    @Override
    public X509Certificate getCertificate(String issuerDN, BigInteger serialNumber)
            throws CertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#findByCommonName(java.
     * lang.String)
     */
    @Override
    public List<X509Certificate> findByCommonName(String commonName) throws CertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#findByFingerprint(java
     * .lang.String)
     */
    @Override
    public List<X509Certificate> findByFingerprint(String fingerprint) throws CertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#findByCertificateHash(
     * java.lang.String)
     */
    @Override
    public List<X509Certificate> findByCertificateHash(String hash) throws CertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#findByIHash(java.lang.
     * String)
     */
    @Override
    public List<X509Certificate> findByIHash(String hash) throws CertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#findBySHash(java.lang.
     * String)
     */
    @Override
    public List<X509Certificate> findBySHash(String hash) throws CertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#findByAkidHash(java.lang
     * .String)
     */
    @Override
    public List<X509Certificate> findByAkidHash(String hash) throws CertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#findBySkidHash(java.lang
     * .String)
     */
    @Override
    public List<X509Certificate> findBySkidHash(String hash) throws CertificateException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.otterca.persistence.dao.X509CertificateDao#deleteCertificate(java
     * .lang .String, java.math.BigInteger)
     */
    @Override
    public void deleteCertificate(String issuerDN, BigInteger serialNumber)
            throws CertificateException {
        // TODO Auto-generated method stub
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
