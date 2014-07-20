package com.otterca.common.crypto;

/**
 * Interface that provides method to perform validation of fields of X509
 * Certificate before it is created.
 * 
 * @author bgiles@otterca.com
 */
public interface X509CertificateBuilderValidator {
    /**
     * Validate X509 Certificate fields.
     * 
     * @throws X509CertificateException
     */
    void validate() throws X509CertificateBuilderException;
}
