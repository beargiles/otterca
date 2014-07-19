package com.otterca.certificateAuthority;

import java.security.KeyStore;

import javax.security.cert.X509Certificate;

public interface CertificateAuthorityService {
	/**
	 * Create and sign a certificate. The subject must be signed
	 * by a valid Registration Authority key. (This is the way the
	 * RA indicates that the subject has been properly vetted.)
	 * 
	 * @param caId
	 * @param subject
	 * @return
	 */
	X509Certificate sign(String caId, X509Certificate subject);

	/**
	 * Create and sign a self-signed certificate. The subject can be
	 * self-signed. This method is useful during initial development
	 * work but should be removed/disabled in production.
	 * 
	 * @param caId
	 * @param subject
	 * @return
	 */
	X509Certificate signSelfSignedCertificate(String caId, X509Certificate subject);

	/**
	 * Generate a random keypair and random CA keypair.
     *
	 * @param caId
	 * @return
	 */
	KeyStore generateKey(String policyId);

	/**
	 * Generate a random keypair and sign with the specified CA key.
     *
	 * @param caId
	 * @return
	 */
	KeyStore generateKey(String policyId, String caId);
}
