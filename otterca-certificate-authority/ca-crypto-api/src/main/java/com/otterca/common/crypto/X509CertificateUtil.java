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

import java.net.URISyntaxException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.naming.InvalidNameException;

/**
 * Utilities for X509Certificates.
 * 
 * The standard extensions are:
 * 
 * <ul>
 * <li>Authority Key Identifier (RFC5280 4.2.1.1) - use X509Certificate method</li>
 * <li>Subject Key Identifier (RFC5280 4.2.1.2) - use X509Certificate method</li>
 * <li>Key Usage (RFC5280 4.2.1.3) - use X509Certificate method</li>
 * <li>Certificate Policies (RFC5280 4.2.1.4) - see below</li>
 * <li>Policy Mappings (RFC5280 4.2.1.5) - see below</li>
 * <li>Subject Alternative Name (RFC5280 4.2.1.6) - use X509Certificate method</li>
 * <li>Issuer Alternative Name (RFC5280 4.2.1.7) - use X509Certificate method</li>
 * <li>Subject Directory Attributes (RFC5280 4.2.1.8) - see below</li>
 * <li>Basic Constraints (RFC5280 4.2.1.9) - use X509Certificate method</li>
 * <li>Name Constraints (RFC5280 4.2.1.10) - see below. Must only appear in CA
 * certificates.</li>
 * <li>Policy Constraits (RFC5280 4.2.1.11) - see below. Must only appear in CA
 * certificates.</li>
 * <li>Extended Key Usage (RFC5280 4.2.1.12) - use X509Certificate method</li>
 * <li>CRL Distribution Points (RFC5280 4.2.1.13) - see below</li>
 * <li>Inhibit anyPolicy (RFC5280 4.2.1.14) - see below</li>
 * <li>Fresh CRL (Delta CRL Distribution Point) (RFC5280 4.2.1.15) - see below</li>
 * <li>Authority Information Access (RFC5280 4.2.2.1) - see below. This includes
 * OCSP responders and cross-certification information.</li>
 * <li>Subject Information Access (RFC5280 4.2.2.2) - see below. This includes
 * CA repository location and Time Stamp Protocol (RFC3161) server.</li>
 * </ul>
 * 
 * @author bgiles@otterca.com
 */
@ParametersAreNonnullByDefault
public interface X509CertificateUtil {

    /**
     * Get CertificatePolicies (RFC 5280 4.2.1.4). Certificate policies may be a
     * Certificate Policy Statement (CPS) URI or a user notice. Notice
     * references are deprecated and not returned.
     * 
     * A special policy of "anyPolicy" (2.5.29.32.0) can be used to specify that
     * no policies for the certification path are required. (See
     * MaxLengthAnyPolicy below.)
     */
    // Map<OID, PollcyInformation[]>
    Object getCertificatePolicies(X509Certificate cert);

    /**
     * Get Certificate PolicyMappings (RFC 5280 4.2.1.5) between issuer
     * certificate policies and subject certificate policies.
     * 
     * @param cert
     * @return
     */
    // List<OID[2]>
    Object getPolicyMappings(X509Certificate cert);

    /**
     * Get Subject Directory Attributes (RFC 5280 4.2.1.8). This is a way to
     * provide additional information about the subject, e.g., nationality.
     * 
     * @param cert
     * @return
     */
    Object getSubjectDirectoryAttributes(X509Certificate cert);

    /**
     * Get list of permitted names (RFC 5280 4.2.1.10). This extension should
     * only appear in CA certificates, and never self-signed certificates unless
     * they're the final certificate. Applications must be able to handle
     * directoryName form and should be able to handle RFC822 Name, URI, DNS
     * name and IP address name as well.
     * 
     * @param cert
     * @return
     */
    List<GeneralSubtree> getPermittedNames(X509Certificate cert);

    /**
     * Get list of permitted names (RFC 5280 4.2.1.10). This extension should
     * only appear in CA certificates, and never self-signed certificates unless
     * they're the final certificate. Applications must be able to handle
     * directoryName form and should be able to handle RFC822 Name, URI, DNS
     * name and IP address name as well.
     * 
     * @param cert
     * @return
     */
    List<GeneralSubtree> getExcludedNames(X509Certificate cert);

    /**
     * Get policy constraints (RFC 5280 4.2.1.11). This extension should only
     * appear in CA certificates.
     * 
     * @param cert
     * @return
     */
    Object getPolicyConstraints(X509Certificate cert);

    // Extensions below this point documents.

    /**
     * Get non-critical CRL distribution points. A distribution point contains
     * three optional elements - a DistributionPoint, Reasons and CRLIssuer.
     * Either (or both) DistributionPoint or CRLIssuer is required.
     * 
     * A distribution point contains either a single value
     * (nameRelativeToCRLIssuer) or a sequence of GeneralName. A GeneralName can
     * be either an X500Name (using local LDAP configuration) or an LDAP, HTTP
     * or FTP URI. RFC5280 4.2.1.13 specifies what must be provided in each
     * case.
     * 
     * The CRLIssuer, if present, must contain only the X500 distinguished name
     * from the issuer field of the CRL that the DistributionPoint refers to.
     * 
     * The reason flags are:
     * <ul>
     * <li>Unused (0)</li>
     * <li>Key Compromise (1)</li>
     * <li>CA Compromise (2)</li>
     * <li>Affiliation Changed (3)</li>
     * <li>Superseded (4)</li>
     * <li>Cessation of Operation (5)</li>
     * <li>Certificate Hold (6)</li>
     * <li>Privilege Withdrawn (7)</li>
     * <li>AA Compromise (8)</li>
     * </ul>
     * 
     * @param cert
     * @return
     */
    List<Object> getCrlDistributionPoints(X509Certificate cert) throws URISyntaxException,
            InvalidNameException;

    /**
     * Get critical Inhibit anyPolicy information. This is the number of
     * additional non-self-issued certificates that may appear in the path
     * before anyPolicy is no longer permitted. This can be used constrain the
     * usage of certificates issued by subordinate certificate authorities.
     * 
     * The results are a single integer.
     * 
     * @param cert
     * @return
     */
    Integer getInhibitAnyPolicy(X509Certificate cert);

    /**
     * Get non-critical information about how delta CRL information is obtained.
     * 
     * The results are identical to what's provided by getCRLDistributionPoints.
     * 
     * @param cert
     * @return
     */
    List<Object> getFreshestCrl(X509Certificate cert) throws URISyntaxException,
            InvalidNameException;

    /**
     * Get non-critical location of certificates issued TO the issuing
     * certificate authority. For instance, a departmental CA may use this to
     * provide the certificate of the organizational CA that issued the
     * departmental CA's root certificate.
     * 
     * The results may be a X500 name (using local LDAP configuration), or LDAP,
     * HTTP or FTP URI. RFC5280 4.2.2.2 specifies what must be provided in each
     * case. Multiple entries are permitted.
     * 
     * @param cert
     * @return
     * @throws URISyntaxException
     */
    List<GeneralName<?>> getCaIssuersLocations(X509Certificate cert) throws URISyntaxException,
            InvalidNameException;

    /**
     * Get locations of Online Certificate Status Protocol (OCSP) responder.
     * 
     * The results are specified in RFC 2560. It is unclear whether multiple
     * entries are permitted but it looks likely.
     * 
     * @param cert
     * @return
     * @throws URISyntaxException
     */
    List<GeneralName<?>> getOcspLocations(X509Certificate cert) throws URISyntaxException,
            InvalidNameException;

    /**
     * Get non-critical location of certificate repository maintained by the
     * subject CA.
     * 
     * The results may be a X500 name (using local LDAP configuration), or LDAP,
     * HTTP or FTP URI. RFC5280 4.2.2.2 specifies what must be provided in each
     * case. Multiple entries are permitted.
     * 
     * @param cert
     * @return
     */
    List<GeneralName<?>> getCaRepositories(X509Certificate cert) throws URISyntaxException,
            InvalidNameException;

    /**
     * Get non-critical locations for timestamping service (RFC3161) offered by
     * end entity.
     * 
     * The results may be HTTP or LDAP (URI), email (RFC822), or TCP/IP (DNS or
     * IP Address). Multiple entries appear to be permitted.
     * 
     * @param cert
     * @return
     */
    List<GeneralName<?>> getTimestamping(X509Certificate cert) throws InvalidNameException,
            URISyntaxException;

    /**
     * 
     * @param cert
     * @return
     */
    Date[] getPrivateKeyUsagePeriod(X509Certificate cert);

    /**
     * 
     * @param cert
     * @return
     */
    List<Object> getIssuingDistributionPoint(X509Certificate cert);

    /**
     * Get a certificate from a byte array. This is a convenience wrapper for
     * the standard CertificateFactory class but handles the setup and exception
     * handling.
     */
    X509Certificate getCertificate(byte[] bytes) throws CertificateException;

    /**
     * Get the subject's common name.
     */
    String getName(X509Certificate cert) throws CertificateEncodingException;

    /**
     * Get the certificate's fingerprint. This is the SHA1 hash of the entire
     * certificate presented in colon-separated hex format. It is used to find
     * certificates in a repository.
     * 
     * @param cert
     * @return
     */
    String getFingerprint(X509Certificate cert) throws CertificateEncodingException;

    /**
     * Get the certificate's certHash. This is the SHA1 hash of the entire
     * certificate presented in RFC4387 format. It is used to find certificates
     * in a repository.
     * 
     * @param cert
     * @return
     */
    String getCertificateHash(X509Certificate cert) throws CertificateEncodingException;

    /**
     * Get the certificate's iHash. This is the SHA1 hash of the IssuerDN
     * presented in RFC4387 format. It is used to find certificates in a
     * repository.
     * 
     * @param cert
     * @return
     */
    String getIHash(X509Certificate cert) throws CertificateEncodingException;

    /**
     * Get the certificate's sHash. This is the SHA1 hash of the subjectDN
     * presented in RFC4387 format. It is used to find certificates in a
     * repository.
     * 
     * @param cert
     * @return
     */
    String getSHash(X509Certificate cert) throws CertificateEncodingException;

    /**
     * Get the certificate's AKID Hash. It is used to find certificates in a
     * repository.
     * 
     * @param cert
     * @return
     */
    String getAkidHash(X509Certificate cert) throws CertificateEncodingException;

    /**
     * Get the certificate's SKID Hash. It is used to find certificates in a
     * repository.
     * 
     * @param cert
     * @return
     */
    String getSkidHash(X509Certificate cert) throws CertificateEncodingException;
}
