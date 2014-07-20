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

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.naming.InvalidNameException;

/**
 * Convenience class that creates X509Certificates. This interface does not
 * introduce any dependencies on a specific JCE implementation.
 * 
 * Implementators should carefully read <a
 * href="http://tools.ietf.org/html/rfc3280">RFC3280</a> and <a
 * href="http://tools.ietf.org/html/rfc5280">RFC5280</a>. These documents
 * contain the specification of X.509v3 certificates and standard exceptions.
 * 
 * As a broad rule certificates should be as specific as possible since users
 * can't check what's not present. Likewise the cert chain validator should be
 * as strict as possible since users may be equally strict.
 * 
 * Finally implementators may choose to create noncomplying builders for testing
 * purposes. In these cases the certs should probably contain a UserNotice that
 * the cert is intended solely for testing purposes. This won't prevent their
 * use but it can serve as a warning.
 * 
 * @author bgiles@otterca.com
 */
@ParametersAreNonnullByDefault
public interface X509CertificateBuilder {

    /**
     * Reset builder to default state.
     */
    void reset();

    /**
     * Set serial number. RFC3280-conforming CAs will not use serial numbers of
     * more than 20 octets.
     * 
     * @param serial
     * @return
     */
    X509CertificateBuilder setSerialNumber(BigInteger serial);

    /**
     * Set subject name (as X509Principal).
     * 
     * @param dirName
     * @return
     */
    X509CertificateBuilder setSubject(String dirName);

    /**
     * Set issuer name (as X509Principal).
     * 
     * @param dirName
     * @return
     */
    X509CertificateBuilder setIssuer(String dirName);

    /**
     * Set 'notBefore' date.
     * 
     * @param notBefore
     * @return
     */
    X509CertificateBuilder setNotBefore(Date notBefore);

    /**
     * Set 'notAfter' date.
     * 
     * @param notAfter
     * @return
     */
    X509CertificateBuilder setNotAfter(Date notAfter);

    /**
     * Set public key.
     * 
     * @param pubkey
     * @return
     */
    X509CertificateBuilder setPublicKey(PublicKey pubkey);

    /**
     * Set issuer's X509 certificate. This provides issuer's DN and alternate
     * names and public key.
     * 
     * @param issuer
     * @param pubkey
     * @return
     */
    X509CertificateBuilder setIssuer(X509Certificate issuer);

    /**
     * Set subject's email addresses (individual, server or CA).
     * 
     * @param emailAddresses
     * @return
     */
    X509CertificateBuilder setEmailAddresses(String... emailAddresses);

    /**
     * Set subject's DNS names (server or CA?). Note: servers should use their
     * canonical hostname as the X.500 CommonName used as their subjectDN. (See
     * above.) This provides more flexibility but many clients won't look for
     * these extensions.
     * 
     * @param dnsNames
     * @return
     */
    X509CertificateBuilder setDnsNames(String... dnsNames);

    /**
     * Set subject's IP Address (server).
     * 
     * @param ipAddresses
     * @return
     */
    X509CertificateBuilder setIpAddresses(String... ipAddresses);

    /**
     * Set subject's directory names. I think this refers to alternate X.500
     * principal names, not filesystem directories.
     * 
     * @param dirNames
     * @return
     */
    X509CertificateBuilder setDirectoryNames(String... dirNames);

    /**
     * Set issuer's email addresses (individual, server or CA).
     * 
     * @param emailAddresses
     * @return
     */
    X509CertificateBuilder setIssuerEmailAddresses(String... emailAddresses);

    /**
     * Set issuer's DNS names (server or CA?). Note: servers should use their
     * canonical hostname as the X.500 CommonName used as their subjectDN. (See
     * above.) This provides more flexibility but many clients won't look for
     * these extensions.
     * 
     * @param dnsNames
     * @return
     */
    X509CertificateBuilder setIssuerDnsNames(String... dnsNames);

    /**
     * Set issuer's IP Address (server).
     * 
     * @param ipAddresses
     * @return
     */
    X509CertificateBuilder setIssuerIpAddresses(String... ipAddresses);

    /**
     * Set issuer's directory names. I think this refers to alternate X.500
     * principal names, not filesystem directories.
     * 
     * @param dirNames
     * @return
     */
    X509CertificateBuilder setIssuerDirectoryNames(String... dirNames);

    /**
     * Set the certificate's Basic Constraint (can this certificate be used to
     * sign other certificates?). There are no restrictions on certification
     * path length.
     * 
     * @param basicConstraint
     * @return
     */
    X509CertificateBuilder setBasicConstraints(boolean basicConstraint);

    /**
     * Set the certificate's Basic Constraint (can this certificate be used to
     * sign other certificates?) and maximum certification path length. A value
     * of 0 means that this certificate can be used to sign leafs but cannot be
     * used to create other signing certs.
     * 
     * @param basicConstraint
     * @param pathLengthConstraint
     * @return
     */
    X509CertificateBuilder setBasicConstraints(boolean basicConstraint, int pathLengthConstraint);

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
     * @param values
     * @return
     */
    X509CertificateBuilder setCrlDistributionPoints(List<Object> values) throws URISyntaxException,
            InvalidNameException;

    /**
     * Get critical Inhibit anyPolicy information. This is the number of
     * additional non-self-issued certificates that may appear in the path
     * before anyPolicy is no longer permitted. This can be used constrain the
     * usage of certificates issued by subordinate certificate authorities.
     * 
     * The results are a single integer.
     * 
     * @param depth
     * @return
     */
    X509CertificateBuilder setInhibitAnyPolicy(int depth);

    /**
     * Set non-critical information about how delta CRL information is obtained.
     * 
     * The results are identical to what's provided by getCRLDistributionPoints.
     * 
     * @param values
     * @return
     */
    X509CertificateBuilder setFreshestCrl(List<Object> values) throws URISyntaxException,
            InvalidNameException;

    /**
     * Set private key usage period.
     */
    X509CertificateBuilder setPrivateKeyUsagePeriod(@Nullable Date notBefore,
            @Nullable Date notAfter);

    /**
     * Set list of permitted names (RFC 5280 4.2.1.10). This extension should
     * only appear in CA certificates, and never self-signed certificates unless
     * they're the final certificate. Applications must be able to handle
     * directoryName form and should be able to handle RFC822 Name, URI, DNS
     * name and IP address name as well.
     */
    X509CertificateBuilder setPermittedNames(String... names);

    /**
     * Set list of excluded names (RFC 5280 4.2.1.10). This extension should
     * only appear in CA certificates, and never self-signed certificates unless
     * they're the final certificate. Applications must be able to handle
     * directoryName form and should be able to handle RFC822 Name, URI, DNS
     * name and IP address name as well.
     */
    X509CertificateBuilder setExcludedNames(String... names);

    /**
     * Set locations of Online Certificate Status Protocol (OCSP) responder.
     * 
     * The results are specified in RFC 2560. It is unclear whether multiple
     * entries are permitted but it looks likely.
     */
    X509CertificateBuilder setOcspLocations(URI... locations);

    /**
     * Set locations of Online Certificate Status Protocol (OCSP) responder.
     * 
     * The results are specified in RFC 2560. It is unclear whether multiple
     * entries are permitted but it looks likely.
     */
    X509CertificateBuilder setOcspLocations(GeneralName<?>... names);

    /**
     * Set non-critical location of certificates issued TO the issuing
     * certificate authority. For instance, a departmental CA may use this to
     * provide the certificate of the organizational CA that issued the
     * departmental CA's root certificate.
     * 
     * The results may be a X500 name (using local LDAP configuration), or LDAP,
     * HTTP or FTP URI. RFC5280 4.2.2.2 specifies what must be provided in each
     * case. Multiple entries are permitted.
     */
    X509CertificateBuilder setCaIssuersLocations(URI... locations);

    /**
     * Set non-critical location of certificates issued TO the issuing
     * certificate authority. For instance, a departmental CA may use this to
     * provide the certificate of the organizational CA that issued the
     * departmental CA's root certificate.
     * 
     * The results may be a X500 name (using local LDAP configuration), or LDAP,
     * HTTP or FTP URI. RFC5280 4.2.2.2 specifies what must be provided in each
     * case. Multiple entries are permitted.
     */
    X509CertificateBuilder setCaIssuersLocations(GeneralName<?>... names);

    /**
     * Set non-critical location of certificate repository maintained by the
     * subject CA.
     * 
     * The results may be a X500 name (using local LDAP configuration), or LDAP,
     * HTTP or FTP URI. RFC5280 4.2.2.2 specifies what must be provided in each
     * case. Multiple entries are permitted.
     */
    X509CertificateBuilder setCaRepositories(URI... locations);

    /**
     * Set non-critical location of certificate repository maintained by the
     * subject CA.
     * 
     * The results may be a X500 name (using local LDAP configuration), or LDAP,
     * HTTP or FTP URI. RFC5280 4.2.2.2 specifies what must be provided in each
     * case. Multiple entries are permitted.
     */
    X509CertificateBuilder setCaRepositories(GeneralName<?>... names);

    /**
     * Set non-critical locations for timestamping service (RFC3161) offered by
     * end entity.
     * 
     * The results may be HTTP or LDAP (URI), email (RFC822), or TCP/IP (DNS or
     * IP Address). Multiple entries appear to be permitted.
     */
    X509CertificateBuilder setTimestampingLocations(URI... locations);

    /**
     * Set non-critical locations for timestamping service (RFC3161) offered by
     * end entity.
     * 
     * The results may be HTTP or LDAP (URI), email (RFC822), or TCP/IP (DNS or
     * IP Address). Multiple entries appear to be permitted.
     */
    X509CertificateBuilder setTimestampingLocations(GeneralName<?>... names);

    /**
     * Build the X509 certificate.
     * 
     * Implementation note: this uses the deprecated methods until I can find
     * documentation on using the newer classes.
     * 
     * @param pkey
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws CertificateEncodingException
     * @throws CertificateParsingException
     */
    X509Certificate build(PrivateKey pkey) throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, CertificateEncodingException, CertificateParsingException,
            KeyStoreException;
}