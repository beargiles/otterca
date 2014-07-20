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
import java.security.cert.X509Certificate;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.security.auth.x500.X500Principal;

/**
 * Interface used by classes to generate X509Extensions. Many of these
 * extensions are discuussed in <a
 * href="http://www.ietf.org/rfc/rfc3280.txt">http
 * ://www.ietf.org/rfc/rfc3280.txt</a>.
 * 
 * Typical extensions provide:
 * <ul>
 * <li><em>Audit identity</em></li>
 * <li><em>Authority Info Access</em></li>
 * <li><em>Biometric Info<li><em>
 * <li><em>Certificate Issuer<li><em>
 * <li><em>Certificate Policies<li><em>
 * <li><em>Extended Key Usage<li><em>
 * <li><em>Inhibit Any Policy<li><em>
 * <li><em>Instruction Code<li><em>
 * <li><em>Invalidity Date<li><em>
 * <li><em>Issuing Distribution Point<li><em>
 * <li><em>Key Usage<li><em>
 * <li><em>Logo Type<li><em>
 * <li><em>Name Constraints<li><em>
 * <li><em>No Rev Avail<li><em>
 * <li><em>Policy Constraints<li><em>
 * <li><em>Policy Mappings<li><em>
 * <li><em>Private Key Usage Period<li><em>
 * <li><em>QCStatements<li><em>
 * <li><em>Subject Directory Attributes<li><em>
 * <li><em>Subject Info Access<li><em>
 * <li><em>Target Information<li><em>
 * </ul>
 * 
 * These standard extensions are already supported via the
 * X509CertificateBuilder interface:
 * 
 * <ul>
 * <li><em>Authority Key Identifier</em></li>
 * <li><em>Basic Constraints</em></li>
 * <li><em>Issuer Alternate Name</em>
 * <li><em>Key Usage<li> (only for SignCertificates)<em>
 * <li><em>Subject Alternative Names<li><em>
 * <li><em>Subject Key Identifier<li><em>
 * </ul>
 * 
 * These standard extensions are used with Certificate Revocation Lists (CRLs).
 * New development will almost certainly use Online Certificate Status Protocol
 * (OCSP) instead of CRLs.
 * 
 * <ul>
 * <li><em>CRL Distribution Points<li><em>
 * <li><em>CRL Number<li><em>
 * <li><em>Delta CRL Indicator<li><em>
 * <li><em>Fresh CRL<li><em>
 * <li><em>Reason Code<li><em>
 * </ul>
 * 
 * Finally a CA is free to create its own extensions after registering the
 * necessary OIDIdentifiers.
 * 
 * @author bgiles@otterca.com
 */
@ParametersAreNonnullByDefault
public interface X509ExtensionGenerator {

    /**
     * Get byte array containing Policy X509Extension objects: certificate
     * policy statement (CPS) urls, user notifications, etc.
     * 
     * Note: this method returns a byte array since there's no X509Extension
     * object in the standard Java libraries.
     * 
     * @param subject
     *            the subject of the certificate. It can be used to access
     *            additional information required for the certificate extension.
     *            This is especially easy with LDAP since the latter also uses
     *            X500Names.
     * @param issuer
     *            the issuer of the certificate. It can be used to access
     *            additional information required for the certificate extension,
     *            e.g., to restrict permissions that would otherwise be
     *            permitted. This value will be null for self-signed
     *            certificates.
     * 
     * @return null if no policy
     */
    byte[] getExtension(X500Principal subject, X509Certificate issuer) throws IOException;

    /**
     * Get ObjectIdentifier for extension
     */
    String getObjectIdentifier();

    /**
     * Is this a critical extension?
     */
    boolean isCritical();
}
